//! The runtime form of a snapshot: lookup structures the request path reads
//! without parsing, hashing strings into new allocations or resolving names.

use std::collections::HashMap;
use std::fmt;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use foldhash::fast::FixedState;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use pcre2::bytes::{CaptureLocations, Regex, RegexBuilder};
use proxelo_api::snapshot::v1::{
    self as ir, NextUpstream, action, error_page, host_match, listener_tls, path_match, rewrite,
    try_files, upstream,
};

use crate::access::{self, Access, Bandwidth, ConnZone, RateZone, RealIp};
use crate::compression::{self, Compression};
use crate::cond::{Cond, Facts};
use crate::lookup::{self, Lookup};
use crate::template::Template;

type Map<V> = HashMap<Box<[u8]>, V, FixedState>;

/// A loaded snapshot. Indexes match the IR arrays it was built from.
#[derive(Debug)]
pub struct Runtime {
    pub revision: u64,
    pub listeners: Box<[Listener]>,
    pub sites: Box<[Site]>,
    pub upstreams: Box<[Upstream]>,
    pub certificates: Box<[Certificate]>,
    pub access_logs: Box<[AccessLog]>,
    pub rate_zones: Box<[RateZone]>,
    pub conn_zones: Box<[ConnZone]>,
    /// Variables of map, geo and split_clients, by `Part::Lookup` index.
    pub lookups: Arc<[Lookup]>,
    /// Compression settings of routes and sites, by their index.
    pub compressions: Arc<[Compression]>,
}

/// A parsed certificate chain and its private key.
#[derive(Debug)]
pub struct Certificate {
    pub id: Box<str>,
    /// Leaf first.
    pub chain: Box<[X509]>,
    pub key: PKey<Private>,
}

impl Certificate {
    /// Parses PEM and checks that the key belongs to the leaf.
    pub fn parse(id: &str, chain_pem: &[u8], key_pem: &[u8]) -> Result<Self, String> {
        let chain = X509::stack_from_pem(chain_pem).map_err(|e| format!("chain: {e}"))?;
        if chain.is_empty() {
            return Err("chain: no certificate".into());
        }
        let key = PKey::private_key_from_pem(key_pem).map_err(|e| format!("key: {e}"))?;
        let public = chain[0].public_key().map_err(|e| format!("chain: {e}"))?;
        if !public.public_eq(&key) {
            return Err("key does not match the certificate".into());
        }
        Ok(Self {
            id: id.into(),
            chain: chain.into(),
            key,
        })
    }
}

#[derive(Debug)]
pub struct AccessLog {
    /// "stdout", "stderr" or an absolute path.
    pub path: Box<str>,
    pub format: Template,
    pub escape_json: bool,
}

/// TLS settings of a listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerTls {
    /// 0x0301 (TLS 1.0) to 0x0304 (TLS 1.3).
    pub min_version: u16,
    pub ciphers: Box<str>,
    pub default_certificate: Option<u32>,
}

/// Changes to a header list: remove, then set, then add.
#[derive(Debug, Default)]
pub struct HeaderOps {
    pub set: Box<[HeaderValue]>,
    pub add: Box<[HeaderValue]>,
    /// Lowercase names.
    pub remove: Box<[Box<[u8]>]>,
}

impl HeaderOps {
    pub fn is_empty(&self) -> bool {
        self.set.is_empty() && self.add.is_empty() && self.remove.is_empty()
    }

    /// Whether the original header `name` is dropped: removed or replaced.
    pub fn drops(&self, name: &[u8]) -> bool {
        self.remove.iter().any(|r| r.eq_ignore_ascii_case(name))
            || self.set.iter().any(|h| h.name.eq_ignore_ascii_case(name))
    }
}

#[derive(Debug)]
pub struct HeaderValue {
    pub name: Box<[u8]>,
    pub value: Template,
    pub always: bool,
}

#[derive(Debug)]
pub struct Listener {
    pub id: Box<str>,
    /// Every address the configured host:port resolved to.
    pub addrs: Box<[SocketAddr]>,
    pub reuse_port: bool,
    pub backlog: u32,
    pub tls: Option<ListenerTls>,
    pub http2: bool,
    hosts: Hosts,
    /// The site answering requests whose host matches no site. nginx uses the
    /// first server of a listen socket when none is marked default.
    default_site: Option<u32>,
}

/// The server names of one listener, in nginx server_name lookup order.
#[derive(Debug, Default)]
struct Hosts {
    exact: Map<u32>,
    /// `*.name` and `.name`, keyed by `name`: match any name under it.
    head: Map<u32>,
    /// `.name`, keyed by `name`: also matches `name` itself.
    head_self: Map<u32>,
    /// `name.*`, keyed by `name`.
    tail: Map<u32>,
    /// Regex names in snapshot order. Shared by every listener of a site.
    regex: Vec<(Arc<Pattern>, u32)>,
}

/// PCRE2 match steps one regex may take per subject. Sane patterns on request
/// paths and hosts stay far below it; catastrophic backtracking hits it in
/// well under a millisecond.
pub const MATCH_LIMIT: u32 = 100_000;

/// A compiled PCRE2 pattern and its source, for errors and debugging.
pub struct Pattern {
    source: Box<str>,
    re: Regex,
    /// Match data for capturing matches, reused so a warm request does not
    /// allocate. One entry per concurrent match at most.
    locs: Mutex<Vec<CaptureLocations>>,
}

impl fmt::Debug for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pattern({:?})", self.source)
    }
}

impl Pattern {
    /// Compiles like nginx: PCRE2 with JIT where the platform has it, bytes
    /// rather than UTF-8 unless the pattern asks for `(*UTF)`.
    ///
    /// A match that needs more than [`MATCH_LIMIT`] steps fails instead of
    /// running on (ReDoS). PCRE2 takes the lower of this limit
    /// and one the pattern sets itself.
    pub(crate) fn new(source: &str, caseless: bool) -> Result<Self, String> {
        let re = RegexBuilder::new()
            .caseless(caseless)
            .jit_if_available(true)
            .build(&format!("(*LIMIT_MATCH={MATCH_LIMIT}){source}"))
            .map_err(|e| e.to_string())?;
        Ok(Self {
            source: source.into(),
            re,
            locs: Mutex::default(),
        })
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn is_match(&self, subject: &[u8]) -> Result<bool, MatchError> {
        self.re.is_match(subject).map_err(|_| MatchError)
    }

    /// Matches `subject` and, on a match, replaces `caps` with its groups.
    pub fn captures(&self, subject: &[u8], caps: &mut Captures) -> Result<bool, MatchError> {
        let pooled = self.locs.lock().unwrap_or_else(|e| e.into_inner()).pop();
        let mut locs = pooled.unwrap_or_else(|| self.re.capture_locations());
        let r = self.re.captures_read(&mut locs, subject);
        if let Ok(Some(_)) = r {
            caps.subject.clear();
            caps.subject.extend_from_slice(subject);
            caps.spans.clear();
            caps.spans
                .extend((0..locs.len()).map(|i| locs.get(i).unwrap_or((usize::MAX, 0))));
        }
        self.locs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(locs);
        r.map(|m| m.is_some()).map_err(|_| MatchError)
    }
}

/// Groups of the last regex that matched, for `$0`..`$9` (nginx keeps the
/// captures of the last successful match of a request).
#[derive(Debug, Default)]
pub struct Captures {
    subject: Vec<u8>,
    spans: Vec<(usize, usize)>,
}

impl Captures {
    pub fn clear(&mut self) {
        self.subject.clear();
        self.spans.clear();
    }

    /// Group `i`, or `None` when it does not exist or did not take part.
    pub fn get(&self, i: usize) -> Option<&[u8]> {
        let &(s, e) = self.spans.get(i)?;
        (s != usize::MAX).then(|| &self.subject[s..e])
    }
}

/// A regex failed to run, for example by hitting the PCRE2 match limit. nginx
/// answers 500 in this case rather than treating it as no match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchError;

/// Routes sharing one path match: those with conditions in definition order,
/// then the first one without.
type Group = Box<[u32]>;

#[derive(Debug)]
struct Prefix {
    path: Box<[u8]>,
    routes: Group,
    /// `^~`: when this is the longest match, regex routes are not checked.
    priority: bool,
}

/// The routes of one nesting level (nginx locations of one block).
#[derive(Debug, Default)]
struct Level {
    exact: Map<Group>,
    /// Prefix and priority prefix routes, longest first.
    prefixes: Box<[Prefix]>,
    /// Regex routes in definition order.
    regex: Box<[(Pattern, u32)]>,
}

#[derive(Debug)]
pub struct Site {
    pub id: Box<str>,
    top: Level,
    /// Every route: the tree in pre-order, then the named routes. Route
    /// numbers index this.
    pub routes: Box<[Route]>,
    pub rewrites: Box<[Rewrite]>,
    pub ret: Option<Return>,
    pub error_pages: Box<[ErrorPage]>,
    /// Listener indexes.
    pub listeners: Box<[u32]>,
    pub certificates: Box<[u32]>,
    pub redirect_https: bool,
    pub response_headers: HeaderOps,
    pub access_log: Option<u32>,
    pub real_ip: Option<RealIp>,
    /// Index into `Runtime::compressions` for responses without a route.
    pub compression: Option<u32>,
}

#[derive(Debug)]
pub struct Route {
    pub id: Box<str>,
    pub cond: Option<Cond>,
    pub action: Action,
    pub rewrites: Box<[Rewrite]>,
    pub error_pages: Box<[ErrorPage]>,
    pub response_headers: HeaderOps,
    pub request_headers: HeaderOps,
    pub access_log: Option<u32>,
    pub access: Access,
    pub bandwidth: Option<Bandwidth>,
    /// Index into `Runtime::compressions`.
    pub compression: Option<u32>,
    children: Option<Level>,
}

#[derive(Debug)]
pub enum Action {
    Static {
        /// Root directory as bytes, without a trailing slash.
        root: Box<[u8]>,
        index: Box<[Box<[u8]>]>,
        try_files: Option<TryFiles>,
    },
    Proxy(Proxy),
    Return(Return),
    /// FastCGI, uwsgi or SCGI.
    Gateway(Box<Gateway>),
    Memcached(Memcached),
    Grpc(Proxy),
}

/// How a gateway frames the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayProtocol {
    FastCgi,
    Uwsgi,
    Scgi,
}

#[derive(Debug)]
pub struct Gateway {
    pub protocol: GatewayProtocol,
    pub proxy: Proxy,
    pub params: Box<[GatewayParam]>,
    pub pass_request_headers: bool,
    pub document_root: Box<[u8]>,
    pub index: Box<[u8]>,
    pub split_path_info: Option<Pattern>,
}

#[derive(Debug)]
pub struct GatewayParam {
    pub name: Box<[u8]>,
    pub value: Template,
    pub if_not_empty: bool,
}

#[derive(Debug)]
pub struct Memcached {
    pub proxy: Proxy,
    /// `None`: `$uri`.
    pub key: Option<Template>,
}

#[derive(Debug, Clone, Copy)]
pub struct Proxy {
    pub upstream: u32,
    pub connect_timeout: Duration,
    pub send_timeout: Duration,
    pub read_timeout: Duration,
    pub next: NextOn,
    /// Zero: no limit.
    pub tries: u32,
}

/// proxy_next_upstream conditions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NextOn {
    pub error: bool,
    pub timeout: bool,
    pub non_idempotent: bool,
    /// Upstream statuses that move on: bit i for STATUSES[i].
    statuses: u8,
}

impl NextOn {
    const STATUSES: [u16; 7] = [500, 502, 503, 504, 403, 404, 429];

    pub fn on_status(&self, status: u16) -> bool {
        Self::STATUSES
            .iter()
            .position(|&s| s == status)
            .is_some_and(|i| self.statuses >> i & 1 == 1)
    }

    pub fn any_status(&self) -> bool {
        self.statuses != 0
    }

    fn build(list: &[i32]) -> Self {
        if list.is_empty() {
            return Self {
                error: true,
                timeout: true,
                ..Self::default()
            };
        }
        let mut n = Self::default();
        for &v in list {
            match NextUpstream::try_from(v).unwrap_or(NextUpstream::Unspecified) {
                NextUpstream::Off => return Self::default(),
                NextUpstream::Error => n.error = true,
                NextUpstream::Timeout => n.timeout = true,
                NextUpstream::NonIdempotent => n.non_idempotent = true,
                NextUpstream::Unspecified => {}
                status => {
                    let code = match status {
                        NextUpstream::Http500 => 500,
                        NextUpstream::Http502 => 502,
                        NextUpstream::Http503 => 503,
                        NextUpstream::Http504 => 504,
                        NextUpstream::Http403 => 403,
                        NextUpstream::Http404 => 404,
                        _ => 429,
                    };
                    if let Some(i) = Self::STATUSES.iter().position(|&s| s == code) {
                        n.statuses |= 1 << i;
                    }
                }
            }
        }
        n
    }
}

#[derive(Debug)]
pub struct Return {
    pub status: u16,
    pub text: Template,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewriteFlag {
    None,
    Last,
    Break,
    Redirect,
    Permanent,
}

#[derive(Debug)]
pub struct Rewrite {
    pub regex: Pattern,
    /// Without a trailing `?`.
    pub replacement: Template,
    pub flag: RewriteFlag,
    /// The request arguments are appended; a trailing `?` turns this off.
    pub add_args: bool,
    /// The replacement starts with `http://`, `https://` or `$scheme`, which
    /// makes the rewrite a redirect whatever the flag.
    pub absolute: bool,
}

#[derive(Debug)]
pub struct TryFiles {
    pub files: Box<[Template]>,
    pub fallback: Fallback,
}

#[derive(Debug)]
pub enum Fallback {
    Uri(Template),
    Status(u16),
    /// A named route, as a route number.
    Route(u32),
}

#[derive(Debug)]
pub struct ErrorPage {
    pub codes: Box<[u16]>,
    pub target: ErrorTarget,
    /// `None` keeps the original code, `Some(0)` the redirected request's.
    pub status: Option<u16>,
}

#[derive(Debug)]
pub enum ErrorTarget {
    /// A path (internal redirect) or an absolute URL (redirect).
    Uri(Template),
    /// A named route, as a route number.
    Route(u32),
}

/// How an upstream picks a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Balancing {
    RoundRobin,
    LeastConn,
    IpHash,
    Hash,
    HashConsistent,
    Random,
    RandomTwo,
}

#[derive(Debug)]
pub struct Upstream {
    pub id: Box<str>,
    pub targets: Box<[Target]>,
    pub balancing: Balancing,
    /// Key of the hash methods.
    pub hash_key: Template,
    pub health_check: Option<HealthCheck>,
    pub sticky: Option<Sticky>,
    /// Requests that may wait for a target at max_conns; 0: none.
    pub queue_size: u32,
    pub queue_timeout: Duration,
    /// Upstream connections close after being open this long.
    pub keepalive_time: Duration,
    /// Idle connections kept per worker and target.
    pub keepalive_idle: u32,
    pub keepalive_timeout: Duration,
    pub keepalive_requests: u32,
    /// Host header for requests to it unless a header operation sets one;
    /// empty: the target's address.
    pub host: Box<str>,
    /// 0 disables passive health.
    pub max_fails: u32,
    pub fail_timeout: Duration,
}

/// One address of a configured target. A host name with several addresses
/// gives one `Target` per address, all with the same `name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub addr: SocketAddr,
    /// The address as configured, host:port.
    pub name: Box<str>,
    pub weight: u32,
    pub backup: bool,
    pub down: bool,
    /// 0: no limit.
    pub max_conns: u32,
    pub slow_start: Duration,
    /// Sticky route value.
    pub route: Box<str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckKind {
    Http,
    Tcp,
}

/// Active health checks of an upstream's targets.
#[derive(Debug)]
pub struct HealthCheck {
    pub kind: CheckKind,
    pub interval: Duration,
    pub timeout: Duration,
    pub fails: u32,
    pub passes: u32,
    /// HTTP request line target.
    pub path: Box<str>,
    /// Host header; empty: the upstream's host or the target's address.
    pub host: Box<str>,
    /// Passing statuses, inclusive ranges.
    pub statuses: Box<[(u16, u16)]>,
    pub body: Option<Pattern>,
    /// 0: the target's port.
    pub port: u16,
}

#[derive(Debug)]
pub enum Sticky {
    Cookie(StickyCookie),
    /// Templates tried in order; the first non-empty value names a target
    /// by its route.
    Route(Box<[Template]>),
}

#[derive(Debug)]
pub struct StickyCookie {
    pub name: Box<str>,
    /// Attributes after the value, starting with "; ".
    pub attributes: Box<str>,
}

/// Addresses of host names, from the DNS re-resolution of targets marked
/// `resolve`, by name as configured.
pub type Resolved = HashMap<String, Box<[SocketAddr]>>;

#[derive(Debug, PartialEq, Eq)]
pub enum BuildError {
    ListenerAddress {
        listener: usize,
        error: String,
    },
    TargetAddress {
        upstream: usize,
        target: usize,
        error: String,
    },
    HostRegex {
        site: usize,
        host: usize,
        error: String,
    },
    /// A top-level field such as `certificates[0].key_pem`.
    Field {
        field: String,
        error: String,
    },
    /// A field of a site or route; `field` is the path below the site, for
    /// example `routes[2].children[0].path.value`.
    Site {
        site: usize,
        field: String,
        error: String,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ListenerAddress { listener, error } => {
                write!(f, "listeners[{listener}].address: {error}")
            }
            Self::TargetAddress {
                upstream,
                target,
                error,
            } => {
                write!(
                    f,
                    "upstreams[{upstream}].targets[{target}].address: {error}"
                )
            }
            Self::HostRegex { site, host, error } => {
                write!(f, "sites[{site}].hostnames[{host}].value: {error}")
            }
            Self::Site { site, field, error } => write!(f, "sites[{site}].{field}: {error}"),
            Self::Field { field, error } => write!(f, "{field}: {error}"),
        }
    }
}

impl std::error::Error for BuildError {}

fn health_check(h: &ir::HealthCheck, at: &str) -> Result<HealthCheck, BuildError> {
    use ir::health_check::Kind;
    let field = |f: &str, error: String| BuildError::Field {
        field: format!("{at}.{f}"),
        error,
    };
    let body = if h.body.is_empty() {
        None
    } else {
        Some(Pattern::new(&h.body, false).map_err(|e| field("body", e))?)
    };
    let mut statuses: Vec<(u16, u16)> = h
        .statuses
        .iter()
        .map(|r| (r.from.min(999) as u16, r.to.min(999) as u16))
        .collect();
    if statuses.is_empty() {
        statuses.push((200, 399));
    }
    Ok(HealthCheck {
        kind: if h.kind() == Kind::Tcp {
            CheckKind::Tcp
        } else {
            CheckKind::Http
        },
        interval: ms(h.interval_ms, Duration::from_secs(5)),
        timeout: ms(h.timeout_ms, Duration::from_secs(1)),
        fails: h.fails.max(1),
        passes: h.passes.max(1),
        path: if h.path.is_empty() { "/" } else { &h.path }.into(),
        host: h.host.as_str().into(),
        statuses: statuses.into(),
        body,
        port: u16::try_from(h.port).map_err(|_| field("port", "out of range".into()))?,
    })
}

fn sticky(s: &ir::Sticky, at: &str, names: &[Box<str>]) -> Result<Sticky, BuildError> {
    use std::fmt::Write as _;
    if s.kind() == ir::sticky::Kind::Route {
        let route = s
            .route
            .iter()
            .enumerate()
            .map(|(i, r)| {
                Template::parse_in(r, names).map_err(|error| BuildError::Field {
                    field: format!("{at}.route[{i}]"),
                    error,
                })
            })
            .collect::<Result<_, _>>()?;
        return Ok(Sticky::Route(route));
    }
    let mut attributes = String::new();
    let _ = write!(
        attributes,
        "; Path={}",
        if s.path.is_empty() { "/" } else { &s.path }
    );
    if !s.domain.is_empty() {
        let _ = write!(attributes, "; Domain={}", s.domain);
    }
    if s.max_age_s > 0 {
        let _ = write!(attributes, "; Max-Age={}", s.max_age_s);
    }
    if s.http_only {
        attributes.push_str("; HttpOnly");
    }
    if s.secure {
        attributes.push_str("; Secure");
    }
    match s.same_site.as_str() {
        "strict" => attributes.push_str("; SameSite=Strict"),
        "lax" => attributes.push_str("; SameSite=Lax"),
        "none" => attributes.push_str("; SameSite=None"),
        _ => {}
    }
    Ok(Sticky::Cookie(StickyCookie {
        name: if s.cookie.is_empty() {
            "route"
        } else {
            &s.cookie
        }
        .into(),
        attributes: attributes.into(),
    }))
}

fn proxy(p: &ir::ProxyAction) -> Proxy {
    Proxy {
        upstream: p.upstream,
        connect_timeout: ms(p.connect_timeout_ms, DEFAULT_TIMEOUT),
        send_timeout: ms(p.send_timeout_ms, DEFAULT_TIMEOUT),
        read_timeout: ms(p.read_timeout_ms, DEFAULT_TIMEOUT),
        next: NextOn::build(&p.next_upstream),
        tries: p.next_upstream_tries,
    }
}

fn ms(v: u32, default: Duration) -> Duration {
    if v == 0 {
        default
    } else {
        Duration::from_millis(u64::from(v))
    }
}

/// nginx's default for the proxy timeouts and the upstream keepalive timeout.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

fn resolve(addr: &str) -> Result<Box<[SocketAddr]>, String> {
    let addrs: Vec<_> = addr.to_socket_addrs().map_err(|e| e.to_string())?.collect();
    if addrs.is_empty() {
        return Err("resolved to no addresses".into());
    }
    Ok(addrs.into())
}

impl Runtime {
    /// Builds the runtime form of a snapshot that passed [`crate::validate`].
    ///
    /// Host names in listener and target addresses are resolved here, once,
    /// like nginx resolves them when it reads its configuration.
    pub fn build(snap: &ir::Snapshot) -> Result<Self, BuildError> {
        Self::build_with(snap, &Resolved::new())
    }

    /// Like [`Self::build`], with the addresses of `resolve` targets taken
    /// from `resolved`. A `resolve` target missing there is resolved now; one
    /// that does not resolve has no addresses until it does, as in nginx.
    pub fn build_with(snap: &ir::Snapshot, resolved: &Resolved) -> Result<Self, BuildError> {
        let (lookups, names) = lookup::build(&snap.lookups)
            .map_err(|(field, error)| BuildError::Field { field, error })?;
        let mut compressions = Vec::new();
        let mut listeners = Vec::with_capacity(snap.listeners.len());
        for (i, l) in snap.listeners.iter().enumerate() {
            let addrs = resolve(&l.address)
                .map_err(|error| BuildError::ListenerAddress { listener: i, error })?;
            let tls = l.tls.as_ref().map(|t| ListenerTls {
                min_version: match t.min_version() {
                    listener_tls::Version::Tls10 => 0x0301,
                    listener_tls::Version::Tls11 => 0x0302,
                    listener_tls::Version::Unspecified | listener_tls::Version::Tls12 => 0x0303,
                    listener_tls::Version::Tls13 => 0x0304,
                },
                ciphers: if t.ciphers.is_empty() {
                    "HIGH:!aNULL:!MD5".into()
                } else {
                    t.ciphers.as_str().into()
                },
                default_certificate: t.default_certificate,
            });
            listeners.push(Listener {
                id: l.id.as_str().into(),
                addrs,
                reuse_port: l.reuse_port,
                backlog: l.backlog,
                tls,
                http2: l.http2,
                hosts: Hosts::default(),
                default_site: l.default_site,
            });
        }

        let mut sites = Vec::with_capacity(snap.sites.len());
        for (s, site) in snap.sites.iter().enumerate() {
            let mut regex_hosts = Vec::new();
            for (h, host) in site.hostnames.iter().enumerate() {
                if host.kind() == host_match::Kind::Regex {
                    // server_name regexes are caseless in nginx.
                    let p =
                        Pattern::new(&host.value, true).map_err(|error| BuildError::HostRegex {
                            site: s,
                            host: h,
                            error,
                        })?;
                    regex_hosts.push(Arc::new(p));
                }
            }
            for &li in &site.listeners {
                let l = &mut listeners[li as usize];
                l.default_site.get_or_insert(s as u32);
                l.hosts.add(&site.hostnames, &regex_hosts, s as u32);
            }

            let mut b = SiteBuilder {
                site: s,
                routes: Vec::new(),
                named_base: tree_len(&site.routes) as u32,
                rate_zones: snap.rate_zones.len(),
                conn_zones: snap.conn_zones.len(),
                upstreams: snap.upstreams.len(),
                names: &names,
                compressions: &mut compressions,
            };
            let top = b.level(&site.routes, "routes")?;
            for (n, route) in site.named_routes.iter().enumerate() {
                let r = b.route(route, &format!("named_routes[{n}]"))?;
                b.routes.push(r);
            }
            sites.push(Site {
                id: site.id.as_str().into(),
                top,
                rewrites: b.rewrites(&site.rewrites, "rewrites")?,
                ret: match &site.r#return {
                    Some(r) => Some(b.ret(r, "return")?),
                    None => None,
                },
                error_pages: b.error_pages(&site.error_pages, "error_pages")?,
                listeners: site.listeners.clone().into(),
                certificates: site.certificates.clone().into(),
                redirect_https: site.redirect_https,
                response_headers: b
                    .header_ops(site.response_headers.as_ref(), "response_headers")?,
                access_log: site.access_log,
                real_ip: site
                    .real_ip
                    .as_ref()
                    .map(access::real_ip)
                    .transpose()
                    .map_err(|(f, e)| b.err(format!("real_ip.{f}"), e))?,
                compression: b.compression(site.compression.as_ref(), "compression")?,
                routes: b.routes.into(),
            });
        }

        let mut upstreams = Vec::with_capacity(snap.upstreams.len());
        for (u, up) in snap.upstreams.iter().enumerate() {
            let mut targets = Vec::new();
            for (t, target) in up.targets.iter().enumerate() {
                let addrs = match resolved.get(&target.address) {
                    Some(a) if target.resolve => a.clone(),
                    _ => match resolve(&target.address) {
                        Ok(a) => a,
                        Err(_) if target.resolve => Box::default(),
                        Err(error) => {
                            return Err(BuildError::TargetAddress {
                                upstream: u,
                                target: t,
                                error,
                            });
                        }
                    },
                };
                // A name with several addresses becomes one peer per address,
                // each with the configured weight, as in nginx.
                targets.extend(addrs.iter().map(|&addr| Target {
                    addr,
                    name: target.address.as_str().into(),
                    weight: target.weight.max(1),
                    backup: target.backup,
                    down: target.down,
                    max_conns: target.max_conns,
                    slow_start: Duration::from_millis(target.slow_start_ms.into()),
                    route: target.route.as_str().into(),
                }));
            }
            let at = format!("upstreams[{u}]");
            let health_check = up
                .health_check
                .as_ref()
                .map(|h| health_check(h, &format!("{at}.health_check")))
                .transpose()?;
            let sticky = up
                .sticky
                .as_ref()
                .map(|s| sticky(s, &format!("{at}.sticky"), &names))
                .transpose()?;
            upstreams.push(Upstream {
                id: up.id.as_str().into(),
                targets: targets.into(),
                balancing: match up.balancing() {
                    upstream::Balancing::LeastConn => Balancing::LeastConn,
                    upstream::Balancing::IpHash => Balancing::IpHash,
                    upstream::Balancing::Hash => Balancing::Hash,
                    upstream::Balancing::HashConsistent => Balancing::HashConsistent,
                    upstream::Balancing::Random => Balancing::Random,
                    upstream::Balancing::RandomTwo => Balancing::RandomTwo,
                    upstream::Balancing::RoundRobin | upstream::Balancing::Unspecified => {
                        Balancing::RoundRobin
                    }
                },
                hash_key: Template::parse_in(&up.hash_key, &names).map_err(|error| {
                    BuildError::Field {
                        field: format!("{at}.hash_key"),
                        error,
                    }
                })?,
                health_check,
                sticky,
                queue_size: up.queue_size,
                queue_timeout: ms(up.queue_timeout_ms, Duration::from_secs(60)),
                keepalive_time: ms(up.keepalive_time_ms, Duration::from_secs(3600)),
                keepalive_idle: up.keepalive_idle,
                keepalive_timeout: ms(up.keepalive_timeout_ms, DEFAULT_TIMEOUT),
                keepalive_requests: if up.keepalive_requests == 0 {
                    1000
                } else {
                    up.keepalive_requests
                },
                host: up.host.as_str().into(),
                max_fails: up.max_fails,
                fail_timeout: ms(up.fail_timeout_ms, Duration::from_secs(10)),
            });
        }

        let certificates = snap
            .certificates
            .iter()
            .enumerate()
            .map(|(i, c)| {
                Certificate::parse(&c.id, c.chain_pem.as_bytes(), c.key_pem.as_bytes()).map_err(
                    |error| BuildError::Field {
                        field: format!("certificates[{i}]"),
                        error,
                    },
                )
            })
            .collect::<Result<_, _>>()?;
        let access_logs = snap
            .access_logs
            .iter()
            .enumerate()
            .map(|(i, l)| {
                let at = format!("access_logs[{i}]");
                if l.path != "stdout" && l.path != "stderr" && !l.path.starts_with('/') {
                    return Err(BuildError::Field {
                        field: format!("{at}.path"),
                        error: "must be stdout, stderr or an absolute path".into(),
                    });
                }
                Ok(AccessLog {
                    path: l.path.as_str().into(),
                    format: Template::parse_in(&l.format, &names).map_err(|error| {
                        BuildError::Field {
                            field: format!("{at}.format"),
                            error,
                        }
                    })?,
                    escape_json: l.escape_json,
                })
            })
            .collect::<Result<_, _>>()?;
        let rate_zones = snap
            .rate_zones
            .iter()
            .enumerate()
            .map(|(i, z)| {
                access::rate_zone(z, &names).map_err(|(f, error)| BuildError::Field {
                    field: format!("rate_zones[{i}].{f}"),
                    error,
                })
            })
            .collect::<Result<_, _>>()?;
        let conn_zones = snap
            .conn_zones
            .iter()
            .enumerate()
            .map(|(i, z)| {
                access::conn_zone(z, &names).map_err(|(f, error)| BuildError::Field {
                    field: format!("conn_zones[{i}].{f}"),
                    error,
                })
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            revision: snap.revision,
            listeners: listeners.into(),
            sites: sites.into(),
            upstreams: upstreams.into(),
            certificates,
            access_logs,
            rate_zones,
            conn_zones,
            lookups: lookups.into(),
            compressions: compressions.into(),
        })
    }
}

/// An RFC 9110 token.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
}

fn tree_len(routes: &[ir::Route]) -> usize {
    routes.iter().map(|r| 1 + tree_len(&r.children)).sum()
}

/// Builds the routes of one site. Route numbers are assigned in pre-order,
/// with named routes after the tree.
struct SiteBuilder<'a> {
    site: usize,
    routes: Vec<Route>,
    /// Route number of named route 0.
    named_base: u32,
    rate_zones: usize,
    conn_zones: usize,
    upstreams: usize,
    /// Lookup variable names templates may use.
    names: &'a [Box<str>],
    /// Compression settings built so far, shared across sites.
    compressions: &'a mut Vec<Compression>,
}

impl SiteBuilder<'_> {
    fn err(&self, field: impl Into<String>, error: impl Into<String>) -> BuildError {
        BuildError::Site {
            site: self.site,
            field: field.into(),
            error: error.into(),
        }
    }

    fn template(&self, s: &str, field: &str) -> Result<Template, BuildError> {
        Template::parse_in(s, self.names).map_err(|e| self.err(field, e))
    }

    /// Builds `c` into `compressions`; each setting is one entry.
    fn compression(
        &mut self,
        c: Option<&ir::Compression>,
        at: &str,
    ) -> Result<Option<u32>, BuildError> {
        let Some(c) = c else { return Ok(None) };
        let built = compression::build(c).map_err(|(f, e)| self.err(format!("{at}.{f}"), e))?;
        self.compressions.push(built);
        Ok(Some(self.compressions.len() as u32 - 1))
    }

    fn level(&mut self, routes: &[ir::Route], field: &str) -> Result<Level, BuildError> {
        let mut exact: Map<Vec<u32>> = Map::default();
        let mut prefixes: Vec<(Prefix, Vec<u32>)> = Vec::new();
        let mut regex = Vec::new();
        for (i, route) in routes.iter().enumerate() {
            let at = format!("{field}[{i}]");
            let r = self.routes.len() as u32;
            let path = route.path.as_ref().expect("validated");
            let key: Box<[u8]> = path.value.as_bytes().into();
            match path.kind() {
                path_match::Kind::Exact => exact.entry(key).or_default().push(r),
                kind @ (path_match::Kind::Prefix | path_match::Kind::PrefixPriority) => {
                    match prefixes.iter_mut().find(|(p, _)| p.path == key) {
                        Some((_, group)) => group.push(r),
                        None => prefixes.push((
                            Prefix {
                                path: key,
                                routes: Box::default(),
                                priority: kind == path_match::Kind::PrefixPriority,
                            },
                            vec![r],
                        )),
                    }
                }
                kind @ (path_match::Kind::Regex | path_match::Kind::RegexCi) => {
                    let p = Pattern::new(&path.value, kind == path_match::Kind::RegexCi)
                        .map_err(|e| self.err(format!("{at}.path.value"), e))?;
                    regex.push((p, r));
                }
                path_match::Kind::Unspecified => unreachable!("validated"),
            }
            let built = self.route(route, &at)?;
            self.routes.push(built);
            if !route.children.is_empty() {
                let children = self.level(&route.children, &format!("{at}.children"))?;
                self.routes[r as usize].children = Some(children);
            }
        }
        prefixes.sort_by_key(|(p, _)| std::cmp::Reverse(p.path.len()));
        let group = |g: Vec<u32>| self.group(g);
        Ok(Level {
            exact: exact.into_iter().map(|(k, g)| (k, group(g))).collect(),
            prefixes: prefixes
                .into_iter()
                .map(|(p, g)| Prefix {
                    routes: group(g),
                    ..p
                })
                .collect(),
            regex: regex.into(),
        })
    }

    /// Orders routes sharing a path: conditional ones in definition order,
    /// then the first unconditional one, like a duplicate nginx location
    /// where the first one wins.
    fn group(&self, g: Vec<u32>) -> Group {
        let plain = g
            .iter()
            .copied()
            .find(|&r| self.routes[r as usize].cond.is_none());
        g.iter()
            .copied()
            .filter(|&r| self.routes[r as usize].cond.is_some())
            .chain(plain)
            .collect()
    }

    /// Builds one route without its children.
    fn route(&mut self, route: &ir::Route, at: &str) -> Result<Route, BuildError> {
        let action = match route.action.as_ref().and_then(|a| a.kind.as_ref()) {
            Some(action::Kind::Static(st)) => {
                if !st.root.starts_with('/') {
                    return Err(self.err(
                        format!("{at}.action.static.root"),
                        "must be an absolute path",
                    ));
                }
                let try_files = match &st.try_files {
                    Some(t) => Some(self.try_files(t, &format!("{at}.action.static.try_files"))?),
                    None => None,
                };
                Action::Static {
                    root: st.root.trim_end_matches('/').as_bytes().into(),
                    index: st.index.iter().map(|i| i.as_bytes().into()).collect(),
                    try_files,
                }
            }
            Some(action::Kind::Proxy(p)) => Action::Proxy(proxy(p)),
            Some(action::Kind::Gateway(g)) => {
                Action::Gateway(Box::new(self.gateway(g, &format!("{at}.action.gateway"))?))
            }
            Some(action::Kind::Memcached(m)) => Action::Memcached(Memcached {
                proxy: proxy(m.proxy.as_ref().expect("validated")),
                key: if m.key.is_empty() {
                    None
                } else {
                    Some(self.template(&m.key, &format!("{at}.action.memcached.key"))?)
                },
            }),
            Some(action::Kind::Grpc(g)) => {
                Action::Grpc(proxy(g.proxy.as_ref().expect("validated")))
            }
            Some(action::Kind::Return(r)) => {
                Action::Return(self.ret(r, &format!("{at}.action.return"))?)
            }
            None => unreachable!("validated"),
        };
        Ok(Route {
            id: route.id.as_str().into(),
            cond: Cond::build(route).map_err(|(f, e)| self.err(format!("{at}.{f}"), e))?,
            action,
            rewrites: self.rewrites(&route.rewrites, &format!("{at}.rewrites"))?,
            error_pages: self.error_pages(&route.error_pages, &format!("{at}.error_pages"))?,
            response_headers: self.header_ops(
                route.response_headers.as_ref(),
                &format!("{at}.response_headers"),
            )?,
            request_headers: self.header_ops(
                route.request_headers.as_ref(),
                &format!("{at}.request_headers"),
            )?,
            access_log: route.access_log,
            access: match &route.access {
                Some(a) => access::access(
                    a,
                    self.rate_zones,
                    self.conn_zones,
                    self.upstreams,
                    self.names,
                )
                .map_err(|(f, e)| self.err(format!("{at}.access.{f}"), e))?,
                None => Access::default(),
            },
            bandwidth: route.bandwidth.as_ref().and_then(access::bandwidth),
            compression: self
                .compression(route.compression.as_ref(), &format!("{at}.compression"))?,
            children: None,
        })
    }

    fn header_ops(&self, ops: Option<&ir::HeaderOps>, at: &str) -> Result<HeaderOps, BuildError> {
        let Some(ops) = ops else {
            return Ok(HeaderOps::default());
        };
        let values = |list: &[ir::HeaderValue], field: &str| {
            list.iter()
                .enumerate()
                .map(|(i, h)| {
                    if !valid_name(&h.name) {
                        return Err(
                            self.err(format!("{at}.{field}[{i}].name"), "not a header name")
                        );
                    }
                    Ok(HeaderValue {
                        name: h.name.as_bytes().into(),
                        value: self.template(&h.value, &format!("{at}.{field}[{i}].value"))?,
                        always: h.always,
                    })
                })
                .collect::<Result<Box<[_]>, _>>()
        };
        Ok(HeaderOps {
            set: values(&ops.set, "set")?,
            add: values(&ops.add, "add")?,
            remove: ops
                .remove
                .iter()
                .map(|n| n.to_ascii_lowercase().into_bytes().into())
                .collect(),
        })
    }

    fn gateway(&self, g: &ir::GatewayAction, at: &str) -> Result<Gateway, BuildError> {
        use ir::gateway_action::Protocol as P;
        let protocol = match g.protocol() {
            P::Uwsgi => GatewayProtocol::Uwsgi,
            P::Scgi => GatewayProtocol::Scgi,
            P::Fastcgi | P::Unspecified => GatewayProtocol::FastCgi,
        };
        let params = g
            .params
            .iter()
            .enumerate()
            .map(|(i, p)| {
                if p.name.is_empty() || p.name.bytes().any(|c| c == 0) {
                    return Err(self.err(format!("{at}.params[{i}].name"), "must not be empty"));
                }
                Ok(GatewayParam {
                    name: p.name.as_bytes().into(),
                    value: self.template(&p.value, &format!("{at}.params[{i}].value"))?,
                    if_not_empty: p.if_not_empty,
                })
            })
            .collect::<Result<_, _>>()?;
        let split_path_info = if g.split_path_info.is_empty() {
            None
        } else {
            Some(
                Pattern::new(&g.split_path_info, false)
                    .map_err(|e| self.err(format!("{at}.split_path_info"), e))?,
            )
        };
        Ok(Gateway {
            protocol,
            proxy: proxy(g.proxy.as_ref().expect("validated")),
            params,
            pass_request_headers: g.pass_request_headers,
            document_root: g.document_root.trim_end_matches('/').as_bytes().into(),
            index: g.index.as_bytes().into(),
            split_path_info,
        })
    }

    fn ret(&self, r: &ir::ReturnAction, at: &str) -> Result<Return, BuildError> {
        Ok(Return {
            status: r.status as u16,
            text: self.template(&r.text, &format!("{at}.text"))?,
        })
    }

    fn try_files(&self, t: &ir::TryFiles, at: &str) -> Result<TryFiles, BuildError> {
        let files = t
            .files
            .iter()
            .enumerate()
            .map(|(i, f)| self.template(f, &format!("{at}.files[{i}]")))
            .collect::<Result<_, _>>()?;
        let fallback = match t.fallback.as_ref().expect("validated") {
            try_files::Fallback::Uri(u) => Fallback::Uri(self.template(u, &format!("{at}.uri"))?),
            try_files::Fallback::Status(s) => Fallback::Status(*s as u16),
            try_files::Fallback::Named(n) => Fallback::Route(self.named_base + n),
        };
        Ok(TryFiles { files, fallback })
    }

    fn rewrites(&self, rs: &[ir::Rewrite], at: &str) -> Result<Box<[Rewrite]>, BuildError> {
        rs.iter()
            .enumerate()
            .map(|(i, r)| {
                let at = format!("{at}[{i}]");
                let regex = Pattern::new(&r.regex, false)
                    .map_err(|e| self.err(format!("{at}.regex"), e))?;
                let (repl, add_args) = match r.replacement.strip_suffix('?') {
                    Some(rest) => (rest, false),
                    None => (r.replacement.as_str(), true),
                };
                Ok(Rewrite {
                    regex,
                    replacement: self.template(repl, &format!("{at}.replacement"))?,
                    flag: match r.flag() {
                        rewrite::Flag::Unspecified => RewriteFlag::None,
                        rewrite::Flag::Last => RewriteFlag::Last,
                        rewrite::Flag::Break => RewriteFlag::Break,
                        rewrite::Flag::Redirect => RewriteFlag::Redirect,
                        rewrite::Flag::Permanent => RewriteFlag::Permanent,
                    },
                    add_args,
                    absolute: ["http://", "https://", "$scheme"]
                        .iter()
                        .any(|p| r.replacement.starts_with(p)),
                })
            })
            .collect()
    }

    fn error_pages(&self, eps: &[ir::ErrorPage], at: &str) -> Result<Box<[ErrorPage]>, BuildError> {
        eps.iter()
            .enumerate()
            .map(|(i, e)| {
                let target = match e.target.as_ref().expect("validated") {
                    error_page::Target::Uri(u) => {
                        ErrorTarget::Uri(self.template(u, &format!("{at}[{i}].uri"))?)
                    }
                    error_page::Target::Named(n) => ErrorTarget::Route(self.named_base + n),
                };
                Ok(ErrorPage {
                    codes: e.codes.iter().map(|&c| c as u16).collect(),
                    target,
                    status: e.status.map(|s| s as u16),
                })
            })
            .collect()
    }
}

impl Runtime {
    /// A runtime with nothing configured: no listeners, so no traffic. The
    /// state of a proxy before its first snapshot.
    pub fn empty() -> Self {
        Self {
            revision: 0,
            listeners: Box::default(),
            sites: Box::default(),
            upstreams: Box::default(),
            certificates: Box::default(),
            access_logs: Box::default(),
            rate_zones: Box::default(),
            conn_zones: Box::default(),
            lookups: Arc::from([]),
            compressions: Arc::from([]),
        }
    }

    /// The listener bound to `addr`. Snapshots are small and a connection
    /// looks this up once per request, so a scan beats a map here.
    pub fn listener(&self, addr: SocketAddr) -> Option<&Listener> {
        self.listeners.iter().find(|l| l.addrs.contains(&addr))
    }
}

impl Hosts {
    fn add(&mut self, names: &[ir::HostMatch], regex: &[Arc<Pattern>], site: u32) {
        // The control plane rejects the same name on one listener twice;
        // keep the first in case an older one did not, like nginx keeps the
        // first server with a duplicate name.
        fn put(map: &mut Map<u32>, key: &str, site: u32) {
            map.entry(key.to_ascii_lowercase().into_bytes().into())
                .or_insert(site);
        }
        for h in names {
            let v = h.value.as_str();
            match h.kind() {
                host_match::Kind::Exact => put(&mut self.exact, v, site),
                host_match::Kind::Wildcard => {
                    if let Some(name) = v.strip_prefix("*.") {
                        put(&mut self.head, name, site);
                    } else if let Some(name) = v.strip_suffix(".*") {
                        put(&mut self.tail, name, site);
                    } else if let Some(name) = v.strip_prefix('.') {
                        put(&mut self.head, name, site);
                        put(&mut self.head_self, name, site);
                    }
                    // Any other form never matches, as the control plane
                    // does not produce it.
                }
                host_match::Kind::Regex | host_match::Kind::Unspecified => {}
            }
        }
        self.regex
            .extend(regex.iter().map(|p| (Arc::clone(p), site)));
    }

    /// nginx server_name order: exact, longest `*.name`, longest `name.*`,
    /// first regex.
    fn find(&self, host: &[u8]) -> Result<Option<u32>, MatchError> {
        if let Some(&s) = self.exact.get(host) {
            return Ok(Some(s));
        }
        if !self.head.is_empty() {
            if let Some(&s) = self.head_self.get(host) {
                return Ok(Some(s));
            }
            // Suffixes after each dot, longest first.
            for (i, _) in host.iter().enumerate().filter(|&(_, &b)| b == b'.') {
                if let Some(&s) = self.head.get(&host[i + 1..]) {
                    return Ok(Some(s));
                }
            }
        }
        if !self.tail.is_empty() {
            // Prefixes before each dot, longest first.
            for (i, _) in host.iter().enumerate().rev().filter(|&(_, &b)| b == b'.') {
                if let Some(&s) = self.tail.get(&host[..i]) {
                    return Ok(Some(s));
                }
            }
        }
        for (p, s) in &self.regex {
            if p.is_match(host)? {
                return Ok(Some(*s));
            }
        }
        Ok(None)
    }
}

impl Listener {
    /// Finds the site for a Host value. `host` must be lowercase with any port
    /// and trailing dot removed.
    pub fn site(&self, host: Option<&[u8]>) -> Result<Option<u32>, MatchError> {
        let found = match host {
            Some(h) => self.hosts.find(h)?,
            None => None,
        };
        Ok(found.or(self.default_site))
    }
}

enum Found {
    None,
    /// A prefix route; regexes of enclosing levels may still win.
    Prefix(u32),
    /// An exact or regex route.
    Final(u32),
}

impl Site {
    /// Finds the route for a normalized path in nginx location order
    /// (`ngx_http_core_find_location`): an exact match wins; otherwise the
    /// longest prefix is found and its nested routes are searched the same
    /// way, where an exact or regex match wins outright; unless that prefix
    /// is `^~`, the regexes of this level are tried in definition order;
    /// otherwise the deepest prefix found wins. A regex match replaces
    /// `caps`.
    ///
    /// Route conditions are checked once the path selected a route; a route
    /// whose conditions fail is skipped as if its path did not match.
    pub fn route(&self, f: &dyn Facts, caps: &mut Captures) -> Result<Option<u32>, MatchError> {
        Ok(match self.find(&self.top, f, caps)? {
            Found::None => None,
            Found::Prefix(r) | Found::Final(r) => Some(r),
        })
    }

    /// The first route of `group` whose conditions hold.
    fn pick(&self, group: &[u32], f: &dyn Facts) -> Result<Option<u32>, MatchError> {
        for &r in group {
            match &self.routes[r as usize].cond {
                Some(c) if !c.holds(f)? => {}
                _ => return Ok(Some(r)),
            }
        }
        Ok(None)
    }

    fn find(&self, level: &Level, f: &dyn Facts, caps: &mut Captures) -> Result<Found, MatchError> {
        let path = f.path();
        if let Some(g) = level.exact.get(path)
            && let Some(r) = self.pick(g, f)?
        {
            return Ok(Found::Final(r));
        }
        let mut found = Found::None;
        let mut noregex = false;
        for p in level.prefixes.iter().filter(|p| path.starts_with(&p.path)) {
            let Some(r) = self.pick(&p.routes, f)? else {
                continue;
            };
            found = Found::Prefix(r);
            noregex = p.priority;
            if let Some(children) = &self.routes[r as usize].children {
                match self.find(children, f, caps)? {
                    Found::Final(r) => return Ok(Found::Final(r)),
                    Found::Prefix(r) => found = Found::Prefix(r),
                    Found::None => {}
                }
            }
            break;
        }
        if !noregex {
            for (p, r) in &level.regex {
                if p.captures(path, caps)?
                    && self.routes[*r as usize]
                        .cond
                        .as_ref()
                        .map_or(Ok(true), |c| c.holds(f))?
                {
                    return Ok(Found::Final(*r));
                }
            }
        }
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A GET for a path, without headers.
    struct Path<'a, P: AsRef<[u8]> + ?Sized>(&'a P);

    impl<P: AsRef<[u8]> + ?Sized> Facts for Path<'_, P> {
        fn method(&self) -> &[u8] {
            b"GET"
        }
        fn path(&self) -> &[u8] {
            self.0.as_ref()
        }
        fn uri(&self) -> &[u8] {
            self.0.as_ref()
        }
        fn args(&self) -> &[u8] {
            b""
        }
        fn host(&self) -> &[u8] {
            b""
        }
        fn scheme(&self) -> &[u8] {
            b"http"
        }
        fn remote_addr(&self) -> std::net::IpAddr {
            std::net::Ipv4Addr::LOCALHOST.into()
        }
        fn find_header(&self, _: &mut dyn FnMut(&[u8], &[u8]) -> bool) -> bool {
            false
        }
    }
    use proxelo_api::snapshot::v1::{
        Action as IrAction, HostMatch, Listener as IrListener, PathMatch, ProxyAction,
        Route as IrRoute, Site as IrSite, StaticAction, Target as IrTarget, Upstream as IrUpstream,
        host_match,
    };

    fn route(kind: path_match::Kind, value: &str, upstream: u32) -> IrRoute {
        IrRoute {
            path: Some(PathMatch {
                kind: kind as i32,
                value: value.into(),
            }),
            action: Some(IrAction {
                kind: Some(action::Kind::Proxy(ProxyAction {
                    upstream,
                    ..Default::default()
                })),
            }),
            ..Default::default()
        }
    }

    fn named(listeners: Vec<u32>, hosts: &[(host_match::Kind, &str)]) -> IrSite {
        IrSite {
            listeners,
            hostnames: hosts
                .iter()
                .map(|&(kind, value)| HostMatch {
                    kind: kind as i32,
                    value: value.into(),
                })
                .collect(),
            ..Default::default()
        }
    }

    fn site(listeners: Vec<u32>, hosts: &[&str], routes: Vec<IrRoute>) -> IrSite {
        IrSite {
            listeners,
            hostnames: hosts
                .iter()
                .map(|h| HostMatch {
                    kind: host_match::Kind::Exact as i32,
                    value: (*h).into(),
                })
                .collect(),
            routes,
            ..Default::default()
        }
    }

    fn snapshot(sites: Vec<IrSite>, default_site: Option<u32>) -> ir::Snapshot {
        ir::Snapshot {
            revision: 7,
            listeners: vec![IrListener {
                address: "127.0.0.1:8080".into(),
                default_site,
                ..Default::default()
            }],
            sites,
            upstreams: vec![IrUpstream {
                targets: vec![IrTarget {
                    address: "127.0.0.1:9000".into(),
                    weight: 0,
                    ..Default::default()
                }],
                keepalive_idle: 4,
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn host_lookup_and_default_site() {
        let snap = snapshot(
            vec![
                site(vec![0], &["a.example"], vec![]),
                site(vec![0], &["b.example", "c.example"], vec![]),
            ],
            None,
        );
        let rt = Runtime::build(&snap).unwrap();
        let l = &rt.listeners[0];
        assert_eq!(l.site(Some(b"a.example")), Ok(Some(0)));
        assert_eq!(l.site(Some(b"c.example")), Ok(Some(1)));
        assert_eq!(
            l.site(Some(b"other")),
            Ok(Some(0)),
            "first site is the default"
        );
        assert_eq!(l.site(None), Ok(Some(0)));

        let snap = snapshot(snap.sites, Some(1));
        let rt = Runtime::build(&snap).unwrap();
        assert_eq!(rt.listeners[0].site(Some(b"other")), Ok(Some(1)));
    }

    #[test]
    fn listener_without_sites_has_no_default() {
        let rt = Runtime::build(&snapshot(vec![], None)).unwrap();
        assert_eq!(rt.listeners[0].site(Some(b"a")), Ok(None));
    }

    #[test]
    fn location_order() {
        use path_match::Kind::{Exact, Prefix};
        let snap = snapshot(
            vec![site(
                vec![0],
                &[],
                vec![
                    route(Prefix, "/", 0),
                    route(Prefix, "/api/", 0),
                    route(Exact, "/api/", 0),
                    route(Prefix, "/api/v1/", 0),
                    route(Prefix, "/api/", 0),
                ],
            )],
            None,
        );
        let rt = Runtime::build(&snap).unwrap();
        let s = &rt.sites[0];
        assert_eq!(s.route(&Path(b"/"), &mut Captures::default()), Ok(Some(0)));
        assert_eq!(
            s.route(&Path(b"/index.html"), &mut Captures::default()),
            Ok(Some(0))
        );
        assert_eq!(
            s.route(&Path(b"/api"), &mut Captures::default()),
            Ok(Some(0))
        );
        assert_eq!(
            s.route(&Path(b"/api/"), &mut Captures::default()),
            Ok(Some(2)),
            "exact wins over prefix"
        );
        assert_eq!(
            s.route(&Path(b"/api/x"), &mut Captures::default()),
            Ok(Some(1)),
            "first duplicate prefix wins"
        );
        assert_eq!(
            s.route(&Path(b"/api/v1/x"), &mut Captures::default()),
            Ok(Some(3)),
            "longest prefix wins"
        );
    }

    #[test]
    fn server_name_order() {
        use host_match::Kind::{Exact, Regex, Wildcard};
        let snap = snapshot(
            vec![
                named(vec![0], &[(Exact, "default.test")]),
                named(vec![0], &[(Wildcard, "*.example.com")]),
                named(vec![0], &[(Wildcard, "*.api.example.com")]),
                named(vec![0], &[(Wildcard, "mail.*")]),
                named(vec![0], &[(Wildcard, "mail.example.*")]),
                named(vec![0], &[(Regex, r"^(www\.)?shop\d+\.")]),
                named(vec![0], &[(Regex, r"^www\.")]),
                named(
                    vec![0],
                    &[(Wildcard, ".dot.test"), (Exact, "exact.example.com")],
                ),
                named(vec![0], &[(Regex, r"^MiXeD\.test$")]),
            ],
            None,
        );
        let rt = Runtime::build(&snap).unwrap();
        let l = &rt.listeners[0];
        let site = |h: &[u8]| l.site(Some(h)).unwrap();
        assert_eq!(site(b"exact.example.com"), Some(7), "exact before wildcard");
        assert_eq!(site(b"a.example.com"), Some(1));
        assert_eq!(site(b"a.b.example.com"), Some(1), "* covers several labels");
        assert_eq!(
            site(b"x.api.example.com"),
            Some(2),
            "longest leading wildcard"
        );
        assert_eq!(site(b"example.com"), Some(0), "*.name does not match name");
        assert_eq!(
            site(b"mail.example.org"),
            Some(4),
            "longest trailing wildcard"
        );
        assert_eq!(site(b"mail.test"), Some(3));
        assert_eq!(
            site(b"mail.example.com"),
            Some(1),
            "leading before trailing"
        );
        assert_eq!(site(b"www.shop1.test"), Some(5), "first regex in order");
        assert_eq!(site(b"www.other.test"), Some(6));
        assert_eq!(site(b"dot.test"), Some(7), ".name matches name");
        assert_eq!(site(b"a.dot.test"), Some(7), ".name matches subdomains");
        assert_eq!(
            site(b"mixed.test"),
            Some(8),
            "server_name regex is caseless"
        );
        assert_eq!(site(b"nothing.test"), Some(0), "default site");
    }

    #[test]
    fn location_regex_order() {
        use path_match::Kind::{Exact, Prefix, PrefixPriority, Regex, RegexCi};
        let snap = snapshot(
            vec![site(
                vec![0],
                &[],
                vec![
                    route(Prefix, "/", 0),
                    route(PrefixPriority, "/static/", 0),
                    route(Regex, r"\.php$", 0),
                    route(RegexCi, r"\.(png|jpg)$", 0),
                    route(Prefix, "/images/", 0),
                    route(Exact, "/logo.png", 0),
                    route(Regex, r"\.png$", 0),
                    route(Prefix, "/static/deep/", 0),
                ],
            )],
            None,
        );
        let rt = Runtime::build(&snap).unwrap();
        let s = &rt.sites[0];
        assert_eq!(
            s.route(&Path(b"/logo.png"), &mut Captures::default()),
            Ok(Some(5)),
            "exact before regex"
        );
        assert_eq!(
            s.route(&Path(b"/static/a.php"), &mut Captures::default()),
            Ok(Some(1)),
            "^~ skips regex"
        );
        assert_eq!(
            s.route(&Path(b"/static/deep/a.php"), &mut Captures::default()),
            Ok(Some(2)),
            "longer plain prefix does not stop regex"
        );
        assert_eq!(
            s.route(&Path(b"/images/a.PNG"), &mut Captures::default()),
            Ok(Some(3)),
            "regex beats prefix"
        );
        assert_eq!(
            s.route(&Path(b"/a.png"), &mut Captures::default()),
            Ok(Some(3)),
            "first regex in order"
        );
        assert_eq!(
            s.route(&Path(b"/a.Png"), &mut Captures::default()),
            Ok(Some(3))
        );
        assert_eq!(
            s.route(&Path(b"/a.PHP"), &mut Captures::default()),
            Ok(Some(0)),
            "~ is case-sensitive"
        );
        assert_eq!(
            s.route(&Path(b"/images/a.gif"), &mut Captures::default()),
            Ok(Some(4)),
            "longest prefix"
        );
    }

    #[test]
    fn catastrophic_regex_fails_instead_of_running() {
        let snap = snapshot(
            vec![site(
                vec![0],
                &[],
                vec![route(path_match::Kind::Regex, "^/(a+)+$", 0)],
            )],
            None,
        );
        let rt = Runtime::build(&snap).unwrap();
        let mut path = b"/".to_vec();
        path.extend([b'a'; 40]);
        assert_eq!(
            rt.sites[0].route(&Path(&path), &mut Captures::default()),
            Ok(Some(0))
        );
        path.push(b'b');
        let start = std::time::Instant::now();
        assert_eq!(
            rt.sites[0].route(&Path(&path), &mut Captures::default()),
            Err(MatchError)
        );
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn bad_regex() {
        let snap = snapshot(
            vec![site(
                vec![0],
                &[],
                vec![route(path_match::Kind::Regex, "(", 0)],
            )],
            None,
        );
        assert!(matches!(
            Runtime::build(&snap),
            Err(BuildError::Site { site: 0, ref field, .. }) if field == "routes[0].path.value"
        ));
        let snap = snapshot(
            vec![named(vec![0], &[(host_match::Kind::Regex, "[")])],
            None,
        );
        assert!(matches!(
            Runtime::build(&snap),
            Err(BuildError::HostRegex {
                site: 0,
                host: 0,
                ..
            })
        ));
    }

    #[test]
    fn no_route() {
        let snap = snapshot(
            vec![site(
                vec![0],
                &[],
                vec![route(path_match::Kind::Exact, "/x", 0)],
            )],
            None,
        );
        let rt = Runtime::build(&snap).unwrap();
        assert_eq!(
            rt.sites[0].route(&Path(b"/y"), &mut Captures::default()),
            Ok(None)
        );
    }

    #[test]
    fn upstream_targets() {
        let rt = Runtime::build(&snapshot(vec![], None)).unwrap();
        assert_eq!(
            &*rt.upstreams[0].targets,
            &[Target {
                addr: "127.0.0.1:9000".parse().unwrap(),
                name: "127.0.0.1:9000".into(),
                weight: 1,
                backup: false,
                down: false,
                max_conns: 0,
                slow_start: Duration::ZERO,
                route: "".into(),
            }]
        );
        assert_eq!(rt.upstreams[0].keepalive_idle, 4);
    }

    #[test]
    fn resolve_targets_wait_for_an_address() {
        let mut snap = snapshot(vec![], None);
        snap.upstreams[0].targets[0].address = "no-such-host.invalid:80".into();
        assert!(Runtime::build(&snap).is_err());
        snap.upstreams[0].targets[0].resolve = true;
        let rt = Runtime::build(&snap).unwrap();
        assert!(rt.upstreams[0].targets.is_empty());
        let mut resolved = Resolved::new();
        resolved.insert(
            "no-such-host.invalid:80".into(),
            vec!["10.0.0.7:80".parse().unwrap()].into(),
        );
        let rt = Runtime::build_with(&snap, &resolved).unwrap();
        assert_eq!(rt.upstreams[0].targets[0].addr.to_string(), "10.0.0.7:80");
    }

    #[test]
    fn sticky_cookie_attributes() {
        let mut snap = snapshot(vec![], None);
        snap.upstreams[0].sticky = Some(ir::Sticky {
            kind: ir::sticky::Kind::Cookie.into(),
            cookie: "srv".into(),
            max_age_s: 60,
            http_only: true,
            same_site: "lax".into(),
            ..Default::default()
        });
        let rt = Runtime::build(&snap).unwrap();
        let Some(Sticky::Cookie(c)) = &rt.upstreams[0].sticky else {
            panic!("no cookie");
        };
        assert_eq!(&*c.name, "srv");
        assert_eq!(
            &*c.attributes,
            "; Path=/; Max-Age=60; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn static_root_trailing_slash() {
        let mut snap = snapshot(vec![site(vec![0], &[], vec![])], None);
        snap.sites[0].routes.push(IrRoute {
            path: Some(PathMatch {
                kind: path_match::Kind::Prefix as i32,
                value: "/".into(),
            }),
            action: Some(IrAction {
                kind: Some(action::Kind::Static(StaticAction {
                    root: "/srv/www/".into(),
                    index: vec!["index.html".into()],
                    ..Default::default()
                })),
            }),
            ..Default::default()
        });
        let rt = Runtime::build(&snap).unwrap();
        match &rt.sites[0].routes[0].action {
            Action::Static { root, index, .. } => {
                assert_eq!(&**root, b"/srv/www");
                assert_eq!(index.len(), 1);
            }
            a => panic!("{a:?}"),
        }
        snap.sites[0].routes[0].action = Some(IrAction {
            kind: Some(action::Kind::Static(StaticAction {
                root: "srv".into(),
                ..Default::default()
            })),
        });
        assert_eq!(
            Runtime::build(&snap).err(),
            Some(BuildError::Site {
                site: 0,
                field: "routes[0].action.static.root".into(),
                error: "must be an absolute path".into()
            })
        );
    }

    #[test]
    fn bad_addresses() {
        let mut snap = snapshot(vec![], None);
        snap.listeners[0].address = "nope".into();
        assert!(matches!(
            Runtime::build(&snap),
            Err(BuildError::ListenerAddress { listener: 0, .. })
        ));
        let mut snap = snapshot(vec![], None);
        snap.upstreams[0].targets[0].address = "127.0.0.1".into();
        assert!(matches!(
            Runtime::build(&snap),
            Err(BuildError::TargetAddress {
                upstream: 0,
                target: 0,
                ..
            })
        ));
    }
}
