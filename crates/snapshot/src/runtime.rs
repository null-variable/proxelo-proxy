//! The runtime form of a snapshot: lookup structures the request path reads
//! without parsing, hashing strings into new allocations or resolving names.

use std::collections::HashMap;
use std::fmt;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use foldhash::fast::FixedState;
use pcre2::bytes::{Regex, RegexBuilder};
use proxelo_api::snapshot::v1::{self as ir, action, host_match, path_match};

type Map<V> = HashMap<Box<[u8]>, V, FixedState>;

/// A loaded snapshot. Indexes match the IR arrays it was built from.
#[derive(Debug)]
pub struct Runtime {
    pub revision: u64,
    pub listeners: Box<[Listener]>,
    pub sites: Box<[Site]>,
    pub upstreams: Box<[Upstream]>,
}

#[derive(Debug)]
pub struct Listener {
    /// Every address the configured host:port resolved to.
    pub addrs: Box<[SocketAddr]>,
    pub reuse_port: bool,
    pub backlog: u32,
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
    fn new(source: &str, caseless: bool) -> Result<Self, String> {
        let re = RegexBuilder::new()
            .caseless(caseless)
            .jit_if_available(true)
            .build(&format!("(*LIMIT_MATCH={MATCH_LIMIT}){source}"))
            .map_err(|e| e.to_string())?;
        Ok(Self {
            source: source.into(),
            re,
        })
    }

    fn is_match(&self, subject: &[u8]) -> Result<bool, MatchError> {
        self.re.is_match(subject).map_err(|_| MatchError)
    }
}

/// A regex failed to run, for example by hitting the PCRE2 match limit. nginx
/// answers 500 in this case rather than treating it as no match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchError;

#[derive(Debug)]
struct Prefix {
    path: Box<[u8]>,
    route: u32,
    /// `^~`: when this is the longest match, regex routes are not checked.
    priority: bool,
}

#[derive(Debug)]
pub struct Site {
    exact: Map<u32>,
    /// Prefix and priority prefix routes, longest first.
    prefixes: Box<[Prefix]>,
    /// Regex routes in definition order.
    regex: Box<[(Pattern, u32)]>,
    pub routes: Box<[Route]>,
}

#[derive(Debug)]
pub struct Route {
    pub action: Action,
}

#[derive(Debug)]
pub enum Action {
    Static {
        /// Root directory as bytes, without a trailing slash.
        root: Box<[u8]>,
        index: Box<[Box<[u8]>]>,
    },
    Proxy {
        upstream: u32,
    },
}

#[derive(Debug)]
pub struct Upstream {
    pub targets: Box<[Target]>,
    /// Idle connections kept per worker and target.
    pub keepalive_idle: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    pub addr: SocketAddr,
    pub weight: u32,
}

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
    StaticRoot {
        site: usize,
        route: usize,
    },
    HostRegex {
        site: usize,
        host: usize,
        error: String,
    },
    PathRegex {
        site: usize,
        route: usize,
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
            Self::StaticRoot { site, route } => {
                write!(
                    f,
                    "sites[{site}].routes[{route}].action.static.root: must be an absolute path"
                )
            }
            Self::HostRegex { site, host, error } => {
                write!(f, "sites[{site}].hostnames[{host}].value: {error}")
            }
            Self::PathRegex { site, route, error } => {
                write!(f, "sites[{site}].routes[{route}].path.value: {error}")
            }
        }
    }
}

impl std::error::Error for BuildError {}

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
        let mut listeners = Vec::with_capacity(snap.listeners.len());
        for (i, l) in snap.listeners.iter().enumerate() {
            let addrs = resolve(&l.address)
                .map_err(|error| BuildError::ListenerAddress { listener: i, error })?;
            listeners.push(Listener {
                addrs,
                reuse_port: l.reuse_port,
                backlog: l.backlog,
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

            let mut exact = Map::default();
            let mut prefixes = Vec::new();
            let mut regex = Vec::new();
            let mut routes = Vec::with_capacity(site.routes.len());
            for (r, route) in site.routes.iter().enumerate() {
                let path = route.path.as_ref().expect("validated");
                let key: Box<[u8]> = path.value.as_bytes().into();
                match path.kind() {
                    path_match::Kind::Exact => {
                        exact.entry(key).or_insert(r as u32);
                    }
                    path_match::Kind::Prefix => prefixes.push(Prefix {
                        path: key,
                        route: r as u32,
                        priority: false,
                    }),
                    path_match::Kind::PrefixPriority => prefixes.push(Prefix {
                        path: key,
                        route: r as u32,
                        priority: true,
                    }),
                    kind @ (path_match::Kind::Regex | path_match::Kind::RegexCi) => {
                        let p = Pattern::new(&path.value, kind == path_match::Kind::RegexCi)
                            .map_err(|error| BuildError::PathRegex {
                                site: s,
                                route: r,
                                error,
                            })?;
                        regex.push((p, r as u32));
                    }
                    path_match::Kind::Unspecified => unreachable!("validated"),
                }
                let action = match route.action.as_ref().and_then(|a| a.kind.as_ref()) {
                    Some(action::Kind::Static(st)) => {
                        let root = st.root.trim_end_matches('/');
                        if !st.root.starts_with('/') {
                            return Err(BuildError::StaticRoot { site: s, route: r });
                        }
                        Action::Static {
                            root: root.as_bytes().into(),
                            index: st.index.iter().map(|i| i.as_bytes().into()).collect(),
                        }
                    }
                    Some(action::Kind::Proxy(p)) => Action::Proxy {
                        upstream: p.upstream,
                    },
                    None => unreachable!("validated"),
                };
                routes.push(Route { action });
            }
            // Stable sort keeps definition order between equal prefixes, so
            // the first one defined wins like a duplicate nginx location.
            prefixes.sort_by_key(|p| std::cmp::Reverse(p.path.len()));
            prefixes.dedup_by(|a, b| a.path == b.path);
            sites.push(Site {
                exact,
                prefixes: prefixes.into(),
                regex: regex.into(),
                routes: routes.into(),
            });
        }

        let mut upstreams = Vec::with_capacity(snap.upstreams.len());
        for (u, up) in snap.upstreams.iter().enumerate() {
            let mut targets = Vec::new();
            for (t, target) in up.targets.iter().enumerate() {
                let addrs =
                    resolve(&target.address).map_err(|error| BuildError::TargetAddress {
                        upstream: u,
                        target: t,
                        error,
                    })?;
                // A name with several addresses becomes one peer per address,
                // each with the configured weight, as in nginx.
                targets.extend(addrs.iter().map(|&addr| Target {
                    addr,
                    weight: target.weight.max(1),
                }));
            }
            upstreams.push(Upstream {
                targets: targets.into(),
                keepalive_idle: up.keepalive_idle,
            });
        }

        Ok(Self {
            revision: snap.revision,
            listeners: listeners.into(),
            sites: sites.into(),
            upstreams: upstreams.into(),
        })
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

impl Site {
    /// Finds the route for a normalized path with nginx location order: an
    /// exact match wins; otherwise the longest prefix is found and wins at
    /// once if it is `^~`; otherwise the first matching regex in definition
    /// order; otherwise that longest prefix.
    pub fn route(&self, path: &[u8]) -> Result<Option<u32>, MatchError> {
        if let Some(&r) = self.exact.get(path) {
            return Ok(Some(r));
        }
        let prefix = self.prefixes.iter().find(|p| path.starts_with(&p.path));
        if let Some(p) = prefix
            && p.priority
        {
            return Ok(Some(p.route));
        }
        for (p, r) in &self.regex {
            if p.is_match(path)? {
                return Ok(Some(*r));
            }
        }
        Ok(prefix.map(|p| p.route))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
                kind: Some(action::Kind::Proxy(ProxyAction { upstream })),
            }),
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
            routes: vec![],
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
        assert_eq!(s.route(b"/"), Ok(Some(0)));
        assert_eq!(s.route(b"/index.html"), Ok(Some(0)));
        assert_eq!(s.route(b"/api"), Ok(Some(0)));
        assert_eq!(s.route(b"/api/"), Ok(Some(2)), "exact wins over prefix");
        assert_eq!(
            s.route(b"/api/x"),
            Ok(Some(1)),
            "first duplicate prefix wins"
        );
        assert_eq!(s.route(b"/api/v1/x"), Ok(Some(3)), "longest prefix wins");
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
        assert_eq!(s.route(b"/logo.png"), Ok(Some(5)), "exact before regex");
        assert_eq!(s.route(b"/static/a.php"), Ok(Some(1)), "^~ skips regex");
        assert_eq!(
            s.route(b"/static/deep/a.php"),
            Ok(Some(2)),
            "longer plain prefix does not stop regex"
        );
        assert_eq!(s.route(b"/images/a.PNG"), Ok(Some(3)), "regex beats prefix");
        assert_eq!(s.route(b"/a.png"), Ok(Some(3)), "first regex in order");
        assert_eq!(s.route(b"/a.Png"), Ok(Some(3)));
        assert_eq!(s.route(b"/a.PHP"), Ok(Some(0)), "~ is case-sensitive");
        assert_eq!(s.route(b"/images/a.gif"), Ok(Some(4)), "longest prefix");
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
        assert_eq!(rt.sites[0].route(&path), Ok(Some(0)));
        path.push(b'b');
        let start = std::time::Instant::now();
        assert_eq!(rt.sites[0].route(&path), Err(MatchError));
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
            Err(BuildError::PathRegex {
                site: 0,
                route: 0,
                ..
            })
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
        assert_eq!(rt.sites[0].route(b"/y"), Ok(None));
    }

    #[test]
    fn upstream_targets() {
        let rt = Runtime::build(&snapshot(vec![], None)).unwrap();
        assert_eq!(
            &*rt.upstreams[0].targets,
            &[Target {
                addr: "127.0.0.1:9000".parse().unwrap(),
                weight: 1
            }]
        );
        assert_eq!(rt.upstreams[0].keepalive_idle, 4);
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
                })),
            }),
        });
        let rt = Runtime::build(&snap).unwrap();
        match &rt.sites[0].routes[0].action {
            Action::Static { root, index } => {
                assert_eq!(&**root, b"/srv/www");
                assert_eq!(index.len(), 1);
            }
            a => panic!("{a:?}"),
        }
        snap.sites[0].routes[0].action = Some(IrAction {
            kind: Some(action::Kind::Static(StaticAction {
                root: "srv".into(),
                index: vec![],
            })),
        });
        assert_eq!(
            Runtime::build(&snap).err(),
            Some(BuildError::StaticRoot { site: 0, route: 0 })
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
