//! Validation of an incoming snapshot before it is swapped in.
//!
//! The control plane resolves references and inheritance. This crate only
//! checks what the proxy depends on to serve traffic safely: every index points
//! at an existing object and every match and action is fully specified.

mod access;
mod auth;
mod cache;
mod compression;
mod cond;
mod edits;
mod filters;
mod lookup;
mod runtime;
mod template;
mod wasm;

use std::fmt;

pub use access::{
    Access, AccessRule, Bandwidth, BasicAuth, BasicUser, Cidr, ConnZone, ForwardAuth, RateZone,
    RealIp, allowed,
};
pub use auth::{Jwt, Key, KeyKind, Oidc, SessionKey, Url, parse_jwks};
pub use cache::{Cache, CacheZone, Ignore as CacheIgnore, Stale, Valid};
pub use compression::{Compression, Encoding, Proxied, StaticGz};
pub use cond::{Cond, Expr, Facts};
pub use edits::{CookieFlags, CookieName, HeaderRewrite, ProxyEdits, RewriteMatch};
pub use filters::{
    Addition, Charset, Filters, Mirror, Recode, Ssi, SubFilter, Types, Userid, UseridMode,
};
pub use lookup::{GeoTable, Lookup, MapTable, SplitTable, Table, murmur2};
pub use runtime::{
    AccessLog, Action, Autoindex, AutoindexFormat, Balancing, BuildError, Captures, Certificate,
    CheckKind, ClientAuth, ClientAuthMode, Dav, ErrorPage, ErrorTarget, Fallback, Gateway,
    GatewayParam, GatewayProtocol, HeaderOps, HeaderValue, HealthCheck, Listener, ListenerTls,
    MatchError, Memcached, Mp4, NextOn, Pattern, Proxy, Resolved, Return, Rewrite, RewriteFlag,
    Route, Runtime, Site, StaticHandlers, Sticky, StickyCookie, Stream, StreamRoute, Target,
    TryFiles, Upstream, UpstreamTls, discovered_key,
};
pub use template::{Part, Template, Var, variable};
pub use wasm::{WasmFilter, WasmModule, hex};

use prost::Message;
use proxelo_api::snapshot::v1::{
    ErrorPage as IrErrorPage, ReturnAction, Route as IrRoute, Snapshot, action, error_page,
    host_match, path_match, try_files,
};

#[derive(Debug, PartialEq, Eq)]
pub enum LoadError {
    Decode(String),
    ListenerSite {
        listener: usize,
        site: u32,
    },
    SiteListener {
        site: usize,
        listener: u32,
    },
    UnspecifiedHost {
        site: usize,
        host: usize,
    },
    /// A field of a site; `field` is the path below the site, for example
    /// `routes[1].children[0].action`.
    Site {
        site: usize,
        field: String,
        error: &'static str,
    },
    EmptyUpstream {
        upstream: usize,
    },
    /// A top-level field, for example `listeners[0].tls.default_certificate`.
    Field {
        field: String,
        error: &'static str,
    },
    /// The hash does not match the bytes.
    Hash,
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "decode: {e}"),
            Self::ListenerSite { listener, site } => {
                write!(f, "listeners[{listener}].default_site: no site {site}")
            }
            Self::SiteListener { site, listener } => {
                write!(f, "sites[{site}].listeners: no listener {listener}")
            }
            Self::UnspecifiedHost { site, host } => {
                write!(f, "sites[{site}].hostnames[{host}]: kind is unspecified")
            }
            Self::Site { site, field, error } => write!(f, "sites[{site}].{field}: {error}"),
            Self::EmptyUpstream { upstream } => write!(f, "upstreams[{upstream}]: no targets"),
            Self::Field { field, error } => write!(f, "{field}: {error}"),
            Self::Hash => f.write_str("hash does not match the snapshot"),
        }
    }
}

impl std::error::Error for LoadError {}

type Invalid = (String, &'static str);

/// Checks of the routes of one site.
struct SiteCheck {
    upstreams: usize,
    named: usize,
    logs: usize,
}

impl SiteCheck {
    fn routes(&self, routes: &[IrRoute], at: &str, matched: bool) -> Result<(), Invalid> {
        for (i, r) in routes.iter().enumerate() {
            self.route(r, &format!("{at}[{i}]"), matched)?;
        }
        Ok(())
    }

    /// The upstream settings of a gateway, memcached or grpc action.
    fn upstream(
        &self,
        p: Option<&proxelo_api::snapshot::v1::ProxyAction>,
        at: &str,
        kind: &str,
    ) -> Result<(), Invalid> {
        match p {
            None => Err((format!("{at}.action.{kind}.proxy"), "missing")),
            Some(p) if p.upstream as usize >= self.upstreams => Err((
                format!("{at}.action.{kind}.proxy.upstream"),
                "no such upstream",
            )),
            Some(_) => Ok(()),
        }
    }

    fn route(&self, route: &IrRoute, at: &str, matched: bool) -> Result<(), Invalid> {
        let kind = route.path.as_ref().map(|p| p.kind());
        if matched {
            match kind {
                Some(path_match::Kind::Unspecified) | None => {
                    return Err((format!("{at}.path"), "missing or unspecified"));
                }
                Some(path_match::Kind::Prefix | path_match::Kind::PrefixPriority) => {}
                Some(_) if !route.children.is_empty() => {
                    return Err((format!("{at}.children"), "only prefix routes have children"));
                }
                Some(_) => {}
            }
        }
        match route.action.as_ref().and_then(|a| a.kind.as_ref()) {
            None => return Err((format!("{at}.action"), "missing")),
            Some(action::Kind::Proxy(p)) if p.upstream as usize >= self.upstreams => {
                return Err((format!("{at}.action.proxy.upstream"), "no such upstream"));
            }
            Some(action::Kind::Static(st)) => {
                if let Some(t) = &st.try_files {
                    let at = format!("{at}.action.static.try_files");
                    if t.files.is_empty() {
                        return Err((format!("{at}.files"), "empty"));
                    }
                    match t.fallback {
                        None => return Err((at, "fallback is missing")),
                        Some(try_files::Fallback::Named(n)) if n as usize >= self.named => {
                            return Err((format!("{at}.named"), "no such named route"));
                        }
                        Some(try_files::Fallback::Status(c)) if !(100..=999).contains(&c) => {
                            return Err((format!("{at}.status"), "must be 100-999"));
                        }
                        Some(_) => {}
                    }
                }
            }
            Some(action::Kind::Return(r)) => check_return(r, format!("{at}.action.return"))?,
            Some(action::Kind::Proxy(_)) => {}
            _ if route.cache.is_some() => {
                return Err((format!("{at}.cache"), "only proxy routes are cached"));
            }
            Some(action::Kind::Gateway(g)) => self.upstream(g.proxy.as_ref(), at, "gateway")?,
            Some(action::Kind::Memcached(m)) => self.upstream(m.proxy.as_ref(), at, "memcached")?,
            Some(action::Kind::Grpc(g)) => self.upstream(g.proxy.as_ref(), at, "grpc")?,
        }
        self.error_pages(&route.error_pages, &format!("{at}.error_pages"))?;
        if route.access_log.is_some_and(|l| l as usize >= self.logs) {
            return Err((format!("{at}.access_log"), "no such access log"));
        }
        if matched {
            self.routes(&route.children, &format!("{at}.children"), true)?;
        }
        Ok(())
    }

    fn error_pages(&self, eps: &[IrErrorPage], at: &str) -> Result<(), Invalid> {
        for (i, e) in eps.iter().enumerate() {
            let at = format!("{at}[{i}]");
            if e.codes.is_empty() || e.codes.iter().any(|c| !(300..=599).contains(c)) {
                return Err((format!("{at}.codes"), "must be 300-599"));
            }
            match e.target {
                None => return Err((at, "target is missing")),
                Some(error_page::Target::Named(n)) if n as usize >= self.named => {
                    return Err((format!("{at}.named"), "no such named route"));
                }
                Some(_) => {}
            }
            if let Some(c) = e.status
                && c != 0
                && !(100..=999).contains(&c)
            {
                return Err((format!("{at}.status"), "must be 0 or 100-999"));
            }
        }
        Ok(())
    }
}

fn check_return(r: &ReturnAction, at: String) -> Result<(), Invalid> {
    if r.status > 999 {
        return Err((format!("{at}.status"), "must be 0-999"));
    }
    Ok(())
}

/// Decodes and validates a serialized snapshot, checking its hash when it
/// has one.
pub fn load(bytes: &[u8]) -> Result<Snapshot, LoadError> {
    let snap = Snapshot::decode(bytes).map_err(|e| LoadError::Decode(e.to_string()))?;
    if !snap.hash.is_empty() && hash(bytes).is_none_or(|h| h[..] != snap.hash[..]) {
        return Err(LoadError::Hash);
    }
    validate(&snap)?;
    Ok(snap)
}

/// SHA-256 of a serialized snapshot without its hash field (number 2), the
/// way the control plane computes it: it serializes the snapshot without the
/// hash, then adds the field. Dropping the field's records from the bytes
/// gives back exactly what was hashed, whatever their position. `None` for
/// malformed bytes.
pub fn hash(bytes: &[u8]) -> Option<[u8; 32]> {
    let mut h = openssl::sha::Sha256::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let start = rest;
        let key = varint(&mut rest)?;
        let len = match key & 7 {
            0 => {
                varint(&mut rest)?;
                0
            }
            1 => 8,
            2 => usize::try_from(varint(&mut rest)?).ok()?,
            5 => 4,
            _ => return None,
        };
        rest = rest.get(len..)?;
        if key >> 3 != 2 {
            h.update(&start[..start.len() - rest.len()]);
        }
    }
    Some(h.finish())
}

fn varint(b: &mut &[u8]) -> Option<u64> {
    let mut v = 0u64;
    for i in 0..10 {
        let (&c, rest) = b.split_first()?;
        *b = rest;
        v |= u64::from(c & 0x7f) << (7 * i);
        if c < 0x80 {
            return Some(v);
        }
    }
    None
}

/// Checks every cross reference and required field.
pub fn validate(snap: &Snapshot) -> Result<(), LoadError> {
    let sites = snap.sites.len();
    let listeners = snap.listeners.len();
    let upstreams = snap.upstreams.len();

    let certs = snap.certificates.len();
    let logs = snap.access_logs.len();
    let field = |field: String, error| Err(LoadError::Field { field, error });
    for (i, l) in snap.listeners.iter().enumerate() {
        if let Some(site) = l.default_site
            && site as usize >= sites
        {
            return Err(LoadError::ListenerSite { listener: i, site });
        }
        if l.tls
            .as_ref()
            .and_then(|t| t.default_certificate)
            .is_some_and(|c| c as usize >= certs)
        {
            return field(
                format!("listeners[{i}].tls.default_certificate"),
                "no such certificate",
            );
        }
        if l.http2 && l.tls.is_none() {
            return field(format!("listeners[{i}].http2"), "requires tls");
        }
        if l.http3 && l.tls.is_none() {
            return field(format!("listeners[{i}].http3"), "requires tls");
        }
    }
    for (i, u) in snap.upstreams.iter().enumerate() {
        if u.tls
            .as_ref()
            .and_then(|t| t.certificate)
            .is_some_and(|c| c as usize >= certs)
        {
            return field(
                format!("upstreams[{i}].tls.certificate"),
                "no such certificate",
            );
        }
    }

    for (i, st) in snap.streams.iter().enumerate() {
        let at = format!("streams[{i}]");
        if st.routes.is_empty() {
            return field(format!("{at}.routes"), "at least one route is required");
        }
        for (r, route) in st.routes.iter().enumerate() {
            if route.upstream as usize >= upstreams {
                return field(format!("{at}.routes[{r}].upstream"), "no such upstream");
            }
            if route
                .server_names
                .iter()
                .any(|h| h.kind() == host_match::Kind::Unspecified)
            {
                return field(format!("{at}.routes[{r}].server_names"), "unspecified kind");
            }
        }
        if st
            .conn_limits
            .iter()
            .any(|&z| z as usize >= snap.conn_zones.len())
        {
            return field(format!("{at}.conn_limits"), "no such connection zone");
        }
        if st.access_log.is_some_and(|l| l as usize >= logs) {
            return field(format!("{at}.access_log"), "no such access log");
        }
        if st.udp && (st.tls.is_some() || st.ssl_preread || st.proxy_protocol) {
            return field(
                format!("{at}.udp"),
                "tls, ssl_preread and proxy_protocol need TCP",
            );
        }
        if st.tls.is_some() && st.ssl_preread {
            return field(format!("{at}.ssl_preread"), "conflicts with tls");
        }
        if let Some(t) = &st.tls
            && t.default_certificate.is_none_or(|c| c as usize >= certs)
        {
            return field(
                format!("{at}.tls.default_certificate"),
                "no such certificate",
            );
        }
    }

    for (s, site) in snap.sites.iter().enumerate() {
        if let Some(&listener) = site.listeners.iter().find(|&&l| l as usize >= listeners) {
            return Err(LoadError::SiteListener { site: s, listener });
        }
        for (h, host) in site.hostnames.iter().enumerate() {
            if host.kind() == host_match::Kind::Unspecified {
                return Err(LoadError::UnspecifiedHost { site: s, host: h });
            }
        }
        if site.certificates.iter().any(|&c| c as usize >= certs) {
            return field(format!("sites[{s}].certificates"), "no such certificate");
        }
        if site.access_log.is_some_and(|l| l as usize >= logs) {
            return field(format!("sites[{s}].access_log"), "no such access log");
        }
        let v = SiteCheck {
            upstreams,
            named: site.named_routes.len(),
            logs,
        };
        let at = |field: String, error| LoadError::Site {
            site: s,
            field,
            error,
        };
        v.routes(&site.routes, "routes", true)
            .and_then(|()| {
                for (n, r) in site.named_routes.iter().enumerate() {
                    // A named route has no path; children are never searched.
                    v.route(r, &format!("named_routes[{n}]"), false)?;
                }
                if let Some(r) = &site.r#return {
                    check_return(r, "return".into())?;
                }
                v.error_pages(&site.error_pages, "error_pages")
            })
            .map_err(|(field, error)| at(field, error))?;
    }

    if let Some(u) = snap
        .upstreams
        .iter()
        .position(|u| u.targets.is_empty() && !u.discovered)
    {
        return Err(LoadError::EmptyUpstream { upstream: u });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxelo_api::snapshot::v1::{
        Action, HostMatch, Listener, PathMatch, ProxyAction, Route, Site, Target, Upstream,
    };

    fn proxy_route(upstream: u32) -> Route {
        Route {
            path: Some(PathMatch {
                kind: path_match::Kind::Prefix as i32,
                value: "/".into(),
            }),
            action: Some(Action {
                kind: Some(action::Kind::Proxy(ProxyAction {
                    upstream,
                    ..Default::default()
                })),
            }),
            ..Default::default()
        }
    }

    fn valid() -> Snapshot {
        Snapshot {
            revision: 1,
            listeners: vec![Listener {
                address: "0.0.0.0:80".into(),
                default_site: Some(0),
                ..Default::default()
            }],
            sites: vec![Site {
                listeners: vec![0],
                hostnames: vec![HostMatch {
                    kind: host_match::Kind::Exact as i32,
                    value: "example.com".into(),
                }],
                routes: vec![proxy_route(0)],
                ..Default::default()
            }],
            upstreams: vec![Upstream {
                targets: vec![Target {
                    address: "127.0.0.1:8080".into(),
                    weight: 1,
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn accepts_valid_snapshot() {
        let bytes = valid().encode_to_vec();
        assert_eq!(load(&bytes).map(|s| s.revision), Ok(1));
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(
            load(&[0xff, 0xff, 0xff]),
            Err(LoadError::Decode(_))
        ));
    }

    #[test]
    fn rejects_dangling_default_site() {
        let mut s = valid();
        s.listeners[0].default_site = Some(3);
        assert_eq!(
            validate(&s),
            Err(LoadError::ListenerSite {
                listener: 0,
                site: 3
            })
        );
    }

    #[test]
    fn rejects_dangling_site_listener() {
        let mut s = valid();
        s.sites[0].listeners = vec![1];
        assert_eq!(
            validate(&s),
            Err(LoadError::SiteListener {
                site: 0,
                listener: 1
            })
        );
    }

    #[test]
    fn rejects_unspecified_host_kind() {
        let mut s = valid();
        s.sites[0].hostnames[0].kind = 0;
        assert_eq!(
            validate(&s),
            Err(LoadError::UnspecifiedHost { site: 0, host: 0 })
        );
    }

    #[test]
    fn rejects_missing_path() {
        let mut s = valid();
        s.sites[0].routes[0].path = None;
        assert_eq!(
            validate(&s),
            Err(LoadError::Site {
                site: 0,
                field: "routes[0].path".into(),
                error: "missing or unspecified"
            })
        );
    }

    #[test]
    fn rejects_missing_action() {
        let mut s = valid();
        s.sites[0].routes[0].action = None;
        assert_eq!(
            validate(&s),
            Err(LoadError::Site {
                site: 0,
                field: "routes[0].action".into(),
                error: "missing"
            })
        );
    }

    #[test]
    fn rejects_dangling_upstream() {
        let mut s = valid();
        s.sites[0].routes[0] = proxy_route(1);
        assert_eq!(
            validate(&s),
            Err(LoadError::Site {
                site: 0,
                field: "routes[0].action.proxy.upstream".into(),
                error: "no such upstream"
            })
        );
    }

    #[test]
    fn checks_hash() {
        let mut s = valid();
        let unhashed = s.encode_to_vec();
        s.hash = openssl::sha::sha256(&unhashed).to_vec();
        let bytes = s.encode_to_vec();
        assert_eq!(hash(&bytes).map(|h| h.to_vec()), Some(s.hash.clone()));
        assert!(load(&bytes).is_ok());
        s.revision = 2;
        assert_eq!(load(&s.encode_to_vec()), Err(LoadError::Hash));
    }

    #[test]
    fn rejects_empty_upstream() {
        let mut s = valid();
        s.upstreams[0].targets.clear();
        assert_eq!(validate(&s), Err(LoadError::EmptyUpstream { upstream: 0 }));
    }
}
