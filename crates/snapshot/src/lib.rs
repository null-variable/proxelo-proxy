//! Validation of an incoming snapshot before it is swapped in.
//!
//! The control plane resolves references and inheritance. This crate only
//! checks what the proxy depends on to serve traffic safely: every index points
//! at an existing object and every match and action is fully specified.

use std::fmt;

use prost::Message;
use proxelo_api::snapshot::v1::{Snapshot, action, host_match, path_match};

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
    UnspecifiedPath {
        site: usize,
        route: usize,
    },
    MissingAction {
        site: usize,
        route: usize,
    },
    ProxyUpstream {
        site: usize,
        route: usize,
        upstream: u32,
    },
    EmptyUpstream {
        upstream: usize,
    },
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
            Self::UnspecifiedPath { site, route } => {
                write!(
                    f,
                    "sites[{site}].routes[{route}].path: missing or unspecified"
                )
            }
            Self::MissingAction { site, route } => {
                write!(f, "sites[{site}].routes[{route}].action: missing")
            }
            Self::ProxyUpstream {
                site,
                route,
                upstream,
            } => {
                write!(
                    f,
                    "sites[{site}].routes[{route}].action.proxy: no upstream {upstream}"
                )
            }
            Self::EmptyUpstream { upstream } => write!(f, "upstreams[{upstream}]: no targets"),
        }
    }
}

impl std::error::Error for LoadError {}

/// Decodes and validates a serialized snapshot.
pub fn load(bytes: &[u8]) -> Result<Snapshot, LoadError> {
    let snap = Snapshot::decode(bytes).map_err(|e| LoadError::Decode(e.to_string()))?;
    validate(&snap)?;
    Ok(snap)
}

/// Checks every cross reference and required field.
pub fn validate(snap: &Snapshot) -> Result<(), LoadError> {
    let sites = snap.sites.len();
    let listeners = snap.listeners.len();
    let upstreams = snap.upstreams.len();

    for (i, l) in snap.listeners.iter().enumerate() {
        if let Some(site) = l.default_site
            && site as usize >= sites
        {
            return Err(LoadError::ListenerSite { listener: i, site });
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
        for (r, route) in site.routes.iter().enumerate() {
            match &route.path {
                Some(p) if p.kind() != path_match::Kind::Unspecified => {}
                _ => return Err(LoadError::UnspecifiedPath { site: s, route: r }),
            }
            match route.action.as_ref().and_then(|a| a.kind.as_ref()) {
                None => return Err(LoadError::MissingAction { site: s, route: r }),
                Some(action::Kind::Proxy(p)) if p.upstream as usize >= upstreams => {
                    return Err(LoadError::ProxyUpstream {
                        site: s,
                        route: r,
                        upstream: p.upstream,
                    });
                }
                Some(_) => {}
            }
        }
    }

    if let Some(u) = snap.upstreams.iter().position(|u| u.targets.is_empty()) {
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
                kind: Some(action::Kind::Proxy(ProxyAction { upstream })),
            }),
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
            }],
            upstreams: vec![Upstream {
                targets: vec![Target {
                    address: "127.0.0.1:8080".into(),
                    weight: 1,
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
            Err(LoadError::UnspecifiedPath { site: 0, route: 0 })
        );
    }

    #[test]
    fn rejects_missing_action() {
        let mut s = valid();
        s.sites[0].routes[0].action = None;
        assert_eq!(
            validate(&s),
            Err(LoadError::MissingAction { site: 0, route: 0 })
        );
    }

    #[test]
    fn rejects_dangling_upstream() {
        let mut s = valid();
        s.sites[0].routes[0] = proxy_route(1);
        assert_eq!(
            validate(&s),
            Err(LoadError::ProxyUpstream {
                site: 0,
                route: 0,
                upstream: 1
            })
        );
    }

    #[test]
    fn rejects_empty_upstream() {
        let mut s = valid();
        s.upstreams[0].targets.clear();
        assert_eq!(validate(&s), Err(LoadError::EmptyUpstream { upstream: 0 }));
    }
}
