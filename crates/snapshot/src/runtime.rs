//! The runtime form of a snapshot: lookup structures the request path reads
//! without parsing, hashing strings into new allocations or resolving names.

use std::collections::HashMap;
use std::fmt;
use std::net::{SocketAddr, ToSocketAddrs};

use foldhash::fast::FixedState;
use proxelo_api::snapshot::v1::{self as ir, action, path_match};

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
    hosts: Map<u32>,
    /// The site answering requests whose host matches no site. nginx uses the
    /// first server of a listen socket when none is marked default.
    default_site: Option<u32>,
}

#[derive(Debug)]
pub struct Site {
    exact: Map<u32>,
    /// Prefix routes, longest first.
    prefixes: Box<[(Box<[u8]>, u32)]>,
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
                hosts: Map::default(),
                default_site: l.default_site,
            });
        }

        let mut sites = Vec::with_capacity(snap.sites.len());
        for (s, site) in snap.sites.iter().enumerate() {
            for &li in &site.listeners {
                let l = &mut listeners[li as usize];
                l.default_site.get_or_insert(s as u32);
                for h in &site.hostnames {
                    // The control plane rejects the same name on one listener
                    // twice; keep the first in case an older one did not.
                    l.hosts
                        .entry(h.value.to_ascii_lowercase().into_bytes().into())
                        .or_insert(s as u32);
                }
            }

            let mut exact = Map::default();
            let mut prefixes = Vec::new();
            let mut routes = Vec::with_capacity(site.routes.len());
            for (r, route) in site.routes.iter().enumerate() {
                let path = route.path.as_ref().expect("validated");
                let key: Box<[u8]> = path.value.as_bytes().into();
                match path.kind() {
                    path_match::Kind::Exact => {
                        exact.entry(key).or_insert(r as u32);
                    }
                    path_match::Kind::Prefix => prefixes.push((key, r as u32)),
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
            prefixes.sort_by_key(|(p, _)| std::cmp::Reverse(p.len()));
            prefixes.dedup_by(|a, b| a.0 == b.0);
            sites.push(Site {
                exact,
                prefixes: prefixes.into(),
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

impl Listener {
    /// Finds the site for a Host value. `host` must be lowercase with any port
    /// and trailing dot removed.
    pub fn site(&self, host: Option<&[u8]>) -> Option<u32> {
        host.and_then(|h| self.hosts.get(h).copied())
            .or(self.default_site)
    }
}

impl Site {
    /// Finds the route for a normalized path with nginx location order: an
    /// exact match wins, otherwise the longest matching prefix.
    pub fn route(&self, path: &[u8]) -> Option<u32> {
        if let Some(&r) = self.exact.get(path) {
            return Some(r);
        }
        self.prefixes
            .iter()
            .find(|(p, _)| path.starts_with(p))
            .map(|&(_, r)| r)
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
        assert_eq!(l.site(Some(b"a.example")), Some(0));
        assert_eq!(l.site(Some(b"c.example")), Some(1));
        assert_eq!(l.site(Some(b"other")), Some(0), "first site is the default");
        assert_eq!(l.site(None), Some(0));

        let snap = snapshot(snap.sites, Some(1));
        let rt = Runtime::build(&snap).unwrap();
        assert_eq!(rt.listeners[0].site(Some(b"other")), Some(1));
    }

    #[test]
    fn listener_without_sites_has_no_default() {
        let rt = Runtime::build(&snapshot(vec![], None)).unwrap();
        assert_eq!(rt.listeners[0].site(Some(b"a")), None);
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
        assert_eq!(s.route(b"/"), Some(0));
        assert_eq!(s.route(b"/index.html"), Some(0));
        assert_eq!(s.route(b"/api"), Some(0));
        assert_eq!(s.route(b"/api/"), Some(2), "exact wins over prefix");
        assert_eq!(s.route(b"/api/x"), Some(1), "first duplicate prefix wins");
        assert_eq!(s.route(b"/api/v1/x"), Some(3), "longest prefix wins");
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
        assert_eq!(rt.sites[0].route(b"/y"), None);
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
