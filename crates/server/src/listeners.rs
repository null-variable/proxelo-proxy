//! Listening sockets that follow the active snapshot.
//!
//! Sockets are keyed by address and kind (HTTP listener, TCP stream, UDP
//! stream). Applying a snapshot binds the sockets it adds before anything
//! changes, swaps the snapshot in, starts serving the new sockets and closes
//! the ones it no longer lists. Sockets present in both snapshots stay open,
//! so a swap never drops a listen queue.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::sync::Arc;

use proxelo_snapshot::Runtime;
use tokio::runtime::Handle;
use tokio::task::JoinHandle;

use crate::handoff::{Handoff, Inherited};
use crate::{Server, bind, bind_udp};

pub struct Listeners {
    /// Runtimes accept loops run on.
    workers: Vec<Handle>,
    /// One SO_REUSEPORT socket per address and worker instead of one socket
    /// per address.
    per_worker: bool,
    open: HashMap<(SocketAddr, Kind), Vec<JoinHandle<()>>>,
    /// Duplicates of the open sockets, for a successor process.
    handoff: Handoff,
    /// Sockets taken over from a predecessor and not yet claimed by a
    /// snapshot.
    inherited: Inherited,
}

/// What a socket serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Kind {
    Http,
    Tcp,
    Udp,
    /// HTTP/3 on a listener's address.
    Quic,
}

impl Kind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Quic => "quic",
        }
    }

    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "http" => Some(Self::Http),
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            "quic" => Some(Self::Quic),
            _ => None,
        }
    }
}

pub(crate) enum Socket {
    Tcp(std::net::TcpListener),
    Udp(std::net::UdpSocket),
}

impl Socket {
    pub(crate) fn set_nonblocking(&self) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.set_nonblocking(true),
            Self::Udp(s) => s.set_nonblocking(true),
        }
    }

    fn dup(&self) -> io::Result<OwnedFd> {
        match self {
            Self::Tcp(s) => s.try_clone().map(OwnedFd::from),
            Self::Udp(s) => s.try_clone().map(OwnedFd::from),
        }
    }
}

/// Why a snapshot could not be applied; nothing changed.
#[derive(Debug)]
pub enum BindError {
    Bind {
        /// "listeners[0]" or "streams[0]".
        at: String,
        addr: SocketAddr,
        error: io::Error,
    },
    /// TLS contexts could not be built.
    Tls(String),
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind { at, addr, error } => write!(f, "{at}: bind {addr}: {error}"),
            Self::Tls(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for BindError {}

impl Listeners {
    /// `workers` must not be empty. With `per_worker`, each worker accepts on
    /// its own socket; otherwise one socket per address is accepted on the
    /// first worker's runtime.
    /// The runtime background tasks run on: the first worker's.
    pub fn background(&self) -> Handle {
        self.workers[0].clone()
    }

    pub fn new(workers: Vec<Handle>, per_worker: bool) -> Self {
        assert!(!workers.is_empty(), "at least one worker runtime");
        Self {
            workers,
            per_worker,
            open: HashMap::new(),
            handoff: Handoff::default(),
            inherited: Inherited(HashMap::new()),
        }
    }

    /// Serves the sockets of a predecessor instead of binding new ones for
    /// the addresses they were bound for. Call before the first
    /// [`Self::apply`]; sockets that snapshot does not list are closed.
    pub fn inherit(&mut self, sockets: Inherited) {
        self.inherited = sockets;
    }

    /// The sockets to hand to a successor process; follows later applies.
    pub fn handoff(&self) -> Handoff {
        self.handoff.clone()
    }

    /// Stops accepting on every socket; connections already accepted carry
    /// on. Used once a successor serves the same sockets.
    pub fn close(&mut self) {
        for tasks in self.open.values() {
            tasks.iter().for_each(JoinHandle::abort);
        }
        self.open.clear();
        self.handoff.retain(|_| false);
    }

    /// Makes `rt` the active snapshot of `server` and opens and closes sockets
    /// to match it. If an address cannot be bound or TLS cannot be set up,
    /// nothing changes.
    ///
    /// The settings of a socket that stays open (`reuse_port`, `backlog`) are
    /// kept until its address is removed; changing them on a live socket
    /// would drop its queued connections.
    pub fn apply(&mut self, server: &Arc<Server>, rt: Runtime) -> Result<(), BindError> {
        let mut want: Vec<(SocketAddr, Kind)> = Vec::new();
        // The flag marks sockets taken from `inherited`.
        let mut fresh: Vec<((SocketAddr, Kind), Vec<Socket>, bool)> = Vec::new();
        let listeners = rt.listeners.iter().enumerate().map(|(i, l)| {
            (
                format!("listeners[{i}]"),
                &l.addrs,
                Kind::Http,
                l.reuse_port,
                l.backlog,
            )
        });
        let quic = rt
            .listeners
            .iter()
            .enumerate()
            .filter(|(_, l)| l.http3)
            .map(|(i, l)| {
                (
                    format!("listeners[{i}].http3"),
                    &l.addrs,
                    Kind::Quic,
                    l.reuse_port,
                    l.backlog,
                )
            });
        let streams = rt.streams.iter().enumerate().map(|(i, s)| {
            let kind = if s.udp { Kind::Udp } else { Kind::Tcp };
            (
                format!("streams[{i}]"),
                &s.addrs,
                kind,
                s.reuse_port,
                s.backlog,
            )
        });
        for (at, addrs, kind, reuse_port, backlog) in listeners.chain(quic).chain(streams) {
            for &addr in addrs.iter() {
                let key = (addr, kind);
                if want.contains(&key) {
                    continue;
                }
                want.push(key);
                if self.open.contains_key(&key) {
                    continue;
                }
                if let Some(sockets) = self.inherited.0.remove(&key) {
                    fresh.push((key, sockets, true));
                    continue;
                }
                // One UDP socket per address: sessions are kept by client
                // address, and SO_REUSEPORT would spread them over sockets.
                let n = if self.per_worker && !matches!(kind, Kind::Udp | Kind::Quic) {
                    self.workers.len()
                } else {
                    1
                };
                let mut sockets = Vec::with_capacity(n);
                for _ in 0..n {
                    // Sockets bound so far close when `fresh` drops.
                    let s = match kind {
                        Kind::Udp | Kind::Quic => bind_udp(addr, reuse_port).map(Socket::Udp),
                        _ => bind(addr, reuse_port || self.per_worker, backlog).map(Socket::Tcp),
                    };
                    match s {
                        Ok(s) => sockets.push(s),
                        Err(error) => {
                            self.restore(fresh);
                            return Err(BindError::Bind {
                                at: at.clone(),
                                addr,
                                error,
                            });
                        }
                    }
                }
                fresh.push((key, sockets, false));
            }
        }

        let next = match server.prepare(rt) {
            Ok(next) => next,
            Err(e) => {
                self.restore(fresh);
                return Err(BindError::Tls(e));
            }
        };
        server.install(next);
        // Inherited sockets the snapshot does not list close here.
        self.inherited.0.clear();

        for (key, sockets, _) in fresh {
            let (addr, kind) = key;
            let dups = sockets
                .iter()
                .map(Socket::dup)
                .collect::<io::Result<Vec<_>>>();
            match dups {
                Ok(fds) => self.handoff.insert(key, fds),
                Err(e) => eprintln!("{addr}: cannot keep for a binary upgrade: {e}"),
            }
            // Inherited sockets may number other than the workers (an
            // upgrade that changed --workers); they are spread round-robin.
            let tasks = sockets
                .into_iter()
                .zip(self.workers.iter().cycle())
                .map(|(s, worker)| {
                    let server = server.clone();
                    worker.spawn(async move {
                        let _ = match (kind, s) {
                            (Kind::Http, Socket::Tcp(s)) => server.accept(addr, s).await,
                            (_, Socket::Tcp(s)) => server.accept_stream(addr, s).await,
                            (Kind::Quic, Socket::Udp(s)) => server.serve_quic(addr, s).await,
                            (_, Socket::Udp(s)) => server.serve_udp(addr, s).await,
                        };
                    })
                })
                .collect();
            self.open.insert(key, tasks);
        }
        // Aborting an accept loop drops its socket. Connections already
        // accepted keep running; see conn::serve for how they end.
        self.open.retain(|key, tasks| {
            let keep = want.contains(key);
            if !keep {
                tasks.iter().for_each(JoinHandle::abort);
            }
            keep
        });
        self.handoff.retain(|key| want.contains(key));
        Ok(())
    }

    /// Puts inherited sockets back after a failed apply, for the next
    /// attempt; the ones bound here close.
    fn restore(&mut self, fresh: Vec<((SocketAddr, Kind), Vec<Socket>, bool)>) {
        for (key, sockets, inherited) in fresh {
            if inherited {
                self.inherited.0.insert(key, sockets);
            }
        }
    }

    /// Addresses currently open, sorted.
    pub fn addrs(&self) -> Vec<SocketAddr> {
        let mut v: Vec<_> = self.open.keys().map(|&(a, _)| a).collect();
        v.sort();
        v.dedup();
        v
    }
}
