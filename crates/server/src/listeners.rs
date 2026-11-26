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
use std::sync::Arc;

use proxelo_snapshot::Runtime;
use tokio::runtime::Handle;
use tokio::task::JoinHandle;

use crate::{Server, bind, bind_udp};

pub struct Listeners {
    /// Runtimes accept loops run on.
    workers: Vec<Handle>,
    /// One SO_REUSEPORT socket per address and worker instead of one socket
    /// per address.
    per_worker: bool,
    open: HashMap<(SocketAddr, Kind), Vec<JoinHandle<()>>>,
}

/// What a socket serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Kind {
    Http,
    Tcp,
    Udp,
}

enum Socket {
    Tcp(std::net::TcpListener),
    Udp(std::net::UdpSocket),
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
        }
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
        let mut fresh: Vec<((SocketAddr, Kind), Vec<Socket>)> = Vec::new();
        let listeners = rt.listeners.iter().enumerate().map(|(i, l)| {
            (
                format!("listeners[{i}]"),
                &l.addrs,
                Kind::Http,
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
        for (at, addrs, kind, reuse_port, backlog) in listeners.chain(streams) {
            for &addr in addrs.iter() {
                let key = (addr, kind);
                if want.contains(&key) {
                    continue;
                }
                want.push(key);
                if self.open.contains_key(&key) {
                    continue;
                }
                // One UDP socket per address: sessions are kept by client
                // address, and SO_REUSEPORT would spread them over sockets.
                let n = if self.per_worker && kind != Kind::Udp {
                    self.workers.len()
                } else {
                    1
                };
                let mut sockets = Vec::with_capacity(n);
                for _ in 0..n {
                    // Sockets bound so far close when `fresh` drops.
                    let s = match kind {
                        Kind::Udp => bind_udp(addr, reuse_port).map(Socket::Udp),
                        _ => bind(addr, reuse_port || self.per_worker, backlog).map(Socket::Tcp),
                    }
                    .map_err(|error| BindError::Bind {
                        at: at.clone(),
                        addr,
                        error,
                    })?;
                    sockets.push(s);
                }
                fresh.push((key, sockets));
            }
        }

        let next = server.prepare(rt).map_err(BindError::Tls)?;
        server.install(next);

        for (key, sockets) in fresh {
            let (addr, kind) = key;
            let tasks = sockets
                .into_iter()
                .zip(&self.workers)
                .map(|(s, worker)| {
                    let server = server.clone();
                    worker.spawn(async move {
                        let _ = match (kind, s) {
                            (Kind::Http, Socket::Tcp(s)) => server.accept(addr, s).await,
                            (_, Socket::Tcp(s)) => server.accept_stream(addr, s).await,
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
        Ok(())
    }

    /// Addresses currently open, sorted.
    pub fn addrs(&self) -> Vec<SocketAddr> {
        let mut v: Vec<_> = self.open.keys().map(|&(a, _)| a).collect();
        v.sort();
        v.dedup();
        v
    }
}
