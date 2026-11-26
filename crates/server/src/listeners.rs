//! Listening sockets that follow the active snapshot.
//!
//! Sockets are keyed by address. Applying a snapshot binds the addresses it
//! adds before anything changes, swaps the snapshot in, starts accepting on the
//! new sockets and closes the ones it no longer lists. Sockets for addresses
//! present in both snapshots stay open, so a swap never drops a listen queue.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use proxelo_snapshot::Runtime;
use tokio::runtime::Handle;
use tokio::task::JoinHandle;

use crate::{Server, bind};

pub struct Listeners {
    /// Runtimes accept loops run on.
    workers: Vec<Handle>,
    /// One SO_REUSEPORT socket per address and worker instead of one socket
    /// per address.
    per_worker: bool,
    open: HashMap<SocketAddr, Vec<JoinHandle<()>>>,
}

/// Why a snapshot could not be applied; nothing changed.
#[derive(Debug)]
pub enum BindError {
    Bind {
        listener: usize,
        addr: SocketAddr,
        error: io::Error,
    },
    /// TLS contexts could not be built.
    Tls(String),
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind {
                listener,
                addr,
                error,
            } => write!(f, "listeners[{listener}]: bind {addr}: {error}"),
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
        let mut want: Vec<SocketAddr> = Vec::new();
        let mut fresh: Vec<(SocketAddr, Vec<std::net::TcpListener>)> = Vec::new();
        for (i, l) in rt.listeners.iter().enumerate() {
            for &addr in &l.addrs {
                if want.contains(&addr) {
                    continue;
                }
                want.push(addr);
                if self.open.contains_key(&addr) {
                    continue;
                }
                let n = if self.per_worker {
                    self.workers.len()
                } else {
                    1
                };
                let mut sockets = Vec::with_capacity(n);
                for _ in 0..n {
                    // Sockets bound so far close when `fresh` drops.
                    let s = bind(addr, l.reuse_port || self.per_worker, l.backlog).map_err(
                        |error| BindError::Bind {
                            listener: i,
                            addr,
                            error,
                        },
                    )?;
                    sockets.push(s);
                }
                fresh.push((addr, sockets));
            }
        }

        let next = server.prepare(rt).map_err(BindError::Tls)?;
        server.install(next);

        for (addr, sockets) in fresh {
            let tasks = sockets
                .into_iter()
                .zip(&self.workers)
                .map(|(s, worker)| {
                    let server = server.clone();
                    worker.spawn(async move {
                        let _ = server.accept(addr, s).await;
                    })
                })
                .collect();
            self.open.insert(addr, tasks);
        }
        // Aborting an accept loop drops its socket. Connections already
        // accepted keep running; see conn::serve for how they end.
        self.open.retain(|addr, tasks| {
            let keep = want.contains(addr);
            if !keep {
                tasks.iter().for_each(JoinHandle::abort);
            }
            keep
        });
        Ok(())
    }

    /// Addresses currently open, sorted.
    pub fn addrs(&self) -> Vec<SocketAddr> {
        let mut v: Vec<_> = self.open.keys().copied().collect();
        v.sort();
        v
    }
}
