//! Serves HTTP/1.1 traffic from the active snapshot.
//!
//! Each request loads the newest snapshot once and uses it to the end, so a
//! swap never mixes two configurations in one request. Upstream connection
//! pools are carried over a swap by target address.

#![forbid(unsafe_code)]

mod buf;
mod conn;
mod listeners;
mod phases;
mod proxy;
mod reply;
mod static_file;
mod upstream;
mod worker;

use std::io;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use arc_swap::ArcSwap;
use proxelo_snapshot::Runtime;
use socket2::{Domain, Protocol, Socket, Type};

pub use listeners::{BindError, Listeners};
pub use worker::set_id as set_worker_id;

/// A snapshot with the upstream state built for it.
pub struct Active {
    pub rt: Runtime,
    upstreams: Box<[upstream::State]>,
}

pub struct Server {
    active: ArcSwap<Active>,
    /// Number of workers; per-worker state is sharded this many ways.
    shards: usize,
}

impl Server {
    pub fn new(rt: Runtime, workers: usize) -> Arc<Self> {
        let shards = workers.max(1);
        let active = build(rt, shards, &upstream::Reuse::new());
        Arc::new(Self {
            active: ArcSwap::from_pointee(active),
            shards,
        })
    }

    pub fn active(&self) -> Arc<Active> {
        self.active.load_full()
    }

    /// Replaces the active snapshot. Requests in progress finish on the old
    /// one; idle upstream connections to targets that remain are kept.
    pub fn swap(&self, rt: Runtime) {
        let old = self.active.load();
        let mut reuse = upstream::Reuse::new();
        for (u, state) in old.upstreams.iter().enumerate() {
            let idle = old.rt.upstreams[u].keepalive_idle;
            for pool in state.pools() {
                reuse
                    .entry((pool.addr, idle))
                    .or_insert_with(|| pool.clone());
            }
        }
        self.active.store(Arc::new(build(rt, self.shards, &reuse)));
    }

    /// Accepts connections on `listener` forever. `addr` is the address the
    /// socket was bound for; each request is served by the snapshot listener
    /// with that address. Must run inside a Tokio runtime.
    pub async fn accept(
        self: Arc<Self>,
        addr: SocketAddr,
        listener: TcpListener,
    ) -> io::Result<()> {
        let listener = tokio::net::TcpListener::from_std(listener)?;
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(conn::serve(self.clone(), addr, stream));
                }
                // Out of descriptors or memory: back off instead of spinning.
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        }
    }
}

fn build(rt: Runtime, shards: usize, reuse: &upstream::Reuse) -> Active {
    let upstreams = rt
        .upstreams
        .iter()
        .map(|u| upstream::State::new(u, shards, reuse))
        .collect();
    Active { rt, upstreams }
}

/// Opens a non-blocking listening socket. `backlog` 0 means 511, the nginx
/// default.
pub fn bind(addr: SocketAddr, reuse_port: bool, backlog: u32) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if reuse_port {
        socket.set_reuse_port(true)?;
    }
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    let backlog = if backlog == 0 { 511 } else { backlog };
    socket.listen(i32::try_from(backlog).unwrap_or(i32::MAX))?;
    Ok(socket.into())
}
