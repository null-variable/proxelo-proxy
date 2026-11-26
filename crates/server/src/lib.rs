//! Serves HTTP/1.1, HTTP/2 and TLS traffic from the active snapshot.
//!
//! Each request loads the newest snapshot once and uses it to the end, so a
//! swap never mixes two configurations in one request. Upstream connection
//! pools, target health and metrics are carried over a swap by stable keys.

#![forbid(unsafe_code)]

mod access;
mod acme;
mod buf;
mod compress;
mod conn;
mod exchange;
mod h2;
mod headers;
mod health;
mod io;
mod limits;
mod listeners;
mod log;
pub mod metrics;
mod passwd;
mod phases;
mod proxy;
mod range;
mod reply;
mod sim;
mod static_file;
mod tls;
mod upstream;
mod vars;
mod worker;

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use proxelo_snapshot::Runtime;
use socket2::{Domain, Protocol, Socket, Type};

pub use acme::set_http_challenges;
pub use health::{resolve_all, resolve_names};
pub use listeners::{BindError, Listeners};
pub use log::reopen as reopen_logs;
pub use sim::simulate;
pub use tls::set_tls_challenges;
pub use worker::set_id as set_worker_id;

/// nginx's client_header_timeout bounds the TLS handshake too.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// A snapshot with the state built for it.
pub struct Active {
    pub rt: Arc<Runtime>,
    upstreams: Box<[upstream::State]>,
    /// Indexed like `rt.listeners`.
    tls: Box<[Option<tls::Acceptor>]>,
    metrics: metrics::Table,
    logs: log::Logs,
    zones: limits::Zones,
}

pub struct Server {
    active: ArcSwap<Active>,
    /// Number of workers; per-worker state is sharded this many ways.
    shards: usize,
    /// Runtime for background tasks such as active health checks.
    background: std::sync::OnceLock<tokio::runtime::Handle>,
}

impl Server {
    pub fn new(rt: Runtime, workers: usize) -> Arc<Self> {
        let shards = workers.max(1);
        let active = build(rt, shards, &upstream::Reuse::default(), None).expect("empty runtime");
        Arc::new(Self {
            active: ArcSwap::from_pointee(active),
            shards,
            background: std::sync::OnceLock::new(),
        })
    }

    /// Sets the runtime background tasks run on when a snapshot is
    /// installed outside one.
    pub fn set_background(&self, h: tokio::runtime::Handle) {
        let _ = self.background.set(h);
    }

    pub fn active(&self) -> Arc<Active> {
        self.active.load_full()
    }

    /// Builds what `rt` needs to serve, including its TLS contexts. Fails,
    /// changing nothing, when OpenSSL rejects a setting or certificate.
    pub(crate) fn prepare(&self, rt: Runtime) -> Result<Active, String> {
        let old = self.active.load();
        let mut reuse = upstream::Reuse::default();
        for state in old.upstreams.iter() {
            for pool in state.pools() {
                reuse
                    .pools
                    .entry(pool.key())
                    .or_insert_with(|| pool.clone());
            }
            for (addr, peer) in state.peers() {
                reuse
                    .peers
                    .entry((state.id.clone(), addr))
                    .or_insert_with(|| peer.clone());
            }
        }
        build(rt, self.shards, &reuse, Some(&old))
    }

    /// Makes `next` active. Requests in progress finish on the old snapshot,
    /// which is freed on a separate thread so a large one does not stall a
    /// worker.
    pub(crate) fn install(&self, next: Active) {
        let started = Instant::now();
        let next = Arc::new(next);
        // Checks run on the caller's runtime, or on the one set with
        // `set_background`; without either there is nothing to run them on.
        if let Some(h) = tokio::runtime::Handle::try_current()
            .ok()
            .or_else(|| self.background.get().cloned())
        {
            health::start_checks(&next, &h);
        }
        let old = self.active.swap(next);
        metrics::swapped(started.elapsed());
        std::thread::spawn(move || drop(old));
    }

    /// Replaces the active snapshot; see [`Self::prepare`].
    pub fn swap(&self, rt: Runtime) -> Result<(), String> {
        let next = self.prepare(rt)?;
        self.install(next);
        Ok(())
    }

    /// Accepts connections on `listener` forever. `addr` is the address the
    /// socket was bound for; each connection is served by the snapshot
    /// listener with that address. Must run inside a Tokio runtime.
    pub async fn accept(
        self: Arc<Self>,
        addr: SocketAddr,
        listener: TcpListener,
    ) -> std::io::Result<()> {
        let listener = tokio::net::TcpListener::from_std(listener)?;
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    tokio::spawn(self.clone().connection(addr, stream, peer));
                }
                // Out of descriptors or memory: back off instead of spinning.
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    }

    async fn connection(
        self: Arc<Self>,
        addr: SocketAddr,
        stream: tokio::net::TcpStream,
        peer: SocketAddr,
    ) {
        metrics::connection_opened();
        let _closed = scopeguard(metrics::connection_closed);
        let _ = stream.set_nodelay(true);
        let Ok(local) = stream.local_addr() else {
            return;
        };
        let active = self.active();
        let index = active
            .rt
            .listeners
            .iter()
            .position(|l| l.addrs.contains(&addr));
        let acceptor = index.and_then(|i| active.tls[i].as_ref());
        let Some(acceptor) = acceptor else {
            drop(active);
            let me = self.clone();
            conn::Conn::new(io::Stream::Tcp(stream), addr, local, peer)
                .serve(move || me.active())
                .await;
            return;
        };
        let Ok(ssl) = acceptor.ssl() else {
            return;
        };
        drop(active);
        let Ok(mut tls) = tokio_openssl::SslStream::new(ssl, stream) else {
            return;
        };
        let ok = matches!(
            tokio::time::timeout(HANDSHAKE_TIMEOUT, std::pin::Pin::new(&mut tls).accept()).await,
            Ok(Ok(()))
        );
        if !ok {
            metrics::tls_handshake_error();
            return;
        }
        let info = tls::TlsInfo::of(tls.ssl());
        match tls.ssl().selected_alpn_protocol() {
            Some(b"h2") => h2::serve(self, addr, tls, local, peer, info).await,
            // A TLS-ALPN-01 validation only needs the handshake.
            Some(b"acme-tls/1") => {}
            _ => {
                let me = self.clone();
                let mut c = conn::Conn::new(io::Stream::Tls(Box::new(tls)), addr, local, peer);
                c.x.tls = Some(info);
                c.serve(move || me.active()).await;
            }
        }
    }
}

/// Runs `f` when dropped.
fn scopeguard(f: fn()) -> impl Drop {
    struct Guard(fn());
    impl Drop for Guard {
        fn drop(&mut self) {
            (self.0)();
        }
    }
    Guard(f)
}

fn build(
    rt: Runtime,
    shards: usize,
    reuse: &upstream::Reuse,
    old: Option<&Active>,
) -> Result<Active, String> {
    let rt = Arc::new(rt);
    let zones = limits::Zones::new(&rt, old.map(|o| (&*o.rt, &o.zones)));
    let tls = tls::build(&rt)?;
    let upstreams = rt
        .upstreams
        .iter()
        .map(|u| upstream::State::new(u, shards, reuse))
        .collect();
    Ok(Active {
        metrics: metrics::Table::new(&rt),
        logs: log::Logs::new(&rt.access_logs),
        zones,
        upstreams,
        tls,
        rt,
    })
}

/// Builds the TLS contexts of `rt` without serving it, for checks and the
/// dry-load helper.
pub fn check_tls(rt: &Runtime) -> Result<(), String> {
    tls::check(rt)
}

/// Opens a non-blocking listening socket. `backlog` 0 means 511, the nginx
/// default.
pub fn bind(addr: SocketAddr, reuse_port: bool, backlog: u32) -> std::io::Result<TcpListener> {
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
