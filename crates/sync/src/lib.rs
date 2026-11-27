//! The proxy side of the snapshot distribution stream.
//!
//! The proxy dials the control plane over a Unix socket, says Hello with the
//! revision it serves, and then receives snapshots for as long as the stream
//! lasts. Every snapshot is handed to an [`Apply`] and answered with an Ack.
//! When the stream ends the proxy keeps serving what it has and dials again
//! with exponential backoff.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use proxelo_api::distrib::v1::{
    Ack, Hello, SyncRequest, distribution_service_client::DistributionServiceClient, sync_request,
    sync_response,
};
pub use proxelo_api::distrib::v1::{
    Challenges, Purge, PurgeDone, RouteStats, SiteStats, Stats, TapEvents, TapFilter, TargetStats,
};
use proxelo_api::snapshot::v1::Snapshot;
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

const MIN_BACKOFF: Duration = Duration::from_millis(100);
const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Makes a received snapshot active.
pub trait Apply {
    /// Revision currently served, reported in Hello; 0 if none.
    fn active_revision(&self) -> u64;
    /// Hash of the snapshot currently served, empty if none.
    fn active_hash(&self) -> &[u8];
    /// Validates, builds and swaps in `snap`, decoded and hash-checked from
    /// `bytes`, which are persisted as received. On error the previous
    /// snapshot stays active.
    fn apply(&mut self, snap: Snapshot, bytes: &[u8]) -> Result<(), String>;
    /// Replaces the ACME challenges answered.
    fn challenges(&mut self, c: Challenges);
    /// SHA-256 (lowercase hex) of the WebAssembly modules stored, reported
    /// in Hello so only missing ones are sent.
    fn wasm_modules(&self) -> Vec<String> {
        Vec::new()
    }
    /// Stores a WebAssembly module received whole.
    fn store_wasm(&mut self, _sha256: &str, _bytes: &[u8]) -> Result<(), String> {
        Err("no wasm host".into())
    }
    /// Traffic counters since start, sent every [`STATS_INTERVAL`].
    fn stats(&self) -> Stats;
    /// Replaces the Live Tap filter.
    fn tap(&mut self, _f: TapFilter) {}
    /// Tapped requests collected since the last call, polled every
    /// [`TAP_INTERVAL`].
    fn tap_events(&mut self) -> Option<TapEvents> {
        None
    }
    /// Removes cached responses; answered with what was removed.
    fn purge(&self, p: Purge) -> impl std::future::Future<Output = PurgeDone> + Send {
        async move {
            PurgeDone {
                id: p.id,
                removed: 0,
                error: "no response cache".into(),
            }
        }
    }
    /// Periodic work, every [`TICK_INTERVAL`], also while the control plane
    /// is unreachable.
    fn tick(&mut self) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }
}

/// How often [`Apply::tick`] runs.
pub const TICK_INTERVAL: Duration = Duration::from_secs(1);

/// How often [`Apply::stats`] is reported.
pub const STATS_INTERVAL: Duration = Duration::from_secs(5);

/// How often tapped requests are sent.
pub const TAP_INTERVAL: Duration = Duration::from_millis(250);

pub struct Client {
    pub socket: PathBuf,
    pub node_id: String,
    pub version: String,
}

impl Client {
    /// Keeps a stream to the control plane open forever, reconnecting after
    /// failures. `log` receives one line per state change.
    pub async fn run<A: Apply + Send>(&self, target: &mut A, log: impl Fn(&str)) {
        let mut backoff = MIN_BACKOFF;
        let mut last_err = String::new();
        loop {
            match self.session(target, &log).await {
                Ok(()) => {
                    log("control plane closed the stream");
                    backoff = MIN_BACKOFF;
                    last_err.clear();
                }
                Err(Session { established, error }) => {
                    if established {
                        backoff = MIN_BACKOFF;
                    }
                    // Repeated identical failures (control plane down) are
                    // logged once.
                    if error != last_err {
                        log(&format!("control plane: {error}"));
                        last_err = error;
                    }
                }
            }
            // Keep ticking while waiting to reconnect.
            let until = tokio::time::Instant::now() + backoff;
            while tokio::time::Instant::now() < until {
                tokio::time::sleep_until(until.min(tokio::time::Instant::now() + TICK_INTERVAL))
                    .await;
                target.tick().await;
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    async fn session<A: Apply>(&self, target: &mut A, log: &impl Fn(&str)) -> Result<(), Session> {
        let path = self.socket.clone();
        // The URI is required by the HTTP/2 layer but never resolved: the
        // connector always dials the socket.
        let channel = Endpoint::from_static("http://control.local")
            .connect_with_connector(service_fn(move |_: Uri| {
                let path = path.clone();
                async move { UnixStream::connect(path).await.map(TokioIo::new) }
            }))
            .await
            .map_err(Session::before)?;
        let mut client = DistributionServiceClient::new(channel);

        let (tx, rx) = mpsc::channel(4);
        let hello = SyncRequest {
            kind: Some(sync_request::Kind::Hello(Hello {
                node_id: self.node_id.clone(),
                proxy_version: self.version.clone(),
                active_revision: target.active_revision(),
                wasm_modules: target.wasm_modules(),
            })),
        };
        tx.send(hello).await.map_err(Session::before)?;
        let mut inbound = client
            .sync(ReceiverStream::new(rx))
            .await
            .map_err(Session::before)?
            .into_inner();
        log("connected to control plane");

        let mut ticker = tokio::time::interval(STATS_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut tick = tokio::time::interval(TICK_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut tap = tokio::time::interval(TAP_INTERVAL);
        tap.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // A tap does not survive a reconnect: the control plane sends the
        // filter again if it is still wanted.
        target.tap(TapFilter::default());
        // The module being received, (sha256, bytes so far).
        let mut wasm: Option<(String, Vec<u8>)> = None;
        loop {
            let msg = tokio::select! {
                _ = tick.tick() => {
                    target.tick().await;
                    continue;
                }
                m = inbound.message() => match m {
                    Ok(Some(m)) => m,
                    Ok(None) => return Ok(()),
                    Err(e) => return Err(Session::after(e)),
                },
                _ = tap.tick() => {
                    if let Some(ev) = target.tap_events() {
                        let req = SyncRequest {
                            kind: Some(sync_request::Kind::TapEvents(ev)),
                        };
                        tx.send(req).await.map_err(Session::after)?;
                    }
                    continue;
                }
                _ = ticker.tick() => {
                    let req = SyncRequest {
                        kind: Some(sync_request::Kind::Stats(target.stats())),
                    };
                    tx.send(req).await.map_err(Session::after)?;
                    continue;
                }
            };
            let bytes = match msg.kind {
                Some(sync_response::Kind::SnapshotData(b)) => b,
                Some(sync_response::Kind::Challenges(c)) => {
                    target.challenges(c);
                    continue;
                }
                Some(sync_response::Kind::Tap(f)) => {
                    target.tap(f);
                    continue;
                }
                Some(sync_response::Kind::WasmChunk(c)) => {
                    let (sha, bytes) = match wasm.take() {
                        Some((sha, b)) if sha == c.sha256 && b.len() as u64 == c.offset => (sha, b),
                        _ if c.offset == 0 => (c.sha256, Vec::new()),
                        // A chunk out of order: the module is sent again
                        // after the next reconnect.
                        _ => continue,
                    };
                    let mut bytes = bytes;
                    bytes.extend_from_slice(&c.data);
                    if c.last {
                        if let Err(e) = target.store_wasm(&sha, &bytes) {
                            log(&format!("wasm module {sha}: {e}"));
                        }
                    } else {
                        wasm = Some((sha, bytes));
                    }
                    continue;
                }
                Some(sync_response::Kind::Purge(p)) => {
                    let done = target.purge(p).await;
                    let req = SyncRequest {
                        kind: Some(sync_request::Kind::PurgeDone(done)),
                    };
                    tx.send(req).await.map_err(Session::after)?;
                    continue;
                }
                // The deprecated embedded form cannot be verified.
                #[allow(deprecated)]
                Some(sync_response::Kind::Snapshot(_)) | None => continue,
            };
            let (revision, result) = match proxelo_snapshot::load(&bytes) {
                Err(e) => (0, Err(e.to_string())),
                Ok(snap) if !snap.hash.is_empty() && snap.hash == target.active_hash() => {
                    // Already serving it, typically the LKG after a restart.
                    (snap.revision, Ok(()))
                }
                Ok(snap) => {
                    let revision = snap.revision;
                    let r = target.apply(snap, &bytes);
                    match &r {
                        Ok(()) => log(&format!("applied revision {revision}")),
                        Err(e) => log(&format!("rejected revision {revision}: {e}")),
                    }
                    (revision, r)
                }
            };
            let ack = Ack {
                revision,
                applied: result.is_ok(),
                error: result.err().unwrap_or_default(),
            };
            let req = SyncRequest {
                kind: Some(sync_request::Kind::Ack(ack)),
            };
            tx.send(req).await.map_err(Session::after)?;
        }
    }
}

/// Why a session ended, and whether the stream had been established.
struct Session {
    established: bool,
    error: String,
}

impl Session {
    fn before(e: impl std::fmt::Display) -> Self {
        Self {
            established: false,
            error: e.to_string(),
        }
    }

    fn after(e: impl std::fmt::Display) -> Self {
        Self {
            established: true,
            error: e.to_string(),
        }
    }
}
