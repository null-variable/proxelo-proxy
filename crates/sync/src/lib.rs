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
use prost::Message;
use proxelo_api::distrib::v1::{
    Ack, Hello, SyncRequest, distribution_service_client::DistributionServiceClient, sync_request,
    sync_response,
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
    /// Validates, builds and swaps in `snap`. `bytes` is its serialized form,
    /// for persisting. On error the previous snapshot stays active.
    fn apply(&mut self, snap: Snapshot, bytes: &[u8]) -> Result<(), String>;
}

pub struct Client {
    pub socket: PathBuf,
    pub node_id: String,
    pub version: String,
}

impl Client {
    /// Keeps a stream to the control plane open forever, reconnecting after
    /// failures. `log` receives one line per state change.
    pub async fn run<A: Apply>(&self, target: &mut A, log: impl Fn(&str)) {
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
            tokio::time::sleep(backoff).await;
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
            })),
        };
        tx.send(hello).await.map_err(Session::before)?;
        let mut inbound = client
            .sync(ReceiverStream::new(rx))
            .await
            .map_err(Session::before)?
            .into_inner();
        log("connected to control plane");

        loop {
            let msg = match inbound.message().await {
                Ok(Some(m)) => m,
                Ok(None) => return Ok(()),
                Err(e) => return Err(Session::after(e)),
            };
            let Some(sync_response::Kind::Snapshot(snap)) = msg.kind else {
                continue;
            };
            let revision = snap.revision;
            let result = if !snap.hash.is_empty() && snap.hash == target.active_hash() {
                // Already serving it, typically the LKG after a restart.
                Ok(())
            } else {
                let bytes = snap.encode_to_vec();
                let r = target.apply(snap, &bytes);
                match &r {
                    Ok(()) => log(&format!("applied revision {revision}")),
                    Err(e) => log(&format!("rejected revision {revision}: {e}")),
                }
                r
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
