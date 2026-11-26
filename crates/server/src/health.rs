//! Active health checks and DNS re-resolution of upstream targets: tasks
//! that run beside traffic and change only shared state, never the snapshot.

use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;

use proxelo_http1::{Response, parse_response};
use proxelo_snapshot::{CheckKind, HealthCheck, Resolved};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::Active;

/// The most of a probe response that is read; the body pattern sees only
/// this much.
const PROBE_MAX: usize = 64 * 1024;

/// Probes `addr` once.
async fn probe(addr: SocketAddr, host: &str, h: &HealthCheck) -> Result<(), String> {
    let addr = if h.port == 0 {
        addr
    } else {
        SocketAddr::new(addr.ip(), h.port)
    };
    let run = async {
        let mut s = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("connect: {e}"))?;
        if h.kind == CheckKind::Tcp {
            return Ok(());
        }
        let host = if host.is_empty() {
            addr.to_string()
        } else {
            host.to_owned()
        };
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: proxelo-health\r\nConnection: close\r\n\r\n",
            h.path
        );
        s.write_all(req.as_bytes())
            .await
            .map_err(|e| format!("send: {e}"))?;
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 4096];
        while buf.len() < PROBE_MAX {
            match s.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(format!("read: {e}")),
            }
        }
        let mut resp = Response::default();
        if !parse_response(&buf, false, &mut resp).unwrap_or(false) {
            return Err("invalid response".into());
        }
        let st = resp.status;
        if !h.statuses.iter().any(|&(a, b)| (a..=b).contains(&st)) {
            return Err(format!("status {st}"));
        }
        if let Some(re) = &h.body
            && !re.is_match(&buf[resp.head_len..]).unwrap_or(false)
        {
            return Err("body does not match".into());
        }
        Ok(())
    };
    match timeout(h.timeout, run).await {
        Ok(r) => r,
        Err(_) => Err("timed out".into()),
    }
}

/// Runs the active health checks of `active` until it is replaced: one
/// task per target with a check.
pub(crate) fn start_checks(active: &Arc<Active>, rt: &tokio::runtime::Handle) {
    for (u, up) in active.rt.upstreams.iter().enumerate() {
        if up.health_check.is_none() {
            continue;
        }
        for i in 0..up.targets.len() {
            let weak = Arc::downgrade(active);
            rt.spawn(check_loop(weak, u, i));
        }
    }
}

async fn check_loop(weak: Weak<Active>, u: usize, i: usize) {
    loop {
        // The snapshot is held only while probing, so a replaced one goes.
        let interval = {
            let Some(active) = weak.upgrade() else {
                return;
            };
            let up = &active.rt.upstreams[u];
            let Some(h) = &up.health_check else {
                return;
            };
            let r = probe(up.targets[i].addr, &up.host, h).await;
            active.upstreams[u].probed(i, r, h.fails, h.passes);
            h.interval
        };
        tokio::time::sleep(interval).await;
    }
}

/// Host names of targets marked `resolve`, with their re-resolution interval.
pub fn resolve_names(snap: &proxelo_api::snapshot::v1::Snapshot) -> Vec<(String, Duration)> {
    let mut out: Vec<(String, Duration)> = Vec::new();
    for t in snap.upstreams.iter().flat_map(|u| &u.targets) {
        if !t.resolve || out.iter().any(|(n, _)| *n == t.address) {
            continue;
        }
        let every = if t.resolve_interval_ms == 0 {
            Duration::from_secs(30)
        } else {
            Duration::from_millis(t.resolve_interval_ms.into())
        };
        out.push((t.address.clone(), every));
    }
    out
}

/// Resolves `names` now. Names that fail keep no entry.
pub async fn resolve_all(names: &[(String, Duration)]) -> Resolved {
    let mut out = Resolved::new();
    for (name, _) in names {
        if let Ok(addrs) = tokio::net::lookup_host(name.as_str()).await {
            let mut v: Vec<SocketAddr> = addrs.collect();
            v.sort();
            v.dedup();
            if !v.is_empty() {
                out.insert(name.clone(), v.into());
            }
        }
    }
    out
}
