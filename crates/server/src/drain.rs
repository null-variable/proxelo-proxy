//! Graceful shutdown: once draining, connections finish the request in
//! progress and close instead of waiting for another (nginx's graceful
//! shutdown of keepalive connections).

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::Notify;

static DRAINING: AtomicBool = AtomicBool::new(false);
static NOTIFY: Notify = Notify::const_new();

/// Starts draining. Idle keepalive connections close now, busy ones after
/// their response, HTTP/2 connections after a GOAWAY.
pub fn start() {
    DRAINING.store(true, Ordering::Release);
    NOTIFY.notify_waiters();
}

pub(crate) fn draining() -> bool {
    DRAINING.load(Ordering::Acquire)
}

/// Completes when draining starts.
pub(crate) async fn started() {
    let notified = NOTIFY.notified();
    tokio::pin!(notified);
    // Registered before the flag is checked, so a start in between is seen.
    notified.as_mut().enable();
    if draining() {
        return;
    }
    notified.await;
}

/// Waits until no client connection is open or `limit` passed; returns how
/// many are still open.
pub async fn wait(limit: Duration) -> u64 {
    let end = tokio::time::Instant::now() + limit;
    loop {
        let open = crate::metrics::connections_active();
        if open == 0 || tokio::time::Instant::now() >= end {
            return open;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
