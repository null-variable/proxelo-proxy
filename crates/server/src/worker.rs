//! Per-thread state: worker index and the cached `Date` header value.

use std::cell::Cell;
use std::time::{SystemTime, UNIX_EPOCH};

use proxelo_http1::{DATE_LEN, http_date};

thread_local! {
    static ID: Cell<usize> = const { Cell::new(0) };
    static DATE: Cell<(u64, [u8; DATE_LEN])> = const { Cell::new((u64::MAX, [0; DATE_LEN])) };
}

/// Marks the current thread as worker `id`. Per-worker state is sharded by it.
pub fn set_id(id: usize) {
    ID.set(id);
}

pub(crate) fn id() -> usize {
    ID.get()
}

/// The current time as an HTTP date, formatted at most once per second.
pub(crate) fn date() -> [u8; DATE_LEN] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let (at, cached) = DATE.get();
    if at == now {
        return cached;
    }
    let fresh = http_date(now);
    DATE.set((now, fresh));
    fresh
}
