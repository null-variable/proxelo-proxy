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

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// UTC civil date of a Unix day number (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn utc_now() -> (i64, u32, u32, u64) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let (y, m, d) = civil((now / 86_400) as i64);
    (y, m, d, now % 86_400)
}

/// `$time_local` in UTC: "26/Nov/2026:07:55:00 +0000".
pub(crate) fn time_local() -> Vec<u8> {
    let (y, m, d, t) = utc_now();
    format!(
        "{d:02}/{}/{y}:{:02}:{:02}:{:02} +0000",
        MONTHS[m as usize - 1],
        t / 3600,
        t / 60 % 60,
        t % 60
    )
    .into_bytes()
}

/// `$time_iso8601` in UTC.
pub(crate) fn time_iso8601() -> Vec<u8> {
    let (y, m, d, t) = utc_now();
    format!(
        "{y}-{m:02}-{d:02}T{:02}:{:02}:{:02}+00:00",
        t / 3600,
        t / 60 % 60,
        t % 60
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    #[test]
    fn civil_dates() {
        assert_eq!(super::civil(0), (1970, 1, 1));
        assert_eq!(super::civil(20_783), (2026, 11, 26));
        assert_eq!(super::civil(11_016), (2000, 2, 29));
    }
}
