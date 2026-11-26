//! Per-thread state: worker index and the cached `Date` header value.

use std::cell::Cell;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

use jiff::Timestamp;
use jiff::tz::TimeZone;
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

/// Civil date of a day number since 1970-01-01 (Howard Hinnant's algorithm).
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

/// The local time zone, read once at start like nginx (`TZ`, else the
/// system zone). An unreadable zone is UTC.
static ZONE: LazyLock<TimeZone> = LazyLock::new(TimeZone::system);

/// `$time_local` ("26/Nov/2026:16:55:00 +0900") and `$time_iso8601`
/// ("2026-11-26T16:55:00+09:00") of one second.
#[derive(Clone, Copy)]
pub(crate) struct Clock {
    at: i64,
    pub local: [u8; 26],
    pub iso8601: [u8; 25],
}

thread_local! {
    static CLOCK: Cell<Clock> = const { Cell::new(Clock { at: i64::MIN, local: [0; 26], iso8601: [0; 25] }) };
}

/// The local time, formatted at most once per second per thread.
pub(crate) fn clock() -> Clock {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let cached = CLOCK.get();
    if cached.at == now {
        return cached;
    }
    let offset = Timestamp::from_second(now).map_or(0, |t| ZONE.to_offset(t).seconds());
    let fresh = format_clock(now, offset);
    CLOCK.set(fresh);
    fresh
}

/// Formats Unix time `now` at a UTC offset of `offset` seconds.
fn format_clock(now: i64, offset: i32) -> Clock {
    use std::io::Write;
    let t = now + i64::from(offset);
    let (y, m, d) = civil(t.div_euclid(86_400));
    let s = t.rem_euclid(86_400);
    let (hh, mm, ss) = (s / 3600, s / 60 % 60, s % 60);
    let sign = if offset < 0 { '-' } else { '+' };
    let (oh, om) = (
        offset.unsigned_abs() / 3600,
        offset.unsigned_abs() / 60 % 60,
    );
    let mut c = Clock {
        at: now,
        local: [b'0'; 26],
        iso8601: [b'0'; 25],
    };
    _ = write!(
        &mut c.local[..],
        "{d:02}/{}/{y:04}:{hh:02}:{mm:02}:{ss:02} {sign}{oh:02}{om:02}",
        MONTHS[m as usize - 1]
    );
    _ = write!(
        &mut c.iso8601[..],
        "{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}{sign}{oh:02}:{om:02}"
    );
    c
}

#[cfg(test)]
mod tests {
    #[test]
    fn civil_dates() {
        assert_eq!(super::civil(0), (1970, 1, 1));
        assert_eq!(super::civil(20_783), (2026, 11, 26));
        assert_eq!(super::civil(11_016), (2000, 2, 29));
    }

    #[test]
    fn clock_offsets() {
        // 2026-11-26T07:55:00Z
        let now = 1_795_679_700;
        let c = super::format_clock(now, 9 * 3600);
        assert_eq!(&c.local, b"26/Nov/2026:16:55:00 +0900");
        assert_eq!(&c.iso8601, b"2026-11-26T16:55:00+09:00");
        // Crosses midnight backwards, with a half-hour offset.
        let c = super::format_clock(now, -(8 * 3600 + 30 * 60));
        assert_eq!(&c.local, b"25/Nov/2026:23:25:00 -0830");
        assert_eq!(&c.iso8601, b"2026-11-25T23:25:00-08:30");
        let c = super::format_clock(now, 0);
        assert_eq!(&c.local, b"26/Nov/2026:07:55:00 +0000");
    }
}
