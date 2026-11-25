//! IMF-fixdate formatting (RFC 9110 §5.6.7) without allocation.

/// Length of an IMF-fixdate such as `Sun, 06 Nov 1994 08:49:37 GMT`.
pub const DATE_LEN: usize = 29;

const DAYS: [&[u8; 3]; 7] = [b"Thu", b"Fri", b"Sat", b"Sun", b"Mon", b"Tue", b"Wed"];
const MONTHS: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

/// Formats seconds since the Unix epoch.
pub fn http_date(secs: u64) -> [u8; DATE_LEN] {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days as i64);

    let mut out = [0u8; DATE_LEN];
    out[..3].copy_from_slice(DAYS[(days % 7) as usize]);
    out[3..5].copy_from_slice(b", ");
    two(&mut out[5..7], d);
    out[7] = b' ';
    out[8..11].copy_from_slice(MONTHS[(m - 1) as usize]);
    out[11] = b' ';
    two(&mut out[12..14], (y / 100) as u32);
    two(&mut out[14..16], (y % 100) as u32);
    out[16] = b' ';
    two(&mut out[17..19], (rem / 3600) as u32);
    out[19] = b':';
    two(&mut out[20..22], (rem / 60 % 60) as u32);
    out[22] = b':';
    two(&mut out[23..25], (rem % 60) as u32);
    out[25..].copy_from_slice(b" GMT");
    out
}

fn two(out: &mut [u8], n: u32) {
    out[0] = b'0' + (n / 10) as u8;
    out[1] = b'0' + (n % 10) as u8;
}

/// Howard Hinnant's days-to-civil algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_dates() {
        assert_eq!(&http_date(0), b"Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(&http_date(784_111_777), b"Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(&http_date(951_782_400), b"Tue, 29 Feb 2000 00:00:00 GMT");
        assert_eq!(&http_date(1_798_761_599), b"Thu, 31 Dec 2026 23:59:59 GMT");
    }
}
