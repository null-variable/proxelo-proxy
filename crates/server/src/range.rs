//! Byte ranges of static files, as nginx's range filter: one range answers
//! 206 with Content-Range, several answer multipart/byteranges, and a Range
//! no part of which lies in the file answers 416.

/// Most ranges in one request. nginx has no limit by default; a request
/// with more is served whole, which nginx also does once the parts add up
/// to more than the file.
pub(crate) const MAX_RANGES: usize = 32;

/// A half-open byte range `start..end` of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Span {
    pub start: u64,
    pub end: u64,
}

/// What a Range header asks of a file of a given length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    /// Send the whole file with `Accept-Ranges: bytes`.
    Whole,
    /// 416.
    Unsatisfiable,
    /// 206 with the parts.
    Partial,
}

/// The answer and, for a partial one, the spans in request order. A fixed
/// array, so parsing a Range header does not allocate.
#[derive(Debug)]
pub(crate) struct Ranges {
    pub answer: Answer,
    n: usize,
    spans: [Span; MAX_RANGES],
}

impl Ranges {
    pub const WHOLE: Ranges = Ranges::of(Answer::Whole);

    const fn of(answer: Answer) -> Self {
        Ranges {
            answer,
            n: 0,
            spans: [Span { start: 0, end: 0 }; MAX_RANGES],
        }
    }

    pub fn parts(&self) -> &[Span] {
        &self.spans[..self.n]
    }
}

/// Parses the value of a Range header against a file of `len` bytes, with
/// nginx's rules: "bytes=" in any case, spaces allowed around numbers, a
/// range past the end is clipped, a range starting past the end is skipped,
/// and a list of ranges whose total exceeds the file is served whole.
pub(crate) fn parse(value: &[u8], len: u64) -> Ranges {
    if value.len() < 7 || !value[..6].eq_ignore_ascii_case(b"bytes=") {
        return Ranges::WHOLE;
    }
    let mut r = Ranges::of(Answer::Partial);
    let mut size: u64 = 0;
    let mut p = &value[6..];
    loop {
        let (start, end);
        p = skip_spaces(p);
        if p.first() == Some(&b'-') {
            // "-N": the last N bytes.
            let Some((suffix, rest)) = number(&p[1..]) else {
                return Ranges::of(Answer::Unsatisfiable);
            };
            p = skip_spaces(rest);
            start = len.saturating_sub(suffix);
            end = len;
        } else {
            let Some((s, rest)) = number(p) else {
                return Ranges::of(Answer::Unsatisfiable);
            };
            start = s;
            p = skip_spaces(rest);
            if p.first() != Some(&b'-') {
                return Ranges::of(Answer::Unsatisfiable);
            }
            p = skip_spaces(&p[1..]);
            if matches!(p.first(), None | Some(b',')) {
                end = len;
            } else {
                let Some((e, rest)) = number(p) else {
                    return Ranges::of(Answer::Unsatisfiable);
                };
                p = skip_spaces(rest);
                end = if e >= len { len } else { e + 1 };
            }
        }
        if !matches!(p.first(), None | Some(b',')) {
            return Ranges::of(Answer::Unsatisfiable);
        }
        if start < end {
            if r.n == MAX_RANGES {
                return Ranges::WHOLE;
            }
            r.spans[r.n] = Span { start, end };
            r.n += 1;
            size = size.saturating_add(end - start);
        } else if start == 0 {
            // "0-" or "-0" of an empty file, or an empty suffix.
            return Ranges::WHOLE;
        }
        if p.first() != Some(&b',') {
            break;
        }
        p = &p[1..];
    }
    match r.n {
        0 => Ranges::of(Answer::Unsatisfiable),
        1 => r,
        // nginx serves overlapping or oversized lists whole rather than
        // sending more than the file.
        n if size > len || size.saturating_add(n as u64 * 256) > len.saturating_add(4096) => {
            Ranges::WHOLE
        }
        _ => r,
    }
}

fn skip_spaces(mut p: &[u8]) -> &[u8] {
    while let [b' ', rest @ ..] = p {
        p = rest;
    }
    p
}

/// A decimal number and the rest; none on no digits or overflow.
fn number(p: &[u8]) -> Option<(u64, &[u8])> {
    let digits = p.iter().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let mut n: u64 = 0;
    for &c in &p[..digits] {
        n = n.checked_mul(10)?.checked_add(u64::from(c - b'0'))?;
    }
    // nginx works in off_t, a signed 64-bit value.
    if n > i64::MAX as u64 {
        return None;
    }
    Some((n, &p[digits..]))
}

/// Appends the 20-digit boundary nginx uses.
pub(crate) fn push_boundary(out: &mut Vec<u8>, boundary: u64) {
    let mut digits = [b'0'; 20];
    let mut n = boundary;
    for d in digits.iter_mut().rev() {
        *d = b'0' + (n % 10) as u8;
        n /= 10;
    }
    out.extend_from_slice(&digits);
}

/// Appends the head of one part: CRLF "--boundary" CRLF, the content type and
/// "Content-Range: bytes S-E/L" CRLF CRLF.
pub(crate) fn push_part_head(out: &mut Vec<u8>, boundary: u64, mime: &[u8], span: Span, len: u64) {
    out.extend_from_slice(b"\r\n--");
    push_boundary(out, boundary);
    out.extend_from_slice(b"\r\nContent-Type: ");
    out.extend_from_slice(mime);
    out.extend_from_slice(b"\r\nContent-Range: bytes ");
    push_span(out, span, len);
    out.extend_from_slice(b"\r\n\r\n");
}

/// Appends the closing CRLF "--boundary--" CRLF.
pub(crate) fn push_close(out: &mut Vec<u8>, boundary: u64) {
    out.extend_from_slice(b"\r\n--");
    push_boundary(out, boundary);
    out.extend_from_slice(b"--\r\n");
}

/// Appends "S-E/L".
pub(crate) fn push_span(out: &mut Vec<u8>, span: Span, len: u64) {
    proxelo_http1::push_u64(out, span.start);
    out.push(b'-');
    proxelo_http1::push_u64(out, span.end - 1);
    out.push(b'/');
    proxelo_http1::push_u64(out, len);
}

/// Length of the multipart body for `spans` of a file of `len` bytes.
pub(crate) fn multipart_len(spans: &[Span], mime: &[u8], len: u64) -> u64 {
    // CRLF "--" boundary CRLF "Content-Type: " mime CRLF "Content-Range: bytes "
    // span CRLF CRLF, then the bytes; and CRLF "--" boundary "--" CRLF.
    const PART: u64 = (4 + 20 + 2 + 14 + 2 + 21 + 4) as u64;
    const CLOSE: u64 = (4 + 20 + 4) as u64;
    let mut total = CLOSE;
    for &s in spans {
        total += PART + mime.len() as u64 + span_len(s, len) + (s.end - s.start);
    }
    total
}

fn span_len(s: Span, len: u64) -> u64 {
    digits(s.start) + 1 + digits(s.end - 1) + 1 + digits(len)
}

fn digits(mut n: u64) -> u64 {
    let mut d = 1;
    while n >= 10 {
        n /= 10;
        d += 1;
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spans(r: &Ranges) -> Vec<(u64, u64)> {
        r.parts().iter().map(|s| (s.start, s.end)).collect()
    }

    #[test]
    fn single_ranges() {
        assert_eq!(spans(&parse(b"bytes=0-3", 11)), [(0, 4)]);
        assert_eq!(spans(&parse(b"BYTES=4-", 11)), [(4, 11)]);
        assert_eq!(spans(&parse(b"bytes=-3", 11)), [(8, 11)]);
        assert_eq!(spans(&parse(b"bytes=-30", 11)), [(0, 11)]);
        assert_eq!(spans(&parse(b"bytes=5-100", 11)), [(5, 11)]);
        assert_eq!(spans(&parse(b"bytes= 1 - 2 ", 11)), [(1, 3)]);
    }

    #[test]
    fn unsatisfiable_and_whole() {
        let answer = |v: &[u8], len| parse(v, len).answer;
        for v in [
            &b"bytes=20-"[..],
            b"bytes=abc",
            b"bytes=5-2",
            b"bytes=1-2x",
            b"bytes=99999999999999999999-",
        ] {
            assert_eq!(answer(v, 11), Answer::Unsatisfiable, "{v:?}");
        }
        assert_eq!(answer(b"items=0-1", 11), Answer::Whole);
        assert_eq!(answer(b"bytes=", 11), Answer::Whole);
        // Overlapping parts add up to more than the file.
        assert_eq!(answer(b"bytes=0-0,0-20", 11), Answer::Whole);
        assert_eq!(answer(b"bytes=0-", 0), Answer::Whole);
    }

    #[test]
    fn several_ranges() {
        assert_eq!(spans(&parse(b"bytes=0-1,4-5", 11)), [(0, 2), (4, 6)]);
        // A part past the end is skipped.
        assert_eq!(spans(&parse(b"bytes=0-1,20-30", 11)), [(0, 2)]);
    }

    #[test]
    fn multipart_body_matches_nginx() {
        // nginx 1.31.10, "Range: bytes=0-1,4-5" of "plain text\n".
        let want = b"\r\n--00000000000000000001\r\nContent-Type: text/plain\r\nContent-Range: bytes 0-1/11\r\n\r\npl\r\n--00000000000000000001\r\nContent-Type: text/plain\r\nContent-Range: bytes 4-5/11\r\n\r\nn \r\n--00000000000000000001--\r\n";
        let file = b"plain text\n";
        let r = parse(b"bytes=0-1,4-5", 11);
        let mut out = Vec::new();
        for &s in r.parts() {
            push_part_head(&mut out, 1, b"text/plain", s, 11);
            out.extend_from_slice(&file[s.start as usize..s.end as usize]);
        }
        push_close(&mut out, 1);
        assert_eq!(out, want);
        assert_eq!(
            multipart_len(r.parts(), b"text/plain", 11),
            want.len() as u64
        );
    }
}
