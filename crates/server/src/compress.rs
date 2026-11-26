//! Response compression: nginx gzip (plus brotli and zstd), gzip_static
//! and gunzip.
//!
//! The decision follows nginx's gzip header filter: a 200, 403 or 404 that
//! is not already encoded, long enough, of a listed type, to a client whose
//! Accept-Encoding allows it (`ngx_http_gzip_ok`). An encoded response loses
//! Content-Length (it is sent chunked to HTTP/1.1 clients and closed for
//! HTTP/1.0), Accept-Ranges and its strong ETag.

use std::io::{self, Write};

use proxelo_http1::Version;
use proxelo_snapshot::{Compression, Encoding};

use crate::exchange::Exchange;

/// nginx gzip_quantity: the q value of a coding, in thousandths; 0 for a
/// malformed one.
fn quantity(v: &[u8]) -> u32 {
    let mut p = v.iter().copied();
    let q = match p.next() {
        Some(b'0') => 0,
        Some(b'1') => 1000,
        _ => return 0,
    };
    match p.next() {
        None | Some(b',' | b' ') => return q,
        Some(b'.') => {}
        _ => return 0,
    }
    let mut q = q;
    let mut scale = 100;
    let mut n = 0;
    for c in p {
        match c {
            b',' | b' ' => break,
            b'0'..=b'9' => {
                q += u32::from(c - b'0') * scale;
                scale /= 10;
                n += 1;
            }
            _ => return 0,
        }
    }
    if q > 1000 || n > 3 { 0 } else { q }
}

/// Whether Accept-Encoding lists `token` with a non-zero q, as nginx's
/// ngx_http_gzip_accept_encoding reads it: the token at the start or after
/// `,` or ` `, then the end, `,`, or `;q=` with a positive value.
pub(crate) fn accepts(ae: &[u8], token: &[u8]) -> bool {
    let mut from = 0;
    let after = loop {
        let Some(at) = ae
            .get(from..)
            .and_then(|rest| {
                rest.windows(token.len())
                    .position(|w| w.eq_ignore_ascii_case(token))
            })
            .map(|i| from + i)
        else {
            return false;
        };
        if at == 0 || matches!(ae[at - 1], b',' | b' ') {
            break at + token.len();
        }
        from = at + token.len();
    };
    let mut i = after;
    while i < ae.len() {
        match ae[i] {
            b',' => return true,
            b';' => {
                i += 1;
                while i < ae.len() && ae[i] == b' ' {
                    i += 1;
                }
                if i >= ae.len() {
                    return true;
                }
                if !matches!(ae[i], b'q' | b'Q') {
                    return false;
                }
                i += 1;
                if i + 2 > ae.len() || ae[i] != b'=' {
                    return false;
                }
                return quantity(&ae[i + 1..]) > 0;
            }
            b' ' => i += 1,
            _ => return false,
        }
    }
    true
}

/// What the response says, for the gzip decision.
#[derive(Default)]
pub(crate) struct RespFacts<'a> {
    pub status: u16,
    pub content_type: &'a [u8],
    /// Content-Length, `None` when unknown.
    pub length: Option<u64>,
    /// A non-empty Content-Encoding is present.
    pub encoded: bool,
    pub expires: Option<&'a [u8]>,
    pub cache_control: Option<&'a [u8]>,
    pub last_modified: bool,
    pub etag: bool,
}

/// nginx ngx_http_gzip_ok for this request, without the token: HTTP
/// version, gzip_proxied for requests with Via, and gzip_disable.
fn request_ok(x: &Exchange, c: &Compression, resp: &RespFacts) -> bool {
    if x.req.version == Version::Http10 && !x.h2 && !c.http10 {
        return false;
    }
    if x.request_header(b"via").is_some() {
        let p = &c.proxied;
        if !p.some() {
            return false;
        }
        if !p.any {
            let auth = p.auth && x.request_header(b"authorization").is_some();
            let ok = auth
                || if let Some(e) = resp.expires {
                    // An Expires in the past, as nginx compares it with Date.
                    p.expired && expired(e)
                } else if let Some(cc) = resp.cache_control {
                    let has = |w: &[u8]| {
                        cc.split(|&b| b == b',')
                            .any(|t| t.trim_ascii().eq_ignore_ascii_case(w))
                    };
                    (p.no_cache && has(b"no-cache"))
                        || (p.no_store && has(b"no-store"))
                        || (p.private && has(b"private"))
                } else {
                    !(p.no_last_modified && resp.last_modified)
                        && !(p.no_etag && resp.etag)
                        && (p.no_last_modified || p.no_etag)
                };
            if !ok {
                return false;
            }
        }
    }
    if let (Some(re), Some(ua)) = (&c.disable, x.request_header(b"user-agent")) {
        // A regex that fails to run does not disable.
        if re.is_match(ua).unwrap_or(false) {
            return false;
        }
    }
    true
}

/// Whether an Expires value is before now.
fn expired(v: &[u8]) -> bool {
    let Ok(s) = std::str::from_utf8(v) else {
        return false;
    };
    match httpdate_secs(s) {
        Some(t) => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .is_ok_and(|now| t < now.as_secs()),
        None => false,
    }
}

/// Seconds since the epoch of an IMF-fixdate ("Sun, 06 Nov 1994 08:49:37
/// GMT"); other forms are not parsed.
fn httpdate_secs(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 29 || &b[25..] != b" GMT" {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u64> { s.get(r)?.parse().ok() };
    let day = num(5..7)?;
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| s.get(8..11) == Some(*m))? as u64
        + 1;
    let year = num(12..16)?;
    let (h, m, sec) = (num(17..19)?, num(20..22)?, num(23..25)?);
    // Days from civil (Howard Hinnant's algorithm).
    let (y, mo) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * mo + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era * 146_097 + doe).checked_sub(719_468)?;
    Some(days * 86400 + h * 3600 + m * 60 + sec)
}

/// The encoding for a response, or `None` to send it as is. `vary` is set
/// when the response could have been encoded, so Vary: Accept-Encoding goes
/// out (nginx sets gzip_vary before testing the client).
pub(crate) fn choose(
    x: &Exchange,
    c: &Compression,
    resp: &RespFacts,
    vary: &mut bool,
) -> Option<Encoding> {
    if c.encodings.is_empty()
        || !matches!(resp.status, 200 | 403 | 404)
        || resp.encoded
        || resp.length.is_some_and(|n| n < c.min_length)
        || !c.type_ok(resp.content_type)
    {
        return None;
    }
    *vary |= c.vary;
    let ae = x.request_header(b"accept-encoding")?;
    if !request_ok(x, c, resp) {
        return None;
    }
    c.encodings.iter().copied().find(|e| accepts(ae, e.token()))
}

/// Whether a gzip response must be decoded for this client (nginx gunzip).
pub(crate) fn must_gunzip(x: &Exchange, c: &Compression, encoding: &[u8]) -> bool {
    if !c.gunzip || !encoding.eq_ignore_ascii_case(b"gzip") {
        return false;
    }
    let ok = x
        .request_header(b"accept-encoding")
        .is_some_and(|ae| accepts(ae, b"gzip"))
        && request_ok(x, c, &RespFacts::default());
    !ok
}

/// gzip_static: whether `file.gz` may be sent for this request. `vary` is
/// set as nginx does for gzip_static on.
pub(crate) fn static_ok(x: &Exchange, c: &Compression, vary: &mut bool) -> bool {
    match c.static_gz {
        proxelo_snapshot::StaticGz::Off => false,
        proxelo_snapshot::StaticGz::Always => true,
        proxelo_snapshot::StaticGz::On => {
            *vary |= c.vary;
            x.request_header(b"accept-encoding")
                .is_some_and(|ae| accepts(ae, b"gzip"))
                && request_ok(x, c, &RespFacts::default())
        }
    }
}

/// A streaming encoder or decoder writing into a Vec the caller drains.
pub(crate) enum Coder {
    Gzip(flate2::write::GzEncoder<Vec<u8>>),
    Brotli(Box<brotli::CompressorWriter<Vec<u8>>>),
    Zstd(zstd::stream::write::Encoder<'static, Vec<u8>>),
    Gunzip(flate2::write::MultiGzDecoder<Vec<u8>>),
}

impl Coder {
    pub fn new(e: Encoding, c: &Compression) -> io::Result<Self> {
        Ok(match e {
            Encoding::Gzip => Self::Gzip(flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::new(c.gzip_level),
            )),
            // A 4 MiB window (lgwin 22) as the brotli tools default to.
            Encoding::Brotli => Self::Brotli(Box::new(brotli::CompressorWriter::new(
                Vec::new(),
                4096,
                c.brotli_level,
                22,
            ))),
            Encoding::Zstd => {
                Self::Zstd(zstd::stream::write::Encoder::new(Vec::new(), c.zstd_level)?)
            }
        })
    }

    pub fn gunzip() -> Self {
        Self::Gunzip(flate2::write::MultiGzDecoder::new(Vec::new()))
    }

    fn out(&mut self) -> &mut Vec<u8> {
        match self {
            Self::Gzip(w) => w.get_mut(),
            Self::Brotli(w) => w.get_mut(),
            Self::Zstd(w) => w.get_mut(),
            Self::Gunzip(w) => w.get_mut(),
        }
    }

    /// Feeds `data` and moves what came out to the end of `out`.
    pub fn write(&mut self, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        match self {
            Self::Gzip(w) => w.write_all(data)?,
            Self::Brotli(w) => w.write_all(data)?,
            Self::Zstd(w) => w.write_all(data)?,
            Self::Gunzip(w) => w.write_all(data)?,
        }
        out.append(self.out());
        Ok(())
    }

    /// Ends the stream and moves the rest to the end of `out`.
    pub fn finish(self, out: &mut Vec<u8>) -> io::Result<()> {
        let mut rest = match self {
            Self::Gzip(w) => w.finish()?,
            Self::Brotli(w) => w.into_inner(),
            Self::Zstd(w) => w.finish()?,
            Self::Gunzip(w) => w.finish()?,
        };
        out.append(&mut rest);
        Ok(())
    }
}

/// Finds a header's value in a head built as complete lines.
fn head_value<'a>(head: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    head.split(|&c| c == b'\n').skip(1).find_map(|line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let colon = line.iter().position(|&c| c == b':')?;
        line[..colon]
            .eq_ignore_ascii_case(name)
            .then(|| line[colon + 1..].trim_ascii())
    })
}

/// Rewrites a complete head (ending with the empty line) for an encoded
/// body: no Content-Length or Accept-Ranges, a weak ETag, and the given
/// lines added. `close` turns Connection into close.
pub(crate) fn rewrite_head(head: &[u8], add: &[&[u8]], close: bool, out: &mut Vec<u8>) {
    let body = head.strip_suffix(b"\r\n").unwrap_or(head);
    for line in body.split_inclusive(|&c| c == b'\n') {
        let name_end = line.iter().position(|&c| c == b':').unwrap_or(0);
        let name = &line[..name_end];
        if name.eq_ignore_ascii_case(b"content-length")
            || name.eq_ignore_ascii_case(b"accept-ranges")
            || (close && name.eq_ignore_ascii_case(b"connection"))
        {
            continue;
        }
        if name.eq_ignore_ascii_case(b"etag") {
            weak_etag(line, name_end, out);
            continue;
        }
        out.extend_from_slice(line);
    }
    for a in add {
        out.extend_from_slice(a);
    }
    if close {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
}

/// nginx ngx_http_weak_etag: a strong ETag becomes W/; anything that is
/// not a quoted tag is dropped.
fn weak_etag(line: &[u8], name_end: usize, out: &mut Vec<u8>) {
    let v = line[name_end + 1..].trim_ascii();
    if v.starts_with(b"W/") {
        out.extend_from_slice(line);
    } else if v.starts_with(b"\"") {
        out.extend_from_slice(&line[..name_end]);
        out.extend_from_slice(b": W/");
        out.extend_from_slice(v);
        out.extend_from_slice(b"\r\n");
    }
}

/// Appends `data` as one chunk.
pub(crate) fn push_chunk(out: &mut Vec<u8>, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    proxelo_http1::push_hex(out, data.len() as u64);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

/// How an encoded body is framed for this client: chunked, or (HTTP/1.0)
/// raw with the connection closed at the end.
pub(crate) fn chunked_for(x: &Exchange) -> bool {
    x.h2 || x.req.version != Version::Http10
}

impl crate::conn::Conn {
    /// The compression settings for the current response, if any.
    pub(crate) fn compression(&self) -> Option<std::sync::Arc<[Compression]>> {
        let i = self.x.compression? as usize;
        (i < self.x.compressions.len()).then(|| std::sync::Arc::clone(&self.x.compressions))
    }

    /// Encodes a complete response built in `out` (`body` bytes after the
    /// head) when the compression settings say so, and adds Vary. Returns
    /// whether the connection must close afterwards.
    pub(crate) fn encode_buffered(&mut self, status: u16, body: usize) -> bool {
        let Some(comps) = self.compression() else {
            return false;
        };
        let c = &comps[self.x.compression.unwrap_or(0) as usize];
        let head_end = self.out.len() - body;
        let head = &self.out[..head_end];
        let length = head_value(head, b"content-length")
            .and_then(|v| std::str::from_utf8(v).ok()?.parse().ok());
        let facts = RespFacts {
            status,
            content_type: head_value(head, b"content-type").unwrap_or_default(),
            length,
            encoded: head_value(head, b"content-encoding").is_some_and(|v| !v.is_empty()),
            expires: head_value(head, b"expires"),
            cache_control: head_value(head, b"cache-control"),
            last_modified: head_value(head, b"last-modified").is_some(),
            etag: head_value(head, b"etag").is_some(),
        };
        let mut vary = false;
        let enc = choose(&self.x, c, &facts, &mut vary);
        if enc.is_none() && !vary {
            return false;
        }
        let head_only = self.x.req.method == proxelo_http1::Method::Head;
        let chunked = chunked_for(&self.x);
        let close = enc.is_some() && !chunked && !head_only;
        let mut out = std::mem::take(&mut self.zout);
        out.clear();
        let vary_line: &[u8] = if vary {
            b"Vary: Accept-Encoding\r\n"
        } else {
            b""
        };
        match enc {
            None => {
                out.extend_from_slice(&self.out[..head_end - 2]);
                out.extend_from_slice(vary_line);
                out.extend_from_slice(b"\r\n");
                out.extend_from_slice(&self.out[head_end..]);
            }
            Some(e) => {
                let mut ce = b"Content-Encoding: ".to_vec();
                ce.extend_from_slice(e.token());
                ce.extend_from_slice(b"\r\n");
                let te: &[u8] = if chunked && !head_only {
                    b"Transfer-Encoding: chunked\r\n"
                } else {
                    b""
                };
                rewrite_head(
                    &self.out[..head_end],
                    &[vary_line, &ce, te],
                    close,
                    &mut out,
                );
                if !head_only {
                    let mut coded = std::mem::take(&mut self.zin);
                    coded.clear();
                    let done = Coder::new(e, c).and_then(|mut k| {
                        k.write(&self.out[head_end..], &mut coded)?;
                        k.finish(&mut coded)
                    });
                    if done.is_ok() {
                        if chunked {
                            push_chunk(&mut out, &coded);
                            out.extend_from_slice(b"0\r\n\r\n");
                        } else {
                            out.extend_from_slice(&coded);
                        }
                    }
                    self.zin = coded;
                }
            }
        }
        std::mem::swap(&mut self.out, &mut out);
        self.zout = out;
        close
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_encoding_as_nginx() {
        for (ae, want) in [
            ("gzip", true),
            ("gzip, deflate", true),
            ("deflate, gzip", true),
            ("deflate,gzip", true),
            ("GZIP", true),
            ("gzip;q=0", false),
            ("gzip;q=0.000", false),
            ("gzip;q=0.001", true),
            ("gzip; q=1", true),
            ("gzip;q=1.0001", false),
            ("x-gzip", false),
            ("gzipx", false),
            ("br, gzip;q=0.5", true),
            ("identity", false),
        ] {
            assert_eq!(accepts(ae.as_bytes(), b"gzip"), want, "{ae}");
        }
        assert!(accepts(b"gzip, br", b"br"));
        assert!(!accepts(b"brotli", b"br"));
    }

    #[test]
    fn http_dates() {
        assert_eq!(
            httpdate_secs("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
        assert_eq!(httpdate_secs("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(httpdate_secs("garbage"), None);
    }

    #[test]
    fn coders_round_trip() {
        use std::io::Read;
        let data = b"hello hello hello hello".repeat(100);
        let rt = test_runtime();
        let comp = &rt.compressions[0];
        for e in [Encoding::Gzip, Encoding::Brotli, Encoding::Zstd] {
            let mut coder = Coder::new(e, comp).unwrap();
            let mut out = Vec::new();
            for part in data.chunks(500) {
                coder.write(part, &mut out).unwrap();
            }
            coder.finish(&mut out).unwrap();
            assert!(out.len() < data.len() / 4, "{e:?}");
            let mut back = Vec::new();
            match e {
                Encoding::Gzip => {
                    flate2::read::GzDecoder::new(&out[..])
                        .read_to_end(&mut back)
                        .unwrap();
                }
                Encoding::Brotli => {
                    brotli::Decompressor::new(&out[..], 4096)
                        .read_to_end(&mut back)
                        .unwrap();
                }
                Encoding::Zstd => back = zstd::decode_all(&out[..]).unwrap(),
            }
            assert_eq!(back, data, "{e:?}");
            // gunzip undoes gzip.
            if e == Encoding::Gzip {
                let mut g = Coder::gunzip();
                let mut plain = Vec::new();
                g.write(&out, &mut plain).unwrap();
                g.finish(&mut plain).unwrap();
                assert_eq!(plain, data);
            }
        }
    }

    fn test_runtime() -> proxelo_snapshot::Runtime {
        proxelo_snapshot::Runtime::build(&proxelo_api::snapshot::v1::Snapshot {
            sites: vec![proxelo_api::snapshot::v1::Site {
                compression: Some(proxelo_api::snapshot::v1::Compression {
                    encodings: vec![1, 2, 3],
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap()
    }
}
