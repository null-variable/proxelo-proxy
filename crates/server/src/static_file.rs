//! Sending a static file and the directory redirect.

use std::fs::{File, Metadata};
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, UNIX_EPOCH};

use proxelo_http1::{Method, http_date, push_hex, push_u64};
use proxelo_snapshot::{Bandwidth, HeaderOps};

use crate::conn::{Conn, KeepAlive, SEND_TIMEOUT, body_len};
use crate::io::write_timeout;
use crate::range::{self, Answer, Ranges, Span};
use crate::reply;

/// File bytes read per write.
const FILE_CHUNK: usize = 64 * 1024;

/// Multipart boundaries, a process-wide counter as in nginx.
static BOUNDARIES: AtomicU64 = AtomicU64::new(0);

/// nginx limit_rate: after a write took the bytes sent from `before` to
/// `sent`, waits until they are within `rate` per second since the request
/// started (plus one second and the `after` allowance, as nginx counts).
pub(crate) async fn throttle(b: Bandwidth, before: u64, sent: u64, started: Instant) {
    if sent <= b.after || sent == before {
        return;
    }
    let allowed = (started.elapsed().as_secs() + 1).saturating_mul(b.rate);
    let over = sent - b.after;
    if over > allowed {
        let ms = (over - allowed).saturating_mul(1000) / b.rate + 1;
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }
}

impl Conn {
    /// Sends a static file, or the parts a Range header asks for (nginx's
    /// range filter, which runs after error_page: a 416 is not redirected).
    pub async fn send_file(
        &mut self,
        mut file: File,
        meta: &Metadata,
        ops: &HeaderOps,
    ) -> KeepAlive {
        let len = meta.len();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        let modified = http_date(mtime);
        // nginx ETag: hex mtime and length.
        let etag = &mut self.x.scratch;
        etag.clear();
        etag.push(b'"');
        push_hex(etag, mtime);
        etag.push(b'-');
        push_hex(etag, len);
        etag.push(b'"');
        let not_modified = match self.x.request_header(b"if-none-match") {
            Some(v) => v == b"*" || v == &self.x.scratch[..],
            None => self.x.request_header(b"if-modified-since") == Some(&modified[..]),
        };
        // Ranges apply to a 200 only: not to a 304 or a page error_page set.
        let ranges = match self.x.request_header(b"range") {
            Some(v) if !not_modified && self.x.err_status == 0 && self.if_range(&modified) => {
                range::parse(v, len)
            }
            _ => Ranges::WHOLE,
        };
        let status = match (ranges.answer, not_modified) {
            (_, true) => 304,
            (Answer::Unsatisfiable, _) => 416,
            (Answer::Partial, _) => 206,
            (Answer::Whole, _) => self.x.status(200),
        };
        self.extra(ops, status);
        let keep = self.x.req.keep_alive;
        if status == 416 {
            return self.unsatisfiable(len, keep).await;
        }
        let mime = reply::mime(&self.x.path);
        let parts = ranges.parts();
        let boundary = if parts.len() > 1 {
            BOUNDARIES.fetch_add(1, Ordering::Relaxed) + 1
        } else {
            0
        };
        let body_len = match parts {
            [] => len,
            [one] => one.end - one.start,
            many => range::multipart_len(many, mime, len),
        };

        let out = &mut self.out;
        out.clear();
        reply::start(out, status, b"");
        if !not_modified {
            out.extend_from_slice(b"Content-Type: ");
            if boundary != 0 {
                out.extend_from_slice(b"multipart/byteranges; boundary=");
                range::push_boundary(out, boundary);
            } else {
                out.extend_from_slice(mime);
            }
            out.extend_from_slice(b"\r\nContent-Length: ");
            push_u64(out, body_len);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"Last-Modified: ");
        out.extend_from_slice(&modified);
        out.extend_from_slice(b"\r\nETag: ");
        out.extend_from_slice(&self.x.scratch);
        out.extend_from_slice(b"\r\n");
        if let [one] = parts {
            out.extend_from_slice(b"Content-Range: bytes ");
            range::push_span(out, *one, len);
            out.extend_from_slice(b"\r\n");
        } else if status != 304 && parts.is_empty() {
            out.extend_from_slice(b"Accept-Ranges: bytes\r\n");
        }
        reply::connection(out, keep, &self.x.resp_extra);
        out.extend_from_slice(b"\r\n");
        self.x.sent.status = status;
        self.x.sent.bytes = out.len() as u64;

        if not_modified || self.x.req.method == Method::Head {
            return self.respond(keep).await;
        }
        self.x.sent.bytes += body_len;
        self.x.sent.body_bytes = body_len;
        if keep && self.pump_body(None).await.is_err() {
            return false;
        }
        // The head and the first part of the file go out in one write.
        let whole = [Span { start: 0, end: len }];
        let spans = if parts.is_empty() { &whole[..] } else { parts };
        for &span in spans {
            if boundary != 0 {
                range::push_part_head(&mut self.out, boundary, mime, span, len);
            }
            if !self.send_span(&mut file, span).await {
                return false;
            }
        }
        if boundary != 0 {
            range::push_close(&mut self.out, boundary);
        }
        if !self.out.is_empty() {
            return write_timeout(&mut self.client, &self.out, SEND_TIMEOUT)
                .await
                .is_ok()
                && keep;
        }
        keep
    }

    /// Writes `out` followed by `span` of the file, leaving `out` empty.
    async fn send_span(&mut self, file: &mut File, span: Span) -> bool {
        if file.seek(SeekFrom::Start(span.start)).is_err() {
            return false;
        }
        let mut left = span.end - span.start;
        while left > 0 {
            let start = self.out.len();
            // Throttled writes are at most a second's worth, so the pace is
            // even rather than one chunk then a long pause.
            let chunk = match self.x.bandwidth {
                Some(b) if self.x.paced >= b.after => b.rate.clamp(1, FILE_CHUNK as u64),
                _ => FILE_CHUNK as u64,
            };
            let want = left.min(chunk) as usize;
            self.out.resize(start + want, 0);
            let n = match file.read(&mut self.out[start..]) {
                Ok(n) if n > 0 => n,
                // The file shrank after its length was sent.
                _ => return false,
            };
            self.out.truncate(start + n);
            left -= n as u64;
            if write_timeout(&mut self.client, &self.out, SEND_TIMEOUT)
                .await
                .is_err()
            {
                return false;
            }
            if let Some(b) = self.x.bandwidth {
                let before = self.x.paced;
                self.x.paced += self.out.len() as u64;
                throttle(b, before, self.x.paced, self.x.started).await;
            }
            self.out.clear();
        }
        true
    }

    /// nginx If-Range: a quoted value must equal the ETag, anything else the
    /// Last-Modified date; otherwise the whole file is sent.
    fn if_range(&self, modified: &[u8]) -> bool {
        match self.x.request_header(b"if-range") {
            None => true,
            Some(v) if v.len() >= 2 && v.ends_with(b"\"") => v == &self.x.scratch[..],
            Some(v) => v == modified,
        }
    }

    /// 416 with nginx's page and `Content-Range: bytes */len`.
    async fn unsatisfiable(&mut self, len: u64, keep: KeepAlive) -> KeepAlive {
        let out = &mut self.out;
        out.clear();
        reply::start(out, 416, b"");
        out.extend_from_slice(b"Content-Range: bytes */");
        push_u64(out, len);
        out.extend_from_slice(b"\r\n");
        let head = self.x.req.method == Method::Head;
        reply::page(out, 416, keep, head, &self.x.resp_extra);
        self.x.sent.status = 416;
        self.x.sent.bytes = out.len() as u64;
        self.x.sent.body_bytes = body_len(out) as u64;
        self.respond(keep).await
    }

    /// A directory without a trailing slash gets a 301 to the same URI with
    /// one, absolute, from the Host header and the listen port.
    pub async fn redirect_dir(&mut self) -> KeepAlive {
        let keep = self.x.req.keep_alive;
        let out = &mut self.out;
        out.clear();
        reply::start(out, 301, b"");
        out.extend_from_slice(b"Location: ");
        reply::push_origin(out, self.x.tls.is_some(), &self.x.host, self.x.local);
        reply::push_uri_path(out, &self.x.path);
        out.push(b'/');
        if !self.x.args.is_empty() {
            out.push(b'?');
            out.extend_from_slice(&self.x.args);
        }
        out.extend_from_slice(b"\r\n");
        let head = self.x.req.method == Method::Head;
        reply::page(out, 301, keep, head, &self.x.resp_extra);
        self.x.sent.status = 301;
        self.x.sent.bytes = out.len() as u64;
        self.x.sent.body_bytes = body_len(out) as u64;
        self.respond(keep).await
    }
}
