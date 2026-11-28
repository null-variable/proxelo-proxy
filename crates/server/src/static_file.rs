//! Sending a static file and the directory redirect.

use std::fs::{File, Metadata};
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, UNIX_EPOCH};

use proxelo_http1::{Method, http_date, push_hex, push_u64};
use proxelo_snapshot::{Bandwidth, HeaderOps};

use crate::compress;
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
        gz: bool,
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
        let not_modified = match self.x.main_header(b"if-none-match") {
            Some(v) => v == b"*" || v == &self.x.scratch[..],
            None => self.x.main_header(b"if-modified-since") == Some(&modified[..]),
        };
        // Ranges apply to a 200 only: not to a 304 or a page error_page set.
        let ranges = match self.x.main_header(b"range") {
            Some(v) if !not_modified && self.x.err_status == 0 && self.if_range(&modified) => {
                range::parse(v, len)
            }
            _ => Ranges::WHOLE,
        };
        let mime = reply::mime(&self.x.path);
        // The response filters run before compression and ranges; a body
        // they change is sent whole.
        let mut plan = if not_modified {
            crate::filter::Plan::default()
        } else {
            crate::filter::plan(&mut self.x, 200, mime, Some(len), gz)
        };
        let ctype: std::borrow::Cow<'_, [u8]> = match plan.ctype.take() {
            Some(v) => v.into(),
            None => mime.into(),
        };
        let mime = &ctype[..];
        // Dynamic compression runs before the range filter, so an encoded
        // response ignores Range (nginx clears Accept-Ranges).
        let mut vary = self.x.vary;
        let encoding = if gz || not_modified {
            None
        } else {
            self.x
                .compression
                .and_then(|i| self.x.compressions.get(i as usize))
                .and_then(|c| {
                    let facts = compress::RespFacts {
                        status: if self.x.err_status != 0 {
                            self.x.err_status
                        } else {
                            200
                        },
                        content_type: mime,
                        length: (!plan.reframe).then_some(len),
                        last_modified: !plan.drop_validators,
                        etag: !plan.drop_validators,
                        ..Default::default()
                    };
                    compress::choose(&self.x, c, &facts, &mut vary).map(|e| (e, c))
                })
                .and_then(|(e, c)| compress::Coder::new(e, c).ok().map(|k| (e, k)))
        };
        let ranges = if encoding.is_some() || plan.reframe {
            Ranges::WHOLE
        } else {
            ranges
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
        if encoding.is_some() || plan.reframe {
            return self
                .send_encoded(file, encoding, plan, mime, &modified, vary, status)
                .await;
        }
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
        // An error page's status: nginx's header filter drops
        // Last-Modified unless 200, 206 or 304.
        if matches!(status, 200 | 206 | 304) {
            out.extend_from_slice(b"Last-Modified: ");
            out.extend_from_slice(&modified);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"ETag: ");
        out.extend_from_slice(&self.x.scratch);
        out.extend_from_slice(b"\r\n");
        if gz {
            out.extend_from_slice(b"Content-Encoding: gzip\r\n");
        }
        if vary {
            out.extend_from_slice(b"Vary: Accept-Encoding\r\n");
        }
        if let [one] = parts {
            out.extend_from_slice(b"Content-Range: bytes ");
            range::push_span(out, *one, len);
            out.extend_from_slice(b"\r\n");
        } else if status == 200 {
            // nginx's range filter offers ranges on 200 only.
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
        if keep && self.pump_body(crate::conn::Sink::Drop).await.is_err() {
            return false;
        }
        // The head and the first part of the file go out in one write.
        let whole = [Span { start: 0, end: len }];
        let spans = if parts.is_empty() { &whole[..] } else { parts };
        for &span in spans {
            if boundary != 0 {
                range::push_part_head(&mut self.out, boundary, mime, span, len);
            }
            if !self.send_span(&mut file, span, plan.table()).await {
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

    /// Sends the whole file through the response filters and the encoder:
    /// chunked to HTTP/1.1 clients, closed at the end for HTTP/1.0 ones, with
    /// no Content-Length.
    #[allow(clippy::too_many_arguments)]
    async fn send_encoded(
        &mut self,
        mut file: File,
        encoding: Option<(proxelo_snapshot::Encoding, compress::Coder)>,
        mut plan: crate::filter::Plan,
        mime: &[u8],
        modified: &[u8],
        vary: bool,
        status: u16,
    ) -> KeepAlive {
        let head_only = self.x.req.method == Method::Head;
        let chunked = compress::chunked_for(&self.x);
        let keep = self.x.req.keep_alive && (chunked || head_only);
        let (token, coder) = match encoding {
            Some((e, k)) => (Some(e.token()), Some(k)),
            None => (None, None),
        };
        let out = &mut self.out;
        out.clear();
        reply::start(out, status, b"");
        out.extend_from_slice(b"Content-Type: ");
        out.extend_from_slice(mime);
        out.extend_from_slice(b"\r\n");
        if !plan.drop_validators {
            if matches!(status, 200 | 206 | 304) {
                out.extend_from_slice(b"Last-Modified: ");
                out.extend_from_slice(modified);
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(b"ETag: ");
            if plan.etag(token.is_some()) == crate::filter::Etag::Weak {
                out.extend_from_slice(b"W/");
            }
            out.extend_from_slice(&self.x.scratch);
            out.extend_from_slice(b"\r\n");
        }
        if vary {
            out.extend_from_slice(b"Vary: Accept-Encoding\r\n");
        }
        if let Some(t) = token {
            out.extend_from_slice(b"Content-Encoding: ");
            out.extend_from_slice(t);
            out.extend_from_slice(b"\r\n");
        }
        if chunked && !head_only {
            out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }
        reply::connection(out, keep, &self.x.resp_extra);
        out.extend_from_slice(b"\r\n");
        self.x.sent.status = status;
        let head_len = self.out.len() as u64;
        if head_only {
            self.x.sent.bytes = head_len;
            return self.respond(keep).await;
        }
        // Flushes count what they write, the head included.
        self.x.sent.bytes = 0;
        if keep && self.pump_body(crate::conn::Sink::Drop).await.is_err() {
            return false;
        }
        let mut plain = std::mem::take(&mut self.zin);
        let mut coded = std::mem::take(&mut self.zout);
        let mut ok = true;
        let mut coder = Some(plan.chain(coder));
        loop {
            plain.resize(FILE_CHUNK, 0);
            let n = match file.read(&mut plain) {
                Ok(n) => n,
                Err(_) => {
                    ok = false;
                    break;
                }
            };
            coded.clear();
            let last = n == 0;
            let r = match (last, coder.as_mut()) {
                (false, Some(k)) => k.write(&mut self.x, &plain[..n], &mut coded).await,
                _ => match coder.take() {
                    Some(k) => k.finish(&mut self.x, &mut coded).await,
                    None => Ok(()),
                },
            };
            if r.is_err() {
                ok = false;
                break;
            }
            if chunked {
                compress::push_chunk(&mut self.out, &coded);
                if last {
                    self.out.extend_from_slice(b"0\r\n\r\n");
                }
            } else {
                self.out.extend_from_slice(&coded);
            }
            if (last || self.out.len() >= FILE_CHUNK) && !self.out.is_empty() {
                self.x.sent.bytes += self.out.len() as u64;
                if write_timeout(&mut self.client, &self.out, SEND_TIMEOUT)
                    .await
                    .is_err()
                {
                    ok = false;
                    break;
                }
                if let Some(b) = self.x.bandwidth {
                    let before = self.x.paced;
                    self.x.paced += self.out.len() as u64;
                    throttle(b, before, self.x.paced, self.x.started).await;
                }
                self.out.clear();
            }
            if last {
                break;
            }
        }
        self.x.sent.body_bytes = self.x.sent.bytes.saturating_sub(head_len);
        self.zin = plain;
        self.zout = coded;
        ok && keep
    }

    /// Writes `out` followed by `span` of the file through `chain`, chunked
    /// or raw. Flushes count what they write, `out` included.
    pub(crate) async fn send_filtered(
        &mut self,
        file: &mut File,
        span: Span,
        chain: crate::filter::Chain,
        chunked: bool,
    ) -> bool {
        if file.seek(SeekFrom::Start(span.start)).is_err() {
            return false;
        }
        let head_len = self.out.len() as u64;
        let mut plain = std::mem::take(&mut self.zin);
        let mut coded = std::mem::take(&mut self.zout);
        let mut left = span.end - span.start;
        let mut ok = true;
        let mut chain = Some(chain);
        loop {
            let last = left == 0;
            coded.clear();
            let r = if last {
                match chain.take() {
                    Some(c) => c.finish(&mut self.x, &mut coded).await,
                    None => Ok(()),
                }
            } else {
                plain.resize(left.min(FILE_CHUNK as u64) as usize, 0);
                match (file.read(&mut plain), chain.as_mut()) {
                    (Ok(n), Some(c)) if n > 0 => {
                        left -= n as u64;
                        c.write(&mut self.x, &plain[..n], &mut coded).await
                    }
                    (Ok(n), None) if n > 0 => {
                        left -= n as u64;
                        Ok(())
                    }
                    _ => Err(std::io::ErrorKind::UnexpectedEof.into()),
                }
            };
            if r.is_err() {
                ok = false;
                break;
            }
            if chunked {
                compress::push_chunk(&mut self.out, &coded);
                if last {
                    self.out.extend_from_slice(b"0\r\n\r\n");
                }
            } else {
                self.out.extend_from_slice(&coded);
            }
            if (last || self.out.len() >= FILE_CHUNK) && !self.out.is_empty() {
                self.x.sent.bytes += self.out.len() as u64;
                if write_timeout(&mut self.client, &self.out, SEND_TIMEOUT)
                    .await
                    .is_err()
                {
                    ok = false;
                    break;
                }
                self.out.clear();
            }
            if last {
                break;
            }
        }
        self.x.sent.body_bytes = self.x.sent.bytes.saturating_sub(head_len);
        self.zin = plain;
        self.zout = coded;
        ok
    }

    /// Writes `out` followed by `span` of the file, leaving `out` empty.
    /// Sends `span` of `file` after what `out` holds, mapped through the
    /// charset byte table `map`.
    pub(crate) async fn send_span(
        &mut self,
        file: &mut File,
        span: Span,
        map: Option<&[u8; 256]>,
    ) -> bool {
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
            crate::filter::map_bytes(map, &mut self.out[start..]);
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
        match self.x.main_header(b"if-range") {
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

    /// nginx flv: the file from byte `start`, after the 13-byte FLV header,
    /// as a 200 without ranges.
    pub async fn send_flv(
        &mut self,
        mut file: File,
        meta: &Metadata,
        start: u64,
        ops: &HeaderOps,
    ) -> KeepAlive {
        const HEADER: &[u8] = b"FLV\x01\x05\0\0\0\x09\0\0\0\0";
        let len = meta.len();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        let status = self.x.status(200);
        self.extra(ops, status);
        let keep = self.x.req.keep_alive;
        let body_len = HEADER.len() as u64 + len - start;
        let out = &mut self.out;
        out.clear();
        reply::start(out, status, b"");
        out.extend_from_slice(b"Content-Type: ");
        out.extend_from_slice(reply::mime(&self.x.path));
        out.extend_from_slice(b"\r\nContent-Length: ");
        push_u64(out, body_len);
        out.extend_from_slice(b"\r\nLast-Modified: ");
        out.extend_from_slice(&http_date(mtime));
        out.extend_from_slice(b"\r\nETag: \"");
        push_hex(out, mtime);
        out.push(b'-');
        push_hex(out, len);
        out.extend_from_slice(b"\"\r\nAccept-Ranges: bytes\r\n");
        reply::connection(out, keep, &self.x.resp_extra);
        out.extend_from_slice(b"\r\n");
        self.x.sent.status = status;
        self.x.sent.bytes = out.len() as u64;
        if self.x.req.method == Method::Head {
            return self.respond(keep).await;
        }
        self.x.sent.bytes += body_len;
        self.x.sent.body_bytes = body_len;
        if keep && self.pump_body(crate::conn::Sink::Drop).await.is_err() {
            return false;
        }
        self.out.extend_from_slice(HEADER);
        if !self
            .send_span(&mut file, Span { start, end: len }, None)
            .await
        {
            return false;
        }
        keep
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
