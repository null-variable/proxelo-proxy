//! Sending a static file and the directory redirect.

use std::fs::{File, Metadata};
use std::io::Read;
use std::time::UNIX_EPOCH;

use proxelo_http1::{Method, http_date, push_hex, push_u64};

use crate::conn::{Conn, KeepAlive, SEND_TIMEOUT, body_len};
use crate::io::write_timeout;
use crate::reply;

/// File bytes read per write.
const FILE_CHUNK: usize = 64 * 1024;

impl Conn {
    pub async fn send_file(&mut self, mut file: File, meta: &Metadata) -> KeepAlive {
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

        let keep = self.x.req.keep_alive;
        let status = if not_modified {
            304
        } else {
            self.x.status(200)
        };
        let out = &mut self.out;
        out.clear();
        reply::start(out, status, b"");
        if !not_modified {
            out.extend_from_slice(b"Content-Type: ");
            out.extend_from_slice(reply::mime(&self.x.path));
            out.extend_from_slice(b"\r\nContent-Length: ");
            push_u64(out, len);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"Last-Modified: ");
        out.extend_from_slice(&modified);
        out.extend_from_slice(b"\r\nETag: ");
        out.extend_from_slice(&self.x.scratch);
        out.extend_from_slice(b"\r\n");
        if !not_modified {
            out.extend_from_slice(b"Accept-Ranges: bytes\r\n");
        }
        reply::connection(out, keep, &self.x.resp_extra);
        out.extend_from_slice(b"\r\n");
        self.x.sent.status = status;
        self.x.sent.bytes = out.len() as u64;

        if not_modified || self.x.req.method == Method::Head {
            return self.respond(keep).await;
        }
        self.x.sent.bytes += len;
        self.x.sent.body_bytes = len;
        if keep && self.pump_body(None).await.is_err() {
            return false;
        }
        // The head and the first part of the file go out in one write.
        let mut left = len;
        while left > 0 {
            let start = self.out.len();
            let want = left.min(FILE_CHUNK as u64) as usize;
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
            self.out.clear();
        }
        if len == 0 {
            return write_timeout(&mut self.client, &self.out, SEND_TIMEOUT)
                .await
                .is_ok()
                && keep;
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
