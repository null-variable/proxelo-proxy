//! `root` + `index` file serving with nginx's status and redirect rules.

use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::time::UNIX_EPOCH;

use proxelo_http1::{Method, http_date, push_hex, push_u64};

use crate::conn::{Conn, KeepAlive, SEND_TIMEOUT, write_timeout};
use crate::reply;

/// File bytes read per write.
const FILE_CHUNK: usize = 64 * 1024;

pub(crate) enum Static {
    File(File, Metadata),
    /// An index file exists; `path` was extended and is routed again.
    Index,
    /// A directory addressed without a trailing slash.
    Directory,
    Status(u16),
}

impl Conn {
    pub fn resolve_static(&mut self, root: &[u8], index: &[Box<[u8]>]) -> Static {
        let file = &mut self.scratch;
        file.clear();
        file.extend_from_slice(root);
        file.extend_from_slice(&self.path);
        if self.path.ends_with(b"/") {
            let dir = file.len();
            for name in index {
                file.truncate(dir);
                file.extend_from_slice(name);
                if std::fs::metadata(OsStr::from_bytes(file)).is_ok_and(|m| !m.is_dir()) {
                    self.path.extend_from_slice(name);
                    return Static::Index;
                }
            }
            file.truncate(dir);
            // nginx answers 403 for an existing directory without an index.
            return match std::fs::metadata(OsStr::from_bytes(file)) {
                Ok(m) if m.is_dir() => Static::Status(403),
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Static::Status(403),
                _ => Static::Status(404),
            };
        }
        match File::open(OsStr::from_bytes(file)) {
            Ok(f) => match f.metadata() {
                Ok(m) if m.is_dir() => Static::Directory,
                Ok(m) => Static::File(f, m),
                Err(_) => Static::Status(500),
            },
            Err(e) => Static::Status(match e.kind() {
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => 404,
                io::ErrorKind::PermissionDenied => 403,
                _ => 500,
            }),
        }
    }

    fn request_header(&self, name: &[u8]) -> Option<&[u8]> {
        self.req
            .headers
            .iter()
            .find(|h| h.name.get(&self.head).eq_ignore_ascii_case(name))
            .map(|h| h.value.get(&self.head))
    }

    pub async fn send_file(&mut self, mut file: File, meta: &Metadata) -> KeepAlive {
        let len = meta.len();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        let modified = http_date(mtime);
        // nginx ETag: hex mtime and length.
        let etag = &mut self.scratch;
        etag.clear();
        etag.push(b'"');
        push_hex(etag, mtime);
        etag.push(b'-');
        push_hex(etag, len);
        etag.push(b'"');
        let not_modified = match self.request_header(b"if-none-match") {
            Some(v) => v == b"*" || v == &self.scratch[..],
            None => self.request_header(b"if-modified-since") == Some(&modified[..]),
        };

        let keep = self.req.keep_alive;
        let status = if not_modified { 304 } else { self.status(200) };
        let out = &mut self.out;
        out.clear();
        reply::start(out, status, b"");
        if !not_modified {
            out.extend_from_slice(b"Content-Type: ");
            out.extend_from_slice(reply::mime(&self.path));
            out.extend_from_slice(b"\r\nContent-Length: ");
            push_u64(out, len);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"Last-Modified: ");
        out.extend_from_slice(&modified);
        out.extend_from_slice(b"\r\nETag: ");
        out.extend_from_slice(&self.scratch);
        out.extend_from_slice(b"\r\n");
        if !not_modified {
            out.extend_from_slice(b"Accept-Ranges: bytes\r\n");
        }
        reply::connection(out, keep);
        out.extend_from_slice(b"\r\n");

        if not_modified || self.req.method == Method::Head {
            return self.respond(keep).await;
        }
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
        let keep = self.req.keep_alive;
        let out = &mut self.out;
        out.clear();
        reply::start(out, 301, b"");
        out.extend_from_slice(b"Location: ");
        reply::push_origin(out, &self.host, self.local);
        reply::push_uri_path(out, &self.path);
        out.push(b'/');
        if !self.args.is_empty() {
            out.push(b'?');
            out.extend_from_slice(&self.args);
        }
        out.extend_from_slice(b"\r\n");
        reply::page(out, 301, keep, self.req.method == Method::Head);
        self.respond(keep).await
    }
}
