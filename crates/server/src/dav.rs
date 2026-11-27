//! nginx WebDAV (dav_methods): PUT, DELETE, MKCOL, COPY and MOVE on the
//! files under a static route's root.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use proxelo_http1::{Body, Method, normalize_path};
use proxelo_snapshot::{Action, Dav};

use crate::conn::{Conn, Fail, KeepAlive, SEND_TIMEOUT, Sink, keeps_alive};
use crate::exchange::Exchange;
use crate::io::write_timeout;
use crate::reply;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DavMethod {
    Put,
    Delete,
    Mkcol,
    Copy,
    Move,
}

/// The DAV method of the request when `d` enables it.
pub(crate) fn method(x: &Exchange, d: &Dav) -> Option<DavMethod> {
    let m = match x.req.method {
        Method::Put => DavMethod::Put,
        Method::Delete => DavMethod::Delete,
        Method::Other => match x.req.method_span.get(&x.head) {
            b"MKCOL" => DavMethod::Mkcol,
            b"COPY" => DavMethod::Copy,
            b"MOVE" => DavMethod::Move,
            _ => return None,
        },
        _ => return None,
    };
    let on = match m {
        DavMethod::Put => d.put,
        DavMethod::Delete => d.delete,
        DavMethod::Mkcol => d.mkcol,
        DavMethod::Copy => d.copy,
        DavMethod::Move => d.moves,
    };
    on.then_some(m)
}

/// nginx ngx_http_dav_error: the status for a failed file operation.
fn error(e: &io::Error, not_found: u16) -> u16 {
    match e.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory | io::ErrorKind::InvalidFilename => {
            not_found
        }
        io::ErrorKind::PermissionDenied => 403,
        io::ErrorKind::AlreadyExists => 405,
        io::ErrorKind::StorageFull => 507,
        _ => 500,
    }
}

/// nginx ngx_dir_access: directories get x wherever r is set.
fn dir_access(a: u32) -> u32 {
    a | ((a & 0o444) >> 2)
}

fn path(root: &[u8], uri: &[u8]) -> PathBuf {
    let mut p = root.to_vec();
    p.extend_from_slice(uri);
    PathBuf::from(OsStr::from_bytes(&p))
}

/// nginx Depth: 0, 1 or infinity; anything else is invalid.
#[derive(PartialEq, Eq)]
enum Depth {
    Zero,
    One,
    Infinity,
    Invalid,
}

fn depth(x: &Exchange) -> Option<Depth> {
    Some(match x.request_header(b"depth")? {
        b"0" => Depth::Zero,
        b"1" => Depth::One,
        b"infinity" => Depth::Infinity,
        _ => Depth::Invalid,
    })
}

fn has_body(x: &Exchange) -> bool {
    matches!(x.req.body, Body::Chunked) || matches!(x.req.body, Body::Length(n) if n > 0)
}

/// A temporary file next to `dest`, removed unless kept.
struct Temp {
    path: PathBuf,
    keep: bool,
}

impl Drop for Temp {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn remove(p: &Path, dir: bool) -> Result<(), u16> {
    let r = if dir {
        fs::remove_dir_all(p)
    } else {
        fs::remove_file(p)
    };
    r.map_err(|e| error(&e, 404))
}

fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    let perm = fs::metadata(from)?.permissions();
    fs::create_dir(to)?;
    fs::set_permissions(to, perm)?;
    for e in fs::read_dir(from)? {
        let e = e?;
        let t = e.file_type()?;
        let dest = to.join(e.file_name());
        if t.is_dir() {
            copy_tree(&e.path(), &dest)?;
        } else if t.is_file() {
            fs::copy(e.path(), &dest)?;
        }
    }
    Ok(())
}

impl Conn {
    /// Runs the request's DAV method on the static route `route`.
    pub async fn dav(&mut self, action: &Action) -> Result<KeepAlive, u16> {
        let Action::Static { root, handlers, .. } = action else {
            unreachable!("dav outcomes come from static routes")
        };
        let d = handlers.dav.expect("dav outcome");
        let m = method(&self.x, &d).expect("dav outcome");
        let dir_uri = self.x.path.ends_with(b"/");
        let file = path(root, &self.x.path);
        let (status, location) = match m {
            DavMethod::Put => {
                if dir_uri {
                    return Err(409);
                }
                if self.x.request_header(b"content-range").is_some() {
                    return Err(501);
                }
                let status = self.put(&file, &d).await?;
                (status, status == 201)
            }
            DavMethod::Delete => {
                if has_body(&self.x) {
                    return Err(415);
                }
                self.delete(&file, &d, dir_uri)?;
                (204, false)
            }
            DavMethod::Mkcol => {
                if has_body(&self.x) {
                    return Err(415);
                }
                if !dir_uri {
                    return Err(409);
                }
                let mut b = fs::DirBuilder::new();
                std::os::unix::fs::DirBuilderExt::mode(&mut b, dir_access(d.access));
                b.create(&file).map_err(|e| error(&e, 409))?;
                (201, true)
            }
            DavMethod::Copy | DavMethod::Move => (
                self.copy_move(root, &file, m == DavMethod::Move, dir_uri)?,
                false,
            ),
        };
        Ok(self.send_dav(status, location).await)
    }

    async fn put(&mut self, file: &Path, d: &Dav) -> Result<u16, u16> {
        let status = match fs::metadata(file) {
            Ok(m) if m.is_dir() => return Err(409),
            Ok(_) => 204,
            Err(_) => 201,
        };
        let dir = file.parent().unwrap_or(Path::new("/"));
        if d.create_full_put_path && !dir.exists() {
            let mut b = fs::DirBuilder::new();
            b.recursive(true);
            std::os::unix::fs::DirBuilderExt::mode(&mut b, dir_access(d.access));
            b.create(dir).map_err(|_| 500u16)?;
        }
        let name = file.file_name().map(|n| n.as_bytes()).unwrap_or(b"");
        let mut tmp_name = b".".to_vec();
        tmp_name.extend_from_slice(name);
        tmp_name.extend_from_slice(
            format!(".{:010}", crate::upstream::rand() % 10_000_000_000).as_bytes(),
        );
        let mut tmp = Temp {
            path: dir.join(OsStr::from_bytes(&tmp_name)),
            keep: false,
        };
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(d.access)
            .open(&tmp.path)
            .map_err(|e| error(&e, 409))?;
        if self.x.req.expect_continue && self.buf.end == 0 {
            if write_timeout(
                &mut self.client,
                b"HTTP/1.1 100 Continue\r\n\r\n",
                SEND_TIMEOUT,
            )
            .await
            .is_err()
            {
                self.x.req.keep_alive = false;
                return Err(400);
            }
            self.x.req.expect_continue = false;
        }
        let mut body = Vec::new();
        match self.pump_body(Sink::Collect(&mut body)).await {
            Ok(()) => {}
            Err(Fail::TooLarge) => {
                self.x.req.keep_alive = false;
                return Err(413);
            }
            Err(_) => {
                self.x.req.keep_alive = false;
                return Err(400);
            }
        }
        out.write_all(&body).map_err(|e| error(&e, 500))?;
        // nginx dav_access applies whatever the umask.
        let _ = out.set_permissions(fs::Permissions::from_mode(d.access));
        if let Some(t) = self
            .x
            .request_header(b"date")
            .and_then(|v| std::str::from_utf8(v).ok())
            .and_then(crate::compress::httpdate_secs)
        {
            let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(t);
            let _ = out.set_modified(at);
        }
        drop(out);
        fs::rename(&tmp.path, file).map_err(|e| error(&e, 500))?;
        tmp.keep = true;
        Ok(status)
    }

    fn delete(&self, file: &Path, d: &Dav, dir_uri: bool) -> Result<(), u16> {
        if d.min_delete_depth > 0 {
            let uri = &self.x.path;
            let mut n = 0;
            let deep = uri.iter().enumerate().any(|(i, &c)| {
                if c == b'/' {
                    n += 1;
                    n >= d.min_delete_depth && i + 1 < uri.len()
                } else {
                    false
                }
            });
            if !deep {
                return Err(409);
            }
        }
        let meta = fs::symlink_metadata(file).map_err(|e| {
            if e.kind() == io::ErrorKind::NotADirectory {
                409
            } else {
                error(&e, 404)
            }
        })?;
        let dir = meta.is_dir();
        if dir {
            if !dir_uri {
                return Err(409);
            }
            if depth(&self.x).is_some_and(|v| v != Depth::Infinity) {
                return Err(400);
            }
        } else if depth(&self.x).is_some_and(|v| v != Depth::Zero && v != Depth::Infinity) {
            return Err(400);
        }
        remove(file, dir)
    }

    /// The destination path of COPY and MOVE, from the Destination header.
    fn destination(&self) -> Result<Vec<u8>, u16> {
        let dest = self.x.request_header(b"destination").ok_or(400u16)?;
        let path = if dest.starts_with(b"/") {
            dest
        } else {
            let scheme: &[u8] = if self.x.tls.is_some() {
                b"https://"
            } else {
                b"http://"
            };
            let rest = dest.strip_prefix(scheme).ok_or(400u16)?;
            let host = self.x.host().ok_or(400u16)?;
            if rest.len() < host.len() || !rest[..host.len()].eq_ignore_ascii_case(host) {
                return Err(400);
            }
            let after = &rest[host.len()..];
            let slash = after.iter().position(|&c| c == b'/').ok_or(400u16)?;
            &after[slash..]
        };
        let path = match path.iter().position(|&c| c == b'?') {
            Some(q) => &path[..q],
            None => path,
        };
        let mut out = Vec::new();
        normalize_path(path, &mut out).map_err(|_| 400u16)?;
        if path.ends_with(b"/") && !out.ends_with(b"/") {
            out.push(b'/');
        }
        Ok(out)
    }

    fn copy_move(&self, root: &[u8], src: &Path, is_move: bool, dir_uri: bool) -> Result<u16, u16> {
        if has_body(&self.x) {
            return Err(415);
        }
        let duri = self.destination()?;
        if dir_uri != duri.ends_with(b"/") {
            return Err(409);
        }
        match depth(&self.x) {
            None | Some(Depth::Infinity) => {}
            Some(Depth::Zero) if !is_move => {}
            _ => return Err(400),
        }
        let overwrite = match self.x.request_header(b"overwrite") {
            None => true,
            Some(b"T" | b"t") => true,
            Some(b"F" | b"f") => false,
            Some(_) => return Err(400),
        };
        let trimmed = |u: &[u8]| -> Vec<u8> {
            let mut v = u.to_vec();
            while v.len() > 1 && v.ends_with(b"/") {
                v.pop();
            }
            v
        };
        let (s, t) = (trimmed(&self.x.path), trimmed(&duri));
        if s == t {
            return Err(403);
        }
        // A collection into itself or one of its children.
        if dir_uri && (t.starts_with(&s) && t.get(s.len()) == Some(&b'/')) {
            return Err(403);
        }
        let dst = path(root, &t);
        let (overwrite, dst_dir) = match fs::symlink_metadata(&dst) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => (false, false),
            Err(e) => return Err(error(&e, 404)),
            Ok(m) => {
                if m.is_dir() && !dir_uri {
                    return Err(409);
                }
                if !overwrite {
                    return Err(412);
                }
                (true, m.is_dir())
            }
        };
        let meta = fs::symlink_metadata(src).map_err(|e| error(&e, 404))?;
        if meta.is_dir() {
            if !dir_uri {
                return Err(400);
            }
            if overwrite {
                remove(&dst, dst_dir)?;
            }
            if is_move && fs::rename(src, &dst).is_ok() {
                return Ok(201);
            }
            copy_tree(src, &dst).map_err(|e| error(&e, 404))?;
            if is_move {
                remove(src, true)?;
            }
            return Ok(201);
        }
        if is_move {
            if let Some(parent) = dst.parent()
                && !parent.exists()
            {
                fs::create_dir_all(parent).map_err(|_| 500u16)?;
            }
            fs::rename(src, &dst).map_err(|_| 500u16)?;
            return Ok(204);
        }
        fs::copy(src, &dst).map_err(|_| 500u16)?;
        if let Ok(t) = meta.modified() {
            let _ = File::options()
                .write(true)
                .open(&dst)
                .and_then(|f| f.set_modified(t));
        }
        Ok(204)
    }

    /// 201 or 204 without a body; 201 carries Location for PUT and MKCOL.
    async fn send_dav(&mut self, status: u16, location: bool) -> KeepAlive {
        let keep = self.x.req.keep_alive && keeps_alive(status);
        let out = &mut self.out;
        out.clear();
        reply::start(out, status, b"");
        if location {
            // Made absolute like every Location nginx sends itself.
            out.extend_from_slice(b"Location: ");
            reply::push_origin(out, self.x.tls.is_some(), &self.x.host, self.x.local);
            reply::push_uri_path(out, &self.x.path);
            out.extend_from_slice(b"\r\n");
        }
        if status == 201 {
            out.extend_from_slice(b"Content-Length: 0\r\n");
        }
        reply::connection(out, keep, &self.x.resp_extra);
        out.extend_from_slice(b"\r\n");
        self.x.sent.status = status;
        self.x.sent.bytes = self.out.len() as u64;
        self.respond(keep).await
    }
}
