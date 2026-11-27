//! The request phases after the site is known, in nginx order:
//! server_rewrite (site rewrites and return), find_route, rewrite (route
//! rewrites), precontent (try_files), content. Internal redirects re-enter at
//! server_rewrite, `rewrite last` at find_route and named routes at rewrite,
//! with the same request.
//!
//! The phases decide without network I/O and stop at an [`Outcome`]; serving
//! sends it and the simulator reports it. Only a proxy outcome can come back:
//! when the upstream fails, [`Phases::fail`] continues with the error pages.

use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::io;
use std::os::unix::ffi::OsStrExt;

use proxelo_http1::Method;
use proxelo_snapshot::{
    Action, ErrorPage, ErrorTarget, Fallback, MatchError, Return, Rewrite, RewriteFlag, Site,
    TryFiles,
};

use crate::exchange::{Exchange, to_get};
pub(crate) use crate::vars::expand;

/// URI changes per request (rewrites that re-search the route and internal
/// redirects) before answering 500, as nginx's "rewrite or internal
/// redirection cycle".
const MAX_URI_CHANGES: usize = 10;

/// What the request ends with.
pub(crate) enum Outcome {
    /// `return` with a body, in `tmpl`.
    Text(u16),
    /// A redirect to the Location in `tmpl`; a path is made absolute.
    Redirect(u16),
    /// The built-in page for the status.
    Page(u16),
    /// A static file; its file system path is in `scratch`. `true` when it
    /// is the `.gz` of the requested file (gzip_static).
    File(File, Metadata, bool),
    /// A directory without a trailing slash: 301 to the path with one.
    Directory,
    /// A directory listing (autoindex) of the directory in `scratch`.
    Autoindex(proxelo_snapshot::Autoindex),
    /// A WebDAV method of the route's static action.
    Dav,
    /// An FLV file from this byte, after the FLV header (nginx flv).
    Flv(File, Metadata, u64),
    /// Proxy to this upstream with these settings.
    Proxy(proxelo_snapshot::Proxy),
    /// A gateway, memcached or grpc action of the route, with its upstream
    /// settings.
    Pass(proxelo_snapshot::Proxy),
    /// Close without a response (444).
    Close,
    /// The route's access phase must run; continue with
    /// [`Phases::accessed`].
    Access(u32),
}

enum Next {
    /// Internal redirect: site rewrites, then find the route.
    Server,
    /// Find the route for the current path.
    Find,
    /// Run a route without searching for it. `true` for a named route.
    Route(u32, bool),
    /// The route's access phase passed: run its content.
    Content(u32),
    /// The status is answered with the error pages in effect.
    Error(u16),
}

/// Outcome of a list of rewrites.
enum Rw {
    /// Nothing matched, or matches without a flag that left the path as is.
    Continue,
    /// A match without a flag changed the path.
    Changed,
    Last,
    Break,
    /// The Location is in `tmpl`.
    Redirect(u16),
}

/// A phase either ends the request or moves it on.
type Step = Result<Outcome, Next>;

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Where a request is in the phases of one site.
pub(crate) struct Phases<'s> {
    site: &'s Site,
    next: Next,
    pages: &'s [ErrorPage],
    changes: usize,
    /// The route that produced the outcome, if any.
    pub route: Option<u32>,
    /// Steps taken, for the simulator. `None` when serving.
    pub trace: Option<Vec<String>>,
}

impl<'s> Phases<'s> {
    pub fn new(site: &'s Site, trace: bool) -> Self {
        Self {
            site,
            next: Next::Server,
            pages: &site.error_pages,
            changes: 0,
            route: None,
            trace: trace.then(Vec::new),
        }
    }

    fn note(&mut self, f: impl FnOnce() -> String) {
        if let Some(t) = &mut self.trace {
            t.push(f());
        }
    }

    /// A proxy outcome failed with 502 or 504: the error pages apply.
    pub fn fail(&mut self, status: u16) {
        self.note(|| format!("upstream failed: {status}"));
        self.next = Next::Error(status);
    }

    /// Continues after the access phase of route `r`: its content, or the
    /// error pages for the status it was refused with.
    pub fn accessed(&mut self, r: u32, result: Result<(), u16>) {
        self.next = match result {
            Ok(()) => Next::Content(r),
            Err(status) => {
                self.note(|| format!("access denied: {status}"));
                Next::Error(status)
            }
        };
    }

    /// Counts a URI change; past the limit the request ends with 500.
    fn too_many_changes(&mut self) -> bool {
        self.changes += 1;
        let over = self.changes > MAX_URI_CHANGES + 1;
        if over {
            self.note(|| "rewrite or internal redirection cycle".into());
        }
        over
    }

    /// Runs the phases until the request has an outcome.
    pub fn run(&mut self, x: &mut Exchange) -> Outcome {
        let site = self.site;
        loop {
            let step = match self.next {
                Next::Server => self.server(x),
                Next::Find => {
                    // The route lookup reads the request and replaces the
                    // captures, which live in it too.
                    let mut caps = std::mem::take(&mut x.caps);
                    let found = site.route(x, &mut caps);
                    x.caps = caps;
                    match found {
                        Ok(Some(r)) => Err(Next::Route(r, false)),
                        Ok(None) => {
                            self.note(|| "no route".into());
                            Err(Next::Error(404))
                        }
                        Err(MatchError) => Err(Next::Error(500)),
                    }
                }
                Next::Route(r, named) => self.route(x, r, named),
                Next::Content(r) => {
                    let route = &site.routes[r as usize];
                    x.bandwidth = route.bandwidth;
                    self.content(x, &route.action)
                }
                Next::Error(status) => self.error_page(x, status),
            };
            match step {
                Ok(o) => return o,
                Err(next) => self.next = next,
            }
        }
    }

    fn server(&mut self, x: &mut Exchange) -> Step {
        if self.too_many_changes() {
            return Ok(Outcome::Page(500));
        }
        let site = self.site;
        self.pages = &site.error_pages;
        self.route = None;
        x.compression = site.compression;
        match self.rewrite(x, &site.rewrites) {
            Ok(Rw::Continue | Rw::Changed) => match &site.ret {
                Some(r) => self.ret(x, r),
                None => Err(Next::Find),
            },
            // `last` in a server block acts like `break`.
            Ok(Rw::Last | Rw::Break) => Err(Next::Find),
            Ok(Rw::Redirect(s)) => Ok(Outcome::Redirect(s)),
            Err(MatchError) => Err(Next::Error(500)),
        }
    }

    fn route(&mut self, x: &mut Exchange, r: u32, named: bool) -> Step {
        let route = &self.site.routes[r as usize];
        self.route = Some(r);
        self.pages = &route.error_pages;
        x.compression = route.compression;
        self.note(|| {
            let kind = if named { "named route" } else { "route" };
            format!("{kind} {}", route.id)
        });
        match self.rewrite(x, &route.rewrites) {
            // A named route is never searched for, so `last` cannot leave it.
            Ok(Rw::Last | Rw::Changed) if !named => {
                if self.too_many_changes() {
                    return Ok(Outcome::Page(500));
                }
                Err(Next::Find)
            }
            Ok(Rw::Redirect(s)) => Ok(Outcome::Redirect(s)),
            Ok(_) if route.access.is_empty() => Err(Next::Content(r)),
            Ok(_) => Ok(Outcome::Access(r)),
            Err(MatchError) => Err(Next::Error(500)),
        }
    }

    fn content(&mut self, x: &mut Exchange, action: &Action) -> Step {
        match action {
            Action::Return(r) => self.ret(x, r),
            Action::Proxy(p) => Ok(Outcome::Proxy(*p)),
            Action::Gateway(g) => Ok(Outcome::Pass(g.proxy)),
            Action::Memcached(m) => Ok(Outcome::Pass(m.proxy)),
            Action::Grpc(p) => Ok(Outcome::Pass(*p)),
            Action::Static {
                root,
                index,
                try_files,
                handlers,
            } => {
                if let Some(d) = &handlers.dav
                    && crate::dav::method(x, d).is_some()
                {
                    return Ok(Outcome::Dav);
                }
                if !matches!(x.req.method, Method::Get | Method::Head) {
                    // POST to a directory: nginx index takes it; with no
                    // index file every handler declines and the answer is
                    // 403. Other methods get static's 405.
                    if x.req.method == Method::Post && x.path.ends_with(b"/") {
                        if let Static::Index = resolve_static(x, root, index) {
                            x.uri_changed = true;
                            return Err(Next::Server);
                        }
                        return Err(Next::Error(403));
                    }
                    return Err(Next::Error(405));
                }
                if let Some(t) = try_files
                    && !self.try_files(x, root, t)
                {
                    return Err(match &t.fallback {
                        Fallback::Uri(u) => {
                            // nginx keeps only the arguments the fallback
                            // names, as in "/index.php?$args".
                            expand(x, u);
                            set_uri(x, false);
                            self.note(|| {
                                format!("try_files fallback {}", String::from_utf8_lossy(&x.path))
                            });
                            Next::Server
                        }
                        Fallback::Status(s) => Next::Error(*s),
                        Fallback::Route(r) => Next::Route(*r, true),
                    });
                }
                if handlers.random_index
                    && x.path.ends_with(b"/")
                    && crate::autoindex::random_file(x, root)
                {
                    x.uri_changed = true;
                    self.note(|| format!("random_index {}", String::from_utf8_lossy(&x.path)));
                    return Err(Next::Server);
                }
                if handlers.flv
                    && !x.path.ends_with(b"/")
                    && let Some(start) = flv_start(x)
                    && let Static::File(f, m) = resolve_static(x, root, index)
                {
                    if start < m.len() {
                        return Ok(Outcome::Flv(f, m, start));
                    }
                    return Ok(Outcome::File(f, m, false));
                }
                match resolve_static(x, root, index) {
                    Static::Status(403)
                        if x.path.ends_with(b"/") && handlers.autoindex.is_some() =>
                    {
                        Ok(Outcome::Autoindex(handlers.autoindex.expect("checked")))
                    }
                    Static::Index => {
                        x.uri_changed = true;
                        self.note(|| format!("index {}", String::from_utf8_lossy(&x.path)));
                        Err(Next::Server)
                    }
                    Static::File(f, m) => {
                        // gzip_static: file.gz, if it exists, for a client
                        // that takes it.
                        if let Some(gz) = gzip_static(x) {
                            return Ok(Outcome::File(gz.0, gz.1, true));
                        }
                        Ok(Outcome::File(f, m, false))
                    }
                    Static::Directory => Ok(Outcome::Directory),
                    Static::Status(s) => Err(Next::Error(s)),
                }
            }
        }
    }

    /// nginx error_page: the first page listing `status` turns the response
    /// into an internal redirect, a named route or a redirect, once per
    /// request (`recursive_error_pages off`).
    fn error_page(&mut self, x: &mut Exchange, status: u16) -> Step {
        let page = match self.pages.iter().find(|p| p.codes.contains(&status)) {
            Some(p) if !x.error_paged => p,
            _ => return Ok(Outcome::Page(status)),
        };
        x.error_paged = true;
        if let ErrorTarget::Uri(u) = &page.target {
            expand(x, u);
            if !x.tmpl.starts_with(b"/") {
                let code = match page.status {
                    Some(s) if is_redirect(s) => s,
                    _ => 302,
                };
                return Ok(Outcome::Redirect(code));
            }
        }
        x.err_status = page.status.unwrap_or(status);
        // The redirected request is a GET without a body, unless HEAD.
        to_get(x);
        Err(match &page.target {
            ErrorTarget::Uri(_) => {
                set_uri(x, false);
                self.note(|| format!("error_page {status} {}", String::from_utf8_lossy(&x.path)));
                Next::Server
            }
            ErrorTarget::Route(r) => {
                self.note(|| format!("error_page {status}"));
                Next::Route(*r, true)
            }
        })
    }

    /// Runs rewrites against the current path. A match replaces the captures.
    fn rewrite(&mut self, x: &mut Exchange, rules: &[Rewrite]) -> Result<Rw, MatchError> {
        let mut changed = false;
        for rule in rules {
            if !rule.regex.captures(&x.path, &mut x.caps)? {
                continue;
            }
            expand(x, &rule.replacement);
            self.note(|| {
                format!(
                    "rewrite {} -> {}",
                    rule.regex.source(),
                    String::from_utf8_lossy(&x.tmpl)
                )
            });
            if rule.absolute || matches!(rule.flag, RewriteFlag::Redirect | RewriteFlag::Permanent)
            {
                if rule.add_args && !x.args.is_empty() {
                    let sep = if x.tmpl.contains(&b'?') { b'&' } else { b'?' };
                    x.tmpl.push(sep);
                    let Exchange { tmpl, args, .. } = x;
                    tmpl.extend_from_slice(args);
                }
                return Ok(Rw::Redirect(if rule.flag == RewriteFlag::Permanent {
                    301
                } else {
                    302
                }));
            }
            set_uri(x, rule.add_args);
            changed = true;
            match rule.flag {
                RewriteFlag::Last => return Ok(Rw::Last),
                RewriteFlag::Break => return Ok(Rw::Break),
                _ => {}
            }
        }
        Ok(if changed { Rw::Changed } else { Rw::Continue })
    }

    /// nginx try_files: the first name that exists under `root` becomes the
    /// path; a name ending in `/` must be a directory, any other a file.
    fn try_files(&mut self, x: &mut Exchange, root: &[u8], t: &TryFiles) -> bool {
        for name in &t.files {
            expand(x, name);
            let file = &mut x.scratch;
            file.clear();
            file.extend_from_slice(root);
            file.extend_from_slice(&x.tmpl);
            let dir = x.tmpl.ends_with(b"/");
            if std::fs::metadata(OsStr::from_bytes(file)).is_ok_and(|m| m.is_dir() == dir) {
                if x.tmpl != x.path {
                    std::mem::swap(&mut x.path, &mut x.tmpl);
                }
                self.note(|| format!("try_files {}", String::from_utf8_lossy(&x.path)));
                return true;
            }
        }
        false
    }

    /// nginx return. 444 closes the connection without an answer.
    fn ret(&mut self, x: &mut Exchange, r: &Return) -> Step {
        if r.status == 444 {
            return Ok(Outcome::Close);
        }
        if is_redirect(r.status) {
            expand(x, &r.text);
            return Ok(Outcome::Redirect(r.status));
        }
        if r.text.parts().is_empty() && r.status >= 300 {
            return Err(Next::Error(r.status));
        }
        expand(x, &r.text);
        Ok(Outcome::Text(r.status))
    }
}

/// Makes the URI in `tmpl` the current one. A `?` in it starts new arguments,
/// followed by the old ones when `add_args`; without one the old arguments
/// stay when `add_args`.
fn set_uri(x: &mut Exchange, add_args: bool) {
    x.uri_changed = true;
    match x.tmpl.iter().position(|&c| c == b'?') {
        Some(q) => {
            x.scratch.clear();
            x.scratch.extend_from_slice(&x.tmpl[q + 1..]);
            if add_args && !x.args.is_empty() {
                x.scratch.push(b'&');
                x.scratch.extend_from_slice(&x.args);
            }
            std::mem::swap(&mut x.args, &mut x.scratch);
            x.tmpl.truncate(q);
        }
        None if !add_args => x.args.clear(),
        None => {}
    }
    std::mem::swap(&mut x.path, &mut x.tmpl);
}

/// nginx gzip_static: opens `scratch` + ".gz" when the compression settings
/// allow it and the client accepts gzip. Sets `vary` either way for `on`.
fn gzip_static(x: &mut Exchange) -> Option<(File, Metadata)> {
    let comps = std::sync::Arc::clone(&x.compressions);
    let c = comps.get(x.compression? as usize)?;
    if c.static_gz == proxelo_snapshot::StaticGz::Off {
        return None;
    }
    let mut vary = false;
    let ok = crate::compress::static_ok(x, c, &mut vary);
    let n = x.scratch.len();
    x.scratch.extend_from_slice(b".gz");
    let opened = File::open(OsStr::from_bytes(&x.scratch))
        .ok()
        .and_then(|f| Some((f.metadata().ok().filter(|m| m.is_file())?, f)));
    if opened.is_some() {
        // nginx sets Vary for gzip_static on when the file exists.
        x.vary |= vary;
    }
    match opened {
        Some((m, f)) if ok => Some((f, m)),
        _ => {
            x.scratch.truncate(n);
            None
        }
    }
}

pub(crate) enum Static {
    File(File, Metadata),
    /// An index file exists; `path` was extended and is routed again.
    Index,
    /// A directory addressed without a trailing slash.
    Directory,
    Status(u16),
}

/// The `start` argument of an FLV request when it is a positive offset.
fn flv_start(x: &Exchange) -> Option<u64> {
    let v = x
        .args
        .split(|&c| c == b'&')
        .find_map(|kv| kv.strip_prefix(b"start="))?;
    std::str::from_utf8(v).ok()?.parse().ok().filter(|&n| n > 0)
}

/// nginx `root` + `index`. The file system path is left in `scratch`.
fn resolve_static(x: &mut Exchange, root: &[u8], index: &[Box<[u8]>]) -> Static {
    let file = &mut x.scratch;
    file.clear();
    file.extend_from_slice(root);
    file.extend_from_slice(&x.path);
    if x.path.ends_with(b"/") {
        let dir = file.len();
        for name in index {
            file.truncate(dir);
            file.extend_from_slice(name);
            if std::fs::metadata(OsStr::from_bytes(file)).is_ok_and(|m| !m.is_dir()) {
                x.path.extend_from_slice(name);
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
