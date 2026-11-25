//! The request phases after the site is known, in nginx order:
//! server_rewrite (site rewrites and return), find_route, rewrite (route
//! rewrites), precontent (try_files), content. Internal redirects re-enter at
//! server_rewrite, `rewrite last` at find_route and named routes at rewrite,
//! with the same request.

use std::ffi::OsStr;
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt;

use proxelo_http1::{Method, push_u64};
use proxelo_snapshot::{
    Action, ErrorPage, ErrorTarget, Fallback, MatchError, Part, Return, Rewrite, RewriteFlag, Site,
    Template, TryFiles, Var,
};

use crate::conn::{Conn, KeepAlive, keeps_alive};
use crate::static_file::Static;
use crate::{Active, reply};

/// URI changes per request (rewrites that re-search the route and internal
/// redirects) before answering 500, as nginx's "rewrite or internal
/// redirection cycle".
const MAX_URI_CHANGES: usize = 10;

enum Next {
    /// Internal redirect: site rewrites, then find the route.
    Server,
    /// Find the route for the current path.
    Find,
    /// Run a route without searching for it. `true` for a named route.
    Route(u32, bool),
    /// The status is answered with the error pages in effect.
    Error(u16),
    Done(KeepAlive),
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

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

impl Conn {
    pub(crate) async fn run(&mut self, active: &Active, site: &Site) -> KeepAlive {
        let mut next = Next::Server;
        let mut pages: &[ErrorPage] = &site.error_pages;
        let mut changes = 0;
        loop {
            next = match next {
                Next::Done(keep) => return keep,
                Next::Server => {
                    changes += 1;
                    if changes > MAX_URI_CHANGES + 1 {
                        return self.page(500).await;
                    }
                    pages = &site.error_pages;
                    match self.rewrite(&site.rewrites) {
                        Ok(Rw::Continue | Rw::Changed) => match &site.ret {
                            Some(r) => self.ret(r).await,
                            None => Next::Find,
                        },
                        // `last` in a server block acts like `break`.
                        Ok(Rw::Last | Rw::Break) => Next::Find,
                        Ok(Rw::Redirect(s)) => Next::Done(self.send_redirect(s).await),
                        Err(MatchError) => Next::Error(500),
                    }
                }
                Next::Find => match site.route(&self.path, &mut self.caps) {
                    Ok(Some(r)) => Next::Route(r, false),
                    Ok(None) => Next::Error(404),
                    Err(MatchError) => Next::Error(500),
                },
                Next::Route(r, named) => {
                    let route = &site.routes[r as usize];
                    pages = &route.error_pages;
                    match self.rewrite(&route.rewrites) {
                        // A named route is never searched for, so `last`
                        // cannot leave it.
                        Ok(Rw::Last | Rw::Changed) if !named => {
                            changes += 1;
                            if changes > MAX_URI_CHANGES + 1 {
                                return self.page(500).await;
                            }
                            Next::Find
                        }
                        Ok(Rw::Redirect(s)) => Next::Done(self.send_redirect(s).await),
                        Ok(_) => self.content(active, &route.action).await,
                        Err(MatchError) => Next::Error(500),
                    }
                }
                Next::Error(status) => self.error_page(status, pages).await,
            }
        }
    }

    async fn content(&mut self, active: &Active, action: &Action) -> Next {
        match action {
            Action::Return(r) => self.ret(r).await,
            Action::Proxy { upstream } => {
                match self.proxy(&active.upstreams[*upstream as usize]).await {
                    Ok(keep) => Next::Done(keep),
                    Err(status) => Next::Error(status),
                }
            }
            Action::Static {
                root,
                index,
                try_files,
            } => {
                if !matches!(self.req.method, Method::Get | Method::Head) {
                    return Next::Error(405);
                }
                if let Some(t) = try_files
                    && !self.try_files(root, t)
                {
                    return match &t.fallback {
                        Fallback::Uri(u) => {
                            // nginx keeps only the arguments the fallback
                            // names, as in "/index.php?$args".
                            self.expand(u);
                            self.set_uri(false);
                            Next::Server
                        }
                        Fallback::Status(s) => Next::Error(*s),
                        Fallback::Route(r) => Next::Route(*r, true),
                    };
                }
                match self.resolve_static(root, index) {
                    Static::Index => {
                        self.uri_changed = true;
                        Next::Server
                    }
                    Static::File(f, m) => Next::Done(self.send_file(f, &m).await),
                    Static::Directory => Next::Done(self.redirect_dir().await),
                    Static::Status(s) => Next::Error(s),
                }
            }
        }
    }

    /// nginx error_page: the first page listing `status` turns the response
    /// into an internal redirect, a named route or a redirect, once per
    /// request (`recursive_error_pages off`).
    async fn error_page(&mut self, status: u16, pages: &[ErrorPage]) -> Next {
        let page = match pages.iter().find(|p| p.codes.contains(&status)) {
            Some(p) if !self.error_paged => p,
            _ => return Next::Done(self.page(status).await),
        };
        self.error_paged = true;
        if let ErrorTarget::Uri(u) = &page.target {
            self.expand(u);
            if !self.tmpl.starts_with(b"/") {
                let code = match page.status {
                    Some(s) if is_redirect(s) => s,
                    _ => 302,
                };
                return Next::Done(self.send_redirect(code).await);
            }
        }
        self.err_status = page.status.unwrap_or(status);
        // The redirected request is a GET without a body, unless HEAD.
        if self.req.method != Method::Head {
            if self.pump_body(None).await.is_err() {
                return Next::Done(false);
            }
            self.req.method = Method::Get;
            self.as_get = true;
        }
        match &page.target {
            ErrorTarget::Uri(_) => {
                self.set_uri(false);
                Next::Server
            }
            ErrorTarget::Route(r) => Next::Route(*r, true),
        }
    }

    /// Runs rewrites against the current path. A match replaces the captures.
    fn rewrite(&mut self, rules: &[Rewrite]) -> Result<Rw, MatchError> {
        let mut changed = false;
        for rule in rules {
            if !rule.regex.captures(&self.path, &mut self.caps)? {
                continue;
            }
            self.expand(&rule.replacement);
            if rule.absolute || matches!(rule.flag, RewriteFlag::Redirect | RewriteFlag::Permanent)
            {
                if rule.add_args && !self.args.is_empty() {
                    let sep = if self.tmpl.contains(&b'?') {
                        b'&'
                    } else {
                        b'?'
                    };
                    self.tmpl.push(sep);
                    self.tmpl.extend_from_slice(&self.args);
                }
                return Ok(Rw::Redirect(if rule.flag == RewriteFlag::Permanent {
                    301
                } else {
                    302
                }));
            }
            self.set_uri(rule.add_args);
            changed = true;
            match rule.flag {
                RewriteFlag::Last => return Ok(Rw::Last),
                RewriteFlag::Break => return Ok(Rw::Break),
                _ => {}
            }
        }
        Ok(if changed { Rw::Changed } else { Rw::Continue })
    }

    /// Makes the URI in `tmpl` the current one. A `?` in it starts new
    /// arguments, followed by the old ones when `add_args`; without one the
    /// old arguments stay when `add_args`.
    fn set_uri(&mut self, add_args: bool) {
        self.uri_changed = true;
        match self.tmpl.iter().position(|&c| c == b'?') {
            Some(q) => {
                self.scratch.clear();
                self.scratch.extend_from_slice(&self.tmpl[q + 1..]);
                if add_args && !self.args.is_empty() {
                    self.scratch.push(b'&');
                    self.scratch.extend_from_slice(&self.args);
                }
                std::mem::swap(&mut self.args, &mut self.scratch);
                self.tmpl.truncate(q);
            }
            None if !add_args => self.args.clear(),
            None => {}
        }
        std::mem::swap(&mut self.path, &mut self.tmpl);
    }

    /// nginx try_files: the first name that exists under `root` becomes the
    /// path; a name ending in `/` must be a directory, any other a file.
    fn try_files(&mut self, root: &[u8], t: &TryFiles) -> bool {
        for name in &t.files {
            self.expand(name);
            let file = &mut self.scratch;
            file.clear();
            file.extend_from_slice(root);
            file.extend_from_slice(&self.tmpl);
            let dir = self.tmpl.ends_with(b"/");
            if std::fs::metadata(OsStr::from_bytes(file)).is_ok_and(|m| m.is_dir() == dir) {
                if self.tmpl != self.path {
                    std::mem::swap(&mut self.path, &mut self.tmpl);
                }
                return true;
            }
        }
        false
    }

    /// nginx return. 444 closes the connection without an answer.
    async fn ret(&mut self, r: &Return) -> Next {
        if r.status == 444 {
            return Next::Done(false);
        }
        if is_redirect(r.status) {
            self.expand(&r.text);
            return Next::Done(self.send_redirect(r.status).await);
        }
        if r.text.parts().is_empty() && r.status >= 300 {
            return Next::Error(r.status);
        }
        self.expand(&r.text);
        Next::Done(self.send_text(r.status).await)
    }

    /// Answers `status` with the body in `tmpl`.
    async fn send_text(&mut self, status: u16) -> KeepAlive {
        let status = self.status(status);
        let keep = self.req.keep_alive;
        let out = &mut self.out;
        out.clear();
        reply::start(out, status, b"");
        if !self.tmpl.is_empty() {
            out.extend_from_slice(b"Content-Type: text/plain\r\n");
        }
        out.extend_from_slice(b"Content-Length: ");
        push_u64(out, self.tmpl.len() as u64);
        out.extend_from_slice(b"\r\n");
        reply::connection(out, keep);
        out.extend_from_slice(b"\r\n");
        if self.req.method != Method::Head {
            out.extend_from_slice(&self.tmpl);
        }
        self.respond(keep).await
    }

    /// Redirects to the Location in `tmpl`, made absolute with the request
    /// host and port when it is a path (nginx `absolute_redirect on`).
    pub(crate) async fn send_redirect(&mut self, status: u16) -> KeepAlive {
        let status = self.status(status);
        let keep = self.req.keep_alive && keeps_alive(status);
        let out = &mut self.out;
        out.clear();
        reply::start(out, status, b"");
        out.extend_from_slice(b"Location: ");
        if self.tmpl.starts_with(b"/") {
            reply::push_origin(out, &self.host, self.local);
        }
        reply::push_header_value(out, &self.tmpl);
        out.extend_from_slice(b"\r\n");
        reply::page(out, status, keep, self.req.method == Method::Head);
        self.respond(keep).await
    }

    /// The status to send: the one an error page set, if any.
    pub(crate) fn status(&self, status: u16) -> u16 {
        if self.err_status != 0 {
            self.err_status
        } else {
            status
        }
    }

    /// Expands `t` into `tmpl`.
    fn expand(&mut self, t: &Template) {
        let mut out = std::mem::take(&mut self.tmpl);
        out.clear();
        for part in t.parts() {
            match part {
                Part::Lit(l) => out.extend_from_slice(l),
                Part::Var(v) => self.var(*v, &mut out),
                Part::Header(name) => {
                    if let Some(h) = self
                        .req
                        .headers
                        .iter()
                        .find(|h| h.name.get(&self.head).eq_ignore_ascii_case(name))
                    {
                        out.extend_from_slice(h.value.get(&self.head));
                    }
                }
                Part::Arg(name) => {
                    if let Some(v) = self.args.split(|&c| c == b'&').find_map(|kv| {
                        let (k, v) = kv.split_at(kv.iter().position(|&c| c == b'=')?);
                        k.eq_ignore_ascii_case(name).then_some(&v[1..])
                    }) {
                        out.extend_from_slice(v);
                    }
                }
            }
        }
        self.tmpl = out;
    }

    fn var(&self, v: Var, out: &mut Vec<u8>) {
        match v {
            Var::Uri => out.extend_from_slice(&self.path),
            Var::Args => out.extend_from_slice(&self.args),
            Var::IsArgs => {
                if !self.args.is_empty() {
                    out.push(b'?');
                }
            }
            Var::RequestUri => out.extend_from_slice(self.req.target.get(&self.head)),
            Var::Host => {
                if self.host.is_empty() {
                    _ = write!(out, "{}", self.local.ip());
                } else {
                    out.extend_from_slice(&self.host);
                }
            }
            Var::Scheme => out.extend_from_slice(b"http"),
            Var::RequestMethod => {
                if self.as_get {
                    out.extend_from_slice(b"GET");
                } else {
                    out.extend_from_slice(self.req.method_span.get(&self.head));
                }
            }
            Var::ServerPort => push_u64(out, u64::from(self.local.port())),
            Var::RemoteAddr => _ = write!(out, "{}", self.peer.ip()),
            Var::Capture(i) => {
                if let Some(c) = self.caps.get(usize::from(i)) {
                    out.extend_from_slice(c);
                }
            }
        }
    }
}
