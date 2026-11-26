//! One client connection: read a request, route it, answer, repeat.
//!
//! Every buffer lives in [`Conn`] and is reused for the next request, so a warm
//! keepalive connection serves requests without allocating. The connection is
//! plain TCP, TLS, or one HTTP/2 stream bridged as HTTP/1.1 (see `h2`); the
//! code here does not tell them apart.

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use proxelo_http1::{
    Body, ChunkedDecoder, Error as ParseError, Method, Response, parse_request, push_u64,
    request_line_complete,
};
use proxelo_snapshot::{Action, HeaderOps, MatchError};

use crate::buf::Buf;
use crate::exchange::Exchange;
use crate::io::{Stream, write_timeout};
use crate::phases::{Outcome, Phases};
use crate::{Active, acme, headers, log, reply};

// nginx defaults.
const CLIENT_HEADER_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const CLIENT_BODY_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const SEND_TIMEOUT: Duration = Duration::from_secs(60);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(75);
/// `client_header_buffer_size`, growing up to `large_client_header_buffers`.
pub(crate) const HEADER_BUF: usize = 1024;
pub(crate) const MAX_HEADER: usize = 32 * 1024;
/// `client_max_body_size`.
pub(crate) const MAX_BODY: u64 = 1024 * 1024;
/// `keepalive_requests`.
const KEEPALIVE_REQUESTS: u64 = 1000;

/// Unread part of the request body.
pub(crate) enum BodyLeft {
    None,
    Length(u64),
    /// Decoder and data bytes seen so far.
    Chunked(ChunkedDecoder, u64),
}

/// Why reading the request body stopped.
pub(crate) enum Fail {
    Client,
    BadBody,
    TooLarge,
    Upstream,
    UpstreamTimeout,
}

pub(crate) fn upstream_fail(e: io::Error) -> Fail {
    if e.kind() == io::ErrorKind::TimedOut {
        Fail::UpstreamTimeout
    } else {
        Fail::Upstream
    }
}

/// Where [`Conn::pump_body`] puts the request body.
pub(crate) enum Sink<'a> {
    Drop,
    Upstream(&'a mut crate::upstream::UpStream, Duration),
    /// The body without framing, at most [`MAX_BODY`] bytes.
    Collect(&'a mut Vec<u8>),
}

/// Whether the client connection stays open for another request.
pub(crate) type KeepAlive = bool;

pub(crate) struct Conn {
    pub client: Stream,
    /// Address of the socket that accepted the connection.
    listener: SocketAddr,
    served: bool,
    pub buf: Buf,
    pub ubuf: Buf,
    pub resp: Response,
    pub body: BodyLeft,
    pub out: Vec<u8>,
    /// The request being handled.
    pub x: Exchange,
    /// Connection zone counts the request holds until it ends.
    pub holds: Vec<crate::limits::Hold>,
    /// Compression input and output buffers.
    pub zin: Vec<u8>,
    pub zout: Vec<u8>,
    /// Gateway request body and request or response head scratch.
    pub gw_body: Vec<u8>,
    pub gw_buf: Vec<u8>,
}

/// Bytes after the head in a response built in one buffer.
pub(crate) fn body_len(out: &[u8]) -> usize {
    out.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(0, |i| out.len() - i - 4)
}

/// nginx keeps the connection after an error page except for these.
pub(crate) fn keeps_alive(status: u16) -> bool {
    !matches!(status, 400 | 413 | 414 | 500 | 501)
}

static CONN_IDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The next $connection serial number.
pub(crate) fn next_id() -> u64 {
    CONN_IDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
}

/// What the phases decided, for logging and metrics after the response.
struct Done {
    site: Option<u32>,
    route: Option<u32>,
}

impl Conn {
    pub fn new(client: Stream, listener: SocketAddr, local: SocketAddr, peer: SocketAddr) -> Self {
        let mut x = Exchange::new(local, peer);
        x.conn_id = next_id();
        Self {
            client,
            listener,
            served: false,
            buf: Buf::new(),
            ubuf: Buf::new(),
            resp: Response::default(),
            body: BodyLeft::None,
            out: Vec::new(),
            x,
            holds: Vec::new(),
            zin: Vec::new(),
            zout: Vec::new(),
            gw_body: Vec::new(),
            gw_buf: Vec::new(),
        }
    }

    /// Serves requests until the connection ends. `active` gives the newest
    /// snapshot, read once per request.
    pub async fn serve(mut self, active: impl Fn() -> std::sync::Arc<Active>) {
        loop {
            match self.read_head().await {
                Ok(true) => {}
                Ok(false) => return,
                Err(e) => {
                    self.error(e.status()).await;
                    return;
                }
            }
            let active = active();
            self.x.requests += 1;
            if self.x.requests >= KEEPALIVE_REQUESTS {
                self.x.req.keep_alive = false;
            }
            if !self.handle(&active).await {
                return;
            }
            self.served = true;
        }
    }

    /// Reads until a full request head is buffered. `Ok(false)` means the
    /// connection ended or timed out; nginx closes silently then.
    async fn read_head(&mut self) -> Result<bool, ParseError> {
        loop {
            if self.buf.end > 0 && parse_request(self.buf.filled(), &mut self.x.req)? {
                self.x.started = Instant::now();
                return Ok(true);
            }
            if self.buf.end >= MAX_HEADER {
                return Err(if request_line_complete(self.buf.filled()) {
                    ParseError::HeaderTooLarge
                } else {
                    ParseError::UriTooLong
                });
            }
            let wait = if self.buf.end == 0 && self.served {
                KEEPALIVE_TIMEOUT
            } else {
                CLIENT_HEADER_TIMEOUT
            };
            match tokio::time::timeout(
                wait,
                self.buf.fill(&mut self.client, HEADER_BUF, MAX_HEADER),
            )
            .await
            {
                Ok(Ok(n)) if n > 0 => {}
                _ => return Ok(false),
            }
        }
    }

    /// Answers a request that could not be parsed and closes.
    async fn error(&mut self, status: u16) {
        self.out.clear();
        reply::start(&mut self.out, status, b"");
        reply::page(&mut self.out, status, false, false, b"");
        let _ = write_timeout(&mut self.client, &self.out, SEND_TIMEOUT).await;
    }

    async fn handle(&mut self, active: &Active) -> KeepAlive {
        let mut done = Done {
            site: None,
            route: None,
        };
        let keep = self.handle_in(active, &mut done).await;
        self.holds.clear();
        self.finish(active, &done);
        keep
    }

    /// Logs the request and counts it.
    fn finish(&mut self, active: &Active, done: &Done) {
        let Some(site) = done.site else {
            return;
        };
        let rt = &active.rt;
        let s = &rt.sites[site as usize];
        let log_index = match done.route {
            Some(r) => s.routes[r as usize].access_log,
            None => s.access_log,
        };
        if let Some(i) = log_index {
            log::write(&active.logs, &rt.access_logs, i, &mut self.x);
        }
        active.metrics.request(
            site,
            done.route,
            self.x.sent.status,
            self.x.started.elapsed(),
        );
        crate::tap::record(
            &self.x,
            &s.id,
            done.route.map(|r| &*s.routes[r as usize].id),
        );
    }

    async fn handle_in(&mut self, active: &Active, done: &mut Done) -> KeepAlive {
        let head_len = self.x.req.head_len;
        self.x.head.clear();
        self.x.head.extend_from_slice(&self.buf.data[..head_len]);
        self.buf.consume(head_len);
        self.body = match self.x.req.body {
            Body::Length(n) => BodyLeft::Length(n),
            Body::Chunked => BodyLeft::Chunked(ChunkedDecoder::new(), 0),
            Body::None | Body::Close => BodyLeft::None,
        };

        if let Body::Length(n) = self.x.req.body
            && n > MAX_BODY
        {
            return self.page(413).await;
        }
        if !std::sync::Arc::ptr_eq(&self.x.lookups, &active.rt.lookups) {
            self.x.lookups = std::sync::Arc::clone(&active.rt.lookups);
        }
        if !std::sync::Arc::ptr_eq(&self.x.compressions, &active.rt.compressions) {
            self.x.compressions = std::sync::Arc::clone(&active.rt.compressions);
        }
        if let Err(status) = self.x.begin() {
            return self.page(status).await;
        }
        // ACME HTTP-01 is answered on plain listeners before any site, so a
        // certificate can be issued for a site that redirects to https.
        if !self.x.https()
            && matches!(self.x.req.method, Method::Get | Method::Head)
            && acme::http_answer(&self.x.path, &mut self.x.tmpl)
        {
            return self.send_text(200).await;
        }
        // The listener was removed by a swap after this connection was
        // accepted. Its socket is closed; close the connection too.
        let Some(listener) = active.rt.listener(self.listener) else {
            return false;
        };
        // ssl_verify_client: a missing or bad certificate answers 400,
        // which error pages see as 496 or 495.
        if let Some(code) = self.x.tls.as_ref().and_then(|t| t.client_error()) {
            self.x.req.keep_alive = false;
            return self.page(code).await;
        }
        let site_index = match listener.site(self.x.host()) {
            Ok(Some(site)) => site,
            Ok(None) => return self.page(404).await,
            Err(MatchError) => return self.page(500).await,
        };
        done.site = Some(site_index);
        let site = &active.rt.sites[site_index as usize];
        if site.redirect_https && !self.x.https() {
            return self.redirect_https().await;
        }
        if let Some(ri) = &site.real_ip {
            crate::access::real_ip(&mut self.x, ri);
        }
        let mut phases = Phases::new(site, false);
        loop {
            let outcome = phases.run(&mut self.x);
            done.route = phases.route;
            let ops = match phases.route {
                Some(r) => &site.routes[r as usize].response_headers,
                None => &site.response_headers,
            };
            return match outcome {
                Outcome::Proxy(p) => {
                    // An error page made this a GET; its body is not sent on.
                    if self.x.as_get && self.pump_body(Sink::Drop).await.is_err() {
                        return false;
                    }
                    let route = &site.routes[phases.route.expect("proxy has a route") as usize];
                    match self.proxy(active, &p, route).await {
                        Ok(keep) => keep,
                        Err(status) => {
                            phases.fail(status);
                            continue;
                        }
                    }
                }
                Outcome::Pass(_) => {
                    let route = &site.routes[phases.route.expect("pass has a route") as usize];
                    let r = match &route.action {
                        Action::Gateway(g) => self.gateway(active, g, route).await,
                        Action::Memcached(m) => self.memcached(active, m, route).await,
                        Action::Grpc(p) => self.grpc(active, p, route).await,
                        _ => unreachable!("pass outcomes come from these actions"),
                    };
                    match r {
                        Ok(keep) => keep,
                        Err(status) => {
                            phases.fail(status);
                            continue;
                        }
                    }
                }
                Outcome::Text(status) => {
                    let st = self.x.status(status);
                    self.extra(ops, st);
                    self.send_text(status).await
                }
                Outcome::Redirect(status) => {
                    let st = self.x.status(status);
                    self.extra(ops, st);
                    self.send_redirect(status).await
                }
                Outcome::Page(status) => {
                    self.extra(ops, status);
                    self.page(status).await
                }
                Outcome::File(f, m, gz) => self.send_file(f, &m, gz, ops).await,
                Outcome::Directory => {
                    self.extra(ops, 301);
                    self.redirect_dir().await
                }
                Outcome::Close => {
                    self.x.sent.status = 444;
                    false
                }
                Outcome::Access(r) => {
                    let result = self.access(active, site_index, r).await;
                    phases.accessed(r, result);
                    continue;
                }
            };
        }
    }

    /// Expands the configured response headers for `status`.
    pub(crate) fn extra(&mut self, ops: &HeaderOps, status: u16) {
        if ops.is_empty() {
            self.x.resp_extra.clear();
        } else {
            headers::response(&mut self.x, ops, status);
        }
    }

    /// Writes `out` and records what was sent, encoded when the response
    /// is to be compressed.
    async fn send(&mut self, keep: KeepAlive, status: u16, body: usize) -> KeepAlive {
        let head = self.out.len() - body;
        // Encode first: `&&` would skip it for responses that close anyway.
        let close = self.encode_buffered(status, body);
        let keep = keep && !close;
        self.x.sent.status = status;
        self.x.sent.bytes = self.out.len() as u64;
        self.x.sent.body_bytes = (self.out.len() - head.min(self.out.len())) as u64;
        self.respond(keep).await
    }

    /// Answers `status` with the body in `tmpl`.
    pub async fn send_text(&mut self, status: u16) -> KeepAlive {
        let status = self.x.status(status);
        let keep = self.x.req.keep_alive;
        let out = &mut self.out;
        out.clear();
        reply::start(out, status, b"");
        if !self.x.tmpl.is_empty() {
            // nginx types the body by the URI's extension, like a file,
            // falling back to `default_type application/octet-stream`.
            out.extend_from_slice(b"Content-Type: ");
            out.extend_from_slice(reply::mime(&self.x.path));
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"Content-Length: ");
        push_u64(out, self.x.tmpl.len() as u64);
        out.extend_from_slice(b"\r\n");
        reply::connection(out, keep, &self.x.resp_extra);
        out.extend_from_slice(b"\r\n");
        let mut body = 0;
        if self.x.req.method != Method::Head {
            out.extend_from_slice(&self.x.tmpl);
            body = self.x.tmpl.len();
        }
        self.send(keep, status, body).await
    }

    /// Redirects to the Location in `tmpl`, made absolute with the request
    /// scheme, host and port when it is a path (nginx `absolute_redirect on`).
    async fn send_redirect(&mut self, status: u16) -> KeepAlive {
        let status = self.x.status(status);
        let keep = self.x.req.keep_alive && keeps_alive(status);
        let out = &mut self.out;
        out.clear();
        reply::start(out, status, b"");
        out.extend_from_slice(b"Location: ");
        if self.x.tmpl.starts_with(b"/") {
            reply::push_origin(out, self.x.tls.is_some(), &self.x.host, self.x.local);
        }
        reply::push_header_value(out, &self.x.tmpl);
        out.extend_from_slice(b"\r\n");
        let head = self.x.req.method == Method::Head;
        reply::page(out, status, keep, head, &self.x.resp_extra);
        let body = body_len(out);
        self.send(keep, status, body).await
    }

    /// 301 to the same URI over https on the default port, like the nginx
    /// idiom `return 301 https://$host$request_uri`.
    async fn redirect_https(&mut self) -> KeepAlive {
        let keep = self.x.req.keep_alive;
        let out = &mut self.out;
        out.clear();
        reply::start(out, 301, b"");
        out.extend_from_slice(b"Location: https://");
        if self.x.host.is_empty() {
            let _ = std::io::Write::write_fmt(out, format_args!("{}", self.x.local.ip()));
        } else {
            out.extend_from_slice(&self.x.host);
        }
        out.extend_from_slice(self.x.req.target.get(&self.x.head));
        out.extend_from_slice(b"\r\n");
        let head = self.x.req.method == Method::Head;
        reply::page(out, 301, keep, head, b"");
        let body = body_len(out);
        self.send(keep, 301, body).await
    }

    /// Reads the rest of the request body. With `up` the bytes are forwarded
    /// as framed and `client_max_body_size` applies; without it they are
    /// discarded.
    pub async fn pump_body(&mut self, mut sink: Sink<'_>) -> Result<(), Fail> {
        loop {
            if matches!(self.body, BodyLeft::None) {
                return Ok(());
            }
            if self.buf.end == 0 {
                match tokio::time::timeout(
                    CLIENT_BODY_TIMEOUT,
                    self.buf.fill(&mut self.client, HEADER_BUF, MAX_HEADER),
                )
                .await
                {
                    Ok(Ok(n)) if n > 0 => {}
                    _ => return Err(Fail::Client),
                }
            }
            let (take, done) = match &mut self.body {
                BodyLeft::None => unreachable!(),
                BodyLeft::Length(n) => {
                    let take = (*n).min(self.buf.end as u64);
                    *n -= take;
                    (take as usize, *n == 0)
                }
                BodyLeft::Chunked(dec, total) => {
                    let mut data = 0;
                    let filled = &self.buf.data[..self.buf.end];
                    let take = dec
                        .advance_with(filled, |r| {
                            data += r.len() as u64;
                            if let Sink::Collect(v) = &mut sink {
                                v.extend_from_slice(&filled[r]);
                            }
                        })
                        .map_err(|_| Fail::BadBody)?;
                    *total += data;
                    if !matches!(sink, Sink::Drop) && *total > MAX_BODY {
                        return Err(Fail::TooLarge);
                    }
                    (take, dec.is_done())
                }
            };
            match &mut sink {
                Sink::Drop => {}
                Sink::Upstream(u, t) => {
                    write_timeout(*u, &self.buf.data[..take], *t)
                        .await
                        .map_err(upstream_fail)?;
                }
                Sink::Collect(v) => {
                    if matches!(self.body, BodyLeft::Length(_)) {
                        v.extend_from_slice(&self.buf.data[..take]);
                    }
                }
            }
            self.buf.consume(take);
            if done {
                self.body = BodyLeft::None;
            }
        }
    }

    /// Writes `out` after draining the request body, so the connection is at
    /// the next request when `keep` holds.
    pub async fn respond(&mut self, keep: KeepAlive) -> KeepAlive {
        if keep && self.pump_body(Sink::Drop).await.is_err() {
            return false;
        }
        write_timeout(&mut self.client, &self.out, SEND_TIMEOUT)
            .await
            .is_ok()
            && keep
    }

    pub async fn page(&mut self, status: u16) -> KeepAlive {
        let keep = self.x.req.keep_alive && keeps_alive(status);
        self.out.clear();
        // 495 and 496 are nginx's internal codes; the client sees 400.
        let wire = if matches!(status, 495 | 496) {
            400
        } else {
            status
        };
        reply::start(&mut self.out, wire, b"");
        if status == 401 {
            self.out.extend_from_slice(&self.x.auth_header);
        }
        let head = self.x.req.method == Method::Head;
        reply::page(&mut self.out, status, keep, head, &self.x.resp_extra);
        let body = body_len(&self.out);
        self.send(keep, wire, body).await
    }
}
