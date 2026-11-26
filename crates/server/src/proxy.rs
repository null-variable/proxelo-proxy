//! `proxy_pass` to an upstream over HTTP/1.1 with keepalive connections.

use std::io::Write as _;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use proxelo_http1::{Body, ChunkedDecoder, HeaderKind, Method, Version, parse_response, push_hex};
use proxelo_snapshot::{Balancing, Proxy, Route, Sticky};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::conn::{BodyLeft, Conn, Fail, KeepAlive, SEND_TIMEOUT as CLIENT_SEND, upstream_fail};
use crate::io::write_timeout;
use crate::upstream::{Choice, Conn as UpConn, Pool, State};
use crate::{Active, headers, reply};

/// `proxy_buffer_size`: the upstream response head must fit.
const HEAD_BUF: usize = 16 * 1024;
/// Upstream body bytes read per client write.
const BODY_BUF: usize = 64 * 1024;

/// How the response body is framed toward the client.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    None,
    Length(u64),
    /// Chunked both ways; forwarded as is.
    Chunked,
    /// Chunked upstream, HTTP/1.0 client: framing removed, close at end.
    Dechunk,
    /// Upstream body ends at close, HTTP/1.1 client: chunked framing added.
    Encode,
    /// Upstream body ends at close, HTTP/1.0 client: close at end too.
    Raw,
}

fn idempotent(m: Method) -> bool {
    !matches!(
        m,
        Method::Post | Method::Patch | Method::Connect | Method::Other
    )
}

async fn read(
    s: &mut TcpStream,
    buf: &mut crate::buf::Buf,
    max: usize,
    t: Duration,
) -> Result<usize, Fail> {
    match timeout(t, buf.fill(s, HEAD_BUF, max)).await {
        Ok(Ok(n)) => Ok(n),
        Ok(Err(e)) => Err(upstream_fail(e)),
        Err(_) => Err(Fail::UpstreamTimeout),
    }
}

/// An attempt that got a response head the route wants to retry on.
struct Retry;

impl Conn {
    /// Proxies the request. `Err` carries the 502 or 504 to answer, which an
    /// error page may replace.
    pub async fn proxy(
        &mut self,
        active: &Active,
        p: &Proxy,
        route: &Route,
    ) -> Result<KeepAlive, u16> {
        let ups = &active.upstreams[p.upstream as usize];
        // After the request went out, a retry is only safe when it can be
        // replayed: no body and a method that tolerates repetition, unless
        // the route allows non_idempotent.
        let replayable = (self.x.req.body == Body::None || self.x.as_get)
            && (p.next.non_idempotent || idempotent(self.x.req.method));
        let started = Instant::now();
        let mut choice = Choice {
            prefer: self.sticky(active, p.upstream),
            ..Default::default()
        };
        // The key of the hash methods, in `tmpl`.
        self.balancing_key(active, p.upstream);
        let mut queue_deadline = None;
        let mut tries = 0u32;
        let mut status = 502;
        loop {
            if p.tries != 0 && tries >= p.tries {
                break;
            }
            let Some(picked) = ups.pick(&mut choice, &self.x.tmpl) else {
                // Every target that could take it is at max_conns: wait in
                // the queue (nginx queue), then pick again.
                if ups.full(choice.tried) {
                    let deadline = *queue_deadline.get_or_insert_with(|| ups.queue_deadline());
                    if ups.wait(Some(deadline)).await {
                        continue;
                    }
                }
                break;
            };
            tries += 1;
            let i = picked.index;
            let pool = &ups.pools()[i];
            self.x.sent.upstream_addr = Some(pool.addr);
            let connect = Instant::now();
            let mut up = match pool.take() {
                Some(c) => c,
                None => match timeout(p.connect_timeout, TcpStream::connect(pool.addr)).await {
                    Ok(Ok(s)) => {
                        let _ = s.set_nodelay(true);
                        UpConn {
                            stream: s,
                            used: 0,
                            opened: Instant::now(),
                        }
                    }
                    // Nothing was sent, so any request may move on.
                    Ok(Err(_)) => {
                        ups.failed(i);
                        active.metrics.upstream_failure(p.upstream, i);
                        status = 502;
                        if !p.next.error {
                            break;
                        }
                        continue;
                    }
                    Err(_) => {
                        ups.failed(i);
                        active.metrics.upstream_failure(p.upstream, i);
                        status = 504;
                        if !p.next.timeout {
                            break;
                        }
                        continue;
                    }
                },
            };
            let reused = up.used > 0;
            self.x.sent.upstream_connect = Some(connect.elapsed().as_secs_f64());
            self.upstream_head(pool.addr, &ups.host, ups.keepalive, route);
            let last =
                !replayable || !ups.has_next(choice.tried) || (p.tries != 0 && tries >= p.tries);
            match self.exchange(&mut up.stream, p, last).await {
                Ok(()) => {
                    let st = self.resp.status;
                    self.x.sent.upstream_status = st;
                    self.x.sent.upstream_header = Some(connect.elapsed().as_secs_f64());
                    let failure = p.next.on_status(st) && !matches!(st, 403 | 404);
                    if failure {
                        ups.failed(i);
                    } else {
                        ups.succeeded(i);
                    }
                    self.sticky_cookie(active, p.upstream, i);
                    up.used += 1;
                    let keep_up = ups.keepalive
                        && up.used < ups.keepalive_requests
                        && up.opened.elapsed() < ups.keepalive_time;
                    let keep = self.relay(up, pool, keep_up, route, p.read_timeout).await;
                    let took = started.elapsed();
                    self.x.sent.upstream_response = Some(connect.elapsed().as_secs_f64());
                    active.metrics.upstream_response(p.upstream, i, st, took);
                    return Ok(keep);
                }
                Err(Ok(Retry)) => {
                    // A status listed in next_upstream: try the next target.
                    let st = self.resp.status;
                    if !matches!(st, 403 | 404) {
                        ups.failed(i);
                    }
                    active
                        .metrics
                        .upstream_response(p.upstream, i, st, connect.elapsed());
                    self.x.sent.upstream_status = st;
                    status = 502;
                }
                Err(Err(Fail::Client)) => return Ok(false),
                Err(Err(Fail::BadBody)) => {
                    self.x.req.keep_alive = false;
                    return Ok(self.page(400).await);
                }
                Err(Err(Fail::TooLarge)) => {
                    self.x.req.keep_alive = false;
                    return Ok(self.page(413).await);
                }
                Err(Err(f)) => {
                    let timed_out = matches!(f, Fail::UpstreamTimeout);
                    status = if timed_out { 504 } else { 502 };
                    // A pooled connection the upstream closed while idle says
                    // nothing about the target; allow it again on a fresh one.
                    if reused && matches!(f, Fail::Upstream) {
                        if i < 64 {
                            choice.tried &= !(1 << i);
                        }
                        tries -= 1;
                        continue;
                    }
                    ups.failed(i);
                    active.metrics.upstream_failure(p.upstream, i);
                    let allowed = if timed_out {
                        p.next.timeout
                    } else {
                        p.next.error
                    };
                    if !replayable || !allowed {
                        break;
                    }
                }
            }
        }
        if !matches!(self.body, BodyLeft::None) {
            // Part of the body went to a failed upstream; what is left cannot
            // be told apart from a next request.
            self.x.req.keep_alive = false;
        }
        Err(status)
    }

    /// The target a sticky session names: the sticky cookie's value, or the
    /// first non-empty route template matched against target routes.
    fn sticky(&mut self, active: &Active, upstream: u32) -> Option<usize> {
        let ups: &State = &active.upstreams[upstream as usize];
        match &active.rt.upstreams[upstream as usize].sticky {
            None => None,
            Some(Sticky::Cookie(c)) => ups.by_cookie(self.x.cookie(c.name.as_bytes())?),
            Some(Sticky::Route(ts)) => ts.iter().find_map(|t| {
                crate::vars::expand(&mut self.x, t);
                (!self.x.tmpl.is_empty())
                    .then(|| ups.by_route(&self.x.tmpl))
                    .flatten()
            }),
        }
    }

    /// Leaves the balancing key in `tmpl`: the client network for ip_hash,
    /// the expanded hash key for the hash methods, nothing otherwise.
    fn balancing_key(&mut self, active: &Active, upstream: u32) {
        let up = &active.rt.upstreams[upstream as usize];
        self.x.tmpl.clear();
        match up.balancing {
            Balancing::IpHash => match self.x.peer.ip() {
                std::net::IpAddr::V4(a) => self.x.tmpl.extend_from_slice(&a.octets()[..3]),
                std::net::IpAddr::V6(a) => self.x.tmpl.extend_from_slice(&a.octets()),
            },
            Balancing::Hash | Balancing::HashConsistent => {
                crate::vars::expand(&mut self.x, &up.hash_key);
            }
            _ => {}
        }
    }

    /// Sets the sticky cookie naming target `i` unless the request already
    /// carries it.
    fn sticky_cookie(&mut self, active: &Active, upstream: u32, i: usize) {
        let Some(Sticky::Cookie(c)) = &active.rt.upstreams[upstream as usize].sticky else {
            return;
        };
        let value = active.upstreams[upstream as usize].cookie(i);
        if self.x.cookie(c.name.as_bytes()) == Some(&value[..]) {
            return;
        }
        self.x.sticky_cookie.clear();
        self.x.sticky_cookie.extend_from_slice(b"Set-Cookie: ");
        self.x.sticky_cookie.extend_from_slice(c.name.as_bytes());
        self.x.sticky_cookie.push(b'=');
        self.x.sticky_cookie.extend_from_slice(value);
        self.x
            .sticky_cookie
            .extend_from_slice(c.attributes.as_bytes());
        self.x.sticky_cookie.extend_from_slice(b"\r\n");
    }

    /// Builds the upstream request head into `out`: the original target, or
    /// the changed URI after a rewrite or internal redirect, as `proxy_pass`
    /// without a URI part does. Host is the upstream's ($proxy_host) unless a
    /// header operation sets it, as nginx's default `proxy_set_header Host
    /// $proxy_host`. The route's request headers are applied.
    fn upstream_head(&mut self, target: SocketAddr, host: &str, keepalive: bool, route: &Route) {
        let mut out = std::mem::take(&mut self.out);
        out.clear();
        if self.x.as_get {
            out.extend_from_slice(b"GET");
        } else {
            out.extend_from_slice(self.x.req.method_span.get(&self.x.head));
        }
        out.push(b' ');
        if self.x.uri_changed {
            reply::push_uri_path(&mut out, &self.x.path);
            if !self.x.args.is_empty() {
                out.push(b'?');
                out.extend_from_slice(&self.x.args);
            }
        } else {
            out.extend_from_slice(self.x.req.target.get(&self.x.head));
        }
        out.extend_from_slice(b" HTTP/1.1\r\n");
        let ops = &route.request_headers;
        let has_host = ops.drops(b"host");
        for h in self.x.req.headers.iter() {
            // Expect is answered here, not by the upstream. A request an
            // error page turned into a GET has no body any more.
            let name = h.name.get(&self.x.head);
            if h.kind.is_hop_by_hop()
                || h.kind == HeaderKind::Host
                || h.kind == HeaderKind::Expect
                || (self.x.as_get && h.kind == HeaderKind::ContentLength)
                || (!ops.is_empty() && ops.drops(name))
            {
                continue;
            }
            out.extend_from_slice(name);
            out.extend_from_slice(b": ");
            out.extend_from_slice(h.value.get(&self.x.head));
            out.extend_from_slice(b"\r\n");
        }
        if !has_host {
            if host.is_empty() {
                _ = write!(out, "Host: {target}\r\n");
            } else {
                out.extend_from_slice(b"Host: ");
                out.extend_from_slice(host.as_bytes());
                out.extend_from_slice(b"\r\n");
            }
        }
        if !ops.is_empty() {
            headers::request(&mut self.x, ops, &mut out);
        }
        if self.x.req.body == Body::Chunked && !self.x.as_get {
            out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }
        if !keepalive {
            out.extend_from_slice(b"Connection: close\r\n");
        }
        out.extend_from_slice(b"\r\n");
        self.out = out;
    }

    /// Sends the head in `out` and the body, then reads the response head
    /// into `resp`, skipping interim responses. `Err(Ok(Retry))` means the
    /// status is one to move on from and `last` is false; its body is not
    /// read.
    async fn exchange(
        &mut self,
        up: &mut TcpStream,
        p: &Proxy,
        last: bool,
    ) -> Result<(), Result<Retry, Fail>> {
        write_timeout(up, &self.out, p.send_timeout)
            .await
            .map_err(|e| Err(upstream_fail(e)))?;
        if self.x.req.expect_continue && !matches!(self.body, BodyLeft::None) && self.buf.end == 0 {
            write_timeout(
                &mut self.client,
                b"HTTP/1.1 100 Continue\r\n\r\n",
                CLIENT_SEND,
            )
            .await
            .map_err(|_| Err(Fail::Client))?;
            self.x.req.expect_continue = false;
        }
        self.pump_body(Some((up, p.send_timeout)))
            .await
            .map_err(Err)?;

        let head = self.x.req.method == Method::Head;
        self.ubuf.end = 0;
        loop {
            if self.ubuf.end > 0
                && parse_response(self.ubuf.filled(), head, &mut self.resp)
                    .map_err(|_| Err(Fail::Upstream))?
            {
                // Upgrade is never requested, so 101 is a protocol error.
                if self.resp.status == 101 {
                    return Err(Err(Fail::Upstream));
                }
                if self.resp.status >= 200 {
                    if !last && p.next.on_status(self.resp.status) {
                        return Err(Ok(Retry));
                    }
                    return Ok(());
                }
                self.ubuf.consume(self.resp.head_len);
                continue;
            }
            if self.ubuf.end >= HEAD_BUF {
                return Err(Err(Fail::Upstream));
            }
            if read(up, &mut self.ubuf, HEAD_BUF, p.read_timeout)
                .await
                .map_err(Err)?
                == 0
            {
                return Err(Err(Fail::Upstream));
            }
        }
    }

    /// Sends the upstream response to the client and pools the upstream
    /// connection when it is reusable.
    async fn relay(
        &mut self,
        mut up: UpConn,
        pool: &Pool,
        pool_ok: bool,
        route: &Route,
        read_timeout: Duration,
    ) -> KeepAlive {
        let client11 = self.x.req.version == Version::Http11;
        let mut keep = self.x.req.keep_alive;
        let mode = match self.resp.body {
            Body::None => Mode::None,
            Body::Length(n) => Mode::Length(n),
            Body::Chunked if client11 => Mode::Chunked,
            Body::Close if client11 => Mode::Encode,
            Body::Chunked => Mode::Dechunk,
            Body::Close => Mode::Raw,
        };
        if matches!(mode, Mode::Dechunk | Mode::Raw) {
            keep = false;
        }
        // An unread request body means the upstream answered early; the
        // client connection cannot be resynchronized cheaply.
        if !matches!(self.body, BodyLeft::None) {
            keep = false;
        }

        let status = if self.x.err_status != 0 {
            self.x.err_status
        } else {
            self.resp.status
        };
        let ops = &route.response_headers;
        if ops.is_empty() {
            self.x.resp_extra.clear();
        } else {
            headers::response(&mut self.x, ops, status);
        }
        let out = &mut self.out;
        out.clear();
        if self.x.err_status != 0 {
            reply::start(out, self.x.err_status, b"");
        } else {
            reply::start(out, self.resp.status, self.resp.reason.get(&self.ubuf.data));
        }
        for h in self.resp.headers.iter() {
            // nginx hides Date, Server, X-Pad and X-Accel-* by default and
            // sets its own Date and Server.
            let name = h.name.get(&self.ubuf.data);
            if h.kind.is_hop_by_hop()
                || matches!(
                    h.kind,
                    HeaderKind::Date | HeaderKind::Server | HeaderKind::Internal
                )
                || (!ops.is_empty() && ops.drops(name))
            {
                continue;
            }
            out.extend_from_slice(name);
            out.extend_from_slice(b": ");
            out.extend_from_slice(h.value.get(&self.ubuf.data));
            out.extend_from_slice(b"\r\n");
        }
        if matches!(mode, Mode::Chunked | Mode::Encode) {
            out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }
        out.extend_from_slice(&self.x.sticky_cookie);
        reply::connection(out, keep, &self.x.resp_extra);
        out.extend_from_slice(b"\r\n");
        self.ubuf.consume(self.resp.head_len);
        self.x.sent.status = status;
        // `out` holds the head; flushes count it with the body.
        self.x.sent.bytes = 0;
        let head_bytes = out.len() as u64;

        let complete = self.body_out(&mut up.stream, mode, read_timeout).await;
        self.x.sent.body_bytes = self.x.sent.bytes.saturating_sub(head_bytes);
        let Ok(complete) = complete else {
            return false;
        };
        if complete && self.resp.keep_alive && pool_ok && self.ubuf.end == 0 {
            pool.put(up);
        }
        keep
    }

    /// Writes `out` to the client and counts it.
    async fn flush(&mut self) -> Result<(), ()> {
        self.x.sent.bytes += self.out.len() as u64;
        let r = write_timeout(&mut self.client, &self.out, CLIENT_SEND)
            .await
            .map_err(|_| ());
        self.out.clear();
        r
    }

    /// Streams the response body. Returns whether the upstream connection is
    /// at a message boundary afterwards. `Err` means the client connection
    /// must close.
    async fn body_out(&mut self, up: &mut TcpStream, mode: Mode, t: Duration) -> Result<bool, ()> {
        let mut left = match mode {
            Mode::Length(n) => n,
            _ => 0,
        };
        let mut dec = ChunkedDecoder::new();
        loop {
            // Move what is buffered into `out`, framed for the client.
            let done = match mode {
                Mode::None => true,
                Mode::Length(_) => {
                    let take = left.min(self.ubuf.end as u64) as usize;
                    self.out.extend_from_slice(&self.ubuf.data[..take]);
                    self.ubuf.consume(take);
                    left -= take as u64;
                    left == 0
                }
                Mode::Chunked | Mode::Dechunk => {
                    let data = &self.ubuf.data[..self.ubuf.end];
                    let out = &mut self.out;
                    let take = if mode == Mode::Chunked {
                        dec.advance(data)
                    } else {
                        dec.advance_with(data, |r| out.extend_from_slice(&data[r]))
                    }
                    .map_err(|_| ())?;
                    if mode == Mode::Chunked {
                        self.out.extend_from_slice(&self.ubuf.data[..take]);
                    }
                    self.ubuf.consume(take);
                    dec.is_done()
                }
                Mode::Encode | Mode::Raw => {
                    let n = self.ubuf.end;
                    if n > 0 {
                        if mode == Mode::Encode {
                            push_hex(&mut self.out, n as u64);
                            self.out.extend_from_slice(b"\r\n");
                        }
                        self.out.extend_from_slice(&self.ubuf.data[..n]);
                        if mode == Mode::Encode {
                            self.out.extend_from_slice(b"\r\n");
                        }
                        self.ubuf.consume(n);
                    }
                    false
                }
            };
            if done || self.out.len() >= BODY_BUF {
                self.flush().await?;
            }
            if done {
                return Ok(true);
            }
            match read(up, &mut self.ubuf, BODY_BUF, t).await {
                Ok(0) if matches!(mode, Mode::Encode | Mode::Raw) => {
                    if mode == Mode::Encode {
                        self.out.extend_from_slice(b"0\r\n\r\n");
                    }
                    self.flush().await?;
                    return Ok(false);
                }
                // Truncated upstream response: nginx closes the client
                // connection so the client sees the truncation.
                Ok(0) | Err(_) => {
                    let _ = self.flush().await;
                    return Err(());
                }
                Ok(_) => {}
            }
        }
    }
}
