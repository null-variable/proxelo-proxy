//! `proxy_pass` to an upstream over HTTP/1.1 with keepalive connections.

use std::io::Write as _;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use proxelo_http1::{Body, ChunkedDecoder, HeaderKind, Method, Version, parse_response, push_hex};
use proxelo_snapshot::{Balancing, Proxy, Route, Sticky};
use tokio::io::AsyncRead;
use tokio::time::timeout;

use crate::conn::{BodyLeft, Conn, Fail, KeepAlive, SEND_TIMEOUT as CLIENT_SEND, upstream_fail};
use crate::exchange::Exchange;
use crate::io::write_timeout;
use crate::upstream::{Choice, Conn as UpConn, ConnectError, State, UpStream};
use crate::{Active, compress, headers, reply};

/// `proxy_buffer_size`: the upstream response head must fit.
pub(crate) const HEAD_BUF: usize = 16 * 1024;
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

pub(crate) fn idempotent(m: Method) -> bool {
    !matches!(
        m,
        Method::Post | Method::Patch | Method::Connect | Method::Other
    )
}

pub(crate) async fn read<S: AsyncRead + Unpin>(
    s: &mut S,
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

/// A coder chosen before the head is written, built when the body starts.
enum PendingCoder {
    /// The encoding and the index of its settings in `x.compressions`.
    Encode(proxelo_snapshot::Encoding, u32),
    Gunzip,
}

impl PendingCoder {
    fn token(&self) -> &'static [u8] {
        match self {
            Self::Encode(e, _) => e.token(),
            Self::Gunzip => b"",
        }
    }

    fn into_coder(self, all: &[proxelo_snapshot::Compression]) -> std::io::Result<compress::Coder> {
        match self {
            Self::Encode(e, i) => compress::Coder::new(e, &all[i as usize]),
            Self::Gunzip => Ok(compress::Coder::gunzip()),
        }
    }
}

/// Puts the key of `up`'s hash methods in `x.tmpl`; empty for the others.
pub(crate) fn balancing_key(x: &mut Exchange, up: &proxelo_snapshot::Upstream) {
    x.tmpl.clear();
    match up.balancing {
        Balancing::IpHash => match x.peer.ip() {
            std::net::IpAddr::V4(a) => x.tmpl.extend_from_slice(&a.octets()[..3]),
            std::net::IpAddr::V6(a) => x.tmpl.extend_from_slice(&a.octets()),
        },
        Balancing::Hash | Balancing::HashConsistent => crate::vars::expand(x, &up.hash_key),
        _ => {}
    }
}

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
                None => match ups.connect(i, p.connect_timeout).await {
                    Ok(s) => UpConn {
                        stream: s,
                        used: 0,
                        opened: Instant::now(),
                    },
                    // Nothing was sent, so any request may move on.
                    Err(ConnectError::Failed) => {
                        ups.failed(i);
                        active.metrics.upstream_failure(p.upstream, i);
                        status = 502;
                        if !p.next.error {
                            break;
                        }
                        continue;
                    }
                    Err(ConnectError::TimedOut) => {
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
                    let (keep, complete) = self.relay(&mut up.stream, route, p.read_timeout).await;
                    if complete && self.resp.keep_alive && keep_up && self.ubuf.end == 0 {
                        pool.put(up);
                    }
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
    pub(crate) fn sticky(&mut self, active: &Active, upstream: u32) -> Option<usize> {
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
    pub(crate) fn balancing_key(&mut self, active: &Active, upstream: u32) {
        balancing_key(&mut self.x, &active.rt.upstreams[upstream as usize]);
    }

    /// Sets the sticky cookie naming target `i` unless the request already
    /// carries it.
    pub(crate) fn sticky_cookie(&mut self, active: &Active, upstream: u32, i: usize) {
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
    pub(crate) fn upstream_head(
        &mut self,
        target: SocketAddr,
        host: &str,
        keepalive: bool,
        route: &Route,
    ) {
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
        out.extend_from_slice(&self.x.auth_resp);
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
        up: &mut UpStream,
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
        self.pump_body(crate::conn::Sink::Upstream(up, p.send_timeout))
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

    /// Sends the upstream response head in `resp` and its body to the
    /// client. Returns whether the client connection stays and whether the
    /// upstream is at a message boundary afterwards.
    pub(crate) async fn relay<S: AsyncRead + Unpin>(
        &mut self,
        up: &mut S,
        route: &Route,
        read_timeout: Duration,
    ) -> (KeepAlive, bool) {
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
        // Compression or gunzip of the body changes its framing: it goes
        // out chunked to HTTP/1.1 clients and ends with the connection for
        // HTTP/1.0 ones.
        let (mut coder, vary) = self.response_coder(status, mode);
        let coded = coder.as_ref().map(|(_, gunzip)| *gunzip);
        let mode = match (coded, mode) {
            (None, m) => m,
            (Some(_), Mode::None) => Mode::None,
            (Some(_), m) => {
                if !compress::chunked_for(&self.x) {
                    keep = false;
                }
                m
            }
        };
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
            let value = h.value.get(&self.ubuf.data);
            if let Some(gunzip) = coded {
                if h.kind == HeaderKind::ContentLength
                    || name.eq_ignore_ascii_case(b"accept-ranges")
                    || (gunzip && name.eq_ignore_ascii_case(b"content-encoding"))
                {
                    continue;
                }
                if name.eq_ignore_ascii_case(b"etag") {
                    // nginx ngx_http_weak_etag.
                    let v = value.trim_ascii();
                    if v.starts_with(b"\"") {
                        out.extend_from_slice(name);
                        out.extend_from_slice(b": W/");
                        out.extend_from_slice(v);
                        out.extend_from_slice(b"\r\n");
                    } else if v.starts_with(b"W/") {
                        out.extend_from_slice(name);
                        out.extend_from_slice(b": ");
                        out.extend_from_slice(value);
                        out.extend_from_slice(b"\r\n");
                    }
                    continue;
                }
            }
            out.extend_from_slice(name);
            out.extend_from_slice(b": ");
            out.extend_from_slice(value);
            out.extend_from_slice(b"\r\n");
        }
        if vary {
            out.extend_from_slice(b"Vary: Accept-Encoding\r\n");
        }
        if let Some((k, false)) = &coder {
            out.extend_from_slice(b"Content-Encoding: ");
            out.extend_from_slice(k.token());
            out.extend_from_slice(b"\r\n");
        }
        let client_chunked = match coded {
            Some(_) => mode != Mode::None && compress::chunked_for(&self.x),
            None => matches!(mode, Mode::Chunked | Mode::Encode),
        };
        if client_chunked {
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

        let complete = match coder.take() {
            Some((k, _)) if mode != Mode::None => {
                let k = k.into_coder(&std::sync::Arc::clone(&self.x.compressions));
                self.body_coded(up, mode, read_timeout, k, client_chunked)
                    .await
            }
            _ => self.body_out(up, mode, read_timeout).await,
        };
        self.x.sent.body_bytes = self.x.sent.bytes.saturating_sub(head_bytes);
        match complete {
            Ok(complete) => (keep, complete),
            Err(()) => (false, false),
        }
    }

    /// The encoder for the upstream response, `(coder, gunzip)`, and whether
    /// Vary: Accept-Encoding is added, as nginx's gzip and gunzip header
    /// filters decide.
    fn response_coder(&self, status: u16, mode: Mode) -> (Option<(PendingCoder, bool)>, bool) {
        let Some(c) = self
            .x
            .compression
            .and_then(|i| self.x.compressions.get(i as usize))
        else {
            return (None, false);
        };
        let data = &self.ubuf.data;
        let get = |want: &[u8]| {
            self.resp
                .headers
                .iter()
                .find(|h| h.name.get(data).eq_ignore_ascii_case(want))
                .map(|h| h.value.get(data))
        };
        let encoding = get(b"content-encoding").unwrap_or_default();
        let mut vary = false;
        if !encoding.is_empty() {
            if compress::must_gunzip(&self.x, c, encoding) && mode != Mode::None {
                return (Some((PendingCoder::Gunzip, true)), c.vary);
            }
            // gunzip sets gzip_vary for any gzip response it looks at.
            return (
                None,
                c.gunzip && encoding.eq_ignore_ascii_case(b"gzip") && c.vary,
            );
        }
        let length = match mode {
            Mode::Length(n) => Some(n),
            Mode::None => Some(0),
            _ => None,
        };
        let facts = compress::RespFacts {
            status,
            content_type: get(b"content-type").unwrap_or_default(),
            length,
            encoded: false,
            expires: get(b"expires"),
            cache_control: get(b"cache-control"),
            last_modified: get(b"last-modified").is_some(),
            etag: get(b"etag").is_some(),
        };
        let enc = compress::choose(&self.x, c, &facts, &mut vary);
        // HEAD responses and empty bodies carry the encoding headers too.
        let i = self.x.compression.unwrap_or(0);
        (enc.map(|e| (PendingCoder::Encode(e, i), false)), vary)
    }

    /// Streams the response body through an encoder or decoder. The
    /// upstream framing is removed first; the result goes out chunked when
    /// `chunked`, raw otherwise (the connection then ends with it).
    async fn body_coded<S: AsyncRead + Unpin>(
        &mut self,
        up: &mut S,
        mode: Mode,
        t: Duration,
        coder: std::io::Result<compress::Coder>,
        chunked: bool,
    ) -> Result<bool, ()> {
        let mut coder = coder.map_err(|_| ())?;
        let mut left = match mode {
            Mode::Length(n) => n,
            _ => 0,
        };
        let mut dec = ChunkedDecoder::new();
        let mut plain = std::mem::take(&mut self.zin);
        let mut coded = std::mem::take(&mut self.zout);
        let result = loop {
            plain.clear();
            let done = match mode {
                Mode::None => true,
                Mode::Length(_) => {
                    let take = left.min(self.ubuf.end as u64) as usize;
                    plain.extend_from_slice(&self.ubuf.data[..take]);
                    self.ubuf.consume(take);
                    left -= take as u64;
                    left == 0
                }
                Mode::Chunked | Mode::Dechunk => {
                    let data = &self.ubuf.data[..self.ubuf.end];
                    let Ok(take) = dec.advance_with(data, |r| plain.extend_from_slice(&data[r]))
                    else {
                        break Err(());
                    };
                    self.ubuf.consume(take);
                    dec.is_done()
                }
                Mode::Encode | Mode::Raw => {
                    plain.extend_from_slice(self.ubuf.filled());
                    self.ubuf.end = 0;
                    false
                }
            };
            coded.clear();
            if coder.write(&plain, &mut coded).is_err() {
                break Err(());
            }
            if chunked {
                compress::push_chunk(&mut self.out, &coded);
            } else {
                self.out.extend_from_slice(&coded);
            }
            if done {
                break Ok(true);
            }
            if self.out.len() >= BODY_BUF && self.flush().await.is_err() {
                break Err(());
            }
            match read(up, &mut self.ubuf, BODY_BUF, t).await {
                Ok(0) if matches!(mode, Mode::Encode | Mode::Raw) => break Ok(false),
                Ok(0) | Err(_) => {
                    let _ = self.flush().await;
                    break Err(());
                }
                Ok(_) => {}
            }
        };
        let result = match result {
            Ok(complete) => {
                coded.clear();
                if coder.finish(&mut coded).is_err() {
                    Err(())
                } else {
                    if chunked {
                        compress::push_chunk(&mut self.out, &coded);
                        self.out.extend_from_slice(b"0\r\n\r\n");
                    } else {
                        self.out.extend_from_slice(&coded);
                    }
                    self.flush().await.map(|()| complete)
                }
            }
            Err(()) => Err(()),
        };
        self.zin = plain;
        self.zout = coded;
        result
    }

    /// Writes `out` to the client and counts it.
    pub(crate) async fn flush(&mut self) -> Result<(), ()> {
        self.x.sent.bytes += self.out.len() as u64;
        let r = write_timeout(&mut self.client, &self.out, CLIENT_SEND)
            .await
            .map_err(|_| ());
        if let Some(b) = self.x.bandwidth {
            let before = self.x.paced;
            self.x.paced += self.out.len() as u64;
            crate::static_file::throttle(b, before, self.x.paced, self.x.started).await;
        }
        self.out.clear();
        r
    }

    /// Streams the response body. Returns whether the upstream connection is
    /// at a message boundary afterwards. `Err` means the client connection
    /// must close.
    async fn body_out<S: AsyncRead + Unpin>(
        &mut self,
        up: &mut S,
        mode: Mode,
        t: Duration,
    ) -> Result<bool, ()> {
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
            // Throttled responses read at most a second's worth at a time.
            let max = match self.x.bandwidth {
                Some(b) if self.x.paced >= b.after => {
                    (b.rate as usize).clamp(HEAD_BUF.min(BODY_BUF), BODY_BUF)
                }
                _ => BODY_BUF,
            };
            match read(up, &mut self.ubuf, max, t).await {
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
