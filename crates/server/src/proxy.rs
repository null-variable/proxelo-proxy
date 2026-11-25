//! `proxy_pass` to an upstream over HTTP/1.1 with keepalive connections.

use std::io::Write as _;
use std::net::SocketAddr;
use std::time::Duration;

use proxelo_http1::{Body, ChunkedDecoder, HeaderKind, Method, Version, parse_response, push_hex};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::conn::{
    BodyLeft, Conn, Fail, KeepAlive, SEND_TIMEOUT as CLIENT_SEND, upstream_fail, write_timeout,
};
use crate::reply;
use crate::upstream::{self, Pool};

// nginx defaults.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const SEND_TIMEOUT: Duration = Duration::from_secs(60);
const READ_TIMEOUT: Duration = Duration::from_secs(60);
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

async fn read(s: &mut TcpStream, buf: &mut crate::buf::Buf, max: usize) -> Result<usize, Fail> {
    match timeout(READ_TIMEOUT, buf.fill(s, HEAD_BUF, max)).await {
        Ok(Ok(n)) => Ok(n),
        Ok(Err(e)) => Err(upstream_fail(e)),
        Err(_) => Err(Fail::UpstreamTimeout),
    }
}

impl Conn {
    /// Proxies the request. `Err` carries the 502 or 504 to answer, which an
    /// error page may replace.
    pub async fn proxy(&mut self, ups: &upstream::State) -> Result<KeepAlive, u16> {
        // After the request went out, a retry is only safe when it can be
        // replayed: no body and a method that tolerates repetition
        // (`proxy_next_upstream error timeout` without `non_idempotent`).
        let replayable =
            (self.x.req.body == Body::None || self.x.as_get) && idempotent(self.x.req.method);
        let mut tried = 0u64;
        let mut status = 502;
        while let Some(i) = ups.pick(tried) {
            if i < 64 {
                tried |= 1 << i;
            }
            let pool = &ups.pools()[i];
            let (mut up, reused) = match pool.take() {
                Some(s) => (s, true),
                None => match timeout(CONNECT_TIMEOUT, TcpStream::connect(pool.addr)).await {
                    Ok(Ok(s)) => {
                        let _ = s.set_nodelay(true);
                        (s, false)
                    }
                    // Nothing was sent, so any request may move on.
                    Ok(Err(_)) => {
                        status = 502;
                        continue;
                    }
                    Err(_) => {
                        status = 504;
                        continue;
                    }
                },
            };
            self.upstream_head(pool.addr, ups.keepalive);
            match self.exchange(&mut up).await {
                Ok(()) => return Ok(self.relay(up, pool, ups.keepalive).await),
                Err(Fail::Client) => return Ok(false),
                Err(Fail::BadBody) => {
                    self.x.req.keep_alive = false;
                    return Ok(self.page(400).await);
                }
                Err(Fail::TooLarge) => {
                    self.x.req.keep_alive = false;
                    return Ok(self.page(413).await);
                }
                Err(f) => {
                    status = if matches!(f, Fail::UpstreamTimeout) {
                        504
                    } else {
                        502
                    };
                    if !replayable {
                        break;
                    }
                    // A pooled connection the upstream closed while idle says
                    // nothing about the target; allow it again on a fresh one.
                    if reused && matches!(f, Fail::Upstream) && i < 64 {
                        tried &= !(1 << i);
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

    /// Builds the upstream request head into `out`: the original target, or
    /// the changed URI after a rewrite or internal redirect, as `proxy_pass`
    /// without a URI part does.
    fn upstream_head(&mut self, target: SocketAddr, keepalive: bool) {
        let out = &mut self.out;
        out.clear();
        if self.x.as_get {
            out.extend_from_slice(b"GET");
        } else {
            out.extend_from_slice(self.x.req.method_span.get(&self.x.head));
        }
        out.push(b' ');
        if self.x.uri_changed {
            reply::push_uri_path(out, &self.x.path);
            if !self.x.args.is_empty() {
                out.push(b'?');
                out.extend_from_slice(&self.x.args);
            }
        } else {
            out.extend_from_slice(self.x.req.target.get(&self.x.head));
        }
        out.extend_from_slice(b" HTTP/1.1\r\n");
        let mut has_host = false;
        for h in self.x.req.headers.iter() {
            // Expect is answered here, not by the upstream. A request an
            // error page turned into a GET has no body any more.
            if h.kind.is_hop_by_hop()
                || h.kind == HeaderKind::Expect
                || (self.x.as_get && h.kind == HeaderKind::ContentLength)
            {
                continue;
            }
            has_host |= h.kind == HeaderKind::Host;
            out.extend_from_slice(h.name.get(&self.x.head));
            out.extend_from_slice(b": ");
            out.extend_from_slice(h.value.get(&self.x.head));
            out.extend_from_slice(b"\r\n");
        }
        if !has_host {
            _ = write!(out, "Host: {target}\r\n");
        }
        if self.x.req.body == Body::Chunked && !self.x.as_get {
            out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }
        if !keepalive {
            out.extend_from_slice(b"Connection: close\r\n");
        }
        out.extend_from_slice(b"\r\n");
    }

    /// Sends the head in `out` and the body, then reads the response head
    /// into `resp`, skipping interim responses.
    async fn exchange(&mut self, up: &mut TcpStream) -> Result<(), Fail> {
        write_timeout(up, &self.out, SEND_TIMEOUT)
            .await
            .map_err(upstream_fail)?;
        if self.x.req.expect_continue && !matches!(self.body, BodyLeft::None) && self.buf.end == 0 {
            write_timeout(
                &mut self.client,
                b"HTTP/1.1 100 Continue\r\n\r\n",
                CLIENT_SEND,
            )
            .await
            .map_err(|_| Fail::Client)?;
            self.x.req.expect_continue = false;
        }
        self.pump_body(Some(up)).await?;

        let head = self.x.req.method == Method::Head;
        self.ubuf.end = 0;
        loop {
            if self.ubuf.end > 0
                && parse_response(self.ubuf.filled(), head, &mut self.resp)
                    .map_err(|_| Fail::Upstream)?
            {
                // Upgrade is never requested, so 101 is a protocol error.
                if self.resp.status == 101 {
                    return Err(Fail::Upstream);
                }
                if self.resp.status >= 200 {
                    return Ok(());
                }
                self.ubuf.consume(self.resp.head_len);
                continue;
            }
            if self.ubuf.end >= HEAD_BUF {
                return Err(Fail::Upstream);
            }
            if read(up, &mut self.ubuf, HEAD_BUF).await? == 0 {
                return Err(Fail::Upstream);
            }
        }
    }

    /// Sends the upstream response to the client and pools the upstream
    /// connection when it is reusable.
    async fn relay(&mut self, mut up: TcpStream, pool: &Pool, pool_ok: bool) -> KeepAlive {
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
            if h.kind.is_hop_by_hop()
                || matches!(
                    h.kind,
                    HeaderKind::Date | HeaderKind::Server | HeaderKind::Internal
                )
            {
                continue;
            }
            out.extend_from_slice(h.name.get(&self.ubuf.data));
            out.extend_from_slice(b": ");
            out.extend_from_slice(h.value.get(&self.ubuf.data));
            out.extend_from_slice(b"\r\n");
        }
        if matches!(mode, Mode::Chunked | Mode::Encode) {
            out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }
        reply::connection(out, keep);
        out.extend_from_slice(b"\r\n");
        self.ubuf.consume(self.resp.head_len);

        let complete = match self.body_out(&mut up, mode).await {
            Ok(c) => c,
            Err(()) => return false,
        };
        if complete && self.resp.keep_alive && pool_ok && self.ubuf.end == 0 {
            pool.put(up);
        }
        keep
    }

    /// Streams the response body. Returns whether the upstream connection is
    /// at a message boundary afterwards. `Err` means the client connection
    /// must close.
    async fn body_out(&mut self, up: &mut TcpStream, mode: Mode) -> Result<bool, ()> {
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
                write_timeout(&mut self.client, &self.out, CLIENT_SEND)
                    .await
                    .map_err(|_| ())?;
                self.out.clear();
            }
            if done {
                return Ok(true);
            }
            match read(up, &mut self.ubuf, BODY_BUF).await {
                Ok(0) if matches!(mode, Mode::Encode | Mode::Raw) => {
                    if mode == Mode::Encode {
                        self.out.extend_from_slice(b"0\r\n\r\n");
                    }
                    write_timeout(&mut self.client, &self.out, CLIENT_SEND)
                        .await
                        .map_err(|_| ())?;
                    self.out.clear();
                    return Ok(false);
                }
                // Truncated upstream response: nginx closes the client
                // connection so the client sees the truncation.
                Ok(0) | Err(_) => {
                    let _ = write_timeout(&mut self.client, &self.out, CLIENT_SEND).await;
                    return Err(());
                }
                Ok(_) => {}
            }
        }
    }
}
