//! One client connection: read a request, route it, answer, repeat.
//!
//! Every buffer lives in [`Conn`] and is reused for the next request, so a warm
//! keepalive connection serves requests without allocating.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use proxelo_http1::{
    Body, ChunkedDecoder, Error as ParseError, Method, Request, Response, normalize_path,
    parse_request, request_line_complete,
};
use proxelo_snapshot::{Action, MatchError};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::buf::Buf;
use crate::static_file::Static;
use crate::{Active, Server, reply};

// nginx defaults.
const CLIENT_HEADER_TIMEOUT: Duration = Duration::from_secs(60);
const CLIENT_BODY_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const SEND_TIMEOUT: Duration = Duration::from_secs(60);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(75);
/// `client_header_buffer_size`, growing up to `large_client_header_buffers`.
const HEADER_BUF: usize = 1024;
const MAX_HEADER: usize = 32 * 1024;
/// `client_max_body_size`.
pub(crate) const MAX_BODY: u64 = 1024 * 1024;
/// Internal redirects (index files) per request before answering 500.
const MAX_REDIRECTS: usize = 10;

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

pub(crate) async fn write_timeout(s: &mut TcpStream, data: &[u8], t: Duration) -> io::Result<()> {
    match timeout(t, s.write_all(data)).await {
        Ok(r) => r,
        Err(_) => Err(io::ErrorKind::TimedOut.into()),
    }
}

/// Whether the client connection stays open for another request.
pub(crate) type KeepAlive = bool;

pub(crate) struct Conn {
    pub client: TcpStream,
    pub local: SocketAddr,
    /// Address of the socket that accepted the connection.
    listener: SocketAddr,
    served: bool,
    pub buf: Buf,
    pub ubuf: Buf,
    /// The current request head, copied out of `buf` so pipelined bytes can
    /// move up while the request is handled.
    pub head: Vec<u8>,
    pub req: Request,
    pub resp: Response,
    pub body: BodyLeft,
    pub out: Vec<u8>,
    /// Lowercase host without port, empty when the request has none.
    pub host: Vec<u8>,
    /// Decoded, normalized path.
    pub path: Vec<u8>,
    /// Query string without `?`.
    pub args: Vec<u8>,
    pub scratch: Vec<u8>,
}

/// nginx keeps the connection after an error page except for these.
fn keeps_alive(status: u16) -> bool {
    !matches!(status, 400 | 413 | 414 | 500 | 501)
}

/// Lowercases `raw` into `out` without the port and a trailing dot.
fn host_key(raw: &[u8], out: &mut Vec<u8>) {
    let end = if raw.first() == Some(&b'[') {
        raw.iter()
            .position(|&c| c == b']')
            .map_or(raw.len(), |i| i + 1)
    } else {
        raw.iter().position(|&c| c == b':').unwrap_or(raw.len())
    };
    let h = &raw[..end];
    let h = h.strip_suffix(b".").unwrap_or(h);
    out.clear();
    out.extend(h.iter().map(u8::to_ascii_lowercase));
}

pub(crate) async fn serve(server: Arc<Server>, listener: SocketAddr, client: TcpStream) {
    let _ = client.set_nodelay(true);
    let Ok(local) = client.local_addr() else {
        return;
    };
    let mut c = Conn {
        client,
        local,
        listener,
        served: false,
        buf: Buf::new(),
        ubuf: Buf::new(),
        head: Vec::new(),
        req: Request::default(),
        resp: Response::default(),
        body: BodyLeft::None,
        out: Vec::new(),
        host: Vec::new(),
        path: Vec::new(),
        args: Vec::new(),
        scratch: Vec::new(),
    };
    loop {
        match c.read_head().await {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => {
                c.error(e.status()).await;
                return;
            }
        }
        let active = server.active.load_full();
        if !c.handle(&active).await {
            return;
        }
        c.served = true;
    }
}

impl Conn {
    /// Reads until a full request head is buffered. `Ok(false)` means the
    /// connection ended or timed out; nginx closes silently then.
    async fn read_head(&mut self) -> Result<bool, ParseError> {
        loop {
            if self.buf.end > 0 && parse_request(self.buf.filled(), &mut self.req)? {
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
            match timeout(
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
        reply::page(&mut self.out, status, false, false);
        let _ = write_timeout(&mut self.client, &self.out, SEND_TIMEOUT).await;
    }

    async fn handle(&mut self, active: &Active) -> KeepAlive {
        let head_len = self.req.head_len;
        self.head.clear();
        self.head.extend_from_slice(&self.buf.data[..head_len]);
        self.buf.consume(head_len);
        self.body = match self.req.body {
            Body::Length(n) => BodyLeft::Length(n),
            Body::Chunked => BodyLeft::Chunked(ChunkedDecoder::new(), 0),
            Body::None | Body::Close => BodyLeft::None,
        };

        if let Body::Length(n) = self.req.body
            && n > MAX_BODY
        {
            return self.page(413).await;
        }
        match self.req.host {
            Some(h) => host_key(h.get(&self.head), &mut self.host),
            None => self.host.clear(),
        }
        if normalize_path(self.req.path.get(&self.head), &mut self.path).is_err() {
            return self.page(400).await;
        }
        self.args.clear();
        let target = self.req.target.get(&self.head);
        if let Some(q) = target.iter().position(|&c| c == b'?') {
            self.args.extend_from_slice(&target[q + 1..]);
        }

        let host = (!self.host.is_empty()).then_some(&self.host[..]);
        // The listener was removed by a swap after this connection was
        // accepted. Its socket is closed; close the connection too.
        let Some(listener) = active.rt.listener(self.listener) else {
            return false;
        };
        let site = match listener.site(host) {
            Ok(Some(site)) => site,
            Ok(None) => return self.page(404).await,
            Err(MatchError) => return self.page(500).await,
        };
        let site = &active.rt.sites[site as usize];
        let mut redirected = false;
        for _ in 0..=MAX_REDIRECTS {
            let route = match site.route(&self.path) {
                Ok(Some(route)) => route,
                Ok(None) => return self.page(404).await,
                Err(MatchError) => return self.page(500).await,
            };
            match &site.routes[route as usize].action {
                Action::Static { root, index } => {
                    if !matches!(self.req.method, Method::Get | Method::Head) {
                        return self.page(405).await;
                    }
                    match self.resolve_static(root, index) {
                        Static::Index => redirected = true,
                        Static::File(f, m) => return self.send_file(f, &m).await,
                        Static::Directory => return self.redirect_dir().await,
                        Static::Status(s) => return self.page(s).await,
                    }
                }
                Action::Proxy { upstream } => {
                    return self
                        .proxy(&active.upstreams[*upstream as usize], redirected)
                        .await;
                }
            }
        }
        self.page(500).await
    }

    /// Reads the rest of the request body. With `up` the bytes are forwarded
    /// as framed and `client_max_body_size` applies; without it they are
    /// discarded.
    pub async fn pump_body(&mut self, mut up: Option<&mut TcpStream>) -> Result<(), Fail> {
        loop {
            if matches!(self.body, BodyLeft::None) {
                return Ok(());
            }
            if self.buf.end == 0 {
                match timeout(
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
                    let take = dec
                        .advance_with(self.buf.filled(), |r| data += r.len() as u64)
                        .map_err(|_| Fail::BadBody)?;
                    *total += data;
                    if up.is_some() && *total > MAX_BODY {
                        return Err(Fail::TooLarge);
                    }
                    (take, dec.is_done())
                }
            };
            if let Some(u) = up.as_deref_mut() {
                write_timeout(u, &self.buf.data[..take], crate::proxy::SEND_TIMEOUT)
                    .await
                    .map_err(upstream_fail)?;
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
        if keep && self.pump_body(None).await.is_err() {
            return false;
        }
        write_timeout(&mut self.client, &self.out, SEND_TIMEOUT)
            .await
            .is_ok()
            && keep
    }

    pub async fn page(&mut self, status: u16) -> KeepAlive {
        let keep = self.req.keep_alive && keeps_alive(status);
        self.out.clear();
        reply::start(&mut self.out, status, b"");
        reply::page(&mut self.out, status, keep, self.req.method == Method::Head);
        self.respond(keep).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_keys() {
        let mut out = Vec::new();
        for (raw, want) in [
            (&b"Example.COM"[..], &b"example.com"[..]),
            (b"example.com:8080", b"example.com"),
            (b"example.com.", b"example.com"),
            (b"[::1]:80", b"[::1]"),
        ] {
            host_key(raw, &mut out);
            assert_eq!(out, want);
        }
    }
}
