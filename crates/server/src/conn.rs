//! One client connection: read a request, route it, answer, repeat.
//!
//! Every buffer lives in [`Conn`] and is reused for the next request, so a warm
//! keepalive connection serves requests without allocating.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use proxelo_http1::{
    Body, ChunkedDecoder, Error as ParseError, Method, Response, parse_request, push_u64,
    request_line_complete,
};
use proxelo_snapshot::MatchError;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::buf::Buf;
use crate::exchange::Exchange;
use crate::phases::{Outcome, Phases};
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
}

/// nginx keeps the connection after an error page except for these.
pub(crate) fn keeps_alive(status: u16) -> bool {
    !matches!(status, 400 | 413 | 414 | 500 | 501)
}

pub(crate) async fn serve(server: Arc<Server>, listener: SocketAddr, client: TcpStream) {
    let _ = client.set_nodelay(true);
    let (Ok(local), Ok(peer)) = (client.local_addr(), client.peer_addr()) else {
        return;
    };
    let mut c = Conn {
        client,
        listener,
        served: false,
        buf: Buf::new(),
        ubuf: Buf::new(),
        resp: Response::default(),
        body: BodyLeft::None,
        out: Vec::new(),
        x: Exchange::new(local, peer),
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
            if self.buf.end > 0 && parse_request(self.buf.filled(), &mut self.x.req)? {
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
        if let Err(status) = self.x.begin() {
            return self.page(status).await;
        }
        // The listener was removed by a swap after this connection was
        // accepted. Its socket is closed; close the connection too.
        let Some(listener) = active.rt.listener(self.listener) else {
            return false;
        };
        let site = match listener.site(self.x.host()) {
            Ok(Some(site)) => site,
            Ok(None) => return self.page(404).await,
            Err(MatchError) => return self.page(500).await,
        };
        let mut phases = Phases::new(&active.rt.sites[site as usize], false);
        loop {
            return match phases.run(&mut self.x) {
                Outcome::Proxy(u) => {
                    // An error page made this a GET; its body is not sent on.
                    if self.x.as_get && self.pump_body(None).await.is_err() {
                        return false;
                    }
                    match self.proxy(&active.upstreams[u as usize]).await {
                        Ok(keep) => keep,
                        Err(status) => {
                            phases.fail(status);
                            continue;
                        }
                    }
                }
                Outcome::Text(status) => self.send_text(status).await,
                Outcome::Redirect(status) => self.send_redirect(status).await,
                Outcome::Page(status) => self.page(status).await,
                Outcome::File(f, m) => self.send_file(f, &m).await,
                Outcome::Directory => self.redirect_dir().await,
                Outcome::Close => false,
            };
        }
    }

    /// Answers `status` with the body in `tmpl`.
    async fn send_text(&mut self, status: u16) -> KeepAlive {
        let status = self.x.status(status);
        let keep = self.x.req.keep_alive;
        let out = &mut self.out;
        out.clear();
        reply::start(out, status, b"");
        if !self.x.tmpl.is_empty() {
            out.extend_from_slice(b"Content-Type: text/plain\r\n");
        }
        out.extend_from_slice(b"Content-Length: ");
        push_u64(out, self.x.tmpl.len() as u64);
        out.extend_from_slice(b"\r\n");
        reply::connection(out, keep);
        out.extend_from_slice(b"\r\n");
        if self.x.req.method != Method::Head {
            out.extend_from_slice(&self.x.tmpl);
        }
        self.respond(keep).await
    }

    /// Redirects to the Location in `tmpl`, made absolute with the request
    /// host and port when it is a path (nginx `absolute_redirect on`).
    async fn send_redirect(&mut self, status: u16) -> KeepAlive {
        let status = self.x.status(status);
        let keep = self.x.req.keep_alive && keeps_alive(status);
        let out = &mut self.out;
        out.clear();
        reply::start(out, status, b"");
        out.extend_from_slice(b"Location: ");
        if self.x.tmpl.starts_with(b"/") {
            reply::push_origin(out, &self.x.host, self.x.local);
        }
        reply::push_header_value(out, &self.x.tmpl);
        out.extend_from_slice(b"\r\n");
        reply::page(out, status, keep, self.x.req.method == Method::Head);
        self.respond(keep).await
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
        let keep = self.x.req.keep_alive && keeps_alive(status);
        self.out.clear();
        reply::start(&mut self.out, status, b"");
        reply::page(
            &mut self.out,
            status,
            keep,
            self.x.req.method == Method::Head,
        );
        self.respond(keep).await
    }
}
