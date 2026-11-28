//! Application server protocols: FastCGI, uwsgi and SCGI (nginx
//! fastcgi_pass, uwsgi_pass, scgi_pass) and memcached lookups
//! (memcached_pass).
//!
//! The request body is read in full first, as nginx buffers it for these
//! modules, so a failed attempt can be replayed and CONTENT_LENGTH is
//! known. The response is turned into an HTTP/1.1 head in `ubuf` and then
//! sent like a proxied one, so header operations, compression and limits
//! apply alike.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use proxelo_http1::{HeaderKind, Method, parse_response, push_u64};
use proxelo_snapshot::{Gateway, GatewayProtocol, Memcached, Proxy, Route};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::conn::{BodyLeft, CLIENT_BODY_TIMEOUT, Conn, Fail, KeepAlive, Sink, upstream_fail};
use crate::io::write_timeout;
use crate::proxy::{HEAD_BUF, idempotent, read};
use crate::upstream::{Choice, Picked};
use crate::vars::expand;
use crate::{Active, reply};

const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;
/// Content bytes per record, as nginx writes them.
const FCGI_RECORD: usize = 32 * 1024;

/// The response stream of an attempt: the socket, or the FastCGI stdout
/// records read from it.
enum Up<'a> {
    Plain(&'a mut TcpStream),
    Fcgi(Fcgi<'a>),
}

/// Yields the content of FCGI_STDOUT records and ends at FCGI_END_REQUEST;
/// other records, such as stderr, are skipped.
struct Fcgi<'a> {
    s: &'a mut TcpStream,
    hdr: [u8; 8],
    have: usize,
    left: usize,
    pad: usize,
    stdout: bool,
    done: bool,
}

impl AsyncRead for Up<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Up::Plain(s) => Pin::new(&mut **s).poll_read(cx, buf),
            Up::Fcgi(f) => f.poll_read(cx, buf),
        }
    }
}

fn eof() -> io::Error {
    io::ErrorKind::UnexpectedEof.into()
}

impl Fcgi<'_> {
    fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.done || buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if self.left > 0 && self.stdout {
                let n = self.left.min(buf.remaining());
                let mut part = ReadBuf::new(buf.initialize_unfilled_to(n));
                ready!(Pin::new(&mut *self.s).poll_read(cx, &mut part))?;
                let k = part.filled().len();
                if k == 0 {
                    return Poll::Ready(Err(eof()));
                }
                buf.advance(k);
                self.left -= k;
                return Poll::Ready(Ok(()));
            }
            if self.left > 0 || self.pad > 0 {
                let mut skip = [0u8; 512];
                let want = if self.left > 0 { self.left } else { self.pad };
                let mut part = ReadBuf::new(&mut skip[..want.min(512)]);
                ready!(Pin::new(&mut *self.s).poll_read(cx, &mut part))?;
                let k = part.filled().len();
                if k == 0 {
                    return Poll::Ready(Err(eof()));
                }
                if self.left > 0 {
                    self.left -= k;
                } else {
                    self.pad -= k;
                }
                continue;
            }
            let mut part = ReadBuf::new(&mut self.hdr[self.have..]);
            ready!(Pin::new(&mut *self.s).poll_read(cx, &mut part))?;
            let k = part.filled().len();
            if k == 0 {
                return Poll::Ready(Err(eof()));
            }
            self.have += k;
            if self.have == 8 {
                self.have = 0;
                let h = self.hdr;
                if h[0] != 1 {
                    return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                }
                self.left = usize::from(u16::from_be_bytes([h[4], h[5]]));
                self.pad = usize::from(h[6]);
                self.stdout = h[1] == FCGI_STDOUT;
                self.done = h[1] == FCGI_END_REQUEST;
            }
        }
    }
}

fn fcgi_record(out: &mut Vec<u8>, kind: u8, content: &[u8]) {
    let pad = (8 - content.len() % 8) % 8;
    let len = content.len() as u16;
    out.extend_from_slice(&[1, kind, 0, 1]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&[pad as u8, 0]);
    out.extend_from_slice(content);
    out.extend_from_slice(&[0; 8][..pad]);
}

fn fcgi_stream(out: &mut Vec<u8>, kind: u8, data: &[u8]) {
    for part in data.chunks(FCGI_RECORD) {
        fcgi_record(out, kind, part);
    }
    fcgi_record(out, kind, b"");
}

fn fcgi_len(out: &mut Vec<u8>, n: usize) {
    if n < 128 {
        out.push(n as u8);
    } else {
        out.extend_from_slice(&(n as u32 | 0x8000_0000).to_be_bytes());
    }
}

/// Appends one name-value pair in the protocol's encoding. `false` when it
/// does not fit (uwsgi lengths are 16 bits).
fn pair(proto: GatewayProtocol, out: &mut Vec<u8>, name: &[u8], value: &[u8]) -> bool {
    match proto {
        GatewayProtocol::FastCgi => {
            fcgi_len(out, name.len());
            fcgi_len(out, value.len());
            out.extend_from_slice(name);
            out.extend_from_slice(value);
        }
        GatewayProtocol::Scgi => {
            out.extend_from_slice(name);
            out.push(0);
            out.extend_from_slice(value);
            out.push(0);
        }
        GatewayProtocol::Uwsgi => {
            let (Ok(n), Ok(v)) = (u16::try_from(name.len()), u16::try_from(value.len())) else {
                return false;
            };
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(name);
            out.extend_from_slice(&v.to_le_bytes());
            out.extend_from_slice(value);
        }
    }
    true
}

/// The end of a CGI or HTTP response head, after its empty line; lines may
/// end in LF alone.
fn head_end(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    while let Some(n) = buf[i..].iter().position(|&c| c == b'\n') {
        let line = &buf[i..i + n];
        i += n + 1;
        if line.is_empty() || line == b"\r" {
            return Some(i);
        }
    }
    None
}

/// Rewrites the CGI or HTTP head `raw` as an HTTP/1.1 head with CRLF line
/// ends: a Status header gives the status, a Location without one 302,
/// otherwise 200 (RFC 3875 §6.2).
fn normalize_head(raw: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
    let mut lines = raw
        .split(|&c| c == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .filter(|l| !l.is_empty());
    out.clear();
    let mut first = lines.clone();
    if first.next().is_some_and(|l| l.starts_with(b"HTTP/")) {
        out.extend_from_slice(lines.next().unwrap_or_default());
        out.extend_from_slice(b"\r\n");
    } else {
        let mut status = None;
        let mut location = false;
        for l in lines.clone() {
            let (name, value) = header(l)?;
            if name.eq_ignore_ascii_case(b"status") {
                status = Some(value);
            } else if name.eq_ignore_ascii_case(b"location") {
                location = true;
            }
        }
        match status {
            Some(v) => {
                if v.len() < 3 || !v[..3].iter().all(u8::is_ascii_digit) {
                    return Err(());
                }
                out.extend_from_slice(b"HTTP/1.1 ");
                out.extend_from_slice(v);
            }
            None if location => out.extend_from_slice(b"HTTP/1.1 302 Moved Temporarily"),
            None => out.extend_from_slice(b"HTTP/1.1 200 OK"),
        }
        out.extend_from_slice(b"\r\n");
    }
    for l in lines {
        let (name, _) = header(l)?;
        if name.eq_ignore_ascii_case(b"status") {
            continue;
        }
        out.extend_from_slice(l);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Ok(())
}

fn header(l: &[u8]) -> Result<(&[u8], &[u8]), ()> {
    let colon = l.iter().position(|&c| c == b':').ok_or(())?;
    Ok((&l[..colon], l[colon + 1..].trim_ascii()))
}

/// nginx NGX_ESCAPE_MEMCACHED: controls, space and `%`.
fn push_memcached_key(out: &mut Vec<u8>, key: &[u8]) {
    for &c in key {
        if c <= 0x20 || c == b'%' {
            out.push(b'%');
            out.push(b"0123456789ABCDEF"[usize::from(c >> 4)]);
            out.push(b"0123456789ABCDEF"[usize::from(c & 15)]);
        } else {
            out.push(c);
        }
    }
}

impl Conn {
    /// Reads the request body into `gw_body`. `Some` when the request was
    /// answered instead.
    pub(crate) async fn read_body(&mut self) -> Option<KeepAlive> {
        self.gw_body.clear();
        if self.x.req.expect_continue && !matches!(self.body, BodyLeft::None) && self.buf.end == 0 {
            if write_timeout(
                &mut self.client,
                b"HTTP/1.1 100 Continue\r\n\r\n",
                CLIENT_BODY_TIMEOUT,
            )
            .await
            .is_err()
            {
                return Some(false);
            }
            self.x.req.expect_continue = false;
        }
        let mut body = std::mem::take(&mut self.gw_body);
        let r = self.pump_body(Sink::Collect(&mut body)).await;
        // nginx sets $content_length for a chunked body once it is read;
        // without a body it stays empty.
        if matches!(self.x.req.body, proxelo_http1::Body::Chunked) {
            self.x.body_len = Some(body.len() as u64);
        }
        self.gw_body = body;
        match r {
            Ok(()) => None,
            Err(Fail::BadBody) => {
                self.x.req.keep_alive = false;
                Some(self.page(400).await)
            }
            Err(Fail::TooLarge) => {
                self.x.req.keep_alive = false;
                Some(self.page(413).await)
            }
            Err(_) => Some(false),
        }
    }

    /// Picks a target and connects to it, moving on to the next target as
    /// `p` allows. `Err` carries the status to answer.
    async fn connect<'a>(
        &mut self,
        active: &'a Active,
        p: &Proxy,
        choice: &mut Choice,
        tries: &mut u32,
        mut status: u16,
    ) -> Result<(Picked<'a>, TcpStream, Instant), u16> {
        let ups = &active.upstreams[p.upstream as usize];
        let mut queue_deadline = None;
        loop {
            if p.tries != 0 && *tries >= p.tries {
                return Err(status);
            }
            let Some(picked) = ups.pick(choice, &self.x.tmpl) else {
                if ups.full(choice.tried) {
                    let deadline = *queue_deadline.get_or_insert_with(|| ups.queue_deadline());
                    if ups.wait(Some(deadline)).await {
                        continue;
                    }
                }
                return Err(status);
            };
            *tries += 1;
            let i = picked.index;
            let addr = ups.pools()[i].addr;
            self.x.sent.upstream_addr = Some(addr);
            let started = Instant::now();
            match timeout(p.connect_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(s)) => {
                    let _ = s.set_nodelay(true);
                    self.x.sent.upstream_connect = Some(started.elapsed().as_secs_f64());
                    return Ok((picked, s, started));
                }
                Ok(Err(_)) => {
                    ups.failed(i);
                    active.metrics.upstream_failure(p.upstream, i);
                    status = 502;
                    if !p.next.error {
                        return Err(status);
                    }
                }
                Err(_) => {
                    ups.failed(i);
                    active.metrics.upstream_failure(p.upstream, i);
                    status = 504;
                    if !p.next.timeout {
                        return Err(status);
                    }
                }
            }
        }
    }

    /// Builds the request for `g` into `gw_buf` from the body in `gw_body`.
    /// `Err` carries the status to answer.
    fn gateway_request(&mut self, g: &Gateway) -> Result<(), u16> {
        let proto = g.protocol;
        // $document_root, $fastcgi_script_name and $fastcgi_path_info.
        self.x.doc_root.clear();
        self.x.doc_root.extend_from_slice(&g.document_root);
        let mut caps = std::mem::take(&mut self.x.gw_caps);
        let split = match &g.split_path_info {
            Some(re) => re.captures(&self.x.path, &mut caps).map_err(|_| 500u16)?,
            None => false,
        };
        self.x.script_name.clear();
        self.x.path_info.clear();
        if split {
            self.x
                .script_name
                .extend_from_slice(caps.get(1).unwrap_or_default());
            self.x
                .path_info
                .extend_from_slice(caps.get(2).unwrap_or_default());
        } else {
            self.x.script_name.extend_from_slice(&self.x.path);
        }
        self.x.gw_caps = caps;
        if self.x.script_name.ends_with(b"/") {
            self.x.script_name.extend_from_slice(&g.index);
        }

        let mut params = std::mem::take(&mut self.out);
        params.clear();
        let mut fits = true;
        if proto == GatewayProtocol::Scgi {
            // SCGI requires CONTENT_LENGTH first.
            let mut n = Vec::with_capacity(20);
            push_u64(&mut n, self.gw_body.len() as u64);
            pair(proto, &mut params, b"CONTENT_LENGTH", &n);
        }
        for p in &g.params {
            expand(&mut self.x, &p.value);
            if p.if_not_empty && self.x.tmpl.is_empty() {
                continue;
            }
            fits &= pair(proto, &mut params, &p.name, &self.x.tmpl);
        }
        if g.pass_request_headers {
            let mut name = std::mem::take(&mut self.x.scratch);
            let mut value = std::mem::take(&mut self.x.tmpl);
            let headers = &self.x.req.headers;
            let head = &self.x.head;
            for (k, h) in headers.iter().enumerate() {
                let raw = h.name.get(head);
                // Repeated headers go out once, joined.
                if headers
                    .iter()
                    .take(k)
                    .any(|o| o.name.get(head).eq_ignore_ascii_case(raw))
                {
                    continue;
                }
                name.clear();
                name.extend_from_slice(b"HTTP_");
                name.extend(raw.iter().map(|&c| match c {
                    b'-' => b'_',
                    c => c.to_ascii_uppercase(),
                }));
                if g.params.iter().any(|p| *p.name == *name) {
                    continue;
                }
                let sep: &[u8] =
                    if h.kind == HeaderKind::Other && raw.eq_ignore_ascii_case(b"cookie") {
                        b"; "
                    } else {
                        b", "
                    };
                value.clear();
                for o in headers.iter().skip(k) {
                    if o.name.get(head).eq_ignore_ascii_case(raw) {
                        if !value.is_empty() {
                            value.extend_from_slice(sep);
                        }
                        value.extend_from_slice(o.value.get(head));
                    }
                }
                fits &= pair(proto, &mut params, &name, &value);
            }
            self.x.scratch = name;
            self.x.tmpl = value;
        }

        let out = &mut self.gw_buf;
        out.clear();
        let body = &self.gw_body;
        match proto {
            GatewayProtocol::FastCgi => {
                fcgi_record(out, FCGI_BEGIN_REQUEST, &[0, 1, 0, 0, 0, 0, 0, 0]);
                fcgi_stream(out, FCGI_PARAMS, &params);
                fcgi_stream(out, FCGI_STDIN, body);
            }
            GatewayProtocol::Scgi => {
                push_u64(out, params.len() as u64);
                out.push(b':');
                out.extend_from_slice(&params);
                out.push(b',');
                out.extend_from_slice(body);
            }
            GatewayProtocol::Uwsgi => match u16::try_from(params.len()) {
                Ok(n) => {
                    out.push(0);
                    out.extend_from_slice(&n.to_le_bytes());
                    out.push(0);
                    out.extend_from_slice(&params);
                    out.extend_from_slice(body);
                }
                Err(_) => fits = false,
            },
        }
        params.clear();
        self.out = params;
        // nginx: "uwsgi request is too big".
        if fits { Ok(()) } else { Err(500) }
    }

    /// Reads the response head of an attempt and leaves it in `ubuf` and
    /// `resp` as an HTTP/1.1 response.
    async fn gateway_head(&mut self, up: &mut Up<'_>, t: Duration) -> Result<(), Fail> {
        self.ubuf.end = 0;
        let end = loop {
            if let Some(end) = head_end(self.ubuf.filled()) {
                break end;
            }
            if self.ubuf.end >= HEAD_BUF || read(up, &mut self.ubuf, HEAD_BUF, t).await? == 0 {
                return Err(Fail::Upstream);
            }
        };
        let mut head = std::mem::take(&mut self.gw_body);
        let r = normalize_head(&self.ubuf.data[..end], &mut head);
        head.extend_from_slice(&self.ubuf.data[end..self.ubuf.end]);
        std::mem::swap(&mut self.ubuf.data, &mut head);
        self.ubuf.end = self.ubuf.data.len();
        self.gw_body = head;
        r.map_err(|()| Fail::Upstream)?;
        let is_head = self.x.req.method == Method::Head;
        match parse_response(self.ubuf.filled(), is_head, &mut self.resp) {
            Ok(true) => Ok(()),
            _ => Err(Fail::Upstream),
        }
    }

    /// FastCGI, uwsgi or SCGI. `Err` carries the status to answer, which an
    /// error page may replace.
    pub async fn gateway(
        &mut self,
        active: &Active,
        g: &Gateway,
        route: &Route,
    ) -> Result<KeepAlive, u16> {
        if let Some(keep) = self.read_body().await {
            return Ok(keep);
        }
        self.gateway_request(g)?;
        let p = &g.proxy;
        let ups = &active.upstreams[p.upstream as usize];
        let replayable = p.next.non_idempotent || idempotent(self.x.req.method);
        let mut choice = Choice {
            prefer: self.sticky(active, p.upstream),
            ..Default::default()
        };
        self.balancing_key(active, p.upstream);
        let mut tries = 0;
        let mut status = 502;
        loop {
            let (picked, mut stream, started) = self
                .connect(active, p, &mut choice, &mut tries, status)
                .await?;
            let i = picked.index;
            let last =
                !replayable || !ups.has_next(choice.tried) || (p.tries != 0 && tries >= p.tries);
            let sent = write_timeout(&mut stream, &self.gw_buf, p.send_timeout)
                .await
                .map_err(upstream_fail);
            let mut up = match g.protocol {
                GatewayProtocol::FastCgi => Up::Fcgi(Fcgi {
                    s: &mut stream,
                    hdr: [0; 8],
                    have: 0,
                    left: 0,
                    pad: 0,
                    stdout: false,
                    done: false,
                }),
                _ => Up::Plain(&mut stream),
            };
            let head = match sent {
                Ok(()) => self.gateway_head(&mut up, p.read_timeout).await,
                Err(f) => Err(f),
            };
            match head {
                Ok(()) => {
                    let st = self.resp.status;
                    self.x.sent.upstream_status = st;
                    self.x.sent.upstream_header = Some(started.elapsed().as_secs_f64());
                    let failure = p.next.on_status(st) && !matches!(st, 403 | 404);
                    if failure {
                        ups.failed(i);
                    } else {
                        ups.succeeded(i);
                    }
                    if !last && p.next.on_status(st) {
                        active
                            .metrics
                            .upstream_response(p.upstream, i, st, started.elapsed());
                        status = 502;
                        continue;
                    }
                    if self.intercepts(p, route, st) {
                        active
                            .metrics
                            .upstream_response(p.upstream, i, st, started.elapsed());
                        return Err(st);
                    }
                    self.sticky_cookie(active, p.upstream, i);
                    let (keep, _) = self.relay(&mut up, route, p.read_timeout).await;
                    self.x.sent.upstream_response = Some(started.elapsed().as_secs_f64());
                    active
                        .metrics
                        .upstream_response(p.upstream, i, st, started.elapsed());
                    return Ok(keep);
                }
                Err(f) => {
                    let timed_out = matches!(f, Fail::UpstreamTimeout);
                    status = if timed_out { 504 } else { 502 };
                    ups.failed(i);
                    active.metrics.upstream_failure(p.upstream, i);
                    let allowed = if timed_out {
                        p.next.timeout
                    } else {
                        p.next.error
                    };
                    if last || !allowed {
                        return Err(status);
                    }
                }
            }
        }
    }

    /// memcached_pass: GET and HEAD only; a missing key is 404.
    pub async fn memcached(
        &mut self,
        active: &Active,
        m: &Memcached,
        route: &Route,
    ) -> Result<KeepAlive, u16> {
        if !matches!(self.x.req.method, Method::Get | Method::Head) {
            return Err(405);
        }
        match &m.key {
            Some(t) => expand(&mut self.x, t),
            None => self.x.tmpl.clone_from(&self.x.path),
        }
        if self.x.tmpl.is_empty() {
            return Err(500);
        }
        let key = &mut self.gw_body;
        key.clear();
        push_memcached_key(key, &self.x.tmpl);
        let req = &mut self.gw_buf;
        req.clear();
        req.extend_from_slice(b"get ");
        req.extend_from_slice(key);
        req.extend_from_slice(b"\r\n");

        let p = &m.proxy;
        let ups = &active.upstreams[p.upstream as usize];
        let mut choice = Choice {
            prefer: self.sticky(active, p.upstream),
            ..Default::default()
        };
        self.balancing_key(active, p.upstream);
        let mut tries = 0;
        let mut status = 502;
        loop {
            let (picked, mut stream, started) = self
                .connect(active, p, &mut choice, &mut tries, status)
                .await?;
            let i = picked.index;
            let last = !ups.has_next(choice.tried) || (p.tries != 0 && tries >= p.tries);
            let r = match write_timeout(&mut stream, &self.gw_buf, p.send_timeout).await {
                Ok(()) => self.memcached_value(&mut stream, p.read_timeout).await,
                Err(e) => Err(upstream_fail(e)),
            };
            match r {
                Ok(found) => {
                    ups.succeeded(i);
                    self.x.sent.upstream_header = Some(started.elapsed().as_secs_f64());
                    let st = if found { 200 } else { 404 };
                    self.x.sent.upstream_status = st;
                    active
                        .metrics
                        .upstream_response(p.upstream, i, st, started.elapsed());
                    if !found {
                        return Err(404);
                    }
                    let (keep, _) = self
                        .relay(&mut tokio::io::empty(), route, p.read_timeout)
                        .await;
                    self.x.sent.upstream_response = Some(started.elapsed().as_secs_f64());
                    return Ok(keep);
                }
                Err(f) => {
                    let timed_out = matches!(f, Fail::UpstreamTimeout);
                    status = if timed_out { 504 } else { 502 };
                    ups.failed(i);
                    active.metrics.upstream_failure(p.upstream, i);
                    let allowed = if timed_out {
                        p.next.timeout
                    } else {
                        p.next.error
                    };
                    if last || !allowed {
                        return Err(status);
                    }
                }
            }
        }
    }

    /// Reads a `get` reply. On a hit the whole response is left in `ubuf`
    /// and `resp`; `false` means the key is missing.
    async fn memcached_value(&mut self, s: &mut TcpStream, t: Duration) -> Result<bool, Fail> {
        self.ubuf.end = 0;
        let line = loop {
            if let Some(n) = self.ubuf.filled().windows(2).position(|w| w == b"\r\n") {
                break n;
            }
            if self.ubuf.end >= HEAD_BUF || read(s, &mut self.ubuf, HEAD_BUF, t).await? == 0 {
                return Err(Fail::Upstream);
            }
        };
        let first = &self.ubuf.data[..line];
        if first == b"END" {
            return Ok(false);
        }
        // VALUE <key> <flags> <bytes>
        let mut f = first.split(|&c| c == b' ');
        let (Some(b"VALUE"), Some(key), Some(_flags), Some(len)) =
            (f.next(), f.next(), f.next(), f.next())
        else {
            return Err(Fail::Upstream);
        };
        if key != self.gw_body.as_slice() {
            return Err(Fail::Upstream);
        }
        let len: usize = std::str::from_utf8(len)
            .ok()
            .and_then(|l| l.parse().ok())
            .ok_or(Fail::Upstream)?;
        let start = line + 2;
        let need = start + len + b"\r\nEND\r\n".len();
        while self.ubuf.end < need {
            if read(s, &mut self.ubuf, need, t).await? == 0 {
                return Err(Fail::Upstream);
            }
        }
        if &self.ubuf.data[start + len..need] != b"\r\nEND\r\n" {
            return Err(Fail::Upstream);
        }
        let mut out = std::mem::take(&mut self.gw_body);
        out.clear();
        out.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: ");
        out.extend_from_slice(reply::mime(&self.x.path));
        out.extend_from_slice(b"\r\nContent-Length: ");
        push_u64(&mut out, len as u64);
        out.extend_from_slice(b"\r\n\r\n");
        out.extend_from_slice(&self.ubuf.data[start..start + len]);
        std::mem::swap(&mut self.ubuf.data, &mut out);
        self.ubuf.end = self.ubuf.data.len();
        self.gw_body = out;
        let is_head = self.x.req.method == Method::Head;
        match parse_response(self.ubuf.filled(), is_head, &mut self.resp) {
            Ok(true) => Ok(true),
            _ => Err(Fail::Upstream),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgi_heads() {
        let mut out = Vec::new();
        normalize_head(
            b"Status: 404 Not Found\nContent-Type: text/plain\n\n",
            &mut out,
        )
        .unwrap();
        assert_eq!(
            out,
            b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\n"
        );
        normalize_head(b"Location: /x\r\n\r\n", &mut out).unwrap();
        assert_eq!(
            out,
            b"HTTP/1.1 302 Moved Temporarily\r\nLocation: /x\r\n\r\n"
        );
        normalize_head(b"X: 1\r\n\r\n", &mut out).unwrap();
        assert_eq!(out, b"HTTP/1.1 200 OK\r\nX: 1\r\n\r\n");
        normalize_head(b"HTTP/1.0 201 Created\nA: b\n\n", &mut out).unwrap();
        assert_eq!(out, b"HTTP/1.0 201 Created\r\nA: b\r\n\r\n");
        assert!(normalize_head(b"no colon\n\n", &mut out).is_err());
        assert!(normalize_head(b"Status: abc\n\n", &mut out).is_err());
        assert_eq!(head_end(b"A: 1\n\nbody"), Some(6));
        assert_eq!(head_end(b"A: 1\r\n\r\nbody"), Some(8));
        assert_eq!(head_end(b"A: 1\r\n"), None);
    }

    #[test]
    fn encodings() {
        let mut out = Vec::new();
        pair(GatewayProtocol::FastCgi, &mut out, b"A", &[b'x'; 200]);
        assert_eq!(&out[..6], &[1, 0x80, 0, 0, 200, b'A']);
        out.clear();
        pair(GatewayProtocol::Uwsgi, &mut out, b"AB", b"c");
        assert_eq!(out, [2, 0, b'A', b'B', 1, 0, b'c']);
        out.clear();
        fcgi_record(&mut out, FCGI_STDIN, b"abc");
        assert_eq!(
            out,
            [1, 5, 0, 1, 0, 3, 5, 0, b'a', b'b', b'c', 0, 0, 0, 0, 0]
        );
        out.clear();
        push_memcached_key(&mut out, b"/a b%\x01");
        assert_eq!(out, b"/a%20b%25%01");
    }
}
