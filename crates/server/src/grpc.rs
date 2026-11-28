//! grpc_pass over HTTP/2 without TLS.
//!
//! Requests to a target share one HTTP/2 connection. The request body is
//! read first (as nginx limits it with client_max_body_size), then the
//! response streams back as an HTTP/1.1 chunked message whose trailer
//! section carries the gRPC trailers, so the HTTP/2 front end can send them
//! as trailers again.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Instant;

use bytes::Bytes;
use h2::RecvStream;
use h2::client::SendRequest;
use http::{HeaderMap, HeaderName, HeaderValue, Request};
use proxelo_http1::{HeaderKind, Method, parse_response, push_hex, push_u64};
use proxelo_snapshot::{Proxy, Route};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::conn::{Conn, KeepAlive};
use crate::upstream::{Choice, Pool};
use crate::{Active, headers, reply};

/// Frames an HTTP/2 response body as HTTP/1.1 chunked data, ending with
/// the trailers.
struct Chunked {
    body: RecvStream,
    pending: Vec<u8>,
    at: usize,
    trailers: bool,
    done: bool,
}

fn push_fields(out: &mut Vec<u8>, map: &HeaderMap) {
    for (name, value) in map {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
}

impl AsyncRead for Chunked {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if me.at < me.pending.len() {
                let n = (me.pending.len() - me.at).min(buf.remaining());
                buf.put_slice(&me.pending[me.at..me.at + n]);
                me.at += n;
                return Poll::Ready(Ok(()));
            }
            if me.done {
                return Poll::Ready(Ok(()));
            }
            me.pending.clear();
            me.at = 0;
            if me.trailers {
                let t = ready!(me.body.poll_trailers(cx)).map_err(io::Error::other)?;
                me.pending.extend_from_slice(b"0\r\n");
                if let Some(t) = t {
                    push_fields(&mut me.pending, &t);
                }
                me.pending.extend_from_slice(b"\r\n");
                me.done = true;
                continue;
            }
            match ready!(me.body.poll_data(cx)) {
                Some(Ok(data)) => {
                    let _ = me.body.flow_control().release_capacity(data.len());
                    if !data.is_empty() {
                        push_hex(&mut me.pending, data.len() as u64);
                        me.pending.extend_from_slice(b"\r\n");
                        me.pending.extend_from_slice(&data);
                        me.pending.extend_from_slice(b"\r\n");
                    }
                }
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                None => me.trailers = true,
            }
        }
    }
}

/// The shared connection to `pool`'s target, made when missing or closed.
async fn sender(pool: &Pool, p: &Proxy) -> Result<SendRequest<Bytes>, u16> {
    let mut slot = pool.h2.lock().await;
    if let Some(s) = slot.as_ref() {
        let mut s = s.clone();
        if std::future::poll_fn(|cx| s.poll_ready(cx)).await.is_ok() {
            return Ok(s);
        }
        *slot = None;
    }
    let tcp = match timeout(p.connect_timeout, TcpStream::connect(pool.addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => return Err(502),
        Err(_) => return Err(504),
    };
    let _ = tcp.set_nodelay(true);
    let (send, conn) = match timeout(p.connect_timeout, h2::client::handshake(tcp)).await {
        Ok(Ok(h)) => h,
        Ok(Err(_)) => return Err(502),
        Err(_) => return Err(504),
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });
    *slot = Some(send.clone());
    Ok(send)
}

impl Conn {
    /// grpc_pass. `Err` carries the status to answer, which an error page
    /// may replace.
    pub async fn grpc(
        &mut self,
        active: &Active,
        p: &Proxy,
        route: &Route,
    ) -> Result<KeepAlive, u16> {
        if let Some(keep) = self.read_body().await {
            return Ok(keep);
        }
        let ups = &active.upstreams[p.upstream as usize];
        let mut choice = Choice {
            prefer: self.sticky(active, p.upstream),
            ..Default::default()
        };
        self.balancing_key(active, p.upstream);
        let mut tries = 0u32;
        let mut status = 502;
        loop {
            if p.tries != 0 && tries >= p.tries {
                return Err(status);
            }
            let Some(picked) = ups.pick(&mut choice, &self.x.tmpl) else {
                return Err(status);
            };
            tries += 1;
            let i = picked.index;
            let pool = &ups.pools()[i];
            self.x.sent.upstream_addr = Some(pool.addr);
            let started = Instant::now();
            let send = match sender(pool, p).await {
                Ok(s) => s,
                Err(st) => {
                    ups.failed(i);
                    active.metrics.upstream_failure(p.upstream, i);
                    status = st;
                    let allowed = if st == 504 {
                        p.next.timeout
                    } else {
                        p.next.error
                    };
                    if !allowed {
                        return Err(status);
                    }
                    continue;
                }
            };
            self.x.sent.upstream_connect = Some(started.elapsed().as_secs_f64());
            let req = self
                .grpc_request(&ups.host, pool, route)
                .map_err(|()| 500u16)?;
            let resp = match self.grpc_exchange(send, req, p).await {
                Ok(r) => r,
                Err(st) => {
                    // The request went out: it is not replayed.
                    ups.failed(i);
                    active.metrics.upstream_failure(p.upstream, i);
                    return Err(st);
                }
            };
            ups.succeeded(i);
            let (parts, body) = resp.into_parts();
            let st = parts.status.as_u16();
            self.x.sent.upstream_status = st;
            self.x.sent.upstream_header = Some(started.elapsed().as_secs_f64());
            self.sticky_cookie(active, p.upstream, i);
            // The response as an HTTP/1.1 head in `ubuf`.
            let end = body.is_end_stream();
            let head = &mut self.gw_body;
            head.clear();
            head.extend_from_slice(b"HTTP/1.1 ");
            push_u64(head, u64::from(st));
            head.extend_from_slice(b" ");
            head.extend_from_slice(proxelo_http1::reason(st).as_bytes());
            head.extend_from_slice(b"\r\n");
            for (name, value) in &parts.headers {
                if name == http::header::CONTENT_LENGTH && !end {
                    continue;
                }
                head.extend_from_slice(name.as_str().as_bytes());
                head.extend_from_slice(b": ");
                head.extend_from_slice(value.as_bytes());
                head.extend_from_slice(b"\r\n");
            }
            if end {
                head.extend_from_slice(b"Content-Length: 0\r\n\r\n");
            } else {
                head.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
            }
            std::mem::swap(&mut self.ubuf.data, head);
            self.ubuf.end = self.ubuf.data.len();
            let is_head = self.x.req.method == Method::Head;
            if !matches!(
                parse_response(self.ubuf.filled(), is_head, &mut self.resp),
                Ok(true)
            ) {
                return Err(502);
            }
            if self.intercepts(p, route, st) {
                active
                    .metrics
                    .upstream_response(p.upstream, i, st, started.elapsed());
                return Err(st);
            }
            let mut rd = Chunked {
                body,
                pending: Vec::new(),
                at: 0,
                trailers: false,
                done: end,
            };
            let (keep, _) = self.relay(&mut rd, route, p.read_timeout).await;
            self.x.sent.upstream_response = Some(started.elapsed().as_secs_f64());
            active
                .metrics
                .upstream_response(p.upstream, i, st, started.elapsed());
            return Ok(keep);
        }
    }

    /// The request for the upstream: the client's headers without
    /// connection-specific ones, the route's request headers, and TE:
    /// trailers, as nginx's grpc module sends.
    fn grpc_request(&mut self, host: &str, pool: &Pool, route: &Route) -> Result<Request<()>, ()> {
        let mut path = std::mem::take(&mut self.x.scratch);
        path.clear();
        if self.x.uri_changed {
            reply::push_uri_path(&mut path, &self.x.path);
            if !self.x.args.is_empty() {
                path.push(b'?');
                path.extend_from_slice(&self.x.args);
            }
        } else {
            path.extend_from_slice(self.x.req.target.get(&self.x.head));
        }
        let authority = if host.is_empty() {
            pool.addr.to_string()
        } else {
            host.to_string()
        };
        let uri = http::Uri::builder()
            .scheme("http")
            .authority(authority)
            .path_and_query(path.as_slice())
            .build();
        self.x.scratch = path;
        let method =
            http::Method::from_bytes(self.x.req.method_span.get(&self.x.head)).map_err(|_| ())?;
        let mut req = Request::builder()
            .method(method)
            .uri(uri.map_err(|_| ())?)
            .body(())
            .map_err(|_| ())?;
        let ops = &route.request_headers;
        let map = req.headers_mut();
        for h in self.x.req.headers.iter() {
            let name = h.name.get(&self.x.head);
            if h.kind.is_hop_by_hop()
                || matches!(
                    h.kind,
                    HeaderKind::Host | HeaderKind::Expect | HeaderKind::ContentLength
                )
                || (!ops.is_empty() && ops.drops(name))
            {
                continue;
            }
            let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(name),
                HeaderValue::from_bytes(h.value.get(&self.x.head)),
            ) else {
                continue;
            };
            map.append(n, v);
        }
        if !ops.is_empty() {
            let mut lines = std::mem::take(&mut self.out);
            lines.clear();
            headers::request(&mut self.x, ops, &mut lines);
            for line in lines.split(|&c| c == b'\n') {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                let Some(colon) = line.iter().position(|&c| c == b':') else {
                    continue;
                };
                if let (Ok(n), Ok(v)) = (
                    HeaderName::from_bytes(&line[..colon]),
                    HeaderValue::from_bytes(line[colon + 1..].trim_ascii()),
                ) {
                    map.append(n, v);
                }
            }
            self.out = lines;
        }
        map.insert(http::header::TE, HeaderValue::from_static("trailers"));
        if !self.gw_body.is_empty() {
            map.insert(
                http::header::CONTENT_LENGTH,
                HeaderValue::from(self.gw_body.len()),
            );
        }
        Ok(req)
    }

    /// Sends `req` with the body in `gw_body` and waits for the response
    /// head.
    async fn grpc_exchange(
        &mut self,
        mut send: SendRequest<Bytes>,
        req: Request<()>,
        p: &Proxy,
    ) -> Result<http::Response<RecvStream>, u16> {
        let empty = self.gw_body.is_empty();
        let (resp, mut body) = send.send_request(req, empty).map_err(|_| 502u16)?;
        if !empty {
            let data = Bytes::copy_from_slice(&self.gw_body);
            let sent = timeout(p.send_timeout, crate::h2::data(&mut body, data, true)).await;
            match sent {
                Ok(Ok(())) => {}
                Ok(Err(())) => return Err(502),
                Err(_) => return Err(504),
            }
        }
        match timeout(p.read_timeout, resp).await {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(_)) => Err(502),
            Err(_) => Err(504),
        }
    }
}
