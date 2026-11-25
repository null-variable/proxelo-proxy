//! HTTP/2 on TLS listeners, with the `h2` crate.
//!
//! Each stream is served by the same request code as HTTP/1.1: the request
//! is written as an HTTP/1.1 message into an in-memory pipe, a [`Conn`] runs
//! it, and its HTTP/1.1 response is turned back into HTTP/2 frames. The
//! phases, error pages, proxying, logs and metrics are therefore identical
//! across versions; only framing differs.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use http::{HeaderName, HeaderValue, Request, Response, StatusCode};
use proxelo_http1::{Body, ChunkedDecoder, Response as Head, parse_response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use crate::buf::Buf;
use crate::conn::Conn;
use crate::io::Stream;
use crate::tls::TlsInfo;
use crate::{Active, Server};

/// nginx http2_max_concurrent_streams.
const MAX_STREAMS: u32 = 128;
const PIPE: usize = 64 * 1024;
/// The response head of a stream must fit, as for upstream heads.
const MAX_HEAD: usize = 64 * 1024;

/// Serves an HTTP/2 connection until the client or the server ends it.
pub(crate) async fn serve(
    server: Arc<Server>,
    listener: SocketAddr,
    tls: SslStream<TcpStream>,
    local: SocketAddr,
    peer: SocketAddr,
    info: TlsInfo,
) {
    let mut builder = h2::server::Builder::new();
    builder
        .max_concurrent_streams(MAX_STREAMS)
        .max_header_list_size(32 * 1024)
        // Rapid reset (CVE-2023-44487): the h2 defaults bound pending
        // resets; keep them.
        .max_send_buffer_size(PIPE);
    let Ok(mut conn) = builder.handshake::<_, Bytes>(tls).await else {
        return;
    };
    while let Some(next) = conn.accept().await {
        let Ok((req, respond)) = next else {
            return;
        };
        let server = server.clone();
        let info = info.clone();
        tokio::spawn(async move {
            stream(server, listener, local, peer, info, req, respond).await;
        });
    }
}

/// Writes the request head an HTTP/1.1 client would send for `req`.
fn head(req: &Request<RecvStream>, out: &mut Vec<u8>) -> bool {
    let target = req.uri().path_and_query().map_or("/", |p| p.as_str());
    out.extend_from_slice(req.method().as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    // :authority stands in for Host.
    let has_host = req.headers().contains_key(http::header::HOST);
    if !has_host && let Some(a) = req.uri().authority() {
        out.extend_from_slice(b"Host: ");
        out.extend_from_slice(a.as_str().as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    let mut has_length = false;
    for (name, value) in req.headers() {
        // Connection-specific headers are not allowed in HTTP/2; h2 rejects
        // them already. Cookies split into several fields join again with
        // "; " (RFC 9113 §8.2.3) simply by being repeated.
        has_length |= name == http::header::CONTENT_LENGTH;
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    let chunked = !req.body().is_end_stream() && !has_length;
    if chunked {
        out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }
    // One request per pipe.
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    chunked
}

async fn stream(
    server: Arc<Server>,
    listener: SocketAddr,
    local: SocketAddr,
    peer: SocketAddr,
    info: TlsInfo,
    req: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
) {
    let is_head = req.method() == http::Method::HEAD;
    let (mut ours, theirs) = tokio::io::duplex(PIPE);
    let mut c = Conn::new(Stream::Pipe(theirs), listener, local, peer);
    c.x.tls = Some(info);
    c.x.h2 = true;
    let active = move || -> Arc<Active> { server.active() };
    let served = tokio::spawn(c.serve(active));

    let mut first = Vec::with_capacity(512);
    let chunked = head(&req, &mut first);
    let (mut rd, mut wr) = tokio::io::split(&mut ours);
    let mut body = req.into_body();
    let send = async {
        wr.write_all(&first).await?;
        while let Some(data) = body.data().await {
            let data = data.map_err(std::io::Error::other)?;
            let n = data.len();
            if chunked && n > 0 {
                wr.write_all(format!("{n:x}\r\n").as_bytes()).await?;
                wr.write_all(&data).await?;
                wr.write_all(b"\r\n").await?;
            } else {
                wr.write_all(&data).await?;
            }
            let _ = body.flow_control().release_capacity(n);
        }
        if chunked {
            wr.write_all(b"0\r\n\r\n").await?;
        }
        Ok::<_, std::io::Error>(())
    };
    let recv = relay(&mut rd, &mut respond, is_head);
    let (sent, received) = tokio::join!(send, recv);
    if received.is_err() {
        respond.send_reset(h2::Reason::INTERNAL_ERROR);
    } else if sent.is_err() {
        // The client reset its side; the response went out or is moot.
    }
    drop(ours);
    let _ = served.await;
}

/// Reads the HTTP/1.1 response from the pipe and sends it as HTTP/2.
async fn relay<R: tokio::io::AsyncRead + Unpin>(
    rd: &mut R,
    respond: &mut SendResponse<Bytes>,
    is_head: bool,
) -> Result<(), ()> {
    let mut buf = Buf::new();
    let mut resp = Head::default();
    loop {
        if buf.end > 0 && parse_response(buf.filled(), is_head, &mut resp).map_err(|_| ())? {
            if resp.status >= 200 {
                break;
            }
            // 100 Continue: HTTP/2 clients do not need it relayed.
            buf.consume(resp.head_len);
            continue;
        }
        if buf.end >= MAX_HEAD || buf.fill(rd, 4096, MAX_HEAD).await.map_err(|_| ())? == 0 {
            // 444 or a closed connection: no response.
            return Err(());
        }
    }
    let mut r = Response::builder().status(StatusCode::from_u16(resp.status).map_err(|_| ())?);
    for h in resp.headers.iter() {
        if h.kind.is_hop_by_hop() {
            continue;
        }
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(h.name.get(&buf.data)),
            HeaderValue::from_bytes(h.value.get(&buf.data)),
        ) else {
            continue;
        };
        r = r.header(name, value);
    }
    let r = r.body(()).map_err(|_| ())?;
    let end = matches!(resp.body, Body::None);
    let mut send = respond.send_response(r, end).map_err(|_| ())?;
    buf.consume(resp.head_len);
    if end {
        return Ok(());
    }

    let mut left = match resp.body {
        Body::Length(n) => n,
        _ => 0,
    };
    let mut dec = ChunkedDecoder::new();
    let mut chunk = Vec::new();
    loop {
        chunk.clear();
        let done = match resp.body {
            Body::Length(_) => {
                let take = left.min(buf.end as u64) as usize;
                chunk.extend_from_slice(&buf.data[..take]);
                buf.consume(take);
                left -= take as u64;
                left == 0
            }
            Body::Chunked => {
                let data = &buf.data[..buf.end];
                let take = dec
                    .advance_with(data, |r| chunk.extend_from_slice(&data[r]))
                    .map_err(|_| ())?;
                buf.consume(take);
                dec.is_done()
            }
            _ => {
                chunk.extend_from_slice(buf.filled());
                buf.end = 0;
                false
            }
        };
        if !chunk.is_empty() || done {
            data(&mut send, Bytes::copy_from_slice(&chunk), done).await?;
        }
        if done {
            return Ok(());
        }
        let mut tmp = [0u8; 16 * 1024];
        let n = rd.read(&mut tmp).await.map_err(|_| ())?;
        if n == 0 {
            return if matches!(resp.body, Body::Close) {
                data(&mut send, Bytes::new(), true).await
            } else {
                // Truncated: reset so the client sees it.
                Err(())
            };
        }
        if buf.data.len() < buf.end + n {
            buf.data.resize(buf.end + n, 0);
        }
        buf.data[buf.end..buf.end + n].copy_from_slice(&tmp[..n]);
        buf.end += n;
    }
}

/// Sends `bytes` within the stream's flow control window.
async fn data(send: &mut SendStream<Bytes>, mut bytes: Bytes, end: bool) -> Result<(), ()> {
    if bytes.is_empty() {
        return send.send_data(bytes, end).map_err(|_| ());
    }
    while !bytes.is_empty() {
        send.reserve_capacity(bytes.len());
        let cap = std::future::poll_fn(|cx| send.poll_capacity(cx))
            .await
            .ok_or(())?
            .map_err(|_| ())?;
        let part = bytes.split_to(cap.min(bytes.len()));
        send.send_data(part, end && bytes.is_empty())
            .map_err(|_| ())?;
    }
    Ok(())
}
