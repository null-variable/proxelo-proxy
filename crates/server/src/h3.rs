//! HTTP/3 over QUIC on TLS listeners that ask for it, with `quinn` and `h3`.
//!
//! As with HTTP/2, each request stream is written as an HTTP/1.1 message
//! into an in-memory pipe and served by a [`Conn`], so phases, proxying,
//! logs and metrics are those of HTTP/1.1. QUIC carries its own TLS 1.3
//! (rustls); the certificate is chosen by SNI the way the OpenSSL
//! listeners choose it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use bytes::{Buf as _, Bytes};
use h3::server::RequestStream;
use http::{HeaderName, HeaderValue, Request, Response, StatusCode};
use proxelo_http1::{Body, ChunkedDecoder, Response as Head, parse_response};
use proxelo_snapshot::Runtime;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::buf::Buf;
use crate::conn::Conn;
use crate::io::Stream;
use crate::tls::TlsInfo;
use crate::{Active, Server, drain};

/// nginx http3_max_concurrent_streams.
const MAX_STREAMS: u32 = 128;
const PIPE: usize = 64 * 1024;
const MAX_HEAD: usize = 64 * 1024;
/// nginx quic idle timeout (keepalive_timeout).
const IDLE: std::time::Duration = std::time::Duration::from_secs(75);

/// The QUIC server settings of a listener: TLS 1.3 with its sites'
/// certificates, ALPN "h3".
pub(crate) fn config(rt: &Arc<Runtime>, li: usize) -> Result<quinn::ServerConfig, String> {
    let err = |e: &dyn std::fmt::Display| format!("listeners[{li}].http3: {e}");
    let mut keys: Vec<Option<Arc<CertifiedKey>>> = Vec::with_capacity(rt.certificates.len());
    for c in rt.certificates.iter() {
        keys.push(Some(certified(c).map_err(|e| err(&e))?));
    }
    let default = rt.listeners[li]
        .tls
        .as_ref()
        .and_then(|t| t.default_certificate)
        .and_then(|c| keys[c as usize].clone());
    let resolver = Resolver {
        rt: Arc::clone(rt),
        listener: li,
        keys,
        default,
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| err(&e))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = 0;
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|e| err(&e))?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(quic));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(MAX_STREAMS.into())
        .max_idle_timeout(Some(IDLE.try_into().map_err(|e| err(&e))?));
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}

/// A certificate in rustls form.
fn certified(c: &proxelo_snapshot::Certificate) -> Result<Arc<CertifiedKey>, String> {
    let chain = c
        .chain
        .iter()
        .map(|x| x.to_der().map(CertificateDer::from))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let der = c.key.private_key_to_pkcs8().map_err(|e| e.to_string())?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der));
    let signer = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| e.to_string())?;
    Ok(Arc::new(CertifiedKey::new(chain, signer)))
}

/// Picks the certificate of the site the SNI name selects, as the OpenSSL
/// servername callback does.
#[derive(Debug)]
struct Resolver {
    rt: Arc<Runtime>,
    listener: usize,
    keys: Vec<Option<Arc<CertifiedKey>>>,
    default: Option<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let Some(name) = hello.server_name() else {
            return self.default.clone();
        };
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let site = match self.rt.listeners[self.listener].site(Some(name.as_bytes())) {
            Ok(Some(s)) => Some(s),
            _ => None,
        };
        site.and_then(|s| self.rt.sites[s as usize].certificates.first())
            .and_then(|&c| self.keys[c as usize].clone())
            .or_else(|| self.default.clone())
    }
}

impl Server {
    /// Serves HTTP/3 on `socket` until the task is aborted. The QUIC
    /// settings follow the active snapshot's listener for `addr`.
    pub(crate) async fn serve_quic(
        self: Arc<Self>,
        addr: SocketAddr,
        socket: std::net::UdpSocket,
    ) -> std::io::Result<()> {
        let Some(cfg) = self.active().quic_config(addr) else {
            return Ok(());
        };
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(cfg),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        let guard = EndpointGuard(endpoint.clone());
        let mut generation = self.active().quic_generation();
        loop {
            tokio::select! {
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else { break };
                    // A snapshot swap changes certificates: new handshakes use
                    // the active snapshot's settings.
                    let active = self.active();
                    if active.quic_generation() != generation {
                        generation = active.quic_generation();
                        if let Some(cfg) = active.quic_config(addr) {
                            endpoint.set_server_config(Some(cfg));
                        }
                    }
                    drop(active);
                    tokio::spawn(self.clone().quic_connection(addr, incoming));
                }
                () = drain::started() => {
                    // No new connections; open ones finish their requests.
                    endpoint.set_server_config(None);
                }
            }
        }
        drop(guard);
        Ok(())
    }

    async fn quic_connection(self: Arc<Self>, addr: SocketAddr, incoming: quinn::Incoming) {
        let peer = incoming.remote_address();
        let Ok(Ok(conn)) = tokio::time::timeout(crate::HANDSHAKE_TIMEOUT, incoming).await else {
            crate::metrics::tls_handshake_error();
            return;
        };
        crate::metrics::connection_opened();
        let _closed = crate::scopeguard(crate::metrics::connection_closed);
        let server_name: Box<[u8]> = conn
            .handshake_data()
            .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|d| d.server_name)
            .map(|n| n.to_ascii_lowercase().into_bytes().into())
            .unwrap_or_default();
        let info = TlsInfo {
            protocol: "TLSv1.3",
            cipher: "TLS_AES_128_GCM_SHA256",
            server_name,
            ..TlsInfo::default()
        };
        let local = conn
            .local_ip()
            .map_or(addr, |ip| SocketAddr::new(ip, addr.port()));
        let Ok(mut h3) = h3::server::builder()
            .max_field_section_size(32 * 1024)
            .build::<_, Bytes>(h3_quinn::Connection::new(conn))
            .await
        else {
            return;
        };
        let in_flight = Arc::new(AtomicU32::new(0));
        let mut closing = false;
        loop {
            let next = if closing {
                h3.accept().await
            } else {
                tokio::select! {
                    next = h3.accept() => next,
                    () = drain::started() => {
                        // GOAWAY; requests already open finish.
                        let _ = h3.shutdown(0).await;
                        closing = true;
                        continue;
                    }
                }
            };
            let Ok(Some(resolver)) = next else {
                return;
            };
            if in_flight.load(Ordering::Relaxed) >= MAX_STREAMS {
                continue;
            }
            in_flight.fetch_add(1, Ordering::Relaxed);
            let done = InFlight(in_flight.clone());
            let server = self.clone();
            let info = info.clone();
            tokio::spawn(async move {
                if let Ok((req, stream)) = resolver.resolve_request().await {
                    request(server, addr, local, peer, info, req, stream).await;
                }
                drop(done);
            });
        }
    }
}

impl Active {
    /// The QUIC settings of the HTTP/3 listener bound to `addr`.
    fn quic_config(&self, addr: SocketAddr) -> Option<quinn::ServerConfig> {
        let i = self
            .rt
            .listeners
            .iter()
            .position(|l| l.http3 && l.addrs.contains(&addr))?;
        self.quic.get(i)?.clone()
    }

    /// Distinguishes snapshots, so endpoints pick up new certificates.
    fn quic_generation(&self) -> usize {
        Arc::as_ptr(&self.rt) as usize
    }
}

/// Closes the endpoint when the serving task ends or is aborted.
struct EndpointGuard(quinn::Endpoint);

impl Drop for EndpointGuard {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"");
    }
}

/// Counts a stream as in flight until dropped.
struct InFlight(Arc<AtomicU32>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Writes the request head an HTTP/1.1 client would send for `req`.
fn head(req: &Request<()>, out: &mut Vec<u8>) {
    let target = req.uri().path_and_query().map_or("/", |p| p.as_str());
    out.extend_from_slice(req.method().as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    if !req.headers().contains_key(http::header::HOST)
        && let Some(a) = req.uri().authority()
    {
        out.extend_from_slice(b"Host: ");
        out.extend_from_slice(a.as_str().as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    for (name, value) in req.headers() {
        // The body is always re-framed as chunked below.
        if name == http::header::CONTENT_LENGTH || name == http::header::TRANSFER_ENCODING {
            continue;
        }
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
}

type Stream3 = RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

async fn request(
    server: Arc<Server>,
    listener: SocketAddr,
    local: SocketAddr,
    peer: SocketAddr,
    info: TlsInfo,
    req: Request<()>,
    stream: Stream3,
) {
    let is_head = req.method() == http::Method::HEAD;
    let (send, mut recv) = stream.split();
    // The request body, if any, is read before the head is written: HTTP/3
    // has no Content-Length obligation, and the first DATA frame tells
    // whether there is a body.
    let first = match recv.recv_data().await {
        Ok(d) => d.map(|mut b| b.copy_to_bytes(b.remaining())),
        Err(_) => return,
    };
    let (mut ours, theirs) = tokio::io::duplex(PIPE);
    let mut c = Conn::new(Stream::Pipe(theirs), listener, local, peer);
    c.x.tls = Some(info);
    c.x.h3 = true;
    let active = move || -> Arc<Active> { server.active() };
    let served = tokio::spawn(c.serve(active));

    let mut start = Vec::with_capacity(512);
    head(&req, &mut start);
    let chunked = first.is_some();
    if chunked {
        start.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }
    start.extend_from_slice(b"Connection: close\r\n\r\n");
    let (mut rd, mut wr) = tokio::io::split(&mut ours);
    let body = async {
        wr.write_all(&start).await?;
        let mut next = first;
        while let Some(data) = next {
            if !data.is_empty() {
                wr.write_all(format!("{:x}\r\n", data.len()).as_bytes())
                    .await?;
                wr.write_all(&data).await?;
                wr.write_all(b"\r\n").await?;
            }
            next = recv
                .recv_data()
                .await
                .map_err(std::io::Error::other)?
                .map(|mut b| b.copy_to_bytes(b.remaining()));
        }
        if chunked {
            wr.write_all(b"0\r\n\r\n").await?;
        }
        Ok::<_, std::io::Error>(())
    };
    let mut send = send;
    let out = relay(&mut rd, &mut send, is_head);
    let (_, sent) = tokio::join!(body, out);
    if sent.is_err() {
        send.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
    }
    drop(ours);
    let _ = served.await;
}

/// Reads the HTTP/1.1 response from the pipe and sends it as HTTP/3.
async fn relay<R: tokio::io::AsyncRead + Unpin>(
    rd: &mut R,
    send: &mut RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    is_head: bool,
) -> Result<(), ()> {
    let mut buf = Buf::new();
    let mut resp = Head::default();
    loop {
        if buf.end > 0 && parse_response(buf.filled(), is_head, &mut resp).map_err(|_| ())? {
            if resp.status >= 200 {
                break;
            }
            buf.consume(resp.head_len);
            continue;
        }
        if buf.end >= MAX_HEAD || buf.fill(rd, 4096, MAX_HEAD).await.map_err(|_| ())? == 0 {
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
    send.send_response(r.body(()).map_err(|_| ())?)
        .await
        .map_err(|_| ())?;
    buf.consume(resp.head_len);
    if matches!(resp.body, Body::None) {
        return send.finish().await.map_err(|_| ());
    }
    let mut left = match resp.body {
        Body::Length(n) => n,
        _ => 0,
    };
    let mut dec = ChunkedDecoder::new();
    let mut chunk = Vec::new();
    let mut trailer = Vec::new();
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
                    .advance_full(
                        data,
                        |r| chunk.extend_from_slice(&data[r]),
                        |c| trailer.push(c),
                    )
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
        if !chunk.is_empty() {
            send.send_data(Bytes::copy_from_slice(&chunk))
                .await
                .map_err(|_| ())?;
        }
        if done {
            if !trailer.is_empty() {
                send.send_trailers(crate::h2::trailer_map(&trailer))
                    .await
                    .map_err(|_| ())?;
            }
            return send.finish().await.map_err(|_| ());
        }
        let mut tmp = [0u8; 16 * 1024];
        let n = rd.read(&mut tmp).await.map_err(|_| ())?;
        if n == 0 {
            return if matches!(resp.body, Body::Close) {
                send.finish().await.map_err(|_| ())
            } else {
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
