//! HTTP/3 over QUIC: requests reach the same routes as HTTP/1.1 and
//! HTTP/2, request bodies are relayed and TLS responses advertise h3.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread;

use bytes::{Buf, Bytes};
use proxelo_api::snapshot::v1::{
    self as ir, Action, Certificate, HostMatch, Listener, ListenerTls, PathMatch, ProxyAction,
    Route, Site, Target, Upstream, action, host_match, path_match,
};
use proxelo_server::{Listeners, Server};
use proxelo_snapshot::Runtime;

/// An upstream echoing the request line and body length.
fn echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut b = [0u8; 4096];
                let head_end = loop {
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break p + 4;
                    }
                    match s.read(&mut b) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&b[..n]),
                        _ => return,
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let line = head.lines().next().unwrap_or_default().to_owned();
                let lower = head.to_ascii_lowercase();
                let mut body = buf[head_end..].to_vec();
                if let Some(n) = lower
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length: "))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                {
                    while body.len() < n {
                        match s.read(&mut b) {
                            Ok(k) if k > 0 => body.extend_from_slice(&b[..k]),
                            _ => break,
                        }
                    }
                } else if lower.contains("transfer-encoding: chunked") {
                    while !body.ends_with(b"0\r\n\r\n") {
                        match s.read(&mut b) {
                            Ok(k) if k > 0 => body.extend_from_slice(&b[..k]),
                            _ => break,
                        }
                    }
                }
                let len = if lower.contains("transfer-encoding: chunked") {
                    dechunked_len(&body)
                } else {
                    body.len()
                };
                let text = format!("{line} body={len}");
                let _ = s.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                        text.len()
                    )
                    .as_bytes(),
                );
            });
        }
    });
    addr
}

/// The data length of a chunked body.
fn dechunked_len(mut b: &[u8]) -> usize {
    let mut n = 0;
    loop {
        let Some(eol) = b.windows(2).position(|w| w == b"\r\n") else {
            return n;
        };
        let size =
            usize::from_str_radix(std::str::from_utf8(&b[..eol]).unwrap().trim(), 16).unwrap();
        if size == 0 {
            return n;
        }
        n += size;
        b = &b[eol + 2 + size + 2..];
    }
}

fn start(upstream: SocketAddr) -> SocketAddr {
    let addr = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let snap = ir::Snapshot {
        revision: 1,
        listeners: vec![Listener {
            address: addr.to_string(),
            tls: Some(ListenerTls {
                default_certificate: Some(0),
                ..Default::default()
            }),
            http2: true,
            http3: true,
            ..Default::default()
        }],
        certificates: vec![Certificate {
            id: "cert".into(),
            chain_pem: include_str!("data/example.com.crt").into(),
            key_pem: include_str!("data/example.com.key").into(),
        }],
        sites: vec![Site {
            listeners: vec![0],
            hostnames: vec![HostMatch {
                kind: host_match::Kind::Exact as i32,
                value: "example.com".into(),
            }],
            certificates: vec![0],
            routes: vec![Route {
                path: Some(PathMatch {
                    kind: path_match::Kind::Prefix as i32,
                    value: "/".into(),
                }),
                action: Some(Action {
                    kind: Some(action::Kind::Proxy(ProxyAction {
                        upstream: 0,
                        ..Default::default()
                    })),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }],
        upstreams: vec![Upstream {
            targets: vec![Target {
                address: upstream.to_string(),
                weight: 1,
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    proxelo_snapshot::validate(&snap).unwrap();
    let rt = Runtime::build(&snap).unwrap();
    let server = Server::new(Runtime::empty(), 2);
    let workers = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let mut listeners = Listeners::new(vec![workers.handle().clone()], false);
    listeners.apply(&server, rt).unwrap();
    // The runtime and sockets live for the rest of the test process.
    std::mem::forget(listeners);
    std::mem::forget(workers);
    addr
}

#[derive(Debug)]
struct AnyCert;

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn get(addr: SocketAddr, method: &str, body: &[u8]) -> (u16, Vec<u8>, http::HeaderMap) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
    let conn = ep.connect(addr, "example.com").unwrap().await.unwrap();
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .unwrap();
    let drive = tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
    let req = http::Request::builder()
        .method(method)
        .uri("https://example.com/x?y=1")
        .body(())
        .unwrap();
    let mut stream = send.send_request(req).await.unwrap();
    if !body.is_empty() {
        stream
            .send_data(Bytes::copy_from_slice(body))
            .await
            .unwrap();
    }
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    let mut out = Vec::new();
    while let Some(mut d) = stream.recv_data().await.unwrap() {
        out.extend_from_slice(&d.copy_to_bytes(d.remaining()));
    }
    drop(stream);
    drop(send);
    drive.abort();
    (resp.status().as_u16(), out, resp.headers().clone())
}

#[tokio::test]
async fn requests_over_http3() {
    let addr = start(echo());
    let (status, body, _) = get(addr, "GET", b"").await;
    assert_eq!(status, 200);
    assert_eq!(String::from_utf8_lossy(&body), "GET /x?y=1 HTTP/1.1 body=0");
    let (status, body, _) = get(addr, "POST", &[7u8; 100_000]).await;
    assert_eq!(status, 200);
    assert!(
        String::from_utf8_lossy(&body).ends_with("body=100000"),
        "{body:?}"
    );
}

#[tokio::test]
async fn tls_responses_advertise_h3() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = start(echo());
    let mut c = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client()).unwrap();
    c.set_verify(openssl::ssl::SslVerifyMode::NONE);
    let ssl = c
        .build()
        .configure()
        .unwrap()
        .into_ssl("example.com")
        .unwrap();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = tokio_openssl::SslStream::new(ssl, tcp).unwrap();
    std::pin::Pin::new(&mut tls).connect().await.unwrap();
    tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut raw = Vec::new();
    // The server closes without close_notify after Connection: close.
    let _ = tls.read_to_end(&mut raw).await;
    let out = String::from_utf8_lossy(&raw);
    let want = format!("Alt-Svc: h3=\":{}\"; ma=86400", addr.port());
    assert!(out.contains(&want), "{out}");
}
