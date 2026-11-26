//! HTTP/2 over TLS: request limits that keep a client from piling up work
//! by resetting streams (rapid reset, CVE-2023-44487).

use std::net::{SocketAddr, TcpListener};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use bytes::Bytes;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use proxelo_api::snapshot::v1::{
    self as ir, Action, Certificate, HostMatch, Listener, ListenerTls, PathMatch, ProxyAction,
    Route, Site, Target, Upstream, action, host_match, path_match,
};
use proxelo_server::{Listeners, Server};
use proxelo_snapshot::Runtime;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

/// An upstream that holds every request for `delay`, then answers 200.
/// Counts the connections it accepted.
fn slow_upstream(delay: Duration) -> (SocketAddr, Arc<AtomicUsize>) {
    use std::io::{Read, Write};
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let seen = Arc::new(AtomicUsize::new(0));
    let count = seen.clone();
    thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            thread::spawn(move || {
                let mut b = [0u8; 4096];
                let _ = s.read(&mut b);
                thread::sleep(delay);
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            });
        }
    });
    (addr, seen)
}

fn start(upstream: SocketAddr) -> SocketAddr {
    let addr = TcpListener::bind("127.0.0.1:0")
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

type Client = h2::client::SendRequest<Bytes>;

/// Opens an HTTP/2 connection; the returned task drives it and ends with it.
async fn connect(addr: SocketAddr) -> (Client, tokio::task::JoinHandle<Result<(), h2::Error>>) {
    let mut c = SslConnector::builder(SslMethod::tls_client()).unwrap();
    c.set_verify(SslVerifyMode::NONE);
    c.set_alpn_protos(b"\x02h2").unwrap();
    let ssl = c
        .build()
        .configure()
        .unwrap()
        .into_ssl("example.com")
        .unwrap();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls = SslStream::new(ssl, tcp).unwrap();
    Pin::new(&mut tls).connect().await.unwrap();
    let (send, conn) = h2::client::handshake(tls).await.unwrap();
    (send, tokio::spawn(conn))
}

fn get() -> http::Request<()> {
    http::Request::get("https://example.com/").body(()).unwrap()
}

#[tokio::test]
async fn serves_requests() {
    let (up, _) = slow_upstream(Duration::ZERO);
    let (mut send, _conn) = connect(start(up)).await;
    for _ in 0..3 {
        send = send.ready().await.unwrap();
        let (resp, _) = send.send_request(get(), true).unwrap();
        let resp = resp.await.unwrap();
        assert_eq!(resp.status(), 200);
        let mut body = resp.into_body();
        let data = body.data().await.unwrap().unwrap();
        assert_eq!(&data[..], b"ok");
    }
}

/// Streams the client resets stop counting against its stream limit, but
/// their requests keep running. The server refuses streams beyond the limit
/// until they finish, and closes a connection that keeps pushing.
#[tokio::test]
async fn rapid_reset_is_bounded() {
    let (up, seen) = slow_upstream(Duration::from_secs(3));
    let (mut send, conn) = connect(start(up)).await;
    // Fill the stream limit with requests the upstream holds, then reset them
    // all once they reached it.
    let mut open = Vec::new();
    for _ in 0..128 {
        send = send.ready().await.unwrap();
        open.push(send.send_request(get(), true).unwrap());
    }
    for _ in 0..100 {
        if seen.load(Ordering::SeqCst) == 128 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(seen.load(Ordering::SeqCst), 128);
    for (_, stream) in &mut open {
        stream.send_reset(h2::Reason::CANCEL);
    }
    drop(open);

    // The client may open new streams, but the old requests still run:
    // new ones are refused without reaching the upstream.
    let mut refused = 0;
    let mut sent = 0;
    let end = loop {
        let ready = match send.ready().await {
            Ok(r) => r,
            Err(e) => break e,
        };
        send = ready;
        let (resp, _) = match send.send_request(get(), true) {
            Ok(r) => r,
            Err(e) => break e,
        };
        sent += 1;
        match resp.await {
            Err(e) if e.reason() == Some(h2::Reason::REFUSED_STREAM) => refused += 1,
            Err(e) => break e,
            Ok(r) => panic!("stream {sent} served: {}", r.status()),
        }
    };
    assert_eq!(seen.load(Ordering::SeqCst), 128, "upstream reached");
    assert_eq!(refused, 128, "refused before closing");
    // The stream may see the closed socket first; the connection saw the
    // GOAWAY.
    let _ = end;
    let ended = tokio::time::timeout(Duration::from_secs(5), conn).await;
    match ended {
        Ok(Ok(Err(e))) => assert_eq!(e.reason(), Some(h2::Reason::ENHANCE_YOUR_CALM), "{e}"),
        other => panic!("connection did not end with ENHANCE_YOUR_CALM: {other:?}"),
    }
}
