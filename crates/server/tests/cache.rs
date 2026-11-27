//! The response cache over real sockets: storing, hits, HEAD, purge and
//! revalidation.
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use proxelo_api::distrib::v1::Purge;
use proxelo_api::snapshot::v1::{
    self as ir, Action, CacheValid, CacheZone, HostMatch, Listener, PathMatch, ProxyAction, Route,
    Site, Target, Upstream, action, host_match, path_match,
};
use proxelo_server::{Listeners, Server};
use proxelo_snapshot::Runtime;

fn snapshot(dir: &str, up: SocketAddr, cache: ir::Cache) -> ir::Snapshot {
    let addr = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    ir::Snapshot {
        revision: 1,
        listeners: vec![Listener {
            address: addr.to_string(),
            ..Default::default()
        }],
        cache_zones: vec![CacheZone {
            id: "z".into(),
            path: dir.into(),
            levels: vec![1, 2],
            ..Default::default()
        }],
        sites: vec![Site {
            listeners: vec![0],
            hostnames: vec![HostMatch {
                kind: host_match::Kind::Exact as i32,
                value: "example.com".into(),
            }],
            routes: vec![Route {
                path: Some(PathMatch {
                    kind: path_match::Kind::Prefix as i32,
                    value: "/".into(),
                }),
                action: Some(Action {
                    kind: Some(action::Kind::Proxy(ProxyAction::default())),
                }),
                cache: Some(cache),
                ..Default::default()
            }],
            ..Default::default()
        }],
        upstreams: vec![Upstream {
            targets: vec![Target {
                address: up.to_string(),
                weight: 1,
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn start(snap: &ir::Snapshot) -> (SocketAddr, Arc<Server>) {
    proxelo_snapshot::validate(snap).unwrap();
    let rt = Runtime::build(snap).unwrap();
    let addr = rt.listeners[0].addrs[0];
    let server = Server::new(Runtime::empty(), 2);
    let workers = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let mut listeners = Listeners::new(vec![workers.handle().clone()], false);
    server.set_background(listeners.background());
    listeners.apply(&server, rt).unwrap();
    std::mem::forget(listeners);
    std::mem::forget(workers);
    (addr, server)
}

/// An upstream counting requests. It answers `304` to a request with
/// If-None-Match, otherwise `body` with `headers`.
fn backend(headers: &'static str, body: &'static str) -> (SocketAddr, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let n = hits.clone();
    thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            let n = n.clone();
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut b = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b) {
                        Ok(k) if k > 0 => buf.extend_from_slice(&b[..k]),
                        _ => return,
                    }
                }
                n.fetch_add(1, Ordering::SeqCst);
                let req = String::from_utf8_lossy(&buf).to_ascii_lowercase();
                let resp = if req.contains("if-none-match") {
                    "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".to_owned()
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    (addr, hits)
}

fn request(addr: SocketAddr, method: &str, extra: &str) -> (String, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "{method} / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n{extra}\r\n"
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let (head, body) = out.split_once("\r\n\r\n").unwrap();
    (head.to_owned(), body.to_owned())
}

fn dir(name: &str) -> String {
    let d = std::env::temp_dir().join(format!("pxc-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d.to_string_lossy().into_owned()
}

fn valid(seconds: u32) -> Vec<CacheValid> {
    vec![CacheValid {
        seconds,
        ..Default::default()
    }]
}

#[test]
fn stores_serves_and_purges() {
    let (up, hits) = backend("Cache-Tag: t1\r\nETag: \"v1\"\r\n", "hello");
    let d = dir("hit");
    let (addr, server) = start(&snapshot(
        &d,
        up,
        ir::Cache {
            zone: 0,
            valid: valid(60),
            ..Default::default()
        },
    ));
    let (h, b) = request(addr, "GET", "");
    assert!(h.starts_with("HTTP/1.1 200"), "{h}");
    assert_eq!(b, "hello");
    let (h, b) = request(addr, "GET", "");
    assert!(h.starts_with("HTTP/1.1 200"), "{h}");
    assert!(h.contains("Content-Length: 5"), "{h}");
    assert_eq!(b, "hello");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "second GET is a hit");
    let (h, b) = request(addr, "HEAD", "");
    assert!(h.contains("Content-Length: 5"), "{h}");
    assert_eq!(b, "");
    let (h, _) = request(addr, "GET", "If-None-Match: \"v1\"\r\n");
    assert!(h.starts_with("HTTP/1.1 304"), "{h}");
    let (h, b) = request(addr, "GET", "Range: bytes=1-2\r\n");
    assert!(h.starts_with("HTTP/1.1 206"), "{h}");
    assert_eq!(b, "el");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let done = server.purge(&Purge {
        id: "p".into(),
        zone_id: "z".into(),
        tags: vec!["t1".into()],
        ..Default::default()
    });
    assert_eq!((done.removed, done.error.as_str()), (1, ""));
    request(addr, "GET", "");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "purged entry is fetched again"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn not_stored_when_private() {
    let (up, hits) = backend("Cache-Control: private\r\n", "x");
    let d = dir("private");
    let (addr, _s) = start(&snapshot(
        &d,
        up,
        ir::Cache {
            valid: valid(60),
            ..Default::default()
        },
    ));
    request(addr, "GET", "");
    request(addr, "GET", "");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn expired_entry_is_revalidated() {
    let (up, hits) = backend("ETag: \"v1\"\r\nCache-Control: max-age=1\r\n", "body");
    let d = dir("reval");
    let (addr, _s) = start(&snapshot(
        &d,
        up,
        ir::Cache {
            valid: valid(60),
            revalidate: true,
            ..Default::default()
        },
    ));
    request(addr, "GET", "");
    thread::sleep(Duration::from_millis(2100));
    // The upstream answers 304; the stored body goes out.
    let (h, b) = request(addr, "GET", "");
    assert!(h.starts_with("HTTP/1.1 200"), "{h}");
    assert_eq!(b, "body");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    let _ = std::fs::remove_dir_all(&d);
}
