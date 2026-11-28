//! End-to-end tests over real sockets: a client, the server, and a scripted
//! upstream.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use proxelo_api::snapshot::v1::{
    self as ir, Action, HostMatch, Listener, PathMatch, ProxyAction, Route, Site, StaticAction,
    Target, Upstream, action, host_match, path_match,
};
use proxelo_server::{Listeners, Server};
use proxelo_snapshot::Runtime;

fn route(kind: path_match::Kind, path: &str, action: action::Kind) -> Route {
    Route {
        path: Some(PathMatch {
            kind: kind as i32,
            value: path.into(),
        }),
        action: Some(Action { kind: Some(action) }),
        ..Default::default()
    }
}

fn proxy(upstream: u32) -> action::Kind {
    action::Kind::Proxy(ProxyAction {
        upstream,
        ..Default::default()
    })
}

fn static_root(root: &std::path::Path) -> action::Kind {
    action::Kind::Static(StaticAction {
        root: root.to_str().unwrap().into(),
        index: vec!["index.html".into()],
        ..Default::default()
    })
}

fn upstream(addrs: &[SocketAddr], keepalive: u32) -> Upstream {
    Upstream {
        targets: addrs
            .iter()
            .map(|a| Target {
                address: a.to_string(),
                weight: 1,
                ..Default::default()
            })
            .collect(),
        keepalive_idle: keepalive,
        ..Default::default()
    }
}

fn snapshot(routes: Vec<Route>, upstreams: Vec<Upstream>) -> ir::Snapshot {
    ir::Snapshot {
        revision: 1,
        listeners: vec![Listener {
            address: free_addr().to_string(),
            ..Default::default()
        }],
        sites: vec![Site {
            listeners: vec![0],
            hostnames: vec![HostMatch {
                kind: host_match::Kind::Exact as i32,
                value: "example.com".into(),
            }],
            routes,
            ..Default::default()
        }],
        upstreams,
        ..Default::default()
    }
}

fn runtime(snap: &ir::Snapshot) -> Runtime {
    proxelo_snapshot::validate(snap).unwrap();
    Runtime::build(snap).unwrap()
}

/// A loopback address with a port nothing listens on right now.
fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// Starts the server for `snap` on a background runtime and returns its
/// address, the snapshot's first listener.
fn start(snap: &ir::Snapshot) -> (Arc<Server>, SocketAddr) {
    let rt = runtime(snap);
    let addr = rt.listeners[0].addrs[0];
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
    (server, addr)
}

fn client(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

/// Reads one response with a Content-Length or chunked body, or up to EOF.
fn read_response(s: &mut TcpStream) -> (String, Vec<u8>) {
    read_response_to(s, false)
}

fn read_response_to(s: &mut TcpStream, head_request: bool) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    let mut b = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = s.read(&mut b).unwrap();
        assert!(n > 0, "eof in head: {:?}", String::from_utf8_lossy(&buf));
        buf.extend_from_slice(&b[..n]);
    };
    let head = String::from_utf8(buf[..head_end].to_vec()).unwrap();
    let mut body = buf[head_end..].to_vec();
    let lower = head.to_ascii_lowercase();
    if head_request {
        return (head, body);
    }
    if let Some(len) = lower
        .lines()
        .find_map(|l| l.strip_prefix("content-length: "))
    {
        let len: usize = len.trim().parse().unwrap();
        while body.len() < len {
            let n = s.read(&mut b).unwrap();
            assert!(n > 0);
            body.extend_from_slice(&b[..n]);
        }
        assert_eq!(body.len(), len, "extra bytes after body");
    } else if lower.contains("transfer-encoding: chunked") {
        while !body.ends_with(b"0\r\n\r\n") {
            let n = s.read(&mut b).unwrap();
            assert!(n > 0);
            body.extend_from_slice(&b[..n]);
        }
    } else if !head.starts_with("HTTP/1.1 304") && !lower.contains("content-length") {
        s.read_to_end(&mut body).unwrap();
    }
    (head, body)
}

fn get(addr: SocketAddr, raw: &str) -> (String, Vec<u8>) {
    let mut s = client(addr);
    s.write_all(raw.as_bytes()).unwrap();
    read_response_to(&mut s, raw.starts_with("HEAD "))
}

fn status(head: &str) -> u16 {
    head[9..12].parse().unwrap()
}

/// A scripted HTTP/1.1 upstream. Each connection serves requests until EOF,
/// answering with the request line and Host it saw. Counts connections.
struct Echo {
    addr: SocketAddr,
    conns: Arc<AtomicUsize>,
}

fn echo(name: &'static str) -> Echo {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let c = conns.clone();
    thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            c.fetch_add(1, Ordering::SeqCst);
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut b = [0u8; 4096];
                loop {
                    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                        match s.read(&mut b) {
                            Ok(n) if n > 0 => buf.extend_from_slice(&b[..n]),
                            _ => return,
                        }
                        continue;
                    };
                    let head = String::from_utf8(buf[..end].to_vec()).unwrap();
                    buf.drain(..end + 4);
                    let lower = head.to_ascii_lowercase();
                    let mut body = Vec::new();
                    if let Some(len) = lower
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length: "))
                    {
                        let len: usize = len.parse().unwrap();
                        while buf.len() < len {
                            let n = s.read(&mut b).unwrap();
                            buf.extend_from_slice(&b[..n]);
                        }
                        body = buf.drain(..len).collect();
                    } else if lower.contains("transfer-encoding: chunked") {
                        while !buf.windows(5).any(|w| w == b"0\r\n\r\n") {
                            let n = s.read(&mut b).unwrap();
                            buf.extend_from_slice(&b[..n]);
                        }
                        let end = buf.windows(5).position(|w| w == b"0\r\n\r\n").unwrap() + 5;
                        body = buf.drain(..end).collect();
                    }
                    let line = head.lines().next().unwrap();
                    let host = head
                        .lines()
                        .find_map(|l| l.strip_prefix("Host: "))
                        .unwrap_or("-");
                    let text = format!(
                        "{name} {line} host={host} body={}",
                        String::from_utf8_lossy(&body)
                    );
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nServer: up\r\nX-Accel-Buffering: no\r\nX-Up: {name}\r\n\r\n{text}",
                        text.len()
                    );
                    if s.write_all(resp.as_bytes()).is_err() {
                        return;
                    }
                    if lower.contains("connection: close") {
                        return;
                    }
                }
            });
        }
    });
    Echo { addr, conns }
}

/// Serves each connection with a fixed response, then closes.
fn canned(resp: &'static [u8]) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            let mut b = [0u8; 4096];
            let _ = s.read(&mut b);
            let _ = s.write_all(resp);
        }
    });
    addr
}

fn dead_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap()
}

/// The static file tree, written once: tests run in parallel and rewriting a
/// file truncates it under a test that is serving it.
fn www() -> PathBuf {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("proxelo-serve-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("docs")).unwrap();
        std::fs::create_dir_all(dir.join("empty")).unwrap();
        std::fs::write(dir.join("index.html"), "<h1>home</h1>").unwrap();
        std::fs::write(dir.join("docs/index.html"), "docs").unwrap();
        std::fs::write(dir.join("a b.txt"), "space").unwrap();
        std::fs::write(dir.join("big.bin"), vec![7u8; 200_000]).unwrap();
        dir
    })
    .clone()
}

#[test]
fn static_files() {
    use path_match::Kind::Prefix;
    let root = www();
    let (_, addr) = start(&snapshot(
        vec![route(Prefix, "/", static_root(&root))],
        vec![],
    ));
    let host = "Host: example.com\r\n";

    let (h, b) = get(addr, &format!("GET / HTTP/1.1\r\n{host}\r\n"));
    assert_eq!(status(&h), 200, "{h}");
    assert!(h.contains("Content-Type: text/html\r\n"));
    assert!(h.contains("Server: proxelo\r\n"));
    assert!(h.contains("ETag: \""));
    assert_eq!(b, b"<h1>home</h1>");

    let (h, b) = get(addr, &format!("GET /a%20b.txt HTTP/1.1\r\n{host}\r\n"));
    assert_eq!(status(&h), 200);
    assert!(h.contains("Content-Type: text/plain\r\n"));
    assert_eq!(b, b"space");

    // Byte ranges, as nginx: one part, several, and none in the file.
    let (h, b) = get(
        addr,
        &format!("GET /a%20b.txt HTTP/1.1\r\n{host}Range: bytes=-3\r\n\r\n"),
    );
    assert_eq!(status(&h), 206, "{h}");
    assert!(h.contains("Content-Range: bytes 2-4/5\r\n"), "{h}");
    assert!(!h.contains("Accept-Ranges"), "{h}");
    assert_eq!(b, b"ace");
    let (h, b) = get(
        addr,
        &format!("GET /a%20b.txt HTTP/1.1\r\n{host}Range: bytes=0-0,3-4\r\n\r\n"),
    );
    assert_eq!(status(&h), 206, "{h}");
    let boundary = h
        .split("boundary=")
        .nth(1)
        .and_then(|r| r.split("\r\n").next())
        .expect("multipart boundary");
    assert_eq!(
        String::from_utf8(b).unwrap(),
        format!(
            "\r\n--{boundary}\r\nContent-Type: text/plain\r\nContent-Range: bytes 0-0/5\r\n\r\ns\r\n--{boundary}\r\nContent-Type: text/plain\r\nContent-Range: bytes 3-4/5\r\n\r\nce\r\n--{boundary}--\r\n"
        )
    );
    let (h, _) = get(
        addr,
        &format!("GET /a%20b.txt HTTP/1.1\r\n{host}Range: bytes=9-\r\n\r\n"),
    );
    assert_eq!(status(&h), 416, "{h}");
    assert!(h.contains("Content-Range: bytes */5\r\n"), "{h}");

    let (h, b) = get(addr, &format!("GET /big.bin HTTP/1.1\r\n{host}\r\n"));
    assert_eq!(status(&h), 200);
    assert_eq!(b.len(), 200_000);

    let (h, _) = get(addr, &format!("GET /docs?x=1 HTTP/1.1\r\n{host}\r\n"));
    assert_eq!(status(&h), 301);
    assert!(
        h.contains(&format!(
            "Location: http://example.com:{}/docs/?x=1\r\n",
            addr.port()
        )),
        "{h}"
    );

    let (h, b) = get(addr, &format!("GET /docs/ HTTP/1.1\r\n{host}\r\n"));
    assert_eq!(status(&h), 200);
    assert_eq!(b, b"docs");

    assert_eq!(
        status(&get(addr, &format!("GET /empty/ HTTP/1.1\r\n{host}\r\n")).0),
        403
    );
    assert_eq!(
        status(&get(addr, &format!("GET /nope HTTP/1.1\r\n{host}\r\n")).0),
        404
    );
    assert_eq!(
        status(&get(addr, &format!("GET /../etc/passwd HTTP/1.1\r\n{host}\r\n")).0),
        400
    );
    assert_eq!(
        status(&get(addr, &format!("DELETE / HTTP/1.1\r\n{host}\r\n")).0),
        405
    );

    let (h, b) = get(
        addr,
        &format!("HEAD /index.html HTTP/1.1\r\n{host}Connection: close\r\n\r\n"),
    );
    assert_eq!(status(&h), 200);
    assert!(h.contains("Content-Length: 13\r\n"));
    assert!(b.is_empty());

    let etag = h
        .lines()
        .find_map(|l| l.strip_prefix("ETag: "))
        .unwrap()
        .to_string();
    let (h, _) = get(
        addr,
        &format!("GET /index.html HTTP/1.1\r\n{host}If-None-Match: {etag}\r\n\r\n"),
    );
    assert_eq!(status(&h), 304, "{h}");
}

#[test]
fn keepalive_pipelining_and_errors() {
    use path_match::Kind::Prefix;
    let root = www();
    let (_, addr) = start(&snapshot(
        vec![route(Prefix, "/", static_root(&root))],
        vec![],
    ));
    let mut s = client(addr);
    // Two pipelined requests and a body that must be skipped on a static route.
    s.write_all(
        b"GET /a%20b.txt HTTP/1.1\r\nHost: example.com\r\n\r\n\
          HEAD /docs/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc\
          GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    .unwrap();
    // Responses may arrive in any split; read until the last body.
    let mut all = Vec::new();
    let mut b = [0u8; 4096];
    while !all.ends_with(b"<h1>home</h1>") {
        let n = s.read(&mut b).unwrap();
        assert!(n > 0, "{:?}", String::from_utf8_lossy(&all));
        all.extend_from_slice(&b[..n]);
    }
    let text = String::from_utf8(all).unwrap();
    let parts: Vec<_> = text.split("HTTP/1.1 ").skip(1).collect();
    assert_eq!(parts.len(), 3, "{text}");
    assert!(parts[0].starts_with("200") && parts[0].contains("Connection: keep-alive"));
    assert!(parts[0].ends_with("\r\n\r\nspace"), "{}", parts[0]);
    // HEAD of the index: headers only, body bytes of the request skipped.
    assert!(
        parts[1].starts_with("200") && parts[1].ends_with("\r\n\r\n"),
        "{}",
        parts[1]
    );
    assert!(parts[2].starts_with("200") && parts[2].ends_with("<h1>home</h1>"));

    // Smuggling attempt: 400 and close.
    let (h, _) = get(
        addr,
        "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
    );
    assert_eq!(status(&h), 400);
    assert!(h.contains("Connection: close"));

    // Unknown host goes to the default site, the first on the listener.
    let (h, _) = get(addr, "GET / HTTP/1.1\r\nHost: other.example\r\n\r\n");
    assert_eq!(status(&h), 200);

    let (h, _) = get(addr, "GET / HTTP/1.1\r\n\r\n");
    assert_eq!(status(&h), 400);

    let long = "a".repeat(40_000);
    let (h, _) = get(addr, &format!("GET /{long} HTTP/1.1\r\nHost: x\r\n\r\n"));
    assert_eq!(status(&h), 414);
}

#[test]
fn proxies_and_balances() {
    use path_match::Kind::{Exact, Prefix};
    let a = echo("a");
    let b = echo("b");
    let root = www();
    let snap = snapshot(
        vec![
            route(Prefix, "/", static_root(&root)),
            route(Prefix, "/api/", proxy(0)),
            route(Exact, "/docs/index.html", proxy(1)),
        ],
        vec![
            Upstream {
                host: "backend".into(),
                ..upstream(&[a.addr, b.addr], 8)
            },
            upstream(&[a.addr], 0),
        ],
    );
    let (_, addr) = start(&snap);

    let mut s = client(addr);
    let mut seen = Vec::new();
    for i in 0..4 {
        s.write_all(format!("GET /api/x?i={i} HTTP/1.1\r\nHost: Example.com:80\r\nConnection: keep-alive\r\nX-Req: 1\r\n\r\n").as_bytes())
            .unwrap();
        let (h, body) = read_response(&mut s);
        assert_eq!(status(&h), 200, "{h}");
        assert!(h.contains("Server: proxelo"), "{h}");
        assert!(!h.contains("Server: up"));
        assert!(!h.contains("X-Accel"), "internal headers hidden: {h}");
        let body = String::from_utf8(body).unwrap();
        assert!(
            body.ends_with(&format!("GET /api/x?i={i} HTTP/1.1 host=backend body=")),
            "{body}"
        );
        seen.push(body[..1].to_string());
    }
    assert_eq!(seen, ["a", "b", "a", "b"], "round robin");
    // Keepalive: one upstream connection each, reused.
    assert_eq!(a.conns.load(Ordering::SeqCst), 1);
    assert_eq!(b.conns.load(Ordering::SeqCst), 1);

    // POST with Content-Length and with a chunked body.
    s.write_all(b"POST /api/p HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello")
        .unwrap();
    let (_, body) = read_response(&mut s);
    assert!(String::from_utf8(body).unwrap().ends_with("body=hello"));
    s.write_all(b"POST /api/p HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
        .unwrap();
    let (_, body) = read_response(&mut s);
    assert!(
        String::from_utf8(body)
            .unwrap()
            .ends_with("body=3\r\nabc\r\n0\r\n\r\n")
    );

    // Index file found by the static route is proxied with the new URI,
    // over a non-keepalive upstream.
    let (h, body) = get(addr, "GET /docs/?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n");
    assert_eq!(status(&h), 200, "{h}");
    assert!(
        String::from_utf8(body)
            .unwrap()
            .starts_with("a GET /docs/index.html?q=1 HTTP/1.1"),
    );

    // An upstream without a name sends its target address, whatever the
    // client sent.
    let (h, body) = get(
        addr,
        "GET /docs/index.html HTTP/1.0\r\nHost: example.com\r\n\r\n",
    );
    assert!(h.contains("Connection: close"));
    let body = String::from_utf8(body).unwrap();
    assert!(body.contains("host=127.0.0.1:"), "{body}");
}

#[test]
fn upstream_failures() {
    use path_match::Kind::Prefix;
    let good = echo("good");
    let snap = snapshot(
        vec![
            route(Prefix, "/next/", proxy(0)),
            route(Prefix, "/dead/", proxy(1)),
            route(Prefix, "/bad/", proxy(2)),
            route(Prefix, "/close/", proxy(3)),
            route(Prefix, "/chunk/", proxy(4)),
            route(Prefix, "/short/", proxy(5)),
        ],
        vec![
            upstream(&[dead_addr(), good.addr], 0),
            upstream(&[dead_addr()], 0),
            upstream(&[canned(b"garbage\r\n\r\n")], 0),
            upstream(&[canned(b"HTTP/1.1 200 OK\r\n\r\nuntil-close")], 0),
            upstream(
                &[canned(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n",
                )],
                0,
            ),
            upstream(
                &[canned(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")],
                0,
            ),
        ],
    );
    let (_, addr) = start(&snap);
    let host = "Host: example.com\r\n";

    for _ in 0..2 {
        let (h, b) = get(addr, &format!("GET /next/ HTTP/1.1\r\n{host}\r\n"));
        assert_eq!(status(&h), 200, "next upstream on connect error: {h}");
        assert!(b.starts_with(b"good"));
    }
    assert_eq!(
        status(&get(addr, &format!("GET /dead/ HTTP/1.1\r\n{host}\r\n")).0),
        502
    );
    assert_eq!(
        status(&get(addr, &format!("GET /bad/ HTTP/1.1\r\n{host}\r\n")).0),
        502
    );

    // A body delimited by close is re-framed as chunked for HTTP/1.1 ...
    let (h, b) = get(addr, &format!("GET /close/ HTTP/1.1\r\n{host}\r\n"));
    assert!(h.contains("Transfer-Encoding: chunked"), "{h}");
    assert_eq!(b, b"b\r\nuntil-close\r\n0\r\n\r\n");
    // ... and chunked framing is removed for HTTP/1.0.
    let (h, b) = get(addr, "GET /chunk/ HTTP/1.0\r\n\r\n");
    assert!(!h.contains("Transfer-Encoding"));
    assert_eq!(b, b"hi");

    // A truncated upstream body closes the client connection.
    let mut s = client(addr);
    s.write_all(format!("GET /short/ HTTP/1.1\r\n{host}\r\n").as_bytes())
        .unwrap();
    let mut all = Vec::new();
    s.read_to_end(&mut all).unwrap();
    assert!(
        all.ends_with(b"\r\n\r\nabc"),
        "{:?}",
        String::from_utf8_lossy(&all)
    );
}

#[test]
fn swap_keeps_serving_and_pools() {
    use path_match::Kind::Prefix;
    let a = echo("a");
    let b = echo("b");
    let snap = snapshot(
        vec![route(Prefix, "/", proxy(0))],
        vec![upstream(&[a.addr], 4)],
    );
    let (server, addr) = start(&snap);
    let mut s = client(addr);
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    s.write_all(req).unwrap();
    assert!(read_response(&mut s).1.starts_with(b"a "));

    // Swap in a snapshot with a new upstream first and the old one second;
    // the old target keeps its warm connection.
    let mut next = snapshot(
        vec![route(Prefix, "/", proxy(1)), route(Prefix, "/b/", proxy(0))],
        vec![upstream(&[b.addr], 4), upstream(&[a.addr], 4)],
    );
    next.revision = 2;
    next.listeners = snap.listeners.clone();
    server.swap(runtime(&next)).unwrap();
    assert_eq!(server.active().rt.revision, 2);

    s.write_all(req).unwrap();
    assert!(
        read_response(&mut s).1.starts_with(b"a "),
        "same connection sees new snapshot"
    );
    s.write_all(b"GET /b/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .unwrap();
    assert!(read_response(&mut s).1.starts_with(b"b "));
    assert_eq!(
        a.conns.load(Ordering::SeqCst),
        1,
        "pool carried over the swap"
    );
}

#[test]
fn apply_opens_and_closes_listeners() {
    use path_match::Kind::Prefix;
    let a = echo("a");
    let first = snapshot(
        vec![route(Prefix, "/", proxy(0))],
        vec![upstream(&[a.addr], 4)],
    );
    let old_addr: SocketAddr = first.listeners[0].address.parse().unwrap();
    let server = Server::new(Runtime::empty(), 1);
    let workers = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let mut listeners = Listeners::new(vec![workers.handle().clone()], false);
    listeners.apply(&server, runtime(&first)).unwrap();
    assert_eq!(listeners.addrs(), vec![old_addr]);
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mut held = client(old_addr);
    held.write_all(req).unwrap();
    assert!(read_response(&mut held).1.starts_with(b"a "));

    // A snapshot whose listener uses an address that is taken changes
    // nothing.
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut bad = first.clone();
    bad.revision = 2;
    bad.listeners[0].address = taken.local_addr().unwrap().to_string();
    assert!(listeners.apply(&server, runtime(&bad)).is_err());
    assert_eq!(server.active().rt.revision, 1);
    assert_eq!(listeners.addrs(), vec![old_addr]);

    // Moving to a new address opens it and closes the old one.
    let mut moved = first.clone();
    moved.revision = 3;
    let new_addr = free_addr();
    moved.listeners[0].address = new_addr.to_string();
    listeners.apply(&server, runtime(&moved)).unwrap();
    assert_eq!(listeners.addrs(), vec![new_addr]);
    let mut s = client(new_addr);
    s.write_all(req).unwrap();
    assert!(read_response(&mut s).1.starts_with(b"a "));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(old_addr).is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "old address still accepts"
        );
        thread::sleep(Duration::from_millis(10));
    }

    // A connection accepted on the removed address closes at its next
    // request instead of being served by a listener that no longer exists.
    held.write_all(req).unwrap();
    let mut rest = Vec::new();
    let _ = held.read_to_end(&mut rest);
    assert!(rest.is_empty(), "{:?}", String::from_utf8_lossy(&rest));
}

/// Decodes a chunked body as the test reader returns it.
fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let line = b.windows(2).position(|w| w == b"\r\n").unwrap();
        let n = usize::from_str_radix(std::str::from_utf8(&b[..line]).unwrap(), 16).unwrap();
        b = &b[line + 2..];
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&b[..n]);
        b = &b[n + 2..];
    }
}

#[test]
fn response_filters() {
    use path_match::Kind::Prefix;
    let root = std::env::temp_dir().join(format!("proxelo-filters-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("page.html"), "<p>Hello hello WORLD</p>").unwrap();
    std::fs::write(root.join("koi.txt"), "\u{416}x").unwrap();
    let mut table = vec![0u32; 256];
    table[0xf6] = 0x416;
    let mut static_route = route(Prefix, "/", static_root(&root));
    static_route.filters = Some(ir::Filters {
        sub: Some(ir::SubFilter {
            pairs: vec![ir::SubPair {
                r#match: "hello".into(),
                replacement: "bye $arg_n".into(),
            }],
            all: true,
            ..Default::default()
        }),
        charset: Some(ir::Charset {
            charset: "koi8-r".into(),
            source: "utf-8".into(),
            types: vec!["text/plain".into()],
            recode: Some(ir::charset::Recode::FromUtf8(ir::CharsetCodes {
                code_points: table,
            })),
            ..Default::default()
        }),
        userid: Some(ir::Userid {
            mode: ir::userid::Mode::On.into(),
            expires_max: true,
            ..Default::default()
        }),
        ..Default::default()
    });
    std::fs::create_dir_all(root.join("hidden")).unwrap();
    std::fs::write(root.join("hidden/top.html"), "<h1>top</h1>").unwrap();
    std::fs::write(root.join("hidden/end.html"), "<i>end</i>").unwrap();
    std::fs::create_dir_all(root.join("add")).unwrap();
    std::fs::write(root.join("add/body.html"), "body").unwrap();
    std::fs::write(root.join("add/data.json"), "{}").unwrap();
    let mut internal = route(Prefix, "/hidden/", static_root(&root));
    internal.internal = true;
    let mut added = route(Prefix, "/add/", static_root(&root));
    added.filters = Some(ir::Filters {
        addition: Some(ir::Addition {
            before: "/hidden/top.html".into(),
            after: "/hidden/end.html".into(),
            ..Default::default()
        }),
        ..Default::default()
    });
    std::fs::create_dir_all(root.join("ssi")).unwrap();
    std::fs::write(
        root.join("ssi/page.html"),
        concat!(
            r#"<!--#set var="who" value="$arg_who" -->"#,
            r#"<!--#include virtual="part.html?n=2" -->|"#,
            r#"<!--#include virtual="/hidden/top.html" set="top" -->"#,
            r#"<!--#echo var="top" -->|"#,
            r#"<!--#block name="miss" -->[<!--#echo var="who" -->]<!--#endblock -->"#,
            r#"<!--#include virtual="/hidden/nope.html" stub="miss" -->|"#,
            r#"<!--#if expr="$who = /^(?<first>.)/" --><!--#echo var="first" --><!--#else -->none<!--#endif -->"#,
        ),
    )
    .unwrap();
    std::fs::write(
        root.join("ssi/part.html"),
        r#"part <!--#echo var="arg_n" --> <!--#echo var="who" -->"#,
    )
    .unwrap();
    let mut ssi = route(Prefix, "/ssi/", static_root(&root));
    ssi.filters = Some(ir::Filters {
        ssi: Some(ir::Ssi::default()),
        ..Default::default()
    });
    let up = canned(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 11\r\nETag: \"x\"\r\n\r\nsay hello!\n");
    let mut proxied = route(Prefix, "/up/", proxy(0));
    proxied.filters = Some(ir::Filters {
        sub: Some(ir::SubFilter {
            pairs: vec![ir::SubPair {
                r#match: "HELLO".into(),
                replacement: "hi".into(),
            }],
            last_modified: true,
            ..Default::default()
        }),
        ..Default::default()
    });
    let (_, addr) = start(&snapshot(
        vec![static_route, internal, proxied, added, ssi],
        vec![upstream(&[up], 0)],
    ));
    let host = "Host: example.com\r\n";

    let (h, b) = get(addr, &format!("GET /page.html?n=1 HTTP/1.1\r\n{host}\r\n"));
    assert_eq!(status(&h), 200, "{h}");
    assert!(h.contains("Transfer-Encoding: chunked\r\n"), "{h}");
    assert!(
        !h.contains("Content-Length") && !h.contains("ETag") && !h.contains("Last-Modified"),
        "{h}"
    );
    assert!(!h.contains("Accept-Ranges"), "{h}");
    assert_eq!(dechunk(&b), b"<p>bye 1 bye 1 WORLD</p>");
    let cookie = h
        .lines()
        .find_map(|l| l.strip_prefix("Set-Cookie: uid="))
        .expect("userid cookie");
    assert!(
        cookie.ends_with("; expires=Thu, 31-Dec-37 23:55:55 GMT; path=/"),
        "{cookie}"
    );
    let value = &cookie[..cookie.find(';').unwrap()];
    assert_eq!(value.len(), 24, "{value}");

    // The client's cookie is kept, not set again.
    let (h, _) = get(
        addr,
        &format!("GET /page.html HTTP/1.1\r\n{host}Cookie: uid={value}\r\n\r\n"),
    );
    assert!(!h.contains("Set-Cookie"), "{h}");

    let (h, b) = get(addr, &format!("GET /koi.txt HTTP/1.1\r\n{host}\r\n"));
    assert!(
        h.contains("Content-Type: text/plain; charset=koi8-r\r\n"),
        "{h}"
    );
    assert_eq!(dechunk(&b), b"\xf6x");

    assert_eq!(
        status(
            &get(
                addr,
                &format!("GET /hidden/page.html HTTP/1.1\r\n{host}\r\n")
            )
            .0
        ),
        404
    );

    let (h, b) = get(addr, &format!("GET /up/ HTTP/1.1\r\n{host}\r\n"));
    assert_eq!(status(&h), 200, "{h}");
    assert!(h.contains("ETag: W/\"x\"\r\n"), "{h}");
    assert!(!h.contains("Content-Length"), "{h}");
    assert_eq!(dechunk(&b), b"say hi!\n");

    // addition wraps a 200 of its types with the internal routes' answers.
    let (h, b) = get(addr, &format!("GET /add/body.html HTTP/1.1\r\n{host}\r\n"));
    assert_eq!(status(&h), 200, "{h}");
    assert!(
        !h.contains("Content-Length") && !h.contains("Accept-Ranges"),
        "{h}"
    );
    assert!(h.contains("ETag: W/\""), "{h}");
    assert_eq!(dechunk(&b), b"<h1>top</h1>body<i>end</i>");
    // HTTP/1.0 gets it unframed, then the connection closes.
    let (h, b) = get(addr, &format!("GET /add/body.html HTTP/1.0\r\n{host}\r\n"));
    assert!(!h.contains("Transfer-Encoding"), "{h}");
    assert_eq!(b, b"<h1>top</h1>body<i>end</i>");
    // Other types and statuses pass as they are.
    let (_, b) = get(addr, &format!("GET /add/data.json HTTP/1.1\r\n{host}\r\n"));
    assert_eq!(b, b"{}");
    let (h, _) = get(addr, &format!("GET /add/nope.html HTTP/1.1\r\n{host}\r\n"));
    assert_eq!(status(&h), 404, "{h}");
    let (h, b) = get(
        addr,
        &format!("GET /add/body.html HTTP/1.1\r\n{host}Range: bytes=0-1\r\n\r\n"),
    );
    assert_eq!(status(&h), 200, "{h}");
    assert_eq!(dechunk(&b), b"<h1>top</h1>body<i>end</i>");

    // ssi: includes run in place, through the filters of their route, and
    // share the variables of the page.
    let (h, b) = get(
        addr,
        &format!("GET /ssi/page.html?who=ann HTTP/1.1\r\n{host}\r\n"),
    );
    assert_eq!(status(&h), 200, "{h}");
    assert!(
        !h.contains("Content-Length") && !h.contains("ETag") && !h.contains("Last-Modified"),
        "{h}"
    );
    assert_eq!(
        String::from_utf8(dechunk(&b)).unwrap(),
        "part 2 ann|&lt;h1&gt;top&lt;/h1&gt;|[ann]|a"
    );
    let (_, b) = get(addr, &format!("GET /ssi/page.html HTTP/1.0\r\n{host}\r\n"));
    assert_eq!(
        String::from_utf8(b).unwrap(),
        "part 2 |&lt;h1&gt;top&lt;/h1&gt;|[]|none"
    );
    // A Range or validator of the page leaves the includes whole.
    let (h, b) = get(
        addr,
        &format!(
            "GET /ssi/page.html?who=ann HTTP/1.1\r\n{host}Range: bytes=0-1\r\nIf-Modified-Since: Thu, 01 Jan 2099 00:00:00 GMT\r\n\r\n"
        ),
    );
    assert_eq!(status(&h), 200, "{h}");
    assert_eq!(
        String::from_utf8(dechunk(&b)).unwrap(),
        "part 2 ann|&lt;h1&gt;top&lt;/h1&gt;|[ann]|a"
    );
}

/// Accepts connections and sends each request head and body it reads down
/// `tx`, answering 200 with an empty body.
fn recorder() -> (SocketAddr, std::sync::mpsc::Receiver<String>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            let tx = tx.clone();
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut b = [0u8; 4096];
                let end = loop {
                    if let Some(e) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break e + 4;
                    }
                    match s.read(&mut b) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&b[..n]),
                        _ => return,
                    }
                };
                let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length: "))
                    .map_or(0, |v| v.parse().unwrap());
                while buf.len() < end + len {
                    let n = s.read(&mut b).unwrap();
                    buf.extend_from_slice(&b[..n]);
                }
                let _ = tx.send(String::from_utf8_lossy(&buf[..end + len]).into_owned());
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            });
        }
    });
    (addr, rx)
}

#[test]
fn mirror() {
    use path_match::Kind::Prefix;
    let (up, seen) = recorder();
    let app = echo("app");
    let mut internal = route(Prefix, "/copy/", proxy(1));
    internal.internal = true;
    let mut main = route(Prefix, "/api/", proxy(0));
    main.mirror = Some(ir::Mirror {
        uris: vec!["/copy/a".into(), "/copy/b".into()],
        request_body: true,
    });
    let mut bodiless = route(Prefix, "/nobody/", proxy(0));
    bodiless.mirror = Some(ir::Mirror {
        uris: vec!["/copy/c".into()],
        request_body: false,
    });
    let (_, addr) = start(&snapshot(
        vec![internal, main, bodiless],
        vec![upstream(&[app.addr], 0), upstream(&[up], 0)],
    ));
    let host = "Host: example.com\r\n";
    let recv = || seen.recv_timeout(Duration::from_secs(5)).expect("mirrored");

    // The client gets the main answer; each mirror URI sees the method,
    // arguments and body.
    let (h, b) = get(
        addr,
        &format!("POST /api/x?q=1 HTTP/1.1\r\n{host}Content-Length: 4\r\n\r\nping"),
    );
    assert_eq!(status(&h), 200, "{h}");
    let b = String::from_utf8(b).unwrap();
    assert!(b.starts_with("app POST /api/x?q=1 HTTP/1.1 "), "{b}");
    assert!(b.ends_with(" body=ping"), "{b}");
    let mut got = [recv(), recv()];
    got.sort();
    for (m, uri) in got.iter().zip(["/copy/a?q=1", "/copy/b?q=1"]) {
        assert!(m.starts_with(&format!("POST {uri} HTTP/1.1\r\n")), "{m}");
        assert!(m.ends_with("\r\n\r\nping"), "{m}");
    }

    let (h, _) = get(
        addr,
        &format!("PUT /nobody/ HTTP/1.1\r\n{host}Content-Length: 2\r\n\r\nhi"),
    );
    assert_eq!(status(&h), 200, "{h}");
    let m = recv();
    assert!(m.starts_with("PUT /copy/c HTTP/1.1\r\n"), "{m}");
    assert!(m.ends_with("\r\n\r\n"), "{m}");

    // The internal route is not reachable from outside.
    let (h, _) = get(addr, &format!("GET /copy/a HTTP/1.1\r\n{host}\r\n"));
    assert_eq!(status(&h), 404, "{h}");
    assert!(seen.recv_timeout(Duration::from_millis(200)).is_err());
}
