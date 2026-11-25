//! Once a keepalive connection is warm, serving a request must not allocate.
//! Kept as its own test binary with one test so the
//! global allocation counters see only this traffic.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use proxelo_api::snapshot::v1::{
    self as ir, Action, Listener, PathMatch, ProxyAction, Route, Site, StaticAction, Target,
    Upstream, action, path_match,
};
use proxelo_server::{Listeners, Server};
use proxelo_snapshot::Runtime;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<std::alloc::System> = &INSTRUMENTED_SYSTEM;

const UPSTREAM_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nContent-Type: text/plain\r\n\r\n";

/// An upstream that answers every request with a fixed 1 KiB body and never
/// allocates after accepting.
fn upstream() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        let mut resp = UPSTREAM_RESPONSE.to_vec();
        resp.resize(UPSTREAM_RESPONSE.len() + 1024, b'x');
        for s in l.incoming() {
            let mut s = s.unwrap();
            let resp = resp.clone();
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let mut end = 0;
                loop {
                    match s.read(&mut buf[end..]) {
                        Ok(n) if n > 0 => end += n,
                        _ => return,
                    }
                    while let Some(i) = buf[..end].windows(4).position(|w| w == b"\r\n\r\n") {
                        buf.copy_within(i + 4..end, 0);
                        end -= i + 4;
                        if s.write_all(&resp).is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    addr
}

fn route(path: &str, action: action::Kind) -> Route {
    route_kind(path_match::Kind::Prefix, path, action)
}

fn route_kind(kind: path_match::Kind, path: &str, action: action::Kind) -> Route {
    Route {
        path: Some(PathMatch {
            kind: kind as i32,
            value: path.into(),
        }),
        action: Some(Action { kind: Some(action) }),
        ..Default::default()
    }
}

/// Reads one response with a Content-Length body into `buf` without
/// allocating. Returns the status.
fn read_one(s: &mut TcpStream, buf: &mut [u8]) -> u16 {
    let mut end = 0;
    loop {
        let n = s.read(&mut buf[end..]).unwrap();
        assert!(n > 0);
        end += n;
        let Some(head) = buf[..end].windows(4).position(|w| w == b"\r\n\r\n") else {
            continue;
        };
        let head = head + 4;
        let text = &buf[..head];
        let at = text
            .windows(16)
            .position(|w| w == b"Content-Length: ")
            .unwrap()
            + 16;
        let len = text[at..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .fold(0usize, |n, &d| n * 10 + usize::from(d - b'0'));
        while end < head + len {
            let n = s.read(&mut buf[end..]).unwrap();
            assert!(n > 0);
            end += n;
        }
        assert_eq!(end, head + len);
        return (buf[9] - b'0') as u16 * 100
            + (buf[10] - b'0') as u16 * 10
            + (buf[11] - b'0') as u16;
    }
}

#[test]
fn warm_requests_do_not_allocate() {
    let root = std::env::temp_dir().join(format!("proxelo-alloc-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("1k.txt"), vec![b'a'; 1024]).unwrap();

    let snap = ir::Snapshot {
        revision: 1,
        listeners: vec![Listener {
            address: TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .to_string(),
            ..Default::default()
        }],
        sites: vec![Site {
            listeners: vec![0],
            routes: vec![
                route(
                    "/",
                    action::Kind::Static(StaticAction {
                        root: root.to_str().unwrap().into(),
                        ..Default::default()
                    }),
                ),
                route("/api/", action::Kind::Proxy(ProxyAction { upstream: 0 })),
                // Regex locations: every request is checked against them, the
                // case-insensitive one matches /img/ requests.
                route_kind(
                    path_match::Kind::Regex,
                    r"\.php$",
                    action::Kind::Proxy(ProxyAction { upstream: 0 }),
                ),
                route_kind(
                    path_match::Kind::RegexCi,
                    r"^/img/.+\.(png|jpg)$",
                    action::Kind::Proxy(ProxyAction { upstream: 0 }),
                ),
            ],
            ..Default::default()
        }],
        upstreams: vec![Upstream {
            targets: vec![Target {
                address: upstream().to_string(),
                weight: 1,
            }],
            keepalive_idle: 4,
            ..Default::default()
        }],
        ..Default::default()
    };
    proxelo_snapshot::validate(&snap).unwrap();
    let rt = Runtime::build(&snap).unwrap();
    let addr = rt.listeners[0].addrs[0];
    let server = Server::new(Runtime::empty(), 1);
    let worker = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut listeners = Listeners::new(vec![worker.handle().clone()], false);
    listeners.apply(&server, rt).unwrap();
    thread::spawn(move || worker.block_on(std::future::pending::<()>()));

    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = vec![0u8; 8192];
    let requests: [&[u8]; 3] = [
        b"GET /1k.txt HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bench\r\nAccept: */*\r\n\r\n",
        b"GET /api/item?id=7 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bench\r\nAccept: */*\r\n\r\n",
        b"GET /img/a.PNG HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bench\r\nAccept: */*\r\n\r\n",
    ];

    // Warm up: buffers grow to size and the upstream connection is pooled.
    for _ in 0..20 {
        for r in requests {
            s.write_all(r).unwrap();
            assert_eq!(read_one(&mut s, &mut buf), 200);
        }
    }

    let region = Region::new(GLOBAL);
    for _ in 0..200 {
        for r in requests {
            s.write_all(r).unwrap();
            assert_eq!(read_one(&mut s, &mut buf), 200);
        }
    }
    let stats = region.change();
    assert_eq!(
        (stats.allocations, stats.reallocations),
        (0, 0),
        "allocations on warm requests: {stats:?}"
    );
}
