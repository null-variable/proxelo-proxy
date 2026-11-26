//! Upstream features over real sockets: active health checks, sticky
//! cookies and the request queue.
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use proxelo_api::snapshot::v1::{
    self as ir, Action, HealthCheck, HostMatch, Listener, PathMatch, ProxyAction, Route, Site,
    Sticky, Target, Upstream, action, health_check, host_match, path_match, sticky,
};
use proxelo_server::{Listeners, Server};
use proxelo_snapshot::Runtime;

fn snapshot(up: Upstream) -> ir::Snapshot {
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
                    kind: Some(action::Kind::Proxy(ProxyAction {
                        upstream: 0,
                        ..Default::default()
                    })),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }],
        upstreams: vec![up],
        ..Default::default()
    }
}

fn upstream(addrs: &[SocketAddr]) -> Upstream {
    Upstream {
        targets: addrs
            .iter()
            .map(|a| Target {
                address: a.to_string(),
                weight: 1,
                ..Default::default()
            })
            .collect(),
        max_fails: 0,
        ..Default::default()
    }
}

fn start(snap: &ir::Snapshot) -> SocketAddr {
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
    std::mem::forget(server);
    addr
}

/// An upstream answering `name` with a status that `healthy` switches
/// between 200 and 503, one request per connection.
fn backend(name: &'static str, healthy: Arc<AtomicBool>, delay: Duration) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            let healthy = healthy.clone();
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut b = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&b[..n]),
                        _ => return,
                    }
                }
                thread::sleep(delay);
                let status = if healthy.load(Ordering::SeqCst) {
                    "200 OK"
                } else {
                    "503 Service Unavailable"
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{name}",
                    name.len()
                );
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    addr
}

fn get(addr: SocketAddr, extra: &str) -> (String, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET /x HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n{extra}\r\n"
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let (head, body) = out.split_once("\r\n\r\n").unwrap();
    (head.to_owned(), body.to_owned())
}

#[test]
fn active_health_check_takes_a_target_out_and_back() {
    let a_ok = Arc::new(AtomicBool::new(true));
    let a = backend("a", a_ok.clone(), Duration::ZERO);
    let b = backend("b", Arc::new(AtomicBool::new(true)), Duration::ZERO);
    let mut up = upstream(&[a, b]);
    up.health_check = Some(HealthCheck {
        kind: health_check::Kind::Http.into(),
        interval_ms: 50,
        timeout_ms: 500,
        ..Default::default()
    });
    let addr = start(&snapshot(up));
    let bodies = |n| (0..n).map(|_| get(addr, "").1).collect::<Vec<_>>();
    assert!(bodies(4).contains(&"a".to_owned()));
    a_ok.store(false, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(300));
    assert!(bodies(6).iter().all(|b| b == "b"), "a is out");
    a_ok.store(true, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(300));
    assert!(bodies(6).contains(&"a".to_owned()), "a is back");
}

#[test]
fn sticky_cookie_pins_the_target() {
    let on = Arc::new(AtomicBool::new(true));
    let a = backend("a", on.clone(), Duration::ZERO);
    let b = backend("b", on, Duration::ZERO);
    let mut up = upstream(&[a, b]);
    up.sticky = Some(Sticky {
        kind: sticky::Kind::Cookie.into(),
        cookie: "srv".into(),
        http_only: true,
        ..Default::default()
    });
    let addr = start(&snapshot(up));
    let (head, first) = get(addr, "");
    let cookie = head
        .lines()
        .find_map(|l| l.strip_prefix("Set-Cookie: srv="))
        .expect("sticky cookie set");
    assert!(cookie.ends_with("; Path=/; HttpOnly"), "{cookie}");
    let value = &cookie[..8];
    for _ in 0..6 {
        let (head, body) = get(addr, &format!("Cookie: x=1; srv={value}\r\n"));
        assert_eq!(body, first);
        assert!(!head.contains("Set-Cookie"), "already pinned: {head}");
    }
}

#[test]
fn queue_waits_for_max_conns() {
    let on = Arc::new(AtomicBool::new(true));
    let a = backend("a", on, Duration::from_millis(150));
    let mut up = upstream(&[a]);
    up.targets[0].max_conns = 1;
    up.queue_size = 4;
    up.queue_timeout_ms = 5000;
    let addr = start(&snapshot(up));
    let reqs: Vec<_> = (0..3)
        .map(|_| thread::spawn(move || get(addr, "")))
        .collect();
    for r in reqs {
        let (head, body) = r.join().unwrap();
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert_eq!(body, "a");
    }

    // Without a queue the second concurrent request fails at once.
    let on = Arc::new(AtomicBool::new(true));
    let a = backend("a", on, Duration::from_millis(300));
    let mut up = upstream(&[a]);
    up.targets[0].max_conns = 1;
    let addr = start(&snapshot(up));
    let slow = thread::spawn(move || get(addr, ""));
    thread::sleep(Duration::from_millis(100));
    let (head, _) = get(addr, "");
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    assert!(slow.join().unwrap().0.starts_with("HTTP/1.1 200"));
}
