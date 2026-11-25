//! Dry runs of requests against a snapshot:
//! the request is parsed by the HTTP/1.1 parser and taken through the same
//! site lookup and phases as served traffic, without sockets. A proxy outcome
//! reports the upstream; static files are looked up on this file system.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use proxelo_api::sim::v1::{HttpRequest, Result as SimResult, result::Kind};
use proxelo_http1::parse_request;
use proxelo_snapshot::{MatchError, Runtime};

use crate::exchange::Exchange;
use crate::phases::{Outcome, Phases};

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Runs one request through `rt`.
pub fn simulate(rt: &Runtime, r: &HttpRequest) -> SimResult {
    let mut out = SimResult::default();
    let Some(listener) = (if r.listener.is_empty() {
        rt.listeners.first()
    } else {
        rt.listeners.iter().find(|l| *l.id == *r.listener)
    }) else {
        out.trace.push(format!("no listener {:?}", r.listener));
        return page(out, 404);
    };
    let local = listener
        .addrs
        .first()
        .copied()
        .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
    let ip: IpAddr = if r.remote_addr.is_empty() {
        Ipv4Addr::LOCALHOST.into()
    } else {
        match r.remote_addr.parse() {
            Ok(ip) => ip,
            Err(_) => {
                out.trace
                    .push(format!("bad remote_addr {:?}", r.remote_addr));
                return page(out, 400);
            }
        }
    };
    let mut x = Exchange::new(local, SocketAddr::new(ip, 0));

    // The request as a client would send it, read by the serving parser.
    let method = if r.method.is_empty() {
        "GET"
    } else {
        &r.method
    };
    let target = if r.target.is_empty() { "/" } else { &r.target };
    let mut head = format!("{method} {target} HTTP/1.1\r\n");
    // HTTP/1.1 requires Host; without one, send what a client connecting to
    // the listener address would.
    if !r.headers.iter().any(|h| h.name.eq_ignore_ascii_case("host")) {
        head.push_str(&format!("Host: {local}\r\n"));
    }
    for h in &r.headers {
        head.push_str(&h.name);
        head.push_str(": ");
        head.push_str(&h.value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    x.head = head.into_bytes();
    match parse_request(&x.head, &mut x.req) {
        Ok(true) => {}
        Ok(false) => return page(out, 400),
        Err(e) => {
            out.trace.push(format!("parse: {e:?}"));
            return page(out, e.status());
        }
    }
    if let Err(status) = x.begin() {
        return page(out, status);
    }
    let site = match listener.site(x.host()) {
        Ok(Some(s)) => s,
        Ok(None) => {
            out.trace.push("no site".into());
            return page(out, 404);
        }
        Err(MatchError) => return page(out, 500),
    };
    let site = &rt.sites[site as usize];
    out.site = site.id.to_string();
    let mut phases = Phases::new(site, true);
    let outcome = phases.run(&mut x);
    let location = |x: &Exchange| {
        if x.tmpl.starts_with(b"/") {
            let mut l = Vec::new();
            crate::reply::push_origin(&mut l, &x.host, x.local);
            l.extend_from_slice(&x.tmpl);
            text(&l)
        } else {
            text(&x.tmpl)
        }
    };
    match outcome {
        Outcome::Text(s) => {
            out.kind = Kind::Response as i32;
            out.status = x.status(s).into();
            out.body = text(&x.tmpl);
        }
        Outcome::Redirect(s) => {
            out.kind = Kind::Redirect as i32;
            out.status = x.status(s).into();
            out.location = location(&x);
        }
        Outcome::Page(s) => {
            out.kind = Kind::Response as i32;
            out.status = s.into();
        }
        Outcome::File(..) => {
            out.kind = Kind::File as i32;
            out.status = x.status(200).into();
            out.file = text(&x.scratch);
        }
        Outcome::Directory => {
            out.kind = Kind::Redirect as i32;
            out.status = 301;
            x.tmpl.clone_from(&x.path);
            x.tmpl.push(b'/');
            if !x.args.is_empty() {
                x.tmpl.push(b'?');
                x.tmpl.extend_from_slice(&x.args);
            }
            out.location = location(&x);
        }
        Outcome::Proxy(u) => {
            let up = &rt.upstreams[u as usize];
            out.kind = Kind::Proxy as i32;
            out.status = x.err_status.into();
            out.upstream = up.id.to_string();
            out.targets = up.targets.iter().map(|t| t.addr.to_string()).collect();
        }
        Outcome::Close => out.kind = Kind::Close as i32,
    }
    if let Some(r) = phases.route {
        out.route = site.routes[r as usize].id.to_string();
    }
    out.uri = text(&x.path);
    if !x.args.is_empty() {
        out.uri.push('?');
        out.uri.push_str(&text(&x.args));
    }
    out.trace = phases.trace.unwrap_or_default();
    out
}

fn page(mut out: SimResult, status: u16) -> SimResult {
    out.kind = Kind::Response as i32;
    out.status = status.into();
    out
}
