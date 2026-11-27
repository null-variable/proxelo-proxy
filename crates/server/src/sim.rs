//! Dry runs of requests against a snapshot:
//! the request is parsed by the HTTP/1.1 parser and taken through the same
//! site lookup and phases as served traffic, without sockets. A proxy outcome
//! reports the upstream; static files are looked up on this file system.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use proxelo_api::sim::v1::{Header, HttpRequest, Result as SimResult, result::Kind};
use proxelo_http1::parse_request;
use proxelo_snapshot::{MatchError, Runtime};

use crate::exchange::Exchange;
use crate::phases::{Outcome, Phases};
use crate::tls::TlsInfo;

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
    x.lookups = std::sync::Arc::clone(&rt.lookups);
    x.compressions = std::sync::Arc::clone(&rt.compressions);
    if r.tls {
        x.tls = Some(TlsInfo::default());
    }

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
    if !r
        .headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("host"))
    {
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
    if site.redirect_https && !r.tls {
        out.kind = Kind::Redirect as i32;
        out.status = 301;
        out.location = format!(
            "https://{}{}",
            if x.host.is_empty() {
                local.ip().to_string()
            } else {
                text(&x.host)
            },
            text(x.req.target.get(&x.head))
        );
        out.trace.push("redirect to https".into());
        return out;
    }
    if let Some(ri) = &site.real_ip {
        crate::access::real_ip(&mut x, ri);
        if x.peer != x.conn_peer {
            out.trace.push(format!("real_ip {}", x.peer.ip()));
        }
    }
    let mut phases = Phases::new(site, true);
    // The access phase runs what needs no network; limits and forward auth
    // are noted and assumed to pass.
    let outcome = loop {
        match phases.run(&mut x) {
            Outcome::Access(r) => {
                let a = &site.routes[r as usize].access;
                if let Some(t) = &mut phases.trace {
                    if !a.rate_limits.is_empty() || !a.conn_limits.is_empty() {
                        t.push("limits not simulated".into());
                    }
                    if a.forward_auth.is_some() {
                        t.push("forward auth not simulated".into());
                    }
                    if a.jwt.is_some() || a.oidc.is_some() {
                        t.push("jwt and oidc not simulated".into());
                    }
                }
                let result = crate::access::check(&mut x, a);
                phases.accessed(r, result);
            }
            o => break o,
        }
    };
    let location = |x: &Exchange| {
        if x.tmpl.starts_with(b"/") {
            let mut l = Vec::new();
            crate::reply::push_origin(&mut l, x.tls.is_some(), &x.host, x.local);
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
        Outcome::Proxy(p) | Outcome::Pass(p) => {
            let up = &rt.upstreams[p.upstream as usize];
            out.kind = Kind::Proxy as i32;
            out.status = x.err_status.into();
            out.upstream = up.id.to_string();
            out.targets = up.targets.iter().map(|t| t.addr.to_string()).collect();
        }
        Outcome::Close => out.kind = Kind::Close as i32,
        Outcome::Access(_) => unreachable!("resolved above"),
    }
    let route = phases.route.map(|r| &site.routes[r as usize]);
    if let Some(r) = route {
        out.route = r.id.to_string();
    }
    let hdr = |b: &[u8]| {
        let line = text(b);
        line.lines()
            .filter_map(|l| l.split_once(": "))
            .map(|(n, v)| Header {
                name: n.into(),
                value: v.into(),
            })
            .collect::<Vec<_>>()
    };
    let ops = route.map_or(&site.response_headers, |r| &r.response_headers);
    if !ops.is_empty() {
        let status = if out.status == 0 {
            200
        } else {
            out.status as u16
        };
        crate::headers::response(&mut x, ops, status);
        out.response_headers = hdr(&x.resp_extra);
    }
    if out.kind == Kind::Proxy as i32
        && let Some(r) = route
        && !r.request_headers.is_empty()
    {
        let mut b = Vec::new();
        crate::headers::request(&mut x, &r.request_headers, &mut b);
        out.request_headers = hdr(&b);
    }
    out.uri = text(&x.path);
    if !x.args.is_empty() {
        out.uri.push('?');
        out.uri.push_str(&text(&x.args));
    }
    out.trace.extend(phases.trace.unwrap_or_default());
    out
}

fn page(mut out: SimResult, status: u16) -> SimResult {
    out.kind = Kind::Response as i32;
    out.status = status.into();
    out
}
