//! nginx post_read and access phases: realip, allow/deny, auth_basic,
//! auth_jwt, OpenID Connect and auth_request (forward auth). Limits are in
//! `limits`.

use std::net::{IpAddr, SocketAddr};

use proxelo_http1::{Body, HeaderKind, parse_response};
use proxelo_snapshot::{Access, BasicAuth, ForwardAuth, RealIp};
use tokio::time::timeout;

use crate::Active;
use crate::conn::Conn;
use crate::exchange::Exchange;
use crate::io::write_timeout;
use crate::upstream::{Choice, Conn as UpConn};
use crate::vars::expand;

/// Forward auth responses larger than this are not read for reuse; the
/// connection is closed instead.
const AUTH_BODY_MAX: u64 = 64 * 1024;

/// Parses an address as nginx ngx_parse_addr_port: `ip`, `ip:port` or
/// `[ip]:port`.
fn parse_addr(s: &[u8]) -> Option<SocketAddr> {
    let s = std::str::from_utf8(s).ok()?;
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 0));
    }
    s.parse().ok()
}

enum Found {
    Declined,
    Ok,
    Done,
}

/// nginx ngx_http_get_forwarded_addr_internal over one header value.
fn forwarded_in(addr: &mut SocketAddr, value: &[u8], ri: &RealIp) -> Found {
    let mut found = false;
    let mut len = value.len();
    loop {
        if !ri.trusted(addr.ip()) {
            return if found { Found::Done } else { Found::Declined };
        }
        let mut end = len;
        while end > 1 && matches!(value[end - 1], b' ' | b',') {
            end -= 1;
        }
        let start = value[..end]
            .iter()
            .rposition(|&c| c == b' ' || c == b',')
            .map_or(0, |i| i + 1);
        let Some(a) = parse_addr(&value[start..end]) else {
            return if found { Found::Done } else { Found::Declined };
        };
        *addr = a;
        found = true;
        if !ri.recursive || start == 0 {
            return Found::Ok;
        }
        len = start - 1;
    }
}

/// nginx realip: replaces the client address with the one the trusted proxy
/// in front reported. X-Forwarded-For headers are read from the last.
pub(crate) fn real_ip(x: &mut Exchange, ri: &RealIp) {
    let mut addr = x.peer;
    let changed = if &*ri.header == b"x-forwarded-for" {
        let mut rc = Found::Declined;
        let mut found = false;
        for h in x.req.headers.iter().rev() {
            if !h.name.get(&x.head).eq_ignore_ascii_case(b"x-forwarded-for") {
                continue;
            }
            rc = forwarded_in(&mut addr, h.value.get(&x.head), ri);
            if !ri.recursive {
                break;
            }
            if matches!(rc, Found::Declined) && found {
                rc = Found::Done;
                break;
            }
            if !matches!(rc, Found::Ok) {
                break;
            }
            found = true;
        }
        !matches!(rc, Found::Declined)
    } else {
        match x.request_header(&ri.header) {
            Some(v) => !matches!(forwarded_in(&mut addr, v, ri), Found::Declined),
            None => false,
        }
    };
    if changed {
        x.peer = addr;
    }
}

/// Decodes base64 into `out`. `None` for bad input.
fn base64_into(s: &[u8], out: &mut Vec<u8>) -> Option<()> {
    let mut acc = 0u32;
    let mut bits = 0;
    for &c in s {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(())
}

/// The `user:password` of a Basic Authorization header, decoded into `out`,
/// as nginx ngx_http_auth_basic_user. Returns the position of the colon.
pub(crate) fn basic_credentials(x: &Exchange, out: &mut Vec<u8>) -> Option<usize> {
    out.clear();
    let v = x.request_header(b"authorization")?;
    if v.len() < 6 || !v[..6].eq_ignore_ascii_case(b"basic ") {
        return None;
    }
    let enc = v[6..].trim_ascii_start();
    if enc.is_empty() {
        return None;
    }
    base64_into(enc, out)?;
    match out.iter().position(|&c| c == b':') {
        Some(0) | None => None,
        Some(i) => Some(i),
    }
}

/// nginx auth_basic. `Err(401)` carries the challenge in `x.auth_header`.
fn basic(x: &mut Exchange, b: &BasicAuth) -> Result<(), u16> {
    let mut creds = std::mem::take(&mut x.scratch);
    let ok = basic_credentials(x, &mut creds).is_some_and(|colon| {
        let (user, pass) = (&creds[..colon], &creds[colon + 1..]);
        b.users
            .iter()
            .find(|u| *u.name == *user)
            .is_some_and(|u| crate::passwd::verify(pass, &u.hash))
    });
    creds.clear();
    x.scratch = creds;
    if ok {
        return Ok(());
    }
    x.auth_header.clear();
    x.auth_header.extend_from_slice(b"WWW-Authenticate: ");
    x.auth_header.extend_from_slice(&b.challenge);
    x.auth_header.extend_from_slice(b"\r\n");
    Err(401)
}

/// The checks that need no I/O: allow/deny and basic auth.
pub(crate) fn check(x: &mut Exchange, a: &Access) -> Result<(), u16> {
    if !a.allows(x.peer.ip()) {
        return Err(403);
    }
    if let Some(b) = &a.basic_auth {
        basic(x, b)?;
    }
    Ok(())
}

impl Conn {
    /// Runs the access phase of `route` in `site`. `Err` is the status to
    /// answer through the error pages.
    pub(crate) async fn access(
        &mut self,
        active: &Active,
        site: u32,
        route: u32,
    ) -> Result<(), u16> {
        let rt = &active.rt;
        let a = &rt.sites[site as usize].routes[route as usize].access;
        if !self.x.limited && (!a.rate_limits.is_empty() || !a.conn_limits.is_empty()) {
            self.x.limited = true;
            match crate::limits::rate(&mut self.x, rt, &active.zones, &a.rate_limits) {
                crate::limits::Limited::Pass => {}
                crate::limits::Limited::Delay(d) => tokio::time::sleep(d).await,
                crate::limits::Limited::Reject(s) => return Err(s),
            }
            crate::limits::conn(
                &mut self.x,
                rt,
                &active.zones,
                &a.conn_limits,
                &mut self.holds,
            )?;
        }
        check(&mut self.x, a)?;
        if let Some(j) = &a.jwt {
            crate::jwt::check(&mut self.x, j).await?;
        }
        if let Some(o) = &a.oidc {
            crate::oidc::check(&mut self.x, o).await?;
        }
        if !a.wasm.is_empty() {
            let plugins = &active.wasm[site as usize][route as usize];
            self.wasm_request(plugins).await?;
        }
        if let Some(f) = &a.forward_auth {
            self.forward_auth(active, f).await?;
        }
        Ok(())
    }

    /// nginx auth_request against the forward auth upstream.
    async fn forward_auth(&mut self, active: &Active, f: &ForwardAuth) -> Result<(), u16> {
        let ups = &active.upstreams[f.upstream as usize];
        let mut choice = Choice::default();
        self.balancing_key(active, f.upstream);
        let key = std::mem::take(&mut self.x.tmpl);
        let picked = ups.pick(&mut choice, &key);
        self.x.tmpl = key;
        let Some(picked) = picked else {
            return Err(500);
        };
        let i = picked.index;
        let pool = &ups.pools()[i];
        let mut up = match pool.take() {
            Some(c) => c,
            None => match ups.connect(i, f.timeout).await {
                Ok(s) => UpConn {
                    stream: s,
                    used: 0,
                    opened: std::time::Instant::now(),
                },
                Err(_) => {
                    ups.failed(i);
                    active.metrics.upstream_failure(f.upstream, i);
                    return Err(500);
                }
            },
        };
        self.auth_head(f, &ups.host, ups.keepalive, pool.addr);
        if write_timeout(&mut up.stream, &self.out, f.timeout)
            .await
            .is_err()
        {
            ups.failed(i);
            return Err(500);
        }
        self.ubuf.end = 0;
        let head = loop {
            match parse_response(self.ubuf.filled(), false, &mut self.resp) {
                Ok(true) if self.resp.status >= 200 => break true,
                Ok(true) => {
                    self.ubuf.consume(self.resp.head_len);
                    continue;
                }
                Ok(false) if self.ubuf.end < 16 * 1024 => {}
                _ => break false,
            }
            match timeout(f.timeout, self.ubuf.fill(&mut up.stream, 4096, 16 * 1024)).await {
                Ok(Ok(n)) if n > 0 => {}
                _ => break false,
            }
        };
        if !head {
            ups.failed(i);
            active.metrics.upstream_failure(f.upstream, i);
            return Err(500);
        }
        ups.succeeded(i);
        let status = self.resp.status;
        self.x.auth_resp.clear();
        self.x.auth_header.clear();
        for h in self.resp.headers.iter() {
            let name = h.name.get(&self.ubuf.data);
            let value = h.value.get(&self.ubuf.data);
            if (200..300).contains(&status)
                && f.copy_headers.iter().any(|c| c.eq_ignore_ascii_case(name))
            {
                self.x.auth_resp.extend_from_slice(name);
                self.x.auth_resp.extend_from_slice(b": ");
                self.x.auth_resp.extend_from_slice(value);
                self.x.auth_resp.extend_from_slice(b"\r\n");
            }
            if status == 401 && name.eq_ignore_ascii_case(b"www-authenticate") {
                self.x.auth_header.extend_from_slice(b"WWW-Authenticate: ");
                self.x.auth_header.extend_from_slice(value);
                self.x.auth_header.extend_from_slice(b"\r\n");
            }
        }
        // Drain a small body so the connection can be reused.
        let reusable = self.resp.keep_alive
            && ups.keepalive
            && match self.resp.body {
                Body::None => true,
                Body::Length(n) if n <= AUTH_BODY_MAX => {
                    let mut left = n as usize;
                    self.ubuf.consume(self.resp.head_len);
                    loop {
                        let take = left.min(self.ubuf.end);
                        self.ubuf.consume(take);
                        left -= take;
                        if left == 0 {
                            break self.ubuf.end == 0;
                        }
                        match timeout(f.timeout, self.ubuf.fill(&mut up.stream, 4096, 16 * 1024))
                            .await
                        {
                            Ok(Ok(n)) if n > 0 => {}
                            _ => break false,
                        }
                    }
                }
                _ => false,
            };
        if reusable {
            up.used += 1;
            if up.used < ups.keepalive_requests && up.opened.elapsed() < ups.keepalive_time {
                pool.put(up);
            }
        }
        self.ubuf.end = 0;
        match status {
            200..=299 => Ok(()),
            401 | 403 => Err(status),
            _ => Err(500),
        }
    }

    /// The forward auth request: GET of the expanded URI with the client's
    /// headers and where the request was going.
    fn auth_head(&mut self, f: &ForwardAuth, host: &str, keepalive: bool, target: SocketAddr) {
        expand(&mut self.x, &f.uri);
        let mut out = std::mem::take(&mut self.out);
        out.clear();
        out.extend_from_slice(b"GET ");
        crate::reply::push_header_value(&mut out, &self.x.tmpl);
        out.extend_from_slice(b" HTTP/1.1\r\n");
        for h in self.x.req.headers.iter() {
            if h.kind.is_hop_by_hop()
                || matches!(
                    h.kind,
                    HeaderKind::Host | HeaderKind::Expect | HeaderKind::ContentLength
                )
            {
                continue;
            }
            out.extend_from_slice(h.name.get(&self.x.head));
            out.extend_from_slice(b": ");
            out.extend_from_slice(h.value.get(&self.x.head));
            out.extend_from_slice(b"\r\n");
        }
        if host.is_empty() {
            let _ = std::io::Write::write_fmt(&mut out, format_args!("Host: {target}\r\n"));
        } else {
            out.extend_from_slice(b"Host: ");
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"X-Forwarded-Method: ");
        out.extend_from_slice(self.x.req.method_span.get(&self.x.head));
        out.extend_from_slice(if self.x.https() {
            b"\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Host: "
        } else {
            b"\r\nX-Forwarded-Proto: http\r\nX-Forwarded-Host: "
        });
        out.extend_from_slice(&self.x.host);
        out.extend_from_slice(b"\r\nX-Forwarded-Uri: ");
        out.extend_from_slice(self.x.req.target.get(&self.x.head));
        out.extend_from_slice(b"\r\n");
        if !keepalive {
            out.extend_from_slice(b"Connection: close\r\n");
        }
        out.extend_from_slice(b"\r\n");
        self.out = out;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxelo_snapshot::Cidr;

    fn exchange(peer: &str, headers: &[(&str, &str)]) -> Exchange {
        let mut x = Exchange::new("127.0.0.1:80".parse().unwrap(), peer.parse().unwrap());
        let mut head = String::from("GET / HTTP/1.1\r\nHost: a\r\n");
        for (n, v) in headers {
            head.push_str(&format!("{n}: {v}\r\n"));
        }
        head.push_str("\r\n");
        x.head = head.into_bytes();
        assert!(proxelo_http1::parse_request(&x.head, &mut x.req).unwrap());
        x.begin().unwrap();
        x
    }

    fn ri(from: &[&str], header: &str, recursive: bool) -> RealIp {
        RealIp {
            from: from.iter().map(|c| Cidr::parse(c).unwrap()).collect(),
            header: header.as_bytes().into(),
            recursive,
        }
    }

    #[test]
    fn real_ip_from_trusted_proxies() {
        let xff = [("X-Forwarded-For", "1.1.1.1, 10.0.0.2, 10.0.0.3")];
        // Not recursive: the last address.
        let mut x = exchange("10.0.0.1:5000", &xff);
        real_ip(&mut x, &ri(&["10.0.0.0/8"], "x-forwarded-for", false));
        assert_eq!(x.peer, "10.0.0.3:0".parse().unwrap());
        // Recursive: the last untrusted one.
        let mut x = exchange("10.0.0.1:5000", &xff);
        real_ip(&mut x, &ri(&["10.0.0.0/8"], "x-forwarded-for", true));
        assert_eq!(x.peer, "1.1.1.1:0".parse().unwrap());
        // An untrusted peer is kept.
        let mut x = exchange("192.0.2.1:5000", &xff);
        real_ip(&mut x, &ri(&["10.0.0.0/8"], "x-forwarded-for", true));
        assert_eq!(x.peer, "192.0.2.1:5000".parse().unwrap());
        let mut x = exchange("10.0.0.1:5000", &[("X-Real-IP", "[2001:db8::1]:443")]);
        real_ip(&mut x, &ri(&["10.0.0.0/8"], "x-real-ip", false));
        assert_eq!(x.peer, "[2001:db8::1]:443".parse().unwrap());
        // begin() restores the connection's address for the next request.
        x.begin().unwrap();
        assert_eq!(x.peer, "10.0.0.1:5000".parse().unwrap());
    }

    #[test]
    fn basic_auth() {
        let b = BasicAuth {
            challenge: (*b"Basic realm=\"r\"").into(),
            users: [proxelo_snapshot::BasicUser {
                name: (*b"alice").into(),
                hash: "{PLAIN}secret".into(),
            }]
            .into(),
        };
        // alice:secret
        let mut x = exchange("1.2.3.4:1", &[("Authorization", "Basic YWxpY2U6c2VjcmV0")]);
        assert_eq!(basic(&mut x, &b), Ok(()));
        // alice:wrong
        let mut x = exchange("1.2.3.4:1", &[("Authorization", "basic  YWxpY2U6d3Jvbmc=")]);
        assert_eq!(basic(&mut x, &b), Err(401));
        assert_eq!(x.auth_header, b"WWW-Authenticate: Basic realm=\"r\"\r\n");
        let mut x = exchange("1.2.3.4:1", &[]);
        assert_eq!(basic(&mut x, &b), Err(401));
    }
}
