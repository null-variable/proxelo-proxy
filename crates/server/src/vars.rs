//! nginx variables: expanding templates against the request.

use std::io::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use proxelo_http1::{Version, push_u64};
use proxelo_snapshot::{Part, Table, Template, Var, murmur2};

use crate::exchange::Exchange;
use crate::tls::ClientVerify;

/// Expands `t` into `tmpl`.
pub(crate) fn expand(x: &mut Exchange, t: &Template) {
    let mut out = std::mem::take(&mut x.tmpl);
    out.clear();
    expand_into(x, t, &mut out, None);
    x.tmpl = out;
}

/// How access logs escape variable values (nginx log_format escape=).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Escape {
    /// `"`, `\` and bytes outside printable ASCII as `\xHH`.
    Default,
    /// JSON string escapes.
    Json,
}

/// Escapes `buf[start..]` in place.
pub(crate) fn escape(buf: &mut Vec<u8>, start: usize, mode: Escape) {
    let json = mode == Escape::Json;
    let needs = buf[start..]
        .iter()
        .any(|&c| c < 0x20 || c == b'"' || c == b'\\' || (!json && c >= 0x7f));
    if !needs {
        return;
    }
    let raw = buf.split_off(start);
    for c in raw {
        match c {
            b'"' | b'\\' if json => {
                buf.push(b'\\');
                buf.push(c);
            }
            b'\n' if json => buf.extend_from_slice(b"\\n"),
            b'\r' if json => buf.extend_from_slice(b"\\r"),
            b'\t' if json => buf.extend_from_slice(b"\\t"),
            c if json && c < 0x20 => _ = write!(buf, "\\u{c:04x}"),
            // UTF-8 passes through JSON as is.
            c if json => buf.push(c),
            c if !(0x20..0x7f).contains(&c) || c == b'"' || c == b'\\' => {
                _ = write!(buf, "\\x{c:02X}");
            }
            c => buf.push(c),
        }
    }
}

/// Appends the expansion of `t` to `out`. With `log`, variable values are
/// escaped and unset ones expand to "-", as in nginx access logs.
pub(crate) fn expand_into(x: &mut Exchange, t: &Template, out: &mut Vec<u8>, log: Option<Escape>) {
    for part in t.parts() {
        let start = out.len();
        match part {
            Part::Lit(l) => {
                out.extend_from_slice(l);
                continue;
            }
            Part::Var(v) => var(x, *v, out),
            Part::Header(name) => {
                if let Some(v) = x.request_header(name) {
                    out.extend_from_slice(v);
                }
            }
            Part::Cookie(name) => {
                if let Some(v) = x.cookie(name) {
                    out.extend_from_slice(v);
                }
            }
            Part::AuthResp(name) => {
                if let Some(v) = x.auth_resp(name) {
                    out.extend_from_slice(v);
                }
            }
            Part::Lookup(i) => {
                let (s, e) = lookup(x, *i);
                out.extend_from_slice(&x.lookup_buf[s as usize..e as usize]);
            }
            Part::Arg(name) => {
                if let Some(v) = x.args.split(|&c| c == b'&').find_map(|kv| {
                    let (k, v) = kv.split_at(kv.iter().position(|&c| c == b'=')?);
                    k.eq_ignore_ascii_case(name).then_some(&v[1..])
                }) {
                    out.extend_from_slice(v);
                }
            }
        }
        if let Some(mode) = log {
            if out.len() == start {
                out.push(b'-');
            } else {
                escape(out, start, mode);
            }
        }
    }
}

/// The value of lookup `i` in this request: a span of `lookup_buf`,
/// computed on first use. A lookup's templates use only earlier lookups, so
/// the recursion is bounded. A map regex leaves its captures as the
/// request's, as nginx does.
fn lookup(x: &mut Exchange, i: u32) -> (u32, u32) {
    if let Some(span) = x.lookup_vals.get(i as usize).copied().flatten() {
        return span;
    }
    let lookups = std::sync::Arc::clone(&x.lookups);
    let Some(l) = lookups.get(i as usize) else {
        return (0, 0);
    };
    // A nested lookup finds the scratch taken and uses a new one.
    let mut src = std::mem::take(&mut x.lookup_src);
    src.clear();
    expand_into(x, &l.source, &mut src, None);
    match &l.table {
        Table::Map(t) => {
            let n = src.len();
            src.extend_from_within(..n);
            src[n..].make_ascii_lowercase();
            let mut caps = std::mem::take(&mut x.caps);
            let found = t.find(&src[..n], &src[n..], &mut caps);
            x.caps = caps;
            src.clear();
            // A regex that fails to run leaves the variable empty.
            if let Ok(v) = found {
                expand_into(x, v, &mut src, None);
            }
        }
        Table::Geo(t) => {
            let v = if l.source.parts().is_empty() {
                t.find(x.peer.ip())
            } else {
                match std::str::from_utf8(&src)
                    .ok()
                    .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                {
                    Some(ip) => t.find(ip),
                    None => t.find_none(),
                }
            };
            src.clear();
            src.extend_from_slice(v);
        }
        Table::Split(t) => {
            let v = t.find(murmur2(&src));
            src.clear();
            src.extend_from_slice(v);
        }
    }
    let start = x.lookup_buf.len() as u32;
    x.lookup_buf.extend_from_slice(&src);
    x.lookup_src = src;
    let span = (start, x.lookup_buf.len() as u32);
    if let Some(slot) = x.lookup_vals.get_mut(i as usize) {
        *slot = Some(span);
    }
    span
}

fn secs(out: &mut Vec<u8>, s: f64) {
    _ = write!(out, "{s:.3}");
}

fn var(x: &mut Exchange, v: Var, out: &mut Vec<u8>) {
    match v {
        Var::Uri => out.extend_from_slice(&x.path),
        Var::Args => out.extend_from_slice(&x.args),
        Var::IsArgs => {
            if !x.args.is_empty() {
                out.push(b'?');
            }
        }
        Var::RequestUri => out.extend_from_slice(x.req.target.get(&x.head)),
        Var::Host => {
            if x.host.is_empty() {
                _ = write!(out, "{}", x.local.ip());
            } else {
                out.extend_from_slice(&x.host);
            }
        }
        Var::Scheme => out.extend_from_slice(if x.https() { b"https" } else { b"http" }),
        Var::RequestMethod => {
            if x.as_get {
                out.extend_from_slice(b"GET");
            } else {
                out.extend_from_slice(x.req.method_span.get(&x.head));
            }
        }
        Var::ServerPort => push_u64(out, u64::from(x.local.port())),
        Var::RemoteAddr => _ = write!(out, "{}", x.peer.ip()),
        Var::BinaryRemoteAddr => match x.peer.ip() {
            std::net::IpAddr::V4(a) => out.extend_from_slice(&a.octets()),
            std::net::IpAddr::V6(a) => out.extend_from_slice(&a.octets()),
        },
        Var::RemotePort => push_u64(out, u64::from(x.peer.port())),
        Var::ServerAddr => _ = write!(out, "{}", x.local.ip()),
        Var::ServerName => out.extend_from_slice(&x.host),
        Var::ServerProtocol => out.extend_from_slice(if x.h2 {
            b"HTTP/2.0"
        } else if x.req.version == Version::Http10 {
            b"HTTP/1.0"
        } else {
            b"HTTP/1.1"
        }),
        Var::Https => {
            if x.https() {
                out.extend_from_slice(b"on");
            }
        }
        Var::SslProtocol => {
            if let Some(t) = &x.tls {
                out.extend_from_slice(t.protocol.as_bytes());
            }
        }
        Var::SslCipher => {
            if let Some(t) = &x.tls {
                out.extend_from_slice(t.cipher.as_bytes());
            }
        }
        Var::SslServerName => {
            if let Some(t) = &x.tls {
                out.extend_from_slice(&t.server_name);
            }
        }
        Var::Request => {
            // The request line as received, without the line ending.
            let line = x.head.split(|&c| c == b'\n').next().unwrap_or_default();
            out.extend_from_slice(line.strip_suffix(b"\r").unwrap_or(line));
        }
        Var::RequestLength => push_u64(out, x.req.head_len as u64),
        Var::RequestId => {
            let id = *x.request_id();
            out.extend_from_slice(&id);
        }
        Var::RequestTime => secs(out, x.started.elapsed().as_secs_f64()),
        Var::Msec => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            _ = write!(out, "{}.{:03}", now.as_secs(), now.subsec_millis());
        }
        Var::TimeLocal => out.extend_from_slice(&crate::worker::clock().local),
        Var::TimeIso8601 => out.extend_from_slice(&crate::worker::clock().iso8601),
        Var::Status => {
            if x.sent.status != 0 {
                push_u64(out, u64::from(x.sent.status));
            }
        }
        Var::BytesSent => push_u64(out, x.sent.bytes),
        Var::BodyBytesSent => push_u64(out, x.sent.body_bytes),
        Var::Connection => push_u64(out, x.conn_id),
        Var::ConnectionRequests => push_u64(out, x.requests),
        Var::UpstreamAddr => {
            if let Some(a) = x.sent.upstream_addr {
                _ = write!(out, "{a}");
            }
        }
        Var::UpstreamStatus => {
            if x.sent.upstream_status != 0 {
                push_u64(out, u64::from(x.sent.upstream_status));
            }
        }
        Var::UpstreamConnectTime => {
            if let Some(s) = x.sent.upstream_connect {
                secs(out, s);
            }
        }
        Var::UpstreamHeaderTime => {
            if let Some(s) = x.sent.upstream_header {
                secs(out, s);
            }
        }
        Var::UpstreamResponseTime => {
            if let Some(s) = x.sent.upstream_response {
                secs(out, s);
            }
        }
        // Set by authentication policies, which do not exist yet.
        Var::RemoteUser => {
            let mut creds = std::mem::take(&mut x.scratch);
            if let Some(colon) = crate::access::basic_credentials(x, &mut creds) {
                out.extend_from_slice(&creds[..colon]);
            }
            creds.clear();
            x.scratch = creds;
        }
        Var::RealipRemoteAddr => _ = write!(out, "{}", x.conn_peer.ip()),
        Var::RealipRemotePort => push_u64(out, u64::from(x.conn_peer.port())),
        Var::Protocol => {
            if let Some(s) = &x.session {
                out.extend_from_slice(if s.udp { b"UDP" } else { b"TCP" });
            }
        }
        Var::BytesReceived => {
            if let Some(s) = &x.session {
                push_u64(out, s.received);
            }
        }
        Var::SessionTime => secs(out, x.started.elapsed().as_secs_f64()),
        Var::UpstreamBytesSent => {
            if let Some(s) = &x.session {
                push_u64(out, s.upstream_sent);
            }
        }
        Var::UpstreamBytesReceived => {
            if let Some(s) = &x.session {
                push_u64(out, s.upstream_received);
            }
        }
        Var::SslPrereadServerName => {
            if let Some(s) = &x.session {
                out.extend_from_slice(&s.preread_server_name);
            }
        }
        Var::SslPrereadAlpnProtocols => {
            if let Some(s) = &x.session {
                out.extend_from_slice(&s.preread_alpn);
            }
        }
        Var::SslPrereadProtocol => {
            if let Some(s) = &x.session {
                out.extend_from_slice(s.preread_protocol.as_bytes());
            }
        }
        Var::SslSessionReused => {
            if let Some(t) = &x.tls {
                out.extend_from_slice(if t.session_reused { b"r" } else { b"." });
            }
        }
        Var::SslClientVerify => {
            if let Some(t) = &x.tls {
                match t.verify {
                    ClientVerify::None => out.extend_from_slice(b"NONE"),
                    ClientVerify::Success => out.extend_from_slice(b"SUCCESS"),
                    ClientVerify::Failed(r) => {
                        out.extend_from_slice(b"FAILED:");
                        out.extend_from_slice(r.error_string().as_bytes());
                    }
                }
            }
        }
        Var::SslClientSDn => {
            if let Some(t) = &x.tls {
                out.extend_from_slice(t.client_subject.as_bytes());
            }
        }
        Var::SslClientIDn => {
            if let Some(t) = &x.tls {
                out.extend_from_slice(t.client_issuer.as_bytes());
            }
        }
        Var::SslClientSerial => {
            if let Some(t) = &x.tls {
                out.extend_from_slice(t.client_serial.as_bytes());
            }
        }
        Var::SslClientCert => {
            if let Some(t) = &x.tls {
                // nginx indents continuation lines so the value fits a header.
                let pem = t.client_cert.trim_end().as_bytes();
                for (i, line) in pem.split(|&c| c == b'\n').enumerate() {
                    if i > 0 {
                        out.extend_from_slice(b"\n\t");
                    }
                    out.extend_from_slice(line);
                }
            }
        }
        Var::SslClientEscapedCert => {
            if let Some(t) = &x.tls {
                for &c in t.client_cert.as_bytes() {
                    if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~') {
                        out.push(c);
                    } else {
                        _ = write!(out, "%{c:02X}");
                    }
                }
            }
        }
        Var::DocumentRoot => out.extend_from_slice(&x.doc_root),
        Var::ContentLength => match x.request_header(b"content-length") {
            Some(v) => out.extend_from_slice(v),
            None => {
                if let Some(n) = x.body_len {
                    push_u64(out, n);
                }
            }
        },
        Var::ContentType => {
            if let Some(v) = x.request_header(b"content-type") {
                out.extend_from_slice(v);
            }
        }
        Var::FastcgiScriptName => out.extend_from_slice(&x.script_name),
        Var::FastcgiPathInfo => out.extend_from_slice(&x.path_info),
        Var::Capture(i) => {
            if let Some(c) = x.caps.get(usize::from(i)) {
                out.extend_from_slice(c);
            }
        }
    }
}
