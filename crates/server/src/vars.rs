//! nginx variables: expanding templates against the request.

use std::io::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use proxelo_http1::{Version, push_u64};
use proxelo_snapshot::{Part, Template, Var};

use crate::exchange::Exchange;

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
        Var::RemoteUser => {}
        Var::Capture(i) => {
            if let Some(c) = x.caps.get(usize::from(i)) {
                out.extend_from_slice(c);
            }
        }
    }
}
