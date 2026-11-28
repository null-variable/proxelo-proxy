//! nginx subrequests: a request the server makes to itself for a filter
//! (addition, ssi include) or a mirror. It is served by a [`Conn`] on an
//! in-memory pipe, like an HTTP/2 stream, with the main request's headers.
//!
//! What nginx skips for `r != r->main` is skipped by the serving side when
//! [`Exchange::is_sub`] holds: the access phase, userid, compression,
//! addition, mirror and the access log.

use std::future::Future;
use std::sync::Arc;

use proxelo_http1::{Body, ChunkedDecoder, Response, parse_response, push_u64};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::conn::Conn;
use crate::exchange::Exchange;
use crate::io::Stream;

/// nginx NGX_HTTP_MAX_SUBREQUESTS: how deep subrequests nest.
const MAX_DEPTH: u8 = 50;
const PIPE: usize = 64 * 1024;

/// What a subrequest answered.
pub(crate) struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
    /// The body is a generated error page, not the handler's output
    /// (nginx `r->request_output` unset).
    pub paged: bool,
}

/// Request headers a subrequest does not take from the main request: its
/// own framing, and what would make it partial or conditional (nginx skips
/// the range and not_modified filters for subrequests).
fn skipped(name: &[u8]) -> bool {
    const SKIP: [&[u8]; 13] = [
        b"host",
        b"content-length",
        b"transfer-encoding",
        b"connection",
        b"keep-alive",
        b"expect",
        b"te",
        b"upgrade",
        b"range",
        b"if-range",
        b"if-none-match",
        b"if-modified-since",
        b"if-match",
    ];
    SKIP.iter().any(|s| name.eq_ignore_ascii_case(s))
        || name.eq_ignore_ascii_case(b"if-unmodified-since")
}

/// Appends decoded `path` as a request target path: bytes with a meaning
/// in a target, `%` itself and anything outside printable ASCII are
/// percent-encoded, so the subrequest sees `path` again once decoded.
fn push_path(h: &mut Vec<u8>, path: &[u8]) {
    for &c in path {
        if c.is_ascii_alphanumeric() || b"/-._~!$&'()*+,;=:@".contains(&c) {
            h.push(c);
        } else {
            h.push(b'%');
            h.push(b"0123456789ABCDEF"[usize::from(c >> 4)]);
            h.push(b"0123456789ABCDEF"[usize::from(c & 15)]);
        }
    }
}

/// The request head of a subrequest for `method` `path`?`args`, with a body
/// of `body_len` bytes when given.
fn head(x: &Exchange, method: &[u8], path: &[u8], args: &[u8], body_len: Option<usize>) -> Vec<u8> {
    let mut h = Vec::with_capacity(x.head.len() + path.len() + args.len() + 64);
    h.extend_from_slice(method);
    h.push(b' ');
    push_path(&mut h, path);
    if !args.is_empty() {
        h.push(b'?');
        h.extend(args.iter().map(|&c| {
            if c <= b' ' || c == 0x7f || c == b'#' {
                b'+'
            } else {
                c
            }
        }));
    }
    h.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    match x.request_header(b"host") {
        Some(v) => h.extend_from_slice(v),
        None if !x.host.is_empty() => h.extend_from_slice(&x.host),
        None => _ = std::io::Write::write_fmt(&mut h, format_args!("{}", x.local.ip())),
    }
    h.extend_from_slice(b"\r\n");
    for hd in x.req.headers.iter() {
        let name = hd.name.get(&x.head);
        if skipped(name) {
            continue;
        }
        h.extend_from_slice(name);
        h.extend_from_slice(b": ");
        h.extend_from_slice(hd.value.get(&x.head));
        h.extend_from_slice(b"\r\n");
    }
    if let Some(n) = body_len {
        h.extend_from_slice(b"Content-Length: ");
        push_u64(&mut h, n as u64);
        h.extend_from_slice(b"\r\n");
    }
    h.extend_from_slice(b"Connection: close\r\n\r\n");
    h
}

/// Makes a subrequest of `x` for the decoded `path` with `args`. The
/// returned future owns what it needs and waits for the whole answer:
/// `None` past the nesting limit or when nothing answers.
pub(crate) fn run(
    x: &Exchange,
    method: &'static [u8],
    path: &[u8],
    args: &[u8],
    body: Option<Vec<u8>>,
) -> impl Future<Output = Option<Reply>> + Send + 'static {
    let start = match &x.active {
        Some(_) if x.depth >= MAX_DEPTH => {
            eprintln!(
                "subrequests cycle while processing \"{}\"",
                String::from_utf8_lossy(path)
            );
            None
        }
        Some(active) => {
            let (ours, theirs) = tokio::io::duplex(PIPE);
            let mut c = Conn::new(Stream::Pipe(theirs), x.listener, x.local, x.peer);
            c.x.tls.clone_from(&x.tls);
            c.x.h2 = x.h2;
            c.x.h3 = x.h3;
            c.x.depth = x.depth + 1;
            c.x.conn_id = x.conn_id;
            c.x.requests = x.requests.saturating_sub(1);
            c.x.ssi.clone_from(&x.ssi);
            let req = head(x, method, path, args, body.as_ref().map(Vec::len));
            Some((ours, c.serve_sub(Arc::clone(active)), req))
        }
        None => None,
    };
    async move {
        let (ours, serve, req) = start?;
        let served = tokio::spawn(serve);
        let (mut rd, mut wr) = tokio::io::split(ours);
        let send = async {
            wr.write_all(&req).await?;
            if let Some(b) = &body {
                wr.write_all(b).await?;
            }
            Ok::<_, std::io::Error>(())
        };
        let mut raw = Vec::new();
        // The server may answer before reading the whole body; only what
        // comes back matters.
        let (_, received) = tokio::join!(send, rd.read_to_end(&mut raw));
        let paged = served.await.unwrap_or(false);
        received.ok()?;
        parse(&raw, method == b"HEAD", paged)
    }
}

/// Splits a complete HTTP/1.1 answer into status and body.
fn parse(raw: &[u8], head_request: bool, paged: bool) -> Option<Reply> {
    let mut resp = Response::default();
    if !parse_response(raw, head_request, &mut resp).ok()? {
        return None;
    }
    let rest = &raw[resp.head_len..];
    let body = match resp.body {
        Body::None => Vec::new(),
        Body::Length(n) => rest.get(..n as usize)?.to_vec(),
        Body::Close => rest.to_vec(),
        Body::Chunked => {
            let mut out = Vec::new();
            let mut dec = ChunkedDecoder::new();
            dec.advance_with(rest, |r| out.extend_from_slice(&rest[r]))
                .ok()?;
            if !dec.is_done() {
                return None;
            }
            out
        }
    };
    Some(Reply {
        status: resp.status,
        body,
        paged,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_answers() {
        let r = parse(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
            false,
            false,
        )
        .unwrap();
        assert_eq!((r.status, &r.body[..]), (200, &b"abc"[..]));
        let r = parse(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nnf",
            false,
            true,
        )
        .unwrap();
        assert_eq!((r.status, &r.body[..], r.paged), (404, &b"nf"[..], true));
        assert!(
            parse(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab",
                false,
                false
            )
            .is_none()
        );
    }

    #[test]
    fn encodes_paths() {
        let mut h = Vec::new();
        push_path(&mut h, "/a b/%?#é".as_bytes());
        assert_eq!(h, b"/a%20b/%25%3F%23%C3%A9");
    }

    #[test]
    fn skips_framing_and_conditions() {
        for n in [
            &b"Host"[..],
            b"content-length",
            b"Range",
            b"If-Unmodified-Since",
        ] {
            assert!(skipped(n));
        }
        assert!(!skipped(b"accept-encoding"));
        assert!(!skipped(b"cookie"));
    }
}
