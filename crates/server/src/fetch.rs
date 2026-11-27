//! A small HTTP/1.1 client for what auth policies fetch themselves: OpenID
//! provider metadata, key sets and token exchanges. One request per
//! connection; https verifies the server against the system trust store.

use std::time::Duration;

use openssl::ssl::{SslConnector, SslMethod};
use proxelo_http1::{Body, ChunkedDecoder, Response, parse_response};
use proxelo_snapshot::Url;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Whole exchange limit.
const TIMEOUT: Duration = Duration::from_secs(10);
/// Larger responses are refused.
const MAX: usize = 1024 * 1024;

pub(crate) struct Fetched {
    pub status: u16,
    pub body: Vec<u8>,
}

/// GET `url`, or POST `form` (application/x-www-form-urlencoded) to it with
/// `auth` as the Authorization header.
pub(crate) async fn fetch(
    url: &Url,
    form: Option<&[u8]>,
    auth: Option<&str>,
) -> Result<Fetched, String> {
    timeout(TIMEOUT, exchange(url, form, auth))
        .await
        .map_err(|_| format!("{url}: timed out"))?
        .map_err(|e| format!("{url}: {e}"))
}

async fn exchange(url: &Url, form: Option<&[u8]>, auth: Option<&str>) -> Result<Fetched, String> {
    let mut req = Vec::with_capacity(512);
    req.extend_from_slice(if form.is_some() { b"POST " } else { b"GET " });
    req.extend_from_slice(url.target.as_bytes());
    req.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    req.extend_from_slice(url.authority().as_bytes());
    req.extend_from_slice(
        b"\r\nAccept: application/json\r\nUser-Agent: proxelo\r\nConnection: close\r\n",
    );
    if let Some(a) = auth {
        req.extend_from_slice(b"Authorization: ");
        req.extend_from_slice(a.as_bytes());
        req.extend_from_slice(b"\r\n");
    }
    if let Some(f) = form {
        req.extend_from_slice(
            b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: ",
        );
        proxelo_http1::push_u64(&mut req, f.len() as u64);
        req.extend_from_slice(b"\r\n\r\n");
        req.extend_from_slice(f);
    } else {
        req.extend_from_slice(b"\r\n");
    }
    let tcp = TcpStream::connect((&*url.host, url.port))
        .await
        .map_err(|e| e.to_string())?;
    let _ = tcp.set_nodelay(true);
    let raw = if url.https {
        let ssl = SslConnector::builder(SslMethod::tls_client())
            .map_err(|e| e.to_string())?
            .build()
            .configure()
            .and_then(|c| c.into_ssl(&url.host))
            .map_err(|e| e.to_string())?;
        let mut tls = tokio_openssl::SslStream::new(ssl, tcp).map_err(|e| e.to_string())?;
        std::pin::Pin::new(&mut tls)
            .connect()
            .await
            .map_err(|e| e.to_string())?;
        round_trip(tls, &req).await?
    } else {
        round_trip(tcp, &req).await?
    };
    let mut resp = Response::default();
    if !parse_response(&raw, false, &mut resp).map_err(|_| "bad response")? {
        return Err("truncated response".into());
    }
    let rest = &raw[resp.head_len..];
    let body = match resp.body {
        Body::None => Vec::new(),
        Body::Length(n) => {
            let n = usize::try_from(n).map_err(|_| "too large")?;
            rest.get(..n).ok_or("truncated body")?.to_vec()
        }
        Body::Chunked => {
            let mut out = Vec::new();
            let mut dec = ChunkedDecoder::new();
            dec.advance_with(rest, |r| out.extend_from_slice(&rest[r]))
                .map_err(|_| "bad chunked body")?;
            if !dec.is_done() {
                return Err("truncated body".into());
            }
            out
        }
        Body::Close => rest.to_vec(),
    };
    Ok(Fetched {
        status: resp.status,
        body,
    })
}

async fn round_trip<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    req: &[u8],
) -> Result<Vec<u8>, String> {
    s.write_all(req).await.map_err(|e| e.to_string())?;
    let mut raw = Vec::with_capacity(8192);
    let mut buf = [0u8; 8192];
    loop {
        // Servers often close TLS without close_notify after Connection:
        // close; what was read is still complete when framed.
        let n = match s.read(&mut buf).await {
            Ok(n) => n,
            Err(_) if !raw.is_empty() => 0,
            Err(e) => return Err(e.to_string()),
        };
        if n == 0 {
            return Ok(raw);
        }
        if raw.len() + n > MAX {
            return Err("response too large".into());
        }
        raw.extend_from_slice(&buf[..n]);
    }
}

/// Appends `s` percent-encoded for a URL query or form value.
pub(crate) fn push_query(out: &mut Vec<u8>, s: &[u8]) {
    for &c in s {
        if c.is_ascii_alphanumeric() || b"-._~".contains(&c) {
            out.push(c);
        } else {
            out.push(b'%');
            out.push(b"0123456789ABCDEF"[usize::from(c >> 4)]);
            out.push(b"0123456789ABCDEF"[usize::from(c & 15)]);
        }
    }
}

/// The decoded value of `name` in a query string.
pub(crate) fn query_arg(query: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    query.split(|&c| c == b'&').find_map(|kv| {
        let (k, v) = match kv.iter().position(|&c| c == b'=') {
            Some(i) => (&kv[..i], &kv[i + 1..]),
            None => (kv, &b""[..]),
        };
        (k == name).then(|| unescape(v))
    })
}

fn unescape(v: &[u8]) -> Vec<u8> {
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(v.len());
    let mut i = 0;
    while i < v.len() {
        match v[i] {
            b'+' => out.push(b' '),
            b'%' => {
                match (
                    v.get(i + 1).copied().and_then(hex),
                    v.get(i + 2).copied().and_then(hex),
                ) {
                    (Some(h), Some(l)) => {
                        out.push(h << 4 | l);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query() {
        assert_eq!(
            query_arg(b"a=1&code=x%2Fy+z&state=s", b"code").as_deref(),
            Some(&b"x/y z"[..])
        );
        assert_eq!(query_arg(b"a=%4", b"a").as_deref(), Some(&b"%4"[..]));
        assert_eq!(query_arg(b"a=%41", b"a").as_deref(), Some(&b"A"[..]));
        assert_eq!(query_arg(b"a", b"b"), None);
        let mut out = Vec::new();
        push_query(&mut out, b"a b/c");
        assert_eq!(out, b"a%20b%2Fc");
    }
}
