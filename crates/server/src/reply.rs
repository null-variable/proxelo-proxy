//! Response head and generated page writers.

use proxelo_http1::{push_u64, reason};

use crate::worker;

/// Writes the status line and the headers every response carries.
pub(crate) fn start(out: &mut Vec<u8>, status: u16, reason_phrase: &[u8]) {
    out.extend_from_slice(b"HTTP/1.1 ");
    push_u64(out, u64::from(status));
    out.push(b' ');
    if reason_phrase.is_empty() {
        out.extend_from_slice(reason(status).as_bytes());
    } else {
        out.extend_from_slice(reason_phrase);
    }
    out.extend_from_slice(b"\r\nServer: proxelo\r\nDate: ");
    out.extend_from_slice(&worker::date());
    out.extend_from_slice(b"\r\n");
}

pub(crate) fn connection(out: &mut Vec<u8>, keep_alive: bool) {
    out.extend_from_slice(if keep_alive {
        b"Connection: keep-alive\r\n"
    } else {
        b"Connection: close\r\n"
    });
}

/// Finishes a head started with [`start`] with the HTML page nginx generates
/// for `status`. `head` omits the body for HEAD requests.
pub(crate) fn page(out: &mut Vec<u8>, status: u16, keep_alive: bool, head: bool) {
    const PRE: &[u8] = b"<html>\r\n<head><title>";
    const MID: &[u8] = b"</title></head>\r\n<body>\r\n<center><h1>";
    const POST: &[u8] = b"</h1></center>\r\n<hr><center>proxelo</center>\r\n</body>\r\n</html>\r\n";
    let reason = reason(status).as_bytes();
    // "404 Not Found": three digits, a space and the reason, twice.
    let title = 4 + reason.len();
    let len = PRE.len() + MID.len() + POST.len() + 2 * title;

    out.extend_from_slice(b"Content-Type: text/html\r\nContent-Length: ");
    push_u64(out, len as u64);
    out.extend_from_slice(b"\r\n");
    connection(out, keep_alive);
    out.extend_from_slice(b"\r\n");
    if head {
        return;
    }
    out.extend_from_slice(PRE);
    for part in [MID, POST] {
        push_u64(out, u64::from(status));
        out.push(b' ');
        out.extend_from_slice(reason);
        out.extend_from_slice(part);
    }
}

/// Appends a decoded path percent-encoded where it could not appear literally
/// in a URI path or header value.
pub(crate) fn push_uri_path(out: &mut Vec<u8>, path: &[u8]) {
    for &c in path {
        if c <= b' ' || c >= 0x7f || matches!(c, b'"' | b'%' | b'?' | b'#') {
            out.push(b'%');
            out.push(b"0123456789ABCDEF"[usize::from(c >> 4)]);
            out.push(b"0123456789ABCDEF"[usize::from(c & 15)]);
        } else {
            out.push(c);
        }
    }
}

/// Content type by file extension, as in nginx's default `mime.types`.
pub(crate) fn mime(path: &[u8]) -> &'static [u8] {
    let ext = match path.iter().rposition(|&c| c == b'.' || c == b'/') {
        Some(i) if path[i] == b'.' => &path[i + 1..],
        _ => return b"application/octet-stream",
    };
    const TABLE: &[(&[u8], &[u8])] = &[
        (b"html", b"text/html"),
        (b"htm", b"text/html"),
        (b"shtml", b"text/html"),
        (b"css", b"text/css"),
        (b"xml", b"text/xml"),
        (b"txt", b"text/plain"),
        (b"js", b"application/javascript"),
        (b"mjs", b"application/javascript"),
        (b"json", b"application/json"),
        (b"wasm", b"application/wasm"),
        (b"pdf", b"application/pdf"),
        (b"zip", b"application/zip"),
        (b"gif", b"image/gif"),
        (b"jpeg", b"image/jpeg"),
        (b"jpg", b"image/jpeg"),
        (b"png", b"image/png"),
        (b"svg", b"image/svg+xml"),
        (b"svgz", b"image/svg+xml"),
        (b"webp", b"image/webp"),
        (b"avif", b"image/avif"),
        (b"ico", b"image/x-icon"),
        (b"woff", b"font/woff"),
        (b"woff2", b"font/woff2"),
        (b"mp4", b"video/mp4"),
        (b"webm", b"video/webm"),
        (b"mp3", b"audio/mpeg"),
    ];
    TABLE
        .iter()
        .find(|(e, _)| e.eq_ignore_ascii_case(ext))
        .map_or(b"application/octet-stream", |&(_, m)| m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_length_matches_body() {
        for status in [301, 400, 404, 502] {
            let mut out = Vec::new();
            page(&mut out, status, true, false);
            let text = String::from_utf8(out).unwrap();
            let (head, body) = text.split_once("\r\n\r\n").unwrap();
            assert!(
                head.contains(&format!("Content-Length: {}", body.len())),
                "{head}"
            );
            assert!(body.contains(&format!("<title>{status} {}</title>", reason(status))));
        }
    }

    #[test]
    fn head_page_has_no_body() {
        let mut out = Vec::new();
        page(&mut out, 404, false, true);
        assert!(out.ends_with(b"Connection: close\r\n\r\n"));
    }

    #[test]
    fn escapes_uri() {
        let mut out = Vec::new();
        push_uri_path(&mut out, b"/a b\r\n%\"?#/\xc3\xa9");
        assert_eq!(out, b"/a%20b%0D%0A%25%22%3F%23/%C3%A9");
    }

    #[test]
    fn mime_types() {
        assert_eq!(mime(b"/a/index.HTML"), b"text/html");
        assert_eq!(mime(b"/a.b/file"), b"application/octet-stream");
        assert_eq!(mime(b"/x.woff2"), b"font/woff2");
        assert_eq!(mime(b"/x."), b"application/octet-stream");
    }
}
