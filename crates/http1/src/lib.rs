//! HTTP/1.1 codec that parses in place.
//!
//! Parsed messages hold offsets into the caller's buffer instead of copies, so a
//! warm connection parses requests without allocating. Parsing is strict where
//! leniency enables request smuggling (RFC 9112 §6.3, §11.2): conflicting
//! framing headers, bare CR, obsolete line folding and malformed chunks are
//! rejected with the status nginx uses.

#![forbid(unsafe_code)]

mod chunked;
mod date;
mod path;

pub use chunked::ChunkedDecoder;
pub use date::{DATE_LEN, http_date};
pub use path::normalize_path;

use memchr::memchr;

/// Maximum number of header lines in one message.
pub const MAX_HEADERS: usize = 100;

/// A byte range of the buffer a message was parsed from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

impl Span {
    fn new(start: usize, end: usize) -> Self {
        Self {
            start: start as u32,
            end: end as u32,
        }
    }

    pub fn get<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.start as usize..self.end as usize]
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Method {
    #[default]
    Get,
    Head,
    Post,
    Put,
    Delete,
    Options,
    Patch,
    Connect,
    Trace,
    Other,
}

impl Method {
    fn from_bytes(b: &[u8]) -> Self {
        match b {
            b"GET" => Self::Get,
            b"HEAD" => Self::Head,
            b"POST" => Self::Post,
            b"PUT" => Self::Put,
            b"DELETE" => Self::Delete,
            b"OPTIONS" => Self::Options,
            b"PATCH" => Self::Patch,
            b"CONNECT" => Self::Connect,
            b"TRACE" => Self::Trace,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Version {
    Http10,
    #[default]
    Http11,
}

/// How the message body is delimited.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Body {
    #[default]
    None,
    Length(u64),
    Chunked,
    /// Response body that ends when the connection closes.
    Close,
}

/// Headers the proxy treats specially. Everything else is `Other`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HeaderKind {
    #[default]
    Other,
    Host,
    ContentLength,
    TransferEncoding,
    Connection,
    KeepAlive,
    ProxyConnection,
    Upgrade,
    Te,
    Trailer,
    Expect,
    Date,
    Server,
    /// `X-Accel-*` and `X-Pad`, which nginx hides from proxied responses.
    Internal,
}

impl HeaderKind {
    fn of(name: &[u8]) -> Self {
        const TABLE: &[(&[u8], HeaderKind)] = &[
            (b"host", HeaderKind::Host),
            (b"content-length", HeaderKind::ContentLength),
            (b"transfer-encoding", HeaderKind::TransferEncoding),
            (b"connection", HeaderKind::Connection),
            (b"keep-alive", HeaderKind::KeepAlive),
            (b"proxy-connection", HeaderKind::ProxyConnection),
            (b"upgrade", HeaderKind::Upgrade),
            (b"te", HeaderKind::Te),
            (b"trailer", HeaderKind::Trailer),
            (b"expect", HeaderKind::Expect),
            (b"date", HeaderKind::Date),
            (b"server", HeaderKind::Server),
            (b"x-pad", HeaderKind::Internal),
        ];
        if let Some(&(_, k)) = TABLE.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)) {
            return k;
        }
        if name.len() > 8 && name[..8].eq_ignore_ascii_case(b"x-accel-") {
            return HeaderKind::Internal;
        }
        HeaderKind::Other
    }

    /// Hop-by-hop headers are consumed by this hop and never forwarded.
    pub fn is_hop_by_hop(self) -> bool {
        matches!(
            self,
            Self::Connection
                | Self::KeepAlive
                | Self::ProxyConnection
                | Self::Upgrade
                | Self::Te
                | Self::Trailer
                | Self::TransferEncoding
        )
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Header {
    pub name: Span,
    pub value: Span,
    pub kind: HeaderKind,
}

/// Parse failures, each mapped to the status nginx answers with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BadRequest,
    UriTooLong,
    HeaderTooLarge,
    NotImplemented,
    VersionNotSupported,
}

impl Error {
    pub fn status(self) -> u16 {
        match self {
            Self::BadRequest | Self::HeaderTooLarge => 400,
            Self::UriTooLong => 414,
            Self::NotImplemented => 501,
            Self::VersionNotSupported => 505,
        }
    }
}

/// Fields shared by request and response parsing.
#[derive(Clone, Debug)]
pub struct Headers {
    list: [Header; MAX_HEADERS],
    len: usize,
}

impl Default for Headers {
    fn default() -> Self {
        Self {
            list: [Header::default(); MAX_HEADERS],
            len: 0,
        }
    }
}

impl Headers {
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &Header> {
        self.list[..self.len].iter()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// A parsed request head. Reused across requests on a connection.
#[derive(Clone, Debug, Default)]
pub struct Request {
    pub method: Method,
    pub method_span: Span,
    /// Request target as sent, origin-form after stripping an absolute-form
    /// scheme and authority: path plus optional query.
    pub target: Span,
    /// Path part of `target`, before `?`.
    pub path: Span,
    pub version: Version,
    pub headers: Headers,
    /// Host from an absolute-form target, otherwise from the Host header.
    pub host: Option<Span>,
    pub body: Body,
    pub keep_alive: bool,
    pub expect_continue: bool,
    /// Length of the request head in bytes, including the final empty line.
    pub head_len: usize,
}

/// A parsed response head from an upstream.
#[derive(Clone, Debug, Default)]
pub struct Response {
    pub version: Version,
    pub status: u16,
    pub reason: Span,
    pub headers: Headers,
    pub body: Body,
    pub keep_alive: bool,
    pub head_len: usize,
}

const fn tchar_table() -> [bool; 256] {
    let mut t = [false; 256];
    let mut i = 0;
    while i < 256 {
        let c = i as u8;
        t[i] = c.is_ascii_alphanumeric()
            || matches!(
                c,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            );
        i += 1;
    }
    t
}

static TCHAR: [bool; 256] = tchar_table();

fn is_token(b: &[u8]) -> bool {
    !b.is_empty() && b.iter().all(|&c| TCHAR[c as usize])
}

/// Splits `buf[pos..]` at the next line ending. Returns the line without its
/// ending and the position after it, or `None` if no full line is buffered.
/// A bare CR anywhere in the line is an error.
fn next_line(buf: &[u8], pos: usize) -> Result<Option<(usize, usize, usize)>, Error> {
    let Some(lf) = memchr(b'\n', &buf[pos..]) else {
        if memchr(b'\r', &buf[pos..]).is_some_and(|cr| pos + cr + 1 < buf.len()) {
            return Err(Error::BadRequest);
        }
        return Ok(None);
    };
    let lf = pos + lf;
    let end = if lf > pos && buf[lf - 1] == b'\r' {
        lf - 1
    } else {
        lf
    };
    if memchr(b'\r', &buf[pos..end]).is_some() {
        return Err(Error::BadRequest);
    }
    Ok(Some((pos, end, lf + 1)))
}

fn trim_ows(buf: &[u8], mut start: usize, mut end: usize) -> (usize, usize) {
    while start < end && matches!(buf[start], b' ' | b'\t') {
        start += 1;
    }
    while end > start && matches!(buf[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    (start, end)
}

fn parse_version(v: &[u8]) -> Result<Version, Error> {
    match v {
        b"HTTP/1.1" => Ok(Version::Http11),
        b"HTTP/1.0" => Ok(Version::Http10),
        [b'H', b'T', b'T', b'P', b'/', maj, b'.', min]
            if maj.is_ascii_digit() && min.is_ascii_digit() =>
        {
            Err(Error::VersionNotSupported)
        }
        _ => Err(Error::BadRequest),
    }
}

fn parse_content_length(v: &[u8]) -> Option<u64> {
    if v.is_empty() || v.len() > 18 || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(v.iter().fold(0u64, |n, &d| n * 10 + u64::from(d - b'0')))
}

/// Calls `f` for each comma-separated token of a header value, trimmed.
fn for_each_token(v: &[u8], mut f: impl FnMut(&[u8])) {
    for part in v.split(|&c| c == b',') {
        let (s, e) = trim_ows(part, 0, part.len());
        if s < e {
            f(&part[s..e]);
        }
    }
}

/// State collected while reading header lines.
#[derive(Default)]
struct Framing {
    content_length: Option<u64>,
    chunked: bool,
    transfer_encoding: bool,
    conn_close: bool,
    conn_keep_alive: bool,
}

/// Reads header lines starting at `pos` into `headers`. Returns the position
/// after the empty line, or `None` if the head is incomplete.
fn parse_headers(
    buf: &[u8],
    mut pos: usize,
    headers: &mut Headers,
    framing: &mut Framing,
    mut on_header: impl FnMut(&Header) -> Result<(), Error>,
) -> Result<Option<usize>, Error> {
    headers.len = 0;
    loop {
        let Some((start, end, next)) = next_line(buf, pos)? else {
            return Ok(None);
        };
        pos = next;
        if start == end {
            return Ok(Some(pos));
        }
        // Obsolete line folding is a smuggling vector (RFC 9112 §5.2).
        if matches!(buf[start], b' ' | b'\t') {
            return Err(Error::BadRequest);
        }
        let colon = memchr(b':', &buf[start..end]).ok_or(Error::BadRequest)? + start;
        if !is_token(&buf[start..colon]) {
            return Err(Error::BadRequest);
        }
        let (vs, ve) = trim_ows(buf, colon + 1, end);
        if buf[vs..ve]
            .iter()
            .any(|&c| (c < 0x20 && c != b'\t') || c == 0x7f)
        {
            return Err(Error::BadRequest);
        }
        if headers.len == MAX_HEADERS {
            return Err(Error::HeaderTooLarge);
        }
        let h = Header {
            name: Span::new(start, colon),
            value: Span::new(vs, ve),
            kind: HeaderKind::of(&buf[start..colon]),
        };
        let value = &buf[vs..ve];
        match h.kind {
            HeaderKind::ContentLength => {
                if framing.content_length.is_some() {
                    return Err(Error::BadRequest);
                }
                framing.content_length =
                    Some(parse_content_length(value).ok_or(Error::BadRequest)?);
            }
            HeaderKind::TransferEncoding => {
                // A second Transfer-Encoding line makes the coding list ambiguous.
                if framing.transfer_encoding {
                    return Err(Error::BadRequest);
                }
                framing.transfer_encoding = true;
                let mut codings = 0;
                let mut chunked = false;
                for_each_token(value, |t| {
                    codings += 1;
                    chunked = t.eq_ignore_ascii_case(b"chunked");
                });
                framing.chunked = codings == 1 && chunked;
            }
            HeaderKind::Connection => for_each_token(value, |t| {
                if t.eq_ignore_ascii_case(b"close") {
                    framing.conn_close = true;
                } else if t.eq_ignore_ascii_case(b"keep-alive") {
                    framing.conn_keep_alive = true;
                }
            }),
            _ => {}
        }
        on_header(&h)?;
        headers.list[headers.len] = h;
        headers.len += 1;
    }
}

/// Parses a request head from `buf`.
///
/// Returns `Ok(false)` when more bytes are needed. Leading empty lines are
/// skipped as RFC 9112 §2.2 allows.
pub fn parse_request(buf: &[u8], req: &mut Request) -> Result<bool, Error> {
    let mut pos = 0;
    while pos < buf.len() && matches!(buf[pos], b'\r' | b'\n') {
        pos += 1;
    }
    let Some((start, end, next)) = next_line(buf, pos)? else {
        return Ok(false);
    };
    let line = &buf[start..end];
    let sp1 = memchr(b' ', line).ok_or(Error::BadRequest)?;
    let sp2 = memchr::memrchr(b' ', line).ok_or(Error::BadRequest)?;
    if sp2 == sp1 || !is_token(&line[..sp1]) {
        return Err(Error::BadRequest);
    }
    let version = parse_version(&line[sp2 + 1..])?;
    let (ts, te) = (start + sp1 + 1, start + sp2);
    if ts == te || buf[ts..te].iter().any(|&c| c <= 0x20 || c == 0x7f) {
        return Err(Error::BadRequest);
    }

    req.method_span = Span::new(start, start + sp1);
    req.method = Method::from_bytes(&line[..sp1]);
    req.version = version;
    req.host = None;
    req.expect_continue = false;

    // absolute-form: scheme "://" authority path-abempty
    let mut path_start = ts;
    let target = &buf[ts..te];
    if target[0] != b'/' {
        let scheme_end = if target.len() > 7 && target[..7].eq_ignore_ascii_case(b"http://") {
            7
        } else if target.len() > 8 && target[..8].eq_ignore_ascii_case(b"https://") {
            8
        } else if target == b"*" && req.method == Method::Options {
            0
        } else {
            return Err(Error::BadRequest);
        };
        if scheme_end > 0 {
            let auth = ts + scheme_end;
            let auth_end = buf[auth..te]
                .iter()
                .position(|&c| c == b'/' || c == b'?')
                .map_or(te, |p| auth + p);
            if auth == auth_end {
                return Err(Error::BadRequest);
            }
            req.host = Some(Span::new(auth, auth_end));
            path_start = auth_end;
        }
    }
    req.target = Span::new(path_start, te);
    let path_end = memchr(b'?', &buf[path_start..te]).map_or(te, |q| path_start + q);
    req.path = Span::new(path_start, path_end);

    let mut framing = Framing::default();
    let mut host_header = None;
    let mut expect = false;
    let Some(head_end) = parse_headers(buf, next, &mut req.headers, &mut framing, |h| {
        match h.kind {
            HeaderKind::Host => {
                if host_header.is_some() {
                    return Err(Error::BadRequest);
                }
                host_header = Some(h.value);
            }
            HeaderKind::Expect if h.value.get(buf).eq_ignore_ascii_case(b"100-continue") => {
                expect = true;
            }
            _ => {}
        }
        Ok(())
    })?
    else {
        return Ok(false);
    };

    if let Some(h) = host_header {
        if !valid_host(h.get(buf)) {
            return Err(Error::BadRequest);
        }
        if req.host.is_none() {
            req.host = Some(h);
        }
    } else if version == Version::Http11 {
        return Err(Error::BadRequest);
    }

    req.body = if framing.transfer_encoding {
        if framing.content_length.is_some() || version == Version::Http10 {
            return Err(Error::BadRequest);
        }
        if !framing.chunked {
            return Err(Error::NotImplemented);
        }
        Body::Chunked
    } else {
        match framing.content_length {
            Some(0) | None => Body::None,
            Some(n) => Body::Length(n),
        }
    };
    req.keep_alive = match version {
        Version::Http11 => !framing.conn_close,
        Version::Http10 => framing.conn_keep_alive && !framing.conn_close,
    };
    req.expect_continue = expect && version == Version::Http11;
    req.head_len = head_end;
    Ok(true)
}

/// Host header syntax nginx accepts: no path separators, no control bytes, no
/// empty labels from `..`.
fn valid_host(h: &[u8]) -> bool {
    !h.iter()
        .any(|&c| c <= 0x20 || c == 0x7f || c == b'/' || c == b'\\')
        && !h.windows(2).any(|w| w == b"..")
}

/// Parses a response head from an upstream.
///
/// `head_request` and the status decide whether a body follows (RFC 9112 §6.3).
/// Returns `Ok(false)` when more bytes are needed. Interim 1xx responses other
/// than 101 are returned like any other; callers skip them.
pub fn parse_response(buf: &[u8], head_request: bool, resp: &mut Response) -> Result<bool, Error> {
    let Some((start, end, next)) = next_line(buf, 0)? else {
        return Ok(false);
    };
    let line = &buf[start..end];
    if line.len() < 12 || line[8] != b' ' || line[12..].first().is_some_and(|&c| c != b' ') {
        return Err(Error::BadRequest);
    }
    resp.version = parse_version(&line[..8]).map_err(|_| Error::BadRequest)?;
    let code = &line[9..12];
    if !code.iter().all(u8::is_ascii_digit) || code[0] == b'0' {
        return Err(Error::BadRequest);
    }
    resp.status = code.iter().fold(0u16, |n, &d| n * 10 + u16::from(d - b'0'));
    resp.reason = if line.len() > 13 {
        Span::new(start + 13, end)
    } else {
        Span::new(end, end)
    };

    let mut framing = Framing::default();
    let Some(head_end) = parse_headers(buf, next, &mut resp.headers, &mut framing, |_| Ok(()))?
    else {
        return Ok(false);
    };

    let no_body = head_request || resp.status < 200 || resp.status == 204 || resp.status == 304;
    resp.body = if no_body {
        Body::None
    } else if framing.transfer_encoding {
        if framing.content_length.is_some() {
            return Err(Error::BadRequest);
        }
        if framing.chunked {
            Body::Chunked
        } else {
            Body::Close
        }
    } else {
        match framing.content_length {
            Some(0) => Body::None,
            Some(n) => Body::Length(n),
            None => Body::Close,
        }
    };
    resp.keep_alive = !matches!(resp.body, Body::Close)
        && match resp.version {
            Version::Http11 => !framing.conn_close,
            Version::Http10 => framing.conn_keep_alive && !framing.conn_close,
        };
    resp.head_len = head_end;
    Ok(true)
}

/// Whether `buf` holds a complete request line. Used to choose between 414 and
/// 400 when the header buffer fills up.
pub fn request_line_complete(buf: &[u8]) -> bool {
    let start = buf
        .iter()
        .position(|&c| !matches!(c, b'\r' | b'\n'))
        .unwrap_or(buf.len());
    memchr(b'\n', &buf[start..]).is_some()
}

/// Appends the decimal form of `n` to `out`.
pub fn push_u64(out: &mut Vec<u8>, mut n: u64) {
    let mut tmp = [0u8; 20];
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&tmp[i..]);
}

/// Appends the lowercase hexadecimal form of `n` to `out`.
pub fn push_hex(out: &mut Vec<u8>, mut n: u64) {
    let mut tmp = [0u8; 16];
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = b"0123456789abcdef"[(n & 15) as usize];
        n >>= 4;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&tmp[i..]);
}

/// Reason phrase nginx sends for a status code.
pub fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Moved Temporarily",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Not Allowed",
        408 => "Request Time-out",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Large",
        416 => "Requested Range Not Satisfiable",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Temporarily Unavailable",
        504 => "Gateway Time-out",
        505 => "HTTP Version Not Supported",
        _ => "",
    }
}

#[cfg(test)]
mod tests;
