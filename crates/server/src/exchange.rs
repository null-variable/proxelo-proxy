//! The state of one request as the phases see it, without the connection:
//! the parsed head, the current URI and what earlier phases decided. Serving
//! and the simulator run requests through the same [`Exchange`].

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use proxelo_http1::{Method, Request, normalize_path};
use proxelo_snapshot::{Captures, Facts};

use crate::tls::TlsInfo;

/// What the access log and metrics need about the response.
#[derive(Debug, Default, Clone)]
pub(crate) struct Sent {
    pub status: u16,
    /// Bytes written to the client, head included.
    pub bytes: u64,
    pub body_bytes: u64,
    pub upstream_addr: Option<SocketAddr>,
    pub upstream_status: u16,
    /// Seconds.
    pub upstream_connect: Option<f64>,
    pub upstream_header: Option<f64>,
    pub upstream_response: Option<f64>,
}

pub(crate) struct Exchange {
    pub local: SocketAddr,
    /// The client address: the connection's, or what real_ip set for this
    /// request.
    pub peer: SocketAddr,
    /// The connection's client address.
    pub conn_peer: SocketAddr,
    /// The current request head, copied out of the read buffer so pipelined
    /// bytes can move up while the request is handled.
    pub head: Vec<u8>,
    pub req: Request,
    /// Lowercase host without port, empty when the request has none.
    pub host: Vec<u8>,
    /// Decoded, normalized path.
    pub path: Vec<u8>,
    /// Query string without `?`.
    pub args: Vec<u8>,
    pub scratch: Vec<u8>,
    /// Expanded templates.
    pub tmpl: Vec<u8>,
    /// Groups of the last regex that matched in this request.
    pub caps: Captures,
    /// `path` or `args` differ from the request target.
    pub uri_changed: bool,
    /// An error page took over this request; another error is answered
    /// directly.
    pub error_paged: bool,
    /// Status set by an error page for the final response, 0 for none.
    pub err_status: u16,
    /// An error page turned the request into a GET; its body is not sent on.
    pub as_get: bool,
    /// Over TLS, with what the handshake chose.
    pub tls: Option<TlsInfo>,
    /// An L4 session, for the stream variables.
    pub session: Option<crate::stream::Session>,
    /// Served through HTTP/2.
    pub h2: bool,
    /// The request came over HTTP/3.
    pub h3: bool,
    pub started: Instant,
    /// Requests served on this connection, this one included.
    pub requests: u64,
    /// Connection serial number ($connection).
    pub conn_id: u64,
    /// $request_id: 32 hex digits, made when first used.
    pub request_id: [u8; 32],
    pub request_id_set: bool,
    pub sent: Sent,
    /// Response headers from the route's (or site's) HeaderOps, expanded
    /// as complete lines, added to generated responses.
    pub resp_extra: Vec<u8>,
    /// A Set-Cookie line for a sticky session, added to a proxied response.
    pub sticky_cookie: Vec<u8>,
    /// The request and connection limits ran for this request.
    pub limited: bool,
    /// Rate limit nodes held between lookup and accounting.
    pub rate_held: Vec<(u32, u32)>,
    /// A WWW-Authenticate line for a 401 from the access phase.
    pub auth_header: Vec<u8>,
    /// Response header lines of the forward auth that the request sent
    /// upstream carries.
    pub auth_resp: Vec<u8>,
    /// The token a jwt policy verified.
    pub jwt: Option<Box<crate::jwt::Verified>>,
    /// The signed in user of an oidc policy.
    pub oidc_sub: Vec<u8>,
    pub oidc_email: Vec<u8>,
    /// Response throttling of the route that serves the request.
    pub bandwidth: Option<proxelo_snapshot::Bandwidth>,
    /// Bytes written to the client so far, for the bandwidth limit.
    pub paced: u64,
    /// The snapshot's lookup variables, set when the request starts.
    pub lookups: std::sync::Arc<[proxelo_snapshot::Lookup]>,
    /// Lookup values computed in this request: spans into `lookup_buf`,
    /// `None` until first used (nginx caches variables per request).
    pub lookup_vals: Vec<Option<(u32, u32)>>,
    pub lookup_buf: Vec<u8>,
    /// Scratch for computing a lookup.
    pub lookup_src: Vec<u8>,
    /// The snapshot's compression settings, set with `lookups`.
    pub compressions: std::sync::Arc<[proxelo_snapshot::Compression]>,
    /// Index into `compressions` for the route (or site) now answering.
    pub compression: Option<u32>,
    /// Vary: Accept-Encoding goes out with the response.
    pub vary: bool,
    /// $document_root, $fastcgi_script_name and $fastcgi_path_info of a
    /// gateway request.
    pub doc_root: Vec<u8>,
    pub script_name: Vec<u8>,
    pub path_info: Vec<u8>,
    /// The request body was read in full with this length.
    pub body_len: Option<u64>,
    /// Groups of fastcgi_split_path_info, kept apart from `$1`..`$9`.
    pub gw_caps: Captures,
    /// $proxy_host of the upstream being proxied to.
    pub proxy_host: Vec<u8>,
    /// $upstream_cache_status; empty when the route is not cached.
    pub cache_status: &'static [u8],
    /// $slice_range while a slice is fetched.
    pub slice_range: Vec<u8>,
    /// Conditional header lines of a cache revalidation, sent upstream.
    pub cache_cond: Vec<u8>,
    /// The upstream request goes out as GET (a cached HEAD).
    pub as_get_upstream: bool,
    /// The Alt-Svc line every response of this connection carries; empty
    /// unless the listener serves HTTP/3.
    pub alt_svc: Vec<u8>,
    /// Rule IDs proxy-wasm filters logged as matching.
    pub waf_rules: Vec<u32>,
}

/// Lowercases `raw` into `out` without the port and a trailing dot.
fn host_key(raw: &[u8], out: &mut Vec<u8>) {
    let end = if raw.first() == Some(&b'[') {
        raw.iter()
            .position(|&c| c == b']')
            .map_or(raw.len(), |i| i + 1)
    } else {
        raw.iter().position(|&c| c == b':').unwrap_or(raw.len())
    };
    let h = &raw[..end];
    let h = h.strip_suffix(b".").unwrap_or(h);
    out.clear();
    out.extend(h.iter().map(u8::to_ascii_lowercase));
}

impl Exchange {
    pub fn new(local: SocketAddr, peer: SocketAddr) -> Self {
        Self {
            local,
            peer,
            conn_peer: peer,
            head: Vec::new(),
            req: Request::default(),
            host: Vec::new(),
            path: Vec::new(),
            args: Vec::new(),
            scratch: Vec::new(),
            tmpl: Vec::new(),
            caps: Captures::default(),
            uri_changed: false,
            error_paged: false,
            err_status: 0,
            as_get: false,
            tls: None,
            session: None,
            h2: false,
            h3: false,
            started: Instant::now(),
            requests: 0,
            conn_id: 0,
            request_id: [0; 32],
            request_id_set: false,
            sent: Sent::default(),
            resp_extra: Vec::new(),
            sticky_cookie: Vec::new(),
            limited: false,
            rate_held: Vec::new(),
            auth_header: Vec::new(),
            auth_resp: Vec::new(),
            jwt: None,
            oidc_sub: Vec::new(),
            oidc_email: Vec::new(),
            bandwidth: None,
            paced: 0,
            lookups: std::sync::Arc::from([]),
            lookup_vals: Vec::new(),
            lookup_buf: Vec::new(),
            lookup_src: Vec::new(),
            compressions: std::sync::Arc::from([]),
            compression: None,
            vary: false,
            doc_root: Vec::new(),
            script_name: Vec::new(),
            path_info: Vec::new(),
            body_len: None,
            gw_caps: Captures::default(),
            proxy_host: Vec::new(),
            cache_status: b"",
            slice_range: Vec::new(),
            cache_cond: Vec::new(),
            as_get_upstream: false,
            alt_svc: Vec::new(),
            waf_rules: Vec::new(),
        }
    }

    pub fn https(&self) -> bool {
        self.tls.is_some()
    }

    /// The unique ID of this request, made from 16 random bytes like nginx.
    pub fn request_id(&mut self) -> &[u8; 32] {
        if !self.request_id_set {
            let mut raw = [0u8; 16];
            if openssl::rand::rand_bytes(&mut raw).is_err() {
                raw = (self.conn_id as u128 ^ (self.requests as u128) << 64).to_le_bytes();
            }
            for (i, b) in raw.iter().enumerate() {
                self.request_id[2 * i] = b"0123456789abcdef"[usize::from(b >> 4)];
                self.request_id[2 * i + 1] = b"0123456789abcdef"[usize::from(b & 15)];
            }
            self.request_id_set = true;
        }
        &self.request_id
    }

    /// Starts the request parsed into `req` from `head`: host, path and
    /// arguments. `Err` is the status to answer, 400 for a path that leaves
    /// the root.
    /// Empties the extra response header lines down to the connection's.
    pub fn reset_extra(&mut self) {
        self.resp_extra.clear();
        self.resp_extra.extend_from_slice(&self.alt_svc);
    }

    pub fn begin(&mut self) -> Result<(), u16> {
        self.caps.clear();
        self.request_id_set = false;
        self.sent = Sent::default();
        self.reset_extra();
        self.sticky_cookie.clear();
        self.peer = self.conn_peer;
        self.limited = false;
        self.auth_header.clear();
        self.auth_resp.clear();
        self.jwt = None;
        self.oidc_sub.clear();
        self.oidc_email.clear();
        self.waf_rules.clear();
        self.bandwidth = None;
        self.paced = 0;
        self.lookup_vals.clear();
        self.lookup_vals.resize(self.lookups.len(), None);
        self.lookup_buf.clear();
        self.compression = None;
        self.vary = false;
        self.doc_root.clear();
        self.script_name.clear();
        self.path_info.clear();
        self.body_len = None;
        self.proxy_host.clear();
        self.cache_status = b"";
        self.slice_range.clear();
        self.uri_changed = false;
        self.error_paged = false;
        self.err_status = 0;
        self.as_get = false;
        match self.req.host {
            Some(h) => host_key(h.get(&self.head), &mut self.host),
            None => self.host.clear(),
        }
        if normalize_path(self.req.path.get(&self.head), &mut self.path).is_err() {
            return Err(400);
        }
        self.args.clear();
        let target = self.req.target.get(&self.head);
        if let Some(q) = target.iter().position(|&c| c == b'?') {
            self.args.extend_from_slice(&target[q + 1..]);
        }
        Ok(())
    }

    /// The host for site lookup, `None` when the request has none.
    pub fn host(&self) -> Option<&[u8]> {
        (!self.host.is_empty()).then_some(&self.host[..])
    }

    /// The status to send: the one an error page set, if any.
    pub fn status(&self, status: u16) -> u16 {
        if self.err_status != 0 {
            self.err_status
        } else {
            status
        }
    }

    /// The value of cookie `name` from the Cookie headers ($cookie_<name>).
    pub fn cookie(&self, name: &[u8]) -> Option<&[u8]> {
        self.req
            .headers
            .iter()
            .filter(|h| h.name.get(&self.head).eq_ignore_ascii_case(b"cookie"))
            .flat_map(|h| h.value.get(&self.head).split(|&c| c == b';'))
            .find_map(|pair| {
                let pair = pair.trim_ascii_start();
                let eq = pair.iter().position(|&c| c == b'=')?;
                (&pair[..eq] == name).then(|| pair[eq + 1..].trim_ascii_end())
            })
    }

    /// The value of `name` in the forward auth response ($auth_resp_<name>).
    pub fn auth_resp(&self, name: &[u8]) -> Option<&[u8]> {
        self.auth_resp
            .split(|&c| c == b'\n')
            .filter_map(|l| {
                let colon = l.iter().position(|&c| c == b':')?;
                Some((&l[..colon], l[colon + 1..].trim_ascii()))
            })
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    pub fn request_header(&self, name: &[u8]) -> Option<&[u8]> {
        self.req
            .headers
            .iter()
            .find(|h| h.name.get(&self.head).eq_ignore_ascii_case(name))
            .map(|h| h.value.get(&self.head))
    }
}

impl Facts for Exchange {
    fn method(&self) -> &[u8] {
        if self.as_get {
            b"GET"
        } else {
            self.req.method_span.get(&self.head)
        }
    }

    fn path(&self) -> &[u8] {
        &self.path
    }

    fn uri(&self) -> &[u8] {
        self.req.target.get(&self.head)
    }

    fn args(&self) -> &[u8] {
        &self.args
    }

    fn host(&self) -> &[u8] {
        &self.host
    }

    fn scheme(&self) -> &[u8] {
        if self.https() { b"https" } else { b"http" }
    }

    fn remote_addr(&self) -> IpAddr {
        self.peer.ip()
    }

    fn find_header(&self, f: &mut dyn FnMut(&[u8], &[u8]) -> bool) -> bool {
        self.req
            .headers
            .iter()
            .any(|h| f(h.name.get(&self.head), h.value.get(&self.head)))
    }
}

/// HEAD keeps its method through an error page; anything else becomes GET.
pub(crate) fn to_get(x: &mut Exchange) {
    if x.req.method != Method::Head {
        x.req.method = Method::Get;
        x.as_get = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_keys() {
        let mut out = Vec::new();
        for (raw, want) in [
            (&b"Example.COM"[..], &b"example.com"[..]),
            (b"example.com:8080", b"example.com"),
            (b"example.com.", b"example.com"),
            (b"[::1]:80", b"[::1]"),
        ] {
            host_key(raw, &mut out);
            assert_eq!(out, want);
        }
    }
}
