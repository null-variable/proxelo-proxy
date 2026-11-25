//! The state of one request as the phases see it, without the connection:
//! the parsed head, the current URI and what earlier phases decided. Serving
//! and the simulator run requests through the same [`Exchange`].

use std::net::{IpAddr, SocketAddr};

use proxelo_http1::{Method, Request, normalize_path};
use proxelo_snapshot::{Captures, Facts};

pub(crate) struct Exchange {
    pub local: SocketAddr,
    pub peer: SocketAddr,
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
        }
    }

    /// Starts the request parsed into `req` from `head`: host, path and
    /// arguments. `Err` is the status to answer, 400 for a path that leaves
    /// the root.
    pub fn begin(&mut self) -> Result<(), u16> {
        self.caps.clear();
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
        b"http"
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
