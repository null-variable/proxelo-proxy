//! nginx-style value templates: literal text, `$variables` and `$0`..`$9`.
//!
//! Parsing happens once when a snapshot is built; the request path only walks
//! the parts.

use std::fmt;

/// A variable whose value comes from the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Var {
    /// `$uri`, `$document_uri`: the current normalized path.
    Uri,
    /// `$args`, `$query_string`.
    Args,
    /// `?` when there are arguments.
    IsArgs,
    /// `$request_uri`: the target as the client sent it.
    RequestUri,
    Host,
    Scheme,
    RequestMethod,
    ServerPort,
    RemoteAddr,
    RemotePort,
    ServerAddr,
    ServerName,
    ServerProtocol,
    /// `$https`: "on" over TLS, empty otherwise.
    Https,
    SslProtocol,
    SslCipher,
    SslServerName,
    /// `$request`: the request line.
    Request,
    RequestLength,
    RequestId,
    /// `$request_time`: seconds with milliseconds since the request began.
    RequestTime,
    Msec,
    TimeLocal,
    TimeIso8601,
    /// The rest are known once the response is sent, for access logs.
    Status,
    BytesSent,
    BodyBytesSent,
    Connection,
    ConnectionRequests,
    UpstreamAddr,
    UpstreamStatus,
    UpstreamResponseTime,
    UpstreamConnectTime,
    UpstreamHeaderTime,
    RemoteUser,
    /// The client address as 4 or 16 bytes.
    BinaryRemoteAddr,
    /// The connection's address before real_ip.
    RealipRemoteAddr,
    RealipRemotePort,
    SslSessionReused,
    /// `$ssl_client_verify`: NONE, SUCCESS or FAILED:<reason>.
    SslClientVerify,
    SslClientSDn,
    SslClientIDn,
    SslClientSerial,
    /// `$ssl_client_cert`: PEM with each line after the first indented.
    SslClientCert,
    /// `$ssl_client_escaped_cert`: PEM, URL-encoded.
    SslClientEscapedCert,
    /// `$document_root`: the gateway's document root.
    DocumentRoot,
    /// `$content_length`: the Content-Length header, or the length of a
    /// body read in full.
    ContentLength,
    ContentType,
    FastcgiScriptName,
    FastcgiPathInfo,
    /// `$0`..`$9`: groups of the last regex that matched.
    Capture(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    Lit(Box<[u8]>),
    Var(Var),
    /// `$http_<name>`, with the lowercase header name using `-`.
    Header(Box<[u8]>),
    /// `$arg_<name>`.
    Arg(Box<[u8]>),
    /// `$cookie_<name>`.
    Cookie(Box<[u8]>),
    /// `$auth_resp_<name>`: a header of the forward auth response, with the
    /// lowercase name using `-`.
    AuthResp(Box<[u8]>),
    /// A lookup variable (map, geo, split_clients), by index into
    /// `Runtime::lookups`.
    Lookup(u32),
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Template {
    parts: Box<[Part]>,
    source: Box<str>,
}

impl fmt::Debug for Template {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Template({:?})", self.source)
    }
}

impl Template {
    /// Parses a template that may use only the built-in variables.
    pub fn parse(s: &str) -> Result<Self, String> {
        Self::parse_in(s, &[])
    }

    /// Parses a template that may also use the lookup variables `lookups`,
    /// by name, as `Part::Lookup` with the index into it.
    pub fn parse_in(s: &str, lookups: &[Box<str>]) -> Result<Self, String> {
        let b = s.as_bytes();
        let mut parts = Vec::new();
        let mut lit = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] != b'$' {
                lit.push(b[i]);
                i += 1;
                continue;
            }
            i += 1;
            let var = if let Some(&d) = b.get(i).filter(|c| c.is_ascii_digit()) {
                // nginx takes one digit: "$10" is $1 followed by "0".
                i += 1;
                Part::Var(Var::Capture(d - b'0'))
            } else {
                let braced = b.get(i) == Some(&b'{');
                if braced {
                    i += 1;
                }
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                if start == i {
                    return Err(format!("{s:?}: '$' must be followed by a variable name"));
                }
                let name = &s[start..i];
                if braced {
                    if b.get(i) != Some(&b'}') {
                        return Err(format!("{s:?}: missing '}}' after ${{{name}"));
                    }
                    i += 1;
                }
                var(name)
                    .or_else(|| {
                        let i = lookups.iter().position(|l| &**l == name)?;
                        Some(Part::Lookup(i as u32))
                    })
                    .ok_or_else(|| format!("{s:?}: unknown variable ${name}"))?
            };
            if !lit.is_empty() {
                parts.push(Part::Lit(std::mem::take(&mut lit).into()));
            }
            parts.push(var);
        }
        if !lit.is_empty() {
            parts.push(Part::Lit(lit.into()));
        }
        Ok(Self {
            parts: parts.into(),
            source: s.into(),
        })
    }

    pub fn parts(&self) -> &[Part] {
        &self.parts
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn uses_captures(&self) -> bool {
        self.parts
            .iter()
            .any(|p| matches!(p, Part::Var(Var::Capture(_))))
    }
}

/// Whether `name` is a built-in variable, which a lookup cannot redefine.
pub(crate) fn is_builtin(name: &str) -> bool {
    var(name).is_some()
}

fn var(name: &str) -> Option<Part> {
    let v = match name {
        "uri" | "document_uri" => Var::Uri,
        "args" | "query_string" => Var::Args,
        "is_args" => Var::IsArgs,
        "request_uri" => Var::RequestUri,
        "host" => Var::Host,
        "scheme" => Var::Scheme,
        "request_method" => Var::RequestMethod,
        "server_port" => Var::ServerPort,
        "remote_addr" => Var::RemoteAddr,
        "binary_remote_addr" => Var::BinaryRemoteAddr,
        "remote_port" => Var::RemotePort,
        "server_addr" => Var::ServerAddr,
        "server_name" => Var::ServerName,
        "server_protocol" => Var::ServerProtocol,
        "https" => Var::Https,
        "ssl_protocol" => Var::SslProtocol,
        "ssl_cipher" => Var::SslCipher,
        "ssl_server_name" => Var::SslServerName,
        "request" => Var::Request,
        "request_length" => Var::RequestLength,
        "request_id" => Var::RequestId,
        "request_time" => Var::RequestTime,
        "msec" => Var::Msec,
        "time_local" => Var::TimeLocal,
        "time_iso8601" => Var::TimeIso8601,
        "status" => Var::Status,
        "bytes_sent" => Var::BytesSent,
        "body_bytes_sent" => Var::BodyBytesSent,
        "connection" => Var::Connection,
        "connection_requests" => Var::ConnectionRequests,
        "upstream_addr" => Var::UpstreamAddr,
        "upstream_status" => Var::UpstreamStatus,
        "upstream_response_time" => Var::UpstreamResponseTime,
        "upstream_connect_time" => Var::UpstreamConnectTime,
        "upstream_header_time" => Var::UpstreamHeaderTime,
        "remote_user" => Var::RemoteUser,
        "realip_remote_addr" => Var::RealipRemoteAddr,
        "realip_remote_port" => Var::RealipRemotePort,
        "ssl_session_reused" => Var::SslSessionReused,
        "ssl_client_verify" => Var::SslClientVerify,
        "ssl_client_s_dn" => Var::SslClientSDn,
        "ssl_client_i_dn" => Var::SslClientIDn,
        "ssl_client_serial" => Var::SslClientSerial,
        "ssl_client_cert" => Var::SslClientCert,
        "ssl_client_escaped_cert" => Var::SslClientEscapedCert,
        "document_root" => Var::DocumentRoot,
        "content_length" => Var::ContentLength,
        "content_type" => Var::ContentType,
        "fastcgi_script_name" => Var::FastcgiScriptName,
        "fastcgi_path_info" => Var::FastcgiPathInfo,
        _ => {
            let header = |h: &str| -> Box<[u8]> {
                h.bytes()
                    .map(|c| match c {
                        b'_' => b'-',
                        c => c.to_ascii_lowercase(),
                    })
                    .collect()
            };
            if let Some(h) = name.strip_prefix("http_").filter(|h| !h.is_empty()) {
                return Some(Part::Header(header(h)));
            }
            if let Some(h) = name.strip_prefix("auth_resp_").filter(|h| !h.is_empty()) {
                return Some(Part::AuthResp(header(h)));
            }
            if let Some(a) = name.strip_prefix("arg_").filter(|a| !a.is_empty()) {
                return Some(Part::Arg(a.as_bytes().into()));
            }
            if let Some(c) = name.strip_prefix("cookie_").filter(|c| !c.is_empty()) {
                return Some(Part::Cookie(c.as_bytes().into()));
            }
            return None;
        }
    };
    Some(Part::Var(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nginx_syntax() {
        let t = Template::parse("/x/$1${uri}?a=$arg_id&h=$http_X_Real_IP$10").unwrap();
        assert_eq!(
            t.parts(),
            &[
                Part::Lit((*b"/x/").into()),
                Part::Var(Var::Capture(1)),
                Part::Var(Var::Uri),
                Part::Lit((*b"?a=").into()),
                Part::Arg((*b"id").into()),
                Part::Lit((*b"&h=").into()),
                Part::Header((*b"x-real-ip").into()),
                Part::Var(Var::Capture(1)),
                Part::Lit((*b"0").into()),
            ]
        );
        assert!(t.uses_captures());
        assert!(!Template::parse("$uri/").unwrap().uses_captures());
    }

    #[test]
    fn lookups_by_name() {
        let names: Vec<Box<str>> = vec!["a".into(), "bucket".into()];
        let t = Template::parse_in("$bucket-$a$uri", &names).unwrap();
        assert_eq!(
            t.parts(),
            &[
                Part::Lookup(1),
                Part::Lit((*b"-").into()),
                Part::Lookup(0),
                Part::Var(Var::Uri),
            ]
        );
        assert!(Template::parse("$bucket").is_err());
    }

    #[test]
    fn rejects_bad_variables() {
        for bad in ["$", "a$", "${uri", "$nope", "$http_", "${}"] {
            assert!(Template::parse(bad).is_err(), "{bad}");
        }
    }
}
