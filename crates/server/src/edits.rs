//! nginx proxy_redirect, proxy_cookie_domain, proxy_cookie_path and
//! proxy_cookie_flags on upstream response headers, and proxy_bind and
//! proxy_method on the upstream request.

use std::net::{IpAddr, SocketAddr};

use proxelo_snapshot::{CookieName, HeaderRewrite, MatchError, ProxyEdits, RewriteMatch};

use crate::exchange::Exchange;
use crate::reply;
use crate::vars::expand_into;

/// Writes the value of upstream header `name` after the edits, without the
/// line end, into `out`. `false`: the header is not one the edits change,
/// no rule applied or a regex gave up (MatchError); the caller sends
/// `value` as it is and `out` is unchanged.
pub(crate) fn header(
    x: &mut Exchange,
    e: &ProxyEdits,
    name: &[u8],
    value: &[u8],
    out: &mut Vec<u8>,
) -> bool {
    let start = out.len();
    let done = matches!(edit(x, e, name, value, out, start), Ok(true));
    if !done {
        out.truncate(start);
    }
    done
}

/// Appends `name: value` of an upstream header, edited by `e`.
pub(crate) fn push_line(
    x: &mut Exchange,
    e: Option<&ProxyEdits>,
    name: &[u8],
    value: &[u8],
    out: &mut Vec<u8>,
) {
    out.extend_from_slice(name);
    out.extend_from_slice(b": ");
    if !e.is_some_and(|e| header(x, e, name, value, out)) {
        out.extend_from_slice(value);
    }
    out.extend_from_slice(b"\r\n");
}

/// The local address of an upstream connection (nginx proxy_bind): `None`
/// when the route has none or its expansion is empty or not an address,
/// which nginx logs and connects without.
pub(crate) fn bind(x: &mut Exchange, e: Option<&ProxyEdits>) -> Option<SocketAddr> {
    let t = e?.bind.as_ref()?;
    let mut out = std::mem::take(&mut x.tmpl);
    out.clear();
    expand_into(x, t, &mut out, None);
    let addr = local_addr(&out);
    if addr.is_none() && !out.is_empty() {
        eprintln!(
            "invalid local address \"{}\"",
            String::from_utf8_lossy(&out)
        );
    }
    x.tmpl = out;
    addr
}

/// An IP address with an optional port, IPv6 in brackets with a port.
fn local_addr(v: &[u8]) -> Option<SocketAddr> {
    let s = std::str::from_utf8(v).ok()?;
    s.parse::<SocketAddr>()
        .ok()
        .or_else(|| s.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 0)))
}

/// Appends the upstream method (nginx proxy_method) when it expands to an
/// HTTP token; `false` keeps the client's.
pub(crate) fn method(x: &mut Exchange, e: Option<&ProxyEdits>, out: &mut Vec<u8>) -> bool {
    let Some(t) = e.and_then(|e| e.method.as_ref()) else {
        return false;
    };
    let start = out.len();
    expand_into(x, t, out, None);
    let ok = out.len() > start && out[start..].iter().all(|&c| is_tchar(c));
    if !ok {
        out.truncate(start);
    }
    ok
}

/// RFC 9110 §5.6.2 tchar.
fn is_tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

fn edit(
    x: &mut Exchange,
    e: &ProxyEdits,
    name: &[u8],
    value: &[u8],
    out: &mut Vec<u8>,
    start: usize,
) -> Result<bool, MatchError> {
    Ok(if name.eq_ignore_ascii_case(b"location") {
        let done = rewrite(x, &e.redirects, value, 0, out)?;
        // A Location a rule made a path is made absolute, as nginx's
        // header filter does for its own (absolute_redirect on).
        if done && out.get(start) == Some(&b'/') {
            let path = out.split_off(start);
            reply::push_origin(out, x.tls.is_some(), &x.host, x.local);
            out.extend_from_slice(&path);
        }
        done
    } else if name.eq_ignore_ascii_case(b"refresh") {
        match find_caseless(value, b"url=") {
            Some(i) => rewrite(x, &e.redirects, value, i + 4, out)?,
            None => false,
        }
    } else if name.eq_ignore_ascii_case(b"set-cookie") && e.cookies() {
        cookie(x, e, value, out)?
    } else {
        false
    })
}

fn find_caseless(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

/// The first of `rules` that matches `value[prefix..]` writes the new value
/// to `out` (ngx_http_proxy_rewrite).
fn rewrite(
    x: &mut Exchange,
    rules: &[HeaderRewrite],
    value: &[u8],
    prefix: usize,
    out: &mut Vec<u8>,
) -> Result<bool, MatchError> {
    let rest = &value[prefix..];
    let mut pat = Vec::new();
    for r in rules {
        // The span of `rest` the replacement takes.
        let (from, to) = match &r.pattern {
            RewriteMatch::Prefix(t) => {
                pat.clear();
                expand_into(x, t, &mut pat, None);
                if !rest.starts_with(&pat) {
                    continue;
                }
                (0, pat.len())
            }
            RewriteMatch::Regex(re) => {
                if !re.captures(rest, &mut x.caps)? {
                    continue;
                }
                (0, rest.len())
            }
            RewriteMatch::Domain(t) => {
                pat.clear();
                expand_into(x, t, &mut pat, None);
                let dot = usize::from(rest.first() == Some(&b'.'));
                if !rest[dot..].eq_ignore_ascii_case(&pat) {
                    continue;
                }
                (dot, rest.len())
            }
        };
        out.extend_from_slice(&value[..prefix + from]);
        expand_into(x, &r.replacement, out, None);
        out.extend_from_slice(&rest[to..]);
        return Ok(true);
    }
    Ok(false)
}

/// One attribute of a Set-Cookie: its name and, after `=`, its value.
struct Attr<'a> {
    key: &'a [u8],
    value: Option<Vec<u8>>,
    dropped: bool,
}

/// Splits a Set-Cookie value at `;` and `=`, trimming spaces
/// (ngx_http_proxy_parse_cookie).
fn trim(s: &[u8]) -> &[u8] {
    let s = &s[s.iter().position(|&c| c != b' ').unwrap_or(s.len())..];
    &s[..s.iter().rposition(|&c| c != b' ').map_or(0, |i| i + 1)]
}

fn parse(v: &[u8]) -> Vec<Attr<'_>> {
    v.split(|&c| c == b';')
        .map(|part| match part.iter().position(|&c| c == b'=') {
            Some(i) => Attr {
                key: trim(&part[..i]),
                value: Some(trim(&part[i + 1..]).to_vec()),
                dropped: false,
            },
            None => Attr {
                key: trim(part),
                value: None,
                dropped: false,
            },
        })
        .collect()
}

const SECURE_ON: u8 = 1;
const SECURE_OFF: u8 = 2;
const HTTPONLY_ON: u8 = 4;
const HTTPONLY_OFF: u8 = 8;
const STRICT: u8 = 16;
const LAX: u8 = 32;
const NONE: u8 = 64;
const SAMESITE_OFF: u8 = 128;

const FLAGS: [(&[u8], u8); 8] = [
    (b"secure", SECURE_ON),
    (b"nosecure", SECURE_OFF),
    (b"httponly", HTTPONLY_ON),
    (b"nohttponly", HTTPONLY_OFF),
    (b"samesite=strict", STRICT),
    (b"samesite=lax", LAX),
    (b"samesite=none", NONE),
    (b"nosamesite", SAMESITE_OFF),
];

/// ngx_http_proxy_rewrite_cookie: rewrites Domain and Path, then the
/// flags, and writes the cookie again when any of them applied.
fn cookie(
    x: &mut Exchange,
    e: &ProxyEdits,
    value: &[u8],
    out: &mut Vec<u8>,
) -> Result<bool, MatchError> {
    let mut attrs = parse(value);
    if attrs[0].value.is_none() {
        return Ok(false);
    }
    let mut changed = false;
    let mut buf = Vec::new();
    for a in &mut attrs[1..] {
        let Some(v) = &a.value else { continue };
        let rules = if a.key.eq_ignore_ascii_case(b"domain") {
            &e.cookie_domains
        } else if a.key.eq_ignore_ascii_case(b"path") {
            &e.cookie_paths
        } else {
            continue;
        };
        buf.clear();
        if rewrite(x, rules, v, 0, &mut buf)? {
            a.value = Some(std::mem::take(&mut buf));
            changed = true;
        }
    }
    let flags = flags(x, e, attrs[0].key)?;
    if flags != 0 {
        edit_flags(&mut attrs, flags);
        changed = true;
    }
    if !changed {
        return Ok(false);
    }
    for (i, a) in attrs.iter().enumerate().filter(|(_, a)| !a.dropped) {
        if i > 0 {
            out.extend_from_slice(b"; ");
        }
        out.extend_from_slice(a.key);
        if let Some(v) = &a.value {
            out.push(b'=');
            out.extend_from_slice(v);
        }
    }
    Ok(true)
}

/// The flags of the first entry naming cookie `name`.
fn flags(x: &mut Exchange, e: &ProxyEdits, name: &[u8]) -> Result<u8, MatchError> {
    let mut buf = Vec::new();
    for c in e.cookie_flags.iter() {
        let hit = match &c.cookie {
            CookieName::Regex(re) => re.captures(name, &mut x.caps)?,
            CookieName::Name(t) => {
                buf.clear();
                expand_into(x, t, &mut buf, None);
                buf.eq_ignore_ascii_case(name)
            }
        };
        if !hit {
            continue;
        }
        let mut f = 0;
        for t in c.flags.iter() {
            buf.clear();
            expand_into(x, t, &mut buf, None);
            if let Some((_, bit)) = FLAGS.iter().find(|(n, _)| n.eq_ignore_ascii_case(&buf)) {
                f |= bit;
            }
        }
        return Ok(f);
    }
    Ok(0)
}

/// ngx_http_proxy_edit_cookie_flags.
fn edit_flags(attrs: &mut Vec<Attr<'_>>, mut f: u8) {
    for a in &mut attrs[1..] {
        if a.key.eq_ignore_ascii_case(b"secure") {
            if f & SECURE_ON != 0 {
                f &= !SECURE_ON;
            } else if f & SECURE_OFF != 0 {
                a.dropped = true;
            }
        } else if a.key.eq_ignore_ascii_case(b"httponly") {
            if f & HTTPONLY_ON != 0 {
                f &= !HTTPONLY_ON;
            } else if f & HTTPONLY_OFF != 0 {
                a.dropped = true;
            }
        } else if a.key.eq_ignore_ascii_case(b"samesite") {
            let want: Option<&[u8]> = if f & STRICT != 0 {
                f &= !STRICT;
                Some(b"Strict")
            } else if f & LAX != 0 {
                f &= !LAX;
                Some(b"Lax")
            } else if f & NONE != 0 {
                f &= !NONE;
                Some(b"None")
            } else {
                if f & SAMESITE_OFF != 0 {
                    a.dropped = true;
                }
                None
            };
            if let Some(w) = want
                && !a
                    .value
                    .as_deref()
                    .is_some_and(|v| v.eq_ignore_ascii_case(w))
            {
                a.key = b"SameSite";
                a.value = Some(w.to_vec());
            }
        }
    }
    let mut push = |key: &'static [u8], value: Option<&[u8]>| {
        attrs.push(Attr {
            key,
            value: value.map(<[u8]>::to_vec),
            dropped: false,
        });
    };
    if f & SECURE_ON != 0 {
        push(b"Secure", None);
    }
    if f & HTTPONLY_ON != 0 {
        push(b"HttpOnly", None);
    }
    if f & STRICT != 0 {
        push(b"SameSite", Some(b"Strict"));
    } else if f & LAX != 0 {
        push(b"SameSite", Some(b"Lax"));
    } else if f & NONE != 0 {
        push(b"SameSite", Some(b"None"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_addrs() {
        assert_eq!(local_addr(b"10.0.0.1"), "10.0.0.1:0".parse().ok());
        assert_eq!(local_addr(b"10.0.0.1:4000"), "10.0.0.1:4000".parse().ok());
        assert_eq!(local_addr(b"[::1]:5"), "[::1]:5".parse().ok());
        assert_eq!(local_addr(b"::1"), "[::1]:0".parse().ok());
        assert_eq!(local_addr(b"localhost"), None);
        assert_eq!(local_addr(b""), None);
    }

    fn rebuilt(v: &[u8], f: u8) -> String {
        let mut attrs = parse(v);
        edit_flags(&mut attrs, f);
        let mut out = Vec::new();
        for (i, a) in attrs.iter().enumerate().filter(|(_, a)| !a.dropped) {
            if i > 0 {
                out.extend_from_slice(b"; ");
            }
            out.extend_from_slice(a.key);
            if let Some(v) = &a.value {
                out.push(b'=');
                out.extend_from_slice(v);
            }
        }
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn flags_as_nginx() {
        assert_eq!(
            rebuilt(b"a=1;path=/ ; secure", SECURE_OFF | HTTPONLY_ON),
            "a=1; path=/; HttpOnly"
        );
        assert_eq!(
            rebuilt(b"a=1; SameSite=lax", STRICT),
            "a=1; SameSite=Strict"
        );
        assert_eq!(
            rebuilt(b"a=1; samesite=STRICT", STRICT),
            "a=1; samesite=STRICT"
        );
        assert_eq!(
            rebuilt(b"a=1; SameSite=Lax", SAMESITE_OFF | SECURE_ON),
            "a=1; Secure"
        );
        assert_eq!(
            rebuilt(b"a=1", NONE | SECURE_ON),
            "a=1; Secure; SameSite=None"
        );
    }

    #[test]
    fn caseless_find() {
        assert_eq!(find_caseless(b"5; URL=/x", b"url="), Some(3));
        assert_eq!(find_caseless(b"5", b"url="), None);
    }
}
