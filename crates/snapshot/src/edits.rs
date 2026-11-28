//! The runtime form of the per-route upstream request and response edits:
//! nginx proxy_redirect, proxy_cookie_*, proxy_pass_header, proxy_method,
//! proxy_set_body, proxy_pass_request_headers, proxy_pass_request_body and
//! proxy_bind.

use proxelo_api::snapshot::v1::{self as ir, header_rewrite::Kind};

use crate::runtime::Pattern;
use crate::template::Template;

/// Upstream request and response edits of a route's proxy, gateway,
/// memcached or grpc action.
#[derive(Debug, Default)]
pub struct ProxyEdits {
    pub redirects: Box<[HeaderRewrite]>,
    pub cookie_domains: Box<[HeaderRewrite]>,
    pub cookie_paths: Box<[HeaderRewrite]>,
    pub cookie_flags: Box<[CookieFlags]>,
    /// Hidden upstream response headers passed on, lowercase.
    pub pass_headers: Box<[Box<[u8]>]>,
    /// The upstream method; `None`: the client's.
    pub method: Option<Template>,
    /// The upstream request body in place of the client's.
    pub body: Option<Template>,
    pub no_request_headers: bool,
    pub no_request_body: bool,
    /// The local address of upstream connections.
    pub bind: Option<Template>,
}

impl ProxyEdits {
    /// Whether the hidden response header `name` is passed on.
    pub fn passes(&self, name: &[u8]) -> bool {
        self.pass_headers
            .iter()
            .any(|p| name.eq_ignore_ascii_case(p))
    }

    /// Whether the client's request body is not sent upstream.
    pub fn replaces_body(&self) -> bool {
        self.body.is_some() || self.no_request_body
    }

    pub fn cookies(&self) -> bool {
        !self.cookie_domains.is_empty()
            || !self.cookie_paths.is_empty()
            || !self.cookie_flags.is_empty()
    }
}

#[derive(Debug)]
pub struct HeaderRewrite {
    pub pattern: RewriteMatch,
    pub replacement: Template,
}

#[derive(Debug)]
pub enum RewriteMatch {
    /// The value starts with the expansion, compared exactly.
    Prefix(Template),
    /// Searched in the value; the whole value is replaced.
    Regex(Pattern),
    /// A cookie domain equal to the expansion ignoring case, past a leading
    /// dot.
    Domain(Template),
}

#[derive(Debug)]
pub struct CookieFlags {
    pub cookie: CookieName,
    pub flags: Box<[Template]>,
}

#[derive(Debug)]
pub enum CookieName {
    /// Compared ignoring case.
    Name(Template),
    /// Caseless.
    Regex(Pattern),
}

type Invalid = (String, String);

pub(crate) fn build(
    p: &ir::ProxyAction,
    names: &[Box<str>],
) -> Result<Option<ProxyEdits>, Invalid> {
    if p.redirects.is_empty()
        && p.cookie_domains.is_empty()
        && p.cookie_paths.is_empty()
        && p.cookie_flags.is_empty()
        && p.pass_headers.is_empty()
        && p.method.is_empty()
        && p.body.is_none()
        && !p.no_request_headers
        && !p.no_request_body
        && p.bind.is_empty()
    {
        return Ok(None);
    }
    let tmpl = |s: &str, f: String| Template::parse_in(s, names).map_err(|e| (f, e));
    let rules = |rs: &[ir::HeaderRewrite], field: &str, domain: bool| {
        rs.iter()
            .enumerate()
            .map(|(i, r)| {
                let at = format!("{field}[{i}]");
                let regex = |caseless| {
                    Pattern::new(&r.pattern, caseless).map_err(|e| (format!("{at}.pattern"), e))
                };
                // nginx drops a leading dot of a domain and its replacement.
                let strip = |s: &'_ str| {
                    if domain {
                        s.strip_prefix('.').unwrap_or(s).to_string()
                    } else {
                        s.to_string()
                    }
                };
                let pattern = match r.kind() {
                    Kind::Unspecified if domain => {
                        RewriteMatch::Domain(tmpl(&strip(&r.pattern), format!("{at}.pattern"))?)
                    }
                    Kind::Unspecified => {
                        RewriteMatch::Prefix(tmpl(&r.pattern, format!("{at}.pattern"))?)
                    }
                    Kind::Domain if domain => {
                        RewriteMatch::Domain(tmpl(&strip(&r.pattern), format!("{at}.pattern"))?)
                    }
                    Kind::Domain => {
                        return Err((format!("{at}.kind"), "only for cookie domains".into()));
                    }
                    Kind::Regex => RewriteMatch::Regex(regex(false)?),
                    Kind::RegexCaseless => RewriteMatch::Regex(regex(true)?),
                };
                let replacement = match pattern {
                    RewriteMatch::Domain(_) => strip(&r.replacement),
                    _ => r.replacement.clone(),
                };
                Ok(HeaderRewrite {
                    pattern,
                    replacement: tmpl(&replacement, format!("{at}.replacement"))?,
                })
            })
            .collect::<Result<Box<[_]>, Invalid>>()
    };
    let cookie_flags = p
        .cookie_flags
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let at = format!("cookie_flags[{i}]");
            let cookie = if c.regex {
                CookieName::Regex(
                    Pattern::new(&c.cookie, true).map_err(|e| (format!("{at}.cookie"), e))?,
                )
            } else {
                CookieName::Name(tmpl(&c.cookie, format!("{at}.cookie"))?)
            };
            let flags = c
                .flags
                .iter()
                .enumerate()
                .map(|(j, f)| tmpl(f, format!("{at}.flags[{j}]")))
                .collect::<Result<_, _>>()?;
            Ok(CookieFlags { cookie, flags })
        })
        .collect::<Result<_, Invalid>>()?;
    let optional = |s: &str, f: &str| (!s.is_empty()).then(|| tmpl(s, f.into())).transpose();
    Ok(Some(ProxyEdits {
        redirects: rules(&p.redirects, "redirects", false)?,
        cookie_domains: rules(&p.cookie_domains, "cookie_domains", true)?,
        cookie_paths: rules(&p.cookie_paths, "cookie_paths", false)?,
        cookie_flags,
        pass_headers: p
            .pass_headers
            .iter()
            .map(|h| h.to_ascii_lowercase().into_bytes().into())
            .collect(),
        method: optional(&p.method, "method")?,
        body: p
            .body
            .as_deref()
            .map(|b| tmpl(b, "body".into()))
            .transpose()?,
        no_request_headers: p.no_request_headers,
        no_request_body: p.no_request_body,
        bind: optional(&p.bind, "bind")?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_drop_the_leading_dot() {
        let p = ir::ProxyAction {
            cookie_domains: vec![ir::HeaderRewrite {
                pattern: ".up.local".into(),
                replacement: ".example.com".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let e = build(&p, &[]).unwrap().unwrap();
        let RewriteMatch::Domain(t) = &e.cookie_domains[0].pattern else {
            panic!()
        };
        assert_eq!(t.source(), "up.local");
        assert_eq!(e.cookie_domains[0].replacement.source(), "example.com");
        assert!(e.cookies());
    }

    #[test]
    fn invalid_rules() {
        let bad = ir::ProxyAction {
            redirects: vec![ir::HeaderRewrite {
                kind: Kind::Regex.into(),
                pattern: "(".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(build(&bad, &[]).unwrap_err().0, "redirects[0].pattern");
        let bad = ir::ProxyAction {
            cookie_paths: vec![ir::HeaderRewrite {
                kind: Kind::Domain.into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(build(&bad, &[]).unwrap_err().0, "cookie_paths[0].kind");
        let bad = ir::ProxyAction {
            bind: "$nope".into(),
            ..Default::default()
        };
        assert_eq!(build(&bad, &[]).unwrap_err().0, "bind");
        assert!(build(&ir::ProxyAction::default(), &[]).unwrap().is_none());
    }

    #[test]
    fn request_edits() {
        let p = ir::ProxyAction {
            pass_headers: vec!["X-Accel-Redirect".into()],
            body: Some(String::new()),
            ..Default::default()
        };
        let e = build(&p, &[]).unwrap().unwrap();
        assert!(e.passes(b"x-accel-REDIRECT") && !e.passes(b"server"));
        // An empty body is a body: the client's is still replaced.
        assert!(e.replaces_body() && e.method.is_none() && !e.cookies());
    }
}
