//! The runtime form of nginx proxy_redirect, proxy_cookie_domain,
//! proxy_cookie_path and proxy_cookie_flags.

use proxelo_api::snapshot::v1::{self as ir, header_rewrite::Kind};

use crate::runtime::Pattern;
use crate::template::Template;

/// Upstream response header edits of a proxy route.
#[derive(Debug, Default)]
pub struct ProxyEdits {
    pub redirects: Box<[HeaderRewrite]>,
    pub cookie_domains: Box<[HeaderRewrite]>,
    pub cookie_paths: Box<[HeaderRewrite]>,
    pub cookie_flags: Box<[CookieFlags]>,
}

impl ProxyEdits {
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
    Ok(Some(ProxyEdits {
        redirects: rules(&p.redirects, "redirects", false)?,
        cookie_domains: rules(&p.cookie_domains, "cookie_domains", true)?,
        cookie_paths: rules(&p.cookie_paths, "cookie_paths", false)?,
        cookie_flags,
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
        assert!(build(&ir::ProxyAction::default(), &[]).unwrap().is_none());
    }
}
