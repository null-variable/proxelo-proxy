//! The runtime form of response filters: nginx sub_filter, ssi, addition,
//! charset and userid.

use proxelo_api::snapshot::v1::{self as ir, charset, userid};

use crate::template::Template;

/// Media types a filter applies to (nginx `*_types`).
#[derive(Debug, Default)]
pub struct Types {
    /// Lowercase, without parameters.
    list: Box<[Box<[u8]>]>,
    any: bool,
    /// text/html counts without being listed.
    html: bool,
}

impl Types {
    fn new(list: &[String], html: bool) -> Self {
        Self {
            any: list.iter().any(|t| t == "*"),
            list: list
                .iter()
                .filter(|t| *t != "*")
                .map(|t| t.to_ascii_lowercase().into_bytes().into())
                .collect(),
            html,
        }
    }

    /// Whether `content_type`, parameters ignored, is one of them. An empty
    /// type never is.
    pub fn matches(&self, content_type: &[u8]) -> bool {
        let end = content_type
            .iter()
            .position(|&c| c == b';')
            .unwrap_or(content_type.len());
        let t = content_type[..end].trim_ascii();
        if t.is_empty() {
            return false;
        }
        self.any
            || (self.html && t.eq_ignore_ascii_case(b"text/html"))
            || self.list.iter().any(|x| t.eq_ignore_ascii_case(x))
    }
}

#[derive(Debug, Default)]
pub struct Filters {
    pub sub: Option<SubFilter>,
    pub ssi: Option<Ssi>,
    pub addition: Option<Addition>,
    pub charset: Option<Charset>,
    pub userid: Option<Userid>,
}

impl Filters {
    /// Whether any filter changes the body of a response of this type.
    pub fn body(&self, content_type: &[u8]) -> bool {
        self.sub
            .as_ref()
            .is_some_and(|s| s.types.matches(content_type))
            || self
                .ssi
                .as_ref()
                .is_some_and(|s| s.types.matches(content_type))
            || self
                .addition
                .as_ref()
                .is_some_and(|a| a.types.matches(content_type))
    }
}

#[derive(Debug)]
pub struct SubFilter {
    /// Pattern and replacement templates.
    pub pairs: Box<[(Template, Template)]>,
    /// Every occurrence rather than the first of each pattern.
    pub all: bool,
    pub last_modified: bool,
    pub types: Types,
}

#[derive(Debug)]
pub struct Ssi {
    pub silent_errors: bool,
    pub last_modified: bool,
    pub value_length: usize,
    pub types: Types,
}

#[derive(Debug)]
pub struct Addition {
    /// URIs; empty when unset.
    pub before: Box<[u8]>,
    pub after: Box<[u8]>,
    pub types: Types,
}

/// How a body is recoded from the source charset.
#[derive(Debug)]
pub enum Recode {
    /// The byte each byte becomes.
    Table(Box<[u8; 256]>),
    /// UTF-8 of the code point of each byte; 0 for none.
    ToUtf8(Box<[u32; 256]>),
    /// The byte of each code point in the destination.
    FromUtf8(std::collections::HashMap<u32, u8>),
}

#[derive(Debug)]
pub struct Charset {
    pub charset: Box<[u8]>,
    /// Empty: off.
    pub source: Box<[u8]>,
    pub override_charset: bool,
    pub types: Types,
    pub recode: Option<Recode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseridMode {
    Log,
    V1,
    On,
}

#[derive(Debug)]
pub struct Userid {
    pub mode: UseridMode,
    pub name: Box<[u8]>,
    /// "; domain=..." or empty.
    pub domain: Box<[u8]>,
    /// "; path=...".
    pub path: Box<[u8]>,
    /// Seconds; 0 for a session cookie.
    pub expires: u32,
    pub expires_max: bool,
    /// "; secure", "; httponly" and "; samesite=..." as configured.
    pub flags: Box<[u8]>,
    pub p3p: Box<[u8]>,
    pub service: Option<u32>,
    /// 0 for none.
    pub mark: u8,
}

/// nginx mirror.
#[derive(Debug)]
pub struct Mirror {
    pub uris: Box<[Box<[u8]>]>,
    pub request_body: bool,
}

pub(crate) fn mirror(m: &ir::Mirror) -> Result<Mirror, Invalid> {
    for (i, u) in m.uris.iter().enumerate() {
        if !u.starts_with('/') || u.bytes().any(|c| c <= b' ' || c == 0x7f) {
            return Err((format!("uris[{i}]"), "must be a path".into()));
        }
    }
    Ok(Mirror {
        uris: m.uris.iter().map(|u| u.as_bytes().into()).collect(),
        request_body: m.request_body,
    })
}

type Invalid = (String, String);

fn codes(c: &ir::CharsetCodes, f: &str) -> Result<Box<[u32; 256]>, Invalid> {
    let v: Box<[u32; 256]> = c
        .code_points
        .clone()
        .into_boxed_slice()
        .try_into()
        .map_err(|_| (f.to_string(), "must have 256 entries".to_string()))?;
    if v.iter().any(|&n| n > 0xffff) {
        return Err((f.to_string(), "code points must be at most U+FFFF".into()));
    }
    Ok(v)
}

/// Builds `f`; templates may use the lookup variables `names`.
pub(crate) fn build(f: &ir::Filters, names: &[Box<str>]) -> Result<Filters, Invalid> {
    let tmpl = |s: &str, at: String| Template::parse_in(s, names).map_err(|e| (at, e));
    let sub = match &f.sub {
        None => None,
        Some(s) => {
            if s.pairs.is_empty() || s.pairs.len() > 255 {
                return Err(("sub.pairs".into(), "must have 1 to 255 pairs".into()));
            }
            let pairs = s
                .pairs
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    if p.r#match.is_empty() {
                        return Err((format!("sub.pairs[{i}].match"), "must not be empty".into()));
                    }
                    Ok((
                        tmpl(&p.r#match, format!("sub.pairs[{i}].match"))?,
                        tmpl(&p.replacement, format!("sub.pairs[{i}].replacement"))?,
                    ))
                })
                .collect::<Result<_, _>>()?;
            Some(SubFilter {
                pairs,
                all: s.all,
                last_modified: s.last_modified,
                types: Types::new(&s.types, true),
            })
        }
    };
    let ssi = f.ssi.as_ref().map(|s| Ssi {
        silent_errors: s.silent_errors,
        last_modified: s.last_modified,
        value_length: if s.value_length == 0 {
            256
        } else {
            s.value_length as usize
        },
        types: Types::new(&s.types, true),
    });
    let addition = match &f.addition {
        None => None,
        Some(a) => {
            for (u, at) in [(&a.before, "addition.before"), (&a.after, "addition.after")] {
                if !u.is_empty() && !u.starts_with('/') {
                    return Err((at.into(), "must be a path".into()));
                }
            }
            Some(Addition {
                before: a.before.as_bytes().into(),
                after: a.after.as_bytes().into(),
                types: Types::new(&a.types, true),
            })
        }
    };
    let charset = match &f.charset {
        None => None,
        Some(c) => {
            if c.charset.is_empty() {
                return Err(("charset.charset".into(), "must not be empty".into()));
            }
            let recode = match &c.recode {
                None => None,
                Some(charset::Recode::Table(t)) => Some(Recode::Table(
                    t.clone().into_boxed_slice().try_into().map_err(|_| {
                        ("charset.table".to_string(), "must be 256 bytes".to_string())
                    })?,
                )),
                Some(charset::Recode::ToUtf8(t)) => {
                    Some(Recode::ToUtf8(codes(t, "charset.to_utf8")?))
                }
                Some(charset::Recode::FromUtf8(t)) => {
                    let v = codes(t, "charset.from_utf8")?;
                    Some(Recode::FromUtf8(
                        v.iter()
                            .enumerate()
                            .filter(|&(b, &n)| n != 0 && b >= 0x80)
                            .map(|(b, &n)| (n, b as u8))
                            .collect(),
                    ))
                }
            };
            Some(Charset {
                charset: c.charset.as_bytes().into(),
                source: c.source.as_bytes().into(),
                override_charset: c.r#override,
                types: Types::new(&c.types, false),
                recode,
            })
        }
    };
    let userid = match &f.userid {
        None => None,
        Some(u) => {
            let mode = match u.mode() {
                userid::Mode::Log => UseridMode::Log,
                userid::Mode::V1 => UseridMode::V1,
                userid::Mode::On => UseridMode::On,
                userid::Mode::Unspecified => {
                    return Err(("userid.mode".into(), "must be set".into()));
                }
            };
            let mark = match u.mark.as_bytes() {
                [] => 0,
                [c] if c.is_ascii_alphanumeric() || *c == b'=' => *c,
                _ => {
                    return Err((
                        "userid.mark".into(),
                        "must be one letter, digit or \"=\"".into(),
                    ));
                }
            };
            let mut flags = Vec::new();
            if u.secure {
                flags.extend_from_slice(b"; secure");
            }
            if u.http_only {
                flags.extend_from_slice(b"; httponly");
            }
            match u.same_site.as_str() {
                "" => {}
                s @ ("strict" | "lax" | "none") => {
                    flags.extend_from_slice(b"; samesite=");
                    flags.extend_from_slice(s.as_bytes());
                }
                _ => {
                    return Err((
                        "userid.same_site".into(),
                        "must be strict, lax or none".into(),
                    ));
                }
            }
            let attr = |prefix: &str, v: &str| -> Box<[u8]> {
                if v.is_empty() {
                    Box::default()
                } else {
                    format!("{prefix}{v}").into_bytes().into()
                }
            };
            for (v, at) in [
                (&u.name, "userid.name"),
                (&u.domain, "userid.domain"),
                (&u.path, "userid.path"),
                (&u.p3p, "userid.p3p"),
            ] {
                if v.bytes().any(|c| c < b' ' || c == 0x7f || c == b';') {
                    return Err((at.into(), "must not have control bytes or \";\"".into()));
                }
            }
            Some(Userid {
                mode,
                name: if u.name.is_empty() {
                    (*b"uid").into()
                } else {
                    u.name.as_bytes().into()
                },
                domain: attr("; domain=", &u.domain),
                path: attr("; path=", if u.path.is_empty() { "/" } else { &u.path }),
                expires: u.expires_s,
                expires_max: u.expires_max,
                flags: flags.into(),
                p3p: u.p3p.as_bytes().into(),
                service: u.service,
                mark,
            })
        }
    };
    Ok(Filters {
        sub,
        ssi,
        addition,
        charset,
        userid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types() {
        let t = Types::new(&["text/css".into()], true);
        assert!(t.matches(b"text/html; charset=utf-8"));
        assert!(t.matches(b"TEXT/CSS"));
        assert!(!t.matches(b"image/png"));
        assert!(!t.matches(b""));
        assert!(Types::new(&["*".into()], false).matches(b"image/png"));
        assert!(!Types::new(&[], false).matches(b"text/html"));
    }

    #[test]
    fn builds() {
        let f = build(
            &ir::Filters {
                userid: Some(ir::Userid {
                    mode: userid::Mode::On.into(),
                    domain: "example.com".into(),
                    http_only: true,
                    same_site: "lax".into(),
                    mark: "x".into(),
                    ..Default::default()
                }),
                charset: Some(ir::Charset {
                    charset: "windows-1251".into(),
                    source: "utf-8".into(),
                    recode: Some(charset::Recode::FromUtf8(ir::CharsetCodes {
                        code_points: (0..256)
                            .map(|i| if i == 0xc0 { 0x410 } else { 0 })
                            .collect(),
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let u = f.userid.unwrap();
        assert_eq!(&*u.name, b"uid");
        assert_eq!(&*u.domain, b"; domain=example.com");
        assert_eq!(&*u.path, b"; path=/");
        assert_eq!(&*u.flags, b"; httponly; samesite=lax");
        assert_eq!(u.mark, b'x');
        let Some(Recode::FromUtf8(m)) = f.charset.unwrap().recode else {
            panic!("recode");
        };
        assert_eq!(m.get(&0x410), Some(&0xc0));
        let bad = ir::Filters {
            sub: Some(ir::SubFilter::default()),
            ..Default::default()
        };
        assert!(build(&bad, &[]).is_err());
    }
}
