//! The runtime form of response compression (nginx gzip, gzip_static,
//! gunzip, plus brotli and zstd).

use proxelo_api::snapshot::v1::{self as ir, compression};

use crate::runtime::Pattern;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Gzip,
    Brotli,
    Zstd,
}

impl Encoding {
    /// The content-coding token.
    pub fn token(self) -> &'static [u8] {
        match self {
            Self::Gzip => b"gzip",
            Self::Brotli => b"br",
            Self::Zstd => b"zstd",
        }
    }
}

/// nginx gzip_proxied flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct Proxied {
    pub expired: bool,
    pub no_cache: bool,
    pub no_store: bool,
    pub private: bool,
    pub no_last_modified: bool,
    pub no_etag: bool,
    pub auth: bool,
    pub any: bool,
}

impl Proxied {
    /// Whether any flag allows encoding responses to requests with Via.
    pub fn some(&self) -> bool {
        self.expired
            || self.no_cache
            || self.no_store
            || self.private
            || self.no_last_modified
            || self.no_etag
            || self.auth
            || self.any
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticGz {
    Off,
    On,
    Always,
}

#[derive(Debug)]
pub struct Compression {
    /// Dynamic encodings in order of preference.
    pub encodings: Box<[Encoding]>,
    /// Lowercase media types besides text/html.
    types: Box<[Box<[u8]>]>,
    any_type: bool,
    pub min_length: u64,
    pub gzip_level: u32,
    pub brotli_level: u32,
    pub zstd_level: i32,
    pub proxied: Proxied,
    pub vary: bool,
    pub static_gz: StaticGz,
    pub gunzip: bool,
    pub http10: bool,
    pub disable: Option<Pattern>,
}

impl Compression {
    /// Whether a response of `content_type` (with any parameters) may be
    /// encoded, as nginx gzip_types.
    pub fn type_ok(&self, content_type: &[u8]) -> bool {
        if self.any_type {
            return true;
        }
        let end = content_type
            .iter()
            .position(|&c| c == b';')
            .unwrap_or(content_type.len());
        let t = content_type[..end].trim_ascii();
        t.eq_ignore_ascii_case(b"text/html") || self.types.iter().any(|x| t.eq_ignore_ascii_case(x))
    }
}

/// `(field, error)` for the caller to place.
type Invalid = (String, String);

pub(crate) fn build(c: &ir::Compression) -> Result<Compression, Invalid> {
    let mut encodings = Vec::new();
    for (i, e) in c.encodings.iter().enumerate() {
        let e = match compression::Encoding::try_from(*e) {
            Ok(compression::Encoding::Gzip) => Encoding::Gzip,
            Ok(compression::Encoding::Brotli) => Encoding::Brotli,
            Ok(compression::Encoding::Zstd) => Encoding::Zstd,
            _ => return Err((format!("encodings[{i}]"), "unknown encoding".into())),
        };
        if !encodings.contains(&e) {
            encodings.push(e);
        }
    }
    let mut proxied = Proxied::default();
    for p in &c.proxied {
        use compression::Proxied as P;
        match P::try_from(*p) {
            Ok(P::Expired) => proxied.expired = true,
            Ok(P::NoCache) => proxied.no_cache = true,
            Ok(P::NoStore) => proxied.no_store = true,
            Ok(P::Private) => proxied.private = true,
            Ok(P::NoLastModified) => proxied.no_last_modified = true,
            Ok(P::NoEtag) => proxied.no_etag = true,
            Ok(P::Auth) => proxied.auth = true,
            Ok(P::Any) => proxied.any = true,
            _ => return Err(("proxied".into(), "unknown value".into())),
        }
    }
    let level = |v: u32, lo: u32, hi: u32, default: u32, f: &str| match v {
        0 => Ok(default),
        v if (lo..=hi).contains(&v) => Ok(v),
        _ => Err((f.to_string(), format!("must be {lo}-{hi}"))),
    };
    let brotli_level = match c.brotli_level {
        None => 6,
        Some(v) if v <= 11 => v,
        Some(_) => return Err(("brotli_level".into(), "must be 0-11".into())),
    };
    Ok(Compression {
        encodings: encodings.into(),
        any_type: c.types.iter().any(|t| t == "*"),
        types: c
            .types
            .iter()
            .filter(|t| *t != "*")
            .map(|t| t.to_ascii_lowercase().into_bytes().into())
            .collect(),
        min_length: c.min_length.into(),
        gzip_level: level(c.gzip_level, 1, 9, 1, "gzip_level")?,
        brotli_level,
        zstd_level: level(c.zstd_level, 1, 22, 3, "zstd_level")? as i32,
        proxied,
        vary: c.vary,
        static_gz: match c.r#static() {
            compression::Static::On => StaticGz::On,
            compression::Static::Always => StaticGz::Always,
            compression::Static::Unspecified => StaticGz::Off,
        },
        gunzip: c.gunzip,
        http10: c.http10,
        disable: if c.disable.is_empty() {
            None
        } else {
            Some(Pattern::new(&c.disable, true).map_err(|e| ("disable".to_string(), e))?)
        },
    })
}
