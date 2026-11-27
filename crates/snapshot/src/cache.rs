//! The runtime form of response caching (nginx proxy_cache_path and the
//! proxy_cache_* directives of a location).

use std::path::PathBuf;
use std::time::Duration;

use proxelo_api::snapshot::v1::{self as ir, cache};

use crate::cond::{Expr, Facts};
use crate::template::Template;

/// A cache on disk, shared by the routes that name it.
#[derive(Debug)]
pub struct CacheZone {
    pub id: Box<str>,
    pub path: PathBuf,
    /// Directory name lengths taken from the end of the hex hash.
    pub levels: Box<[u8]>,
    /// Bytes; 0 for no limit.
    pub max_size: u64,
    pub max_entries: usize,
    pub inactive: Duration,
}

/// The cache settings of a route.
#[derive(Debug)]
pub struct Cache {
    /// Index into `Runtime::cache_zones`.
    pub zone: u32,
    pub key: Template,
    pub valid: Box<[Valid]>,
    /// Uppercase.
    pub methods: Box<[Box<[u8]>]>,
    pub min_uses: u32,
    pub bypass: Option<Expr>,
    pub no_store: Option<Expr>,
    pub lock: bool,
    pub lock_timeout: Duration,
    pub stale: Stale,
    pub background_update: bool,
    pub revalidate: bool,
    pub ignore: Ignore,
    pub keep_head: bool,
}

#[derive(Debug, Clone)]
pub struct Valid {
    /// Empty with `any` false: 200, 301 and 302.
    pub statuses: Box<[u16]>,
    pub any: bool,
    pub ttl: Duration,
}

/// proxy_cache_use_stale.
#[derive(Debug, Clone, Copy, Default)]
pub struct Stale {
    pub error: bool,
    pub timeout: bool,
    pub updating: bool,
    /// Bits for STATUSES.
    statuses: u8,
}

impl Stale {
    const STATUSES: [u16; 7] = [500, 502, 503, 504, 403, 404, 429];

    pub fn on_status(&self, status: u16) -> bool {
        Self::STATUSES
            .iter()
            .position(|&s| s == status)
            .is_some_and(|i| self.statuses & (1 << i) != 0)
    }
}

/// proxy_ignore_headers.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ignore {
    pub x_accel_expires: bool,
    pub expires: bool,
    pub cache_control: bool,
    pub set_cookie: bool,
    pub vary: bool,
}

impl Cache {
    /// The freshness proxy_cache_valid gives `status`, if any.
    pub fn valid_for(&self, status: u16) -> Option<Duration> {
        let mut any = None;
        for v in self.valid.iter() {
            if v.any {
                any.get_or_insert(v.ttl);
            } else if v.statuses.is_empty() {
                if matches!(status, 200 | 301 | 302) {
                    return Some(v.ttl);
                }
            } else if v.statuses.contains(&status) {
                return Some(v.ttl);
            }
        }
        any
    }

    /// Whether the request method is cached.
    pub fn caches_method(&self, method: &[u8]) -> bool {
        if self.methods.is_empty() {
            return method == b"GET" || method == b"HEAD";
        }
        self.methods.iter().any(|m| **m == *method)
    }

    pub fn bypass(&self, f: &dyn Facts) -> bool {
        self.bypass.as_ref().is_some_and(|e| e.eval(f))
    }

    pub fn no_store(&self, f: &dyn Facts) -> bool {
        self.no_store.as_ref().is_some_and(|e| e.eval(f))
    }
}

pub(crate) fn zone(z: &ir::CacheZone) -> Result<CacheZone, (&'static str, String)> {
    let path = PathBuf::from(&z.path);
    let parts_ok = path.components().all(|c| {
        matches!(
            c,
            std::path::Component::Normal(_) | std::path::Component::RootDir
        )
    });
    if z.path.is_empty() || !parts_ok {
        return Err(("path", "must be a directory without . or .. parts".into()));
    }
    if z.levels.len() > 3 || z.levels.iter().any(|&l| !(1..=2).contains(&l)) {
        return Err(("levels", "at most three levels of 1 or 2".into()));
    }
    Ok(CacheZone {
        id: z.id.as_str().into(),
        path,
        levels: z.levels.iter().map(|&l| l as u8).collect(),
        max_size: z.max_size,
        max_entries: if z.max_entries == 0 {
            100_000
        } else {
            z.max_entries as usize
        },
        inactive: Duration::from_secs(if z.inactive_s == 0 {
            600
        } else {
            z.inactive_s.into()
        }),
    })
}

pub(crate) fn build(
    c: &ir::Cache,
    zones: usize,
    names: &[Box<str>],
) -> Result<Cache, (&'static str, String)> {
    if c.zone as usize >= zones {
        return Err(("zone", "no such cache zone".into()));
    }
    let key = if c.key.is_empty() {
        "$scheme$proxy_host$request_uri"
    } else {
        &c.key
    };
    let expr = |s: &str, f: &'static str| -> Result<Option<Expr>, (&'static str, String)> {
        if s.is_empty() {
            return Ok(None);
        }
        Expr::compile(s).map(Some).map_err(|e| (f, e))
    };
    let mut stale = Stale::default();
    for u in c.use_stale() {
        use cache::UseStale as U;
        let bit = |s: u16| {
            1u8 << Stale::STATUSES
                .iter()
                .position(|&x| x == s)
                .expect("listed")
        };
        match u {
            U::Unspecified => {}
            U::Error => stale.error = true,
            U::Timeout => stale.timeout = true,
            U::Updating => stale.updating = true,
            U::Http500 => stale.statuses |= bit(500),
            U::Http502 => stale.statuses |= bit(502),
            U::Http503 => stale.statuses |= bit(503),
            U::Http504 => stale.statuses |= bit(504),
            U::Http403 => stale.statuses |= bit(403),
            U::Http404 => stale.statuses |= bit(404),
            U::Http429 => stale.statuses |= bit(429),
        }
    }
    let mut ignore = Ignore::default();
    for i in c.ignore() {
        use cache::Ignore as I;
        match i {
            I::Unspecified => {}
            I::XAccelExpires => ignore.x_accel_expires = true,
            I::Expires => ignore.expires = true,
            I::CacheControl => ignore.cache_control = true,
            I::SetCookie => ignore.set_cookie = true,
            I::Vary => ignore.vary = true,
        }
    }
    if c.slice != 0 {
        return Err(("slice", "slices are not supported".into()));
    }
    if c.background_update && !stale.updating {
        return Err(("background_update", "needs use_stale updating".into()));
    }
    Ok(Cache {
        zone: c.zone,
        key: Template::parse_in(key, names).map_err(|e| ("key", e))?,
        valid: c
            .valid
            .iter()
            .map(|v| Valid {
                statuses: v
                    .statuses
                    .iter()
                    .map(|&s| u16::try_from(s).unwrap_or(0))
                    .collect(),
                any: v.any,
                ttl: Duration::from_secs(v.seconds.into()),
            })
            .collect(),
        methods: c
            .methods
            .iter()
            .map(|m| m.to_ascii_uppercase().into_bytes().into())
            .collect(),
        min_uses: c.min_uses.max(1),
        bypass: expr(&c.bypass, "bypass")?,
        no_store: expr(&c.no_store, "no_store")?,
        lock: c.lock,
        lock_timeout: Duration::from_millis(if c.lock_timeout_ms == 0 {
            5000
        } else {
            c.lock_timeout_ms.into()
        }),
        stale,
        background_update: c.background_update,
        revalidate: c.revalidate,
        ignore,
        keep_head: c.keep_head,
    })
}
