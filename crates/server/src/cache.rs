//! Response caching, as nginx proxy_cache: the store.
//!
//! Each entry is one file named by the MD5 of its key, under `levels`
//! subdirectories taken from the end of the hex hash as nginx lays them out.
//! A file holds a short text header (freshness, key, Vary names, tags,
//! status), the stored response header lines and the body. An index in
//! memory maps hashes to entries with an LRU order; it is rebuilt from the
//! files when a zone opens. A thread per zone drops entries not used within
//! `inactive` and keeps the zone within its limits.
//!
//! A response with Vary is stored under a hash of the key and the request's
//! values of those headers; the key's own hash then holds a record of the
//! Vary names only.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openssl::hash::{Hasher, MessageDigest};
use proxelo_api::distrib::v1::{Purge, PurgeDone};
use proxelo_snapshot::{Cache, Runtime};
use tokio::sync::Notify;

use crate::Active;
use crate::exchange::Exchange;

pub(crate) type Hash = [u8; 16];
/// Header names of a Vary record, or Cache-Tag values.
pub(crate) type Names = Box<[Box<[u8]>]>;

const MAGIC: &[u8] = b"PXC1 ";
/// Bytes of the first line: magic, expiry (20 digits), stale-while-revalidate
/// and stale-if-error (10 digits each), so it can be rewritten in place.
const FIRST_LINE: usize = MAGIC.len() + 20 + 1 + 10 + 1 + 10 + 1;
/// The text header and stored response head must fit in this.
pub(crate) const MAX_HEAD: usize = 64 * 1024;
/// How often a zone's manager runs.
const MANAGE_EVERY: Duration = Duration::from_secs(5);

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn md5(parts: &[&[u8]]) -> Hash {
    let mut h = Hasher::new(MessageDigest::md5()).expect("md5");
    for p in parts {
        h.update(p).expect("md5");
    }
    let d = h.finish().expect("md5");
    let mut out = [0; 16];
    out.copy_from_slice(&d);
    out
}

fn hex(h: &Hash) -> String {
    let mut s = String::with_capacity(32);
    for b in h {
        s.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
        s.push(char::from(b"0123456789abcdef"[usize::from(b & 15)]));
    }
    s
}

fn unhex(s: &str) -> Option<Hash> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

fn num_of(b: &[u8]) -> Option<u64> {
    std::str::from_utf8(b).ok()?.parse().ok()
}

/// How long a response stays fresh and may be served stale.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Fresh {
    /// Unix seconds.
    pub expires: u64,
    /// stale-while-revalidate and stale-if-error, seconds.
    pub swr: u32,
    pub sie: u32,
}

impl Fresh {
    pub fn fresh(&self, now: u64) -> bool {
        self.expires > now
    }

    pub fn within_swr(&self, now: u64) -> bool {
        now < self.expires.saturating_add(self.swr.into())
    }

    pub fn within_sie(&self, now: u64) -> bool {
        now < self.expires.saturating_add(self.sie.into())
    }
}

/// What the index knows about one hash.
#[derive(Clone, Debug)]
struct Meta {
    key: Box<[u8]>,
    /// Lowercase Vary names when this is the record of a key whose
    /// responses vary; such a record has no file.
    vary: Option<Names>,
    fresh: Fresh,
    /// Bytes on disk.
    size: u64,
    tags: Names,
    /// Unix seconds of the last use.
    used: u64,
    seq: u64,
}

#[derive(Default)]
struct Index {
    map: HashMap<Hash, Meta>,
    lru: BTreeMap<u64, Hash>,
    seq: u64,
    bytes: u64,
    /// Requests per key hash, for min_uses.
    uses: HashMap<Hash, u32>,
}

impl Index {
    fn take(&mut self, h: &Hash) -> Option<Meta> {
        let m = self.map.remove(h)?;
        self.lru.remove(&m.seq);
        self.bytes -= m.size;
        Some(m)
    }

    fn put(&mut self, h: Hash, mut m: Meta) {
        self.take(&h);
        self.seq += 1;
        m.seq = self.seq;
        self.lru.insert(m.seq, h);
        self.bytes += m.size;
        self.map.insert(h, m);
    }

    fn touch(&mut self, h: &Hash, now: u64) {
        let Some(m) = self.map.get_mut(h) else {
            return;
        };
        self.lru.remove(&m.seq);
        self.seq += 1;
        m.seq = self.seq;
        m.used = now;
        self.lru.insert(m.seq, *h);
    }
}

#[derive(Clone, Copy)]
struct Limits {
    max_size: u64,
    max_entries: usize,
    inactive: Duration,
}

/// One cache zone's state, kept across snapshots while its ID, path and
/// levels stay the same.
pub(crate) struct Zone {
    pub id: Box<str>,
    path: PathBuf,
    levels: Box<[u8]>,
    limits: Mutex<Limits>,
    index: Mutex<Index>,
    /// Keys being fetched, for proxy_cache_lock and UPDATING.
    locks: Mutex<HashMap<Hash, Arc<Notify>>>,
}

/// Builds the zones of `rt`, reusing the state of `old` by ID.
pub(crate) fn zones(rt: &Runtime, old: Option<(&Runtime, &[Arc<Zone>])>) -> Box<[Arc<Zone>]> {
    rt.cache_zones
        .iter()
        .map(|z| {
            let limits = Limits {
                max_size: z.max_size,
                max_entries: z.max_entries,
                inactive: z.inactive,
            };
            let reused = old.and_then(|(ort, oz)| {
                let i = ort.cache_zones.iter().position(|o| o.id == z.id)?;
                let o = &oz[i];
                (o.path == z.path && o.levels == z.levels).then(|| o.clone())
            });
            if let Some(o) = reused {
                *o.limits.lock().unwrap_or_else(|e| e.into_inner()) = limits;
                return o;
            }
            let zone = Arc::new(Zone {
                id: z.id.clone(),
                path: z.path.clone(),
                levels: z.levels.clone(),
                limits: Mutex::new(limits),
                index: Mutex::new(Index::default()),
                locks: Mutex::new(HashMap::new()),
            });
            start(&zone);
            zone
        })
        .collect()
}

/// Loads the zone's files, then manages it until the zone is dropped.
fn start(zone: &Arc<Zone>) {
    let weak = Arc::downgrade(zone);
    let spawned = std::thread::Builder::new()
        .name(format!("cache-{}", zone.id))
        .spawn(move || {
            if let Some(z) = weak.upgrade() {
                if let Err(e) = fs::create_dir_all(&z.path) {
                    eprintln!("cache {}: {}: {e}", z.id, z.path.display());
                }
                z.load();
            }
            manage_loop(&weak);
        });
    if let Err(e) = spawned {
        eprintln!("cache {}: {e}", zone.id);
    }
}

fn manage_loop(weak: &Weak<Zone>) {
    loop {
        std::thread::sleep(MANAGE_EVERY);
        let Some(z) = weak.upgrade() else {
            return;
        };
        z.manage();
    }
}

/// A stored entry opened for reading.
pub(crate) struct Entry {
    pub status: u16,
    /// Header lines, each ending with CRLF.
    pub head: Vec<u8>,
    pub body_offset: u64,
    pub body_len: u64,
}

impl Entry {
    pub fn header(&self, name: &[u8]) -> Option<&[u8]> {
        self.head.split(|&c| c == b'\n').find_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let colon = line.iter().position(|&c| c == b':')?;
            line[..colon]
                .eq_ignore_ascii_case(name)
                .then(|| line[colon + 1..].trim_ascii())
        })
    }
}

fn parse_file(f: &mut File) -> io::Result<(Meta, Entry)> {
    let len = f.metadata()?.len();
    let mut buf = vec![0; (len as usize).min(MAX_HEAD)];
    f.seek(SeekFrom::Start(0))?;
    f.read_exact(&mut buf)?;
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "not a cache entry");
    if buf.len() < FIRST_LINE || !buf.starts_with(MAGIC) || buf[FIRST_LINE - 1] != b'\n' {
        return Err(bad());
    }
    let m0 = MAGIC.len();
    let num = |r: std::ops::Range<usize>| num_of(&buf[r]).ok_or_else(bad);
    let fresh = Fresh {
        expires: num(m0..m0 + 20)?,
        swr: num(m0 + 21..m0 + 31)? as u32,
        sie: num(m0 + 32..m0 + 42)? as u32,
    };
    let mut meta = Meta {
        key: Box::default(),
        vary: None,
        fresh,
        size: len,
        tags: Box::default(),
        used: now(),
        seq: 0,
    };
    let mut status = 0;
    let mut pos = FIRST_LINE;
    loop {
        let end = buf[pos..]
            .iter()
            .position(|&c| c == b'\n')
            .ok_or_else(bad)?
            + pos;
        let line = &buf[pos..end];
        pos = end + 1;
        let (tag, value) = line.split_at_checked(2).ok_or_else(bad)?;
        match tag {
            b"K " => meta.key = value.into(),
            b"V " => meta.vary = Some(value.split(|&c| c == b',').map(Box::from).collect()),
            b"T " => meta.tags = value.split(|&c| c == b' ').map(Box::from).collect(),
            b"S " => status = num_of(value).ok_or_else(bad)? as u16,
            b"H " => {
                let head_len = num_of(value).ok_or_else(bad)? as usize;
                let head = buf.get(pos..pos + head_len).ok_or_else(bad)?.to_vec();
                let body_offset = (pos + head_len) as u64;
                let entry = Entry {
                    status,
                    head,
                    body_offset,
                    body_len: len.saturating_sub(body_offset),
                };
                return Ok((meta, entry));
            }
            _ => return Err(bad()),
        }
    }
}

/// The hash a response that varies on `names` is stored under.
fn variant(key: &[u8], names: &[Box<[u8]>], x: &Exchange) -> Hash {
    let mut parts: Vec<&[u8]> = vec![key, b"\0"];
    for n in names {
        parts.push(n);
        parts.push(b":");
        parts.push(x.request_header(n).unwrap_or_default());
        parts.push(b"\n");
    }
    md5(&parts)
}

/// A response being written to a temporary file.
pub(crate) struct Pending {
    tmp: PathBuf,
    file: File,
    hash: Hash,
    /// The key's record when the response varies.
    main: Option<(Hash, Names)>,
    meta: Meta,
    ok: bool,
}

impl Pending {
    pub fn write(&mut self, data: &[u8]) {
        if self.ok && self.file.write_all(data).is_err() {
            self.ok = false;
        }
    }
}

/// How a key's fetch lock went.
pub(crate) enum Locked {
    /// This request fetches; others wait.
    Held(LockGuard),
    /// Another request fetched it meanwhile; look again.
    Released,
    /// The wait timed out; fetch without storing.
    TimedOut,
}

pub(crate) struct LockGuard {
    zone: Arc<Zone>,
    hash: Hash,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        if let Some(n) = self.zone.locks().remove(&self.hash) {
            n.notify_waiters();
        }
    }
}

/// What a response says about storing it.
pub(crate) struct Storable {
    pub fresh: Fresh,
    pub vary: Option<Names>,
    pub tags: Names,
}

impl Zone {
    fn index(&self) -> MutexGuard<'_, Index> {
        self.index.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn locks(&self) -> MutexGuard<'_, HashMap<Hash, Arc<Notify>>> {
        self.locks.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn limits(&self) -> Limits {
        *self.limits.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn file(&self, h: &Hash) -> PathBuf {
        let name = hex(h);
        let mut p = self.path.clone();
        let mut end = name.len();
        for &l in self.levels.iter() {
            let l = usize::from(l);
            p.push(&name[end - l..end]);
            end -= l;
        }
        p.push(&name);
        p
    }

    /// The hash of a key, used for locks and min_uses.
    pub fn key_hash(key: &[u8]) -> Hash {
        md5(&[key])
    }

    /// The entry `x` gets for `key`: its hash and freshness if the index
    /// holds it. A Vary record leads to the request's variant.
    pub fn lookup(&self, key: &[u8], x: &Exchange) -> (Hash, Option<Fresh>) {
        let main = Self::key_hash(key);
        let now = now();
        let mut ix = self.index();
        let Some(m) = ix.map.get(&main) else {
            return (main, None);
        };
        let h = match &m.vary {
            Some(names) => variant(key, names, x),
            None => main,
        };
        ix.touch(&main, now);
        if h != main {
            ix.touch(&h, now);
        }
        let f = ix.map.get(&h).filter(|m| m.vary.is_none()).map(|m| m.fresh);
        (h, f)
    }

    /// Counts a request for `main`; whether it reached `min`.
    pub fn used(&self, main: Hash, min: u32) -> bool {
        if min <= 1 {
            return true;
        }
        let max = self.limits().max_entries;
        let mut ix = self.index();
        if ix.uses.len() >= max {
            ix.uses.clear();
        }
        let n = ix.uses.entry(main).or_insert(0);
        *n += 1;
        *n >= min
    }

    /// Takes the fetch lock of `main` without waiting.
    pub fn try_lock(self: &Arc<Self>, main: Hash) -> Option<LockGuard> {
        let mut locks = self.locks();
        if locks.contains_key(&main) {
            return None;
        }
        locks.insert(main, Arc::new(Notify::new()));
        Some(LockGuard {
            zone: self.clone(),
            hash: main,
        })
    }

    /// Takes the fetch lock of `main`, waiting up to `timeout` for the
    /// request that holds it.
    pub async fn lock(self: &Arc<Self>, main: Hash, timeout: Duration) -> Locked {
        let notify = match self.locks().get(&main) {
            Some(n) => n.clone(),
            None => {
                return match self.try_lock(main) {
                    Some(g) => Locked::Held(g),
                    None => Locked::Released,
                };
            }
        };
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        // The holder may have finished before `enable`.
        if !self
            .locks()
            .get(&main)
            .is_some_and(|n| Arc::ptr_eq(n, &notify))
        {
            return Locked::Released;
        }
        match tokio::time::timeout(timeout, notified).await {
            Ok(()) => Locked::Released,
            Err(_) => Locked::TimedOut,
        }
    }

    pub fn open(&self, h: Hash) -> io::Result<(File, Entry)> {
        let mut f = File::open(self.file(&h))?;
        let (_, e) = parse_file(&mut f)?;
        Ok((f, e))
    }

    /// Starts storing a response; `head` is its header lines.
    pub fn begin(
        &self,
        key: &[u8],
        x: &Exchange,
        s: Storable,
        status: u16,
        head: &[u8],
    ) -> io::Result<Pending> {
        let main = Self::key_hash(key);
        let (hash, main_rec) = match s.vary {
            Some(names) => (variant(key, &names, x), Some((main, names))),
            None => (main, None),
        };
        let dir = self.path.join(".tmp");
        fs::create_dir_all(&dir)?;
        let mut raw = [0u8; 8];
        let _ = openssl::rand::rand_bytes(&mut raw);
        let tmp = dir.join(format!("{}.{:x}", hex(&hash), u64::from_le_bytes(raw)));
        let mut text = Vec::with_capacity(256 + head.len());
        text.extend_from_slice(MAGIC);
        let f = s.fresh;
        text.extend_from_slice(
            format!("{:020} {:010} {:010}\n", f.expires, f.swr, f.sie).as_bytes(),
        );
        text.extend_from_slice(b"K ");
        text.extend_from_slice(key);
        text.push(b'\n');
        if let Some((_, names)) = &main_rec {
            text.extend_from_slice(b"V ");
            text.extend_from_slice(&names.join(&b","[..]));
            text.push(b'\n');
        }
        if !s.tags.is_empty() {
            text.extend_from_slice(b"T ");
            text.extend_from_slice(&s.tags.join(&b" "[..]));
            text.push(b'\n');
        }
        text.extend_from_slice(format!("S {status}\nH {}\n", head.len()).as_bytes());
        text.extend_from_slice(head);
        if text.len() > MAX_HEAD {
            return Err(io::Error::other("response head too large to cache"));
        }
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        if let Err(e) = file.write_all(&text) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        Ok(Pending {
            tmp,
            file,
            hash,
            main: main_rec,
            meta: Meta {
                key: key.into(),
                vary: None,
                fresh: s.fresh,
                size: 0,
                tags: s.tags,
                used: now(),
                seq: 0,
            },
            ok: true,
        })
    }

    /// Makes a stored response visible, or discards it when it did not
    /// arrive complete.
    pub fn commit(&self, mut p: Pending, complete: bool) {
        let done = p.ok && complete && p.file.flush().is_ok();
        let size = p.file.metadata().map_or(0, |m| m.len());
        drop(p.file);
        let path = self.file(&p.hash);
        let placed = done
            && path.parent().is_none_or(|d| fs::create_dir_all(d).is_ok())
            && fs::rename(&p.tmp, &path).is_ok();
        if !placed {
            let _ = fs::remove_file(&p.tmp);
            return;
        }
        p.meta.size = size;
        let mut gone = Vec::new();
        {
            let mut ix = self.index();
            if let Some((main, names)) = p.main {
                // A plain entry under the key gives way to the record.
                if ix.take(&main).is_some_and(|old| old.vary.is_none()) {
                    gone.push(main);
                }
                let rec = Meta {
                    vary: Some(names),
                    size: 0,
                    fresh: Fresh {
                        expires: u64::MAX,
                        ..Fresh::default()
                    },
                    tags: Box::default(),
                    ..p.meta.clone()
                };
                ix.put(main, rec);
            }
            ix.put(p.hash, p.meta);
            self.evict(&mut ix, &mut gone);
        }
        self.unlink(&gone);
    }

    /// Updates the freshness of a revalidated entry.
    pub fn refresh(&self, h: Hash, f: Fresh) {
        if let Ok(mut file) = OpenOptions::new().write(true).open(self.file(&h)) {
            let line = format!("{:020} {:010} {:010}\n", f.expires, f.swr, f.sie);
            let _ = file
                .seek(SeekFrom::Start(MAGIC.len() as u64))
                .and_then(|_| file.write_all(line.as_bytes()));
        }
        if let Some(m) = self.index().map.get_mut(&h) {
            m.fresh = f;
        }
    }

    pub fn remove(&self, h: Hash) {
        if self.index().take(&h).is_some() {
            self.unlink(&[h]);
        }
    }

    /// The stale-if-error window of an entry still in the index.
    pub fn fresh_of(&self, h: Hash) -> Option<Fresh> {
        self.index().map.get(&h).map(|m| m.fresh)
    }

    fn unlink(&self, hashes: &[Hash]) {
        for h in hashes {
            let _ = fs::remove_file(self.file(h));
        }
    }

    /// Drops least recently used entries beyond the limits.
    fn evict(&self, ix: &mut Index, gone: &mut Vec<Hash>) {
        let l = self.limits();
        while ix.map.len() > l.max_entries || (l.max_size != 0 && ix.bytes > l.max_size) {
            let Some((_, h)) = ix.lru.pop_first() else {
                break;
            };
            if let Some(m) = ix.map.remove(&h) {
                ix.bytes -= m.size;
                if m.vary.is_none() {
                    gone.push(h);
                }
            }
        }
    }

    fn drop_where(&self, f: impl Fn(&Meta) -> bool) -> u64 {
        let mut gone = Vec::new();
        {
            let mut ix = self.index();
            let hit: Vec<Hash> = ix
                .map
                .iter()
                .filter(|(_, m)| f(m))
                .map(|(h, _)| *h)
                .collect();
            for h in hit {
                if ix.take(&h).is_some_and(|m| m.vary.is_none()) {
                    gone.push(h);
                }
            }
            self.evict(&mut ix, &mut gone);
        }
        self.unlink(&gone);
        gone.len() as u64
    }

    /// Drops entries not used within `inactive` and keeps the limits.
    fn manage(&self) {
        let inactive = self.limits().inactive.as_secs();
        let now = now();
        self.drop_where(|m| now.saturating_sub(m.used) >= inactive);
        self.clean_tmp();
    }

    /// Removes temporary files older than a minute, left by a crash or an
    /// aborted response.
    fn clean_tmp(&self) {
        let Ok(rd) = fs::read_dir(self.path.join(".tmp")) else {
            return;
        };
        for e in rd.flatten() {
            let old = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|d| d > Duration::from_secs(60));
            if old {
                let _ = fs::remove_file(e.path());
            }
        }
    }

    /// Rebuilds the index from the files (nginx cache loader).
    fn load(&self) {
        let mut found = Vec::new();
        walk(&self.path, self.levels.len(), &mut found);
        let mut gone = Vec::new();
        let n = {
            let mut ix = self.index();
            for (h, path) in found {
                let Ok((mut meta, _)) = File::open(&path).and_then(|mut f| parse_file(&mut f))
                else {
                    let _ = fs::remove_file(&path);
                    continue;
                };
                if let Some(names) = meta.vary.take() {
                    let main = Self::key_hash(&meta.key);
                    if !ix.map.get(&main).is_some_and(|m| m.vary.is_some()) {
                        let rec = Meta {
                            vary: Some(names),
                            size: 0,
                            fresh: Fresh {
                                expires: u64::MAX,
                                ..Fresh::default()
                            },
                            tags: Box::default(),
                            ..meta.clone()
                        };
                        ix.put(main, rec);
                    }
                }
                ix.put(h, meta);
            }
            self.evict(&mut ix, &mut gone);
            ix.map.len()
        };
        self.unlink(&gone);
        if n > 0 {
            eprintln!("cache {}: loaded {n} entries", self.id);
        }
    }

    /// Removes the entries `p` names.
    pub fn purge(&self, p: &Purge) -> u64 {
        self.drop_where(|m| {
            m.vary.is_none()
                && (p.all
                    || p.keys.iter().any(|k| *m.key == *k.as_bytes())
                    || p.prefixes.iter().any(|k| m.key.starts_with(k.as_bytes()))
                    || m.tags
                        .iter()
                        .any(|t| p.tags.iter().any(|w| **t == *w.as_bytes())))
        })
    }
}

/// Entry files below `dir`, `depth` levels down, named by their hash.
fn walk(dir: &Path, depth: usize, out: &mut Vec<(Hash, PathBuf)>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        let path = e.path();
        if depth > 0 {
            if path.is_dir() {
                walk(&path, depth - 1, out);
            }
        } else if let Some(h) = unhex(name) {
            out.push((h, path));
        }
    }
}

/// Purges a zone of the active snapshot.
pub(crate) fn purge(active: &Active, p: &Purge) -> PurgeDone {
    let mut done = PurgeDone {
        id: p.id.clone(),
        ..Default::default()
    };
    match active.caches.iter().find(|z| *z.id == *p.zone_id) {
        Some(z) => done.removed = z.purge(p),
        None => done.error = format!("no cache zone {:?}", p.zone_id),
    }
    done
}

/// Whether a response may be stored and for how long, as nginx decides:
/// X-Accel-Expires, then Cache-Control, then Expires, then
/// proxy_cache_valid.
pub(crate) fn storable(
    c: &Cache,
    status: u16,
    headers: &[(&[u8], &[u8])],
    now: u64,
) -> Option<Storable> {
    let all = |name: &'static [u8]| {
        headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|&(_, v)| v)
    };
    let ig = c.ignore;
    if !ig.set_cookie && all(b"set-cookie").next().is_some() {
        return None;
    }
    let mut vary: Vec<Box<[u8]>> = Vec::new();
    if !ig.vary {
        for v in all(b"vary") {
            for n in v.split(|&c| c == b',') {
                let n = n.trim_ascii();
                if n == b"*" {
                    return None;
                }
                if !n.is_empty() && !vary.iter().any(|x| x.eq_ignore_ascii_case(n)) {
                    vary.push(n.to_ascii_lowercase().into());
                }
            }
        }
    }
    let mut fresh = Fresh::default();
    let mut ttl: Option<u64> = None;
    if !ig.x_accel_expires
        && let Some(v) = all(b"x-accel-expires").next()
    {
        let v = v.trim_ascii();
        let (abs, digits) = match v.strip_prefix(b"@") {
            Some(d) => (true, d),
            None => (false, v),
        };
        let n = num_of(digits)?;
        if n == 0 && !abs {
            return None;
        }
        ttl = Some(if abs { n.saturating_sub(now) } else { n });
    }
    // Statuses whose freshness headers nginx honours.
    let by_header = matches!(
        status,
        200 | 203 | 204 | 206 | 300 | 301 | 302 | 303 | 307 | 308 | 404 | 410
    );
    if ttl.is_none() && !ig.cache_control && by_header {
        let mut max_age = None;
        let mut s_maxage = None;
        for v in all(b"cache-control") {
            for d in v.split(|&c| c == b',') {
                let d = d.trim_ascii();
                let (name, value) = match d.iter().position(|&c| c == b'=') {
                    Some(i) => (d[..i].trim_ascii_end(), d[i + 1..].trim_ascii_start()),
                    None => (d, &b""[..]),
                };
                let value = value.strip_prefix(b"\"").unwrap_or(value);
                let value = value.strip_suffix(b"\"").unwrap_or(value);
                let secs = || num_of(value).unwrap_or(0).min(u32::MAX.into()) as u32;
                match &name.to_ascii_lowercase()[..] {
                    b"no-cache" | b"no-store" | b"private" => return None,
                    b"max-age" => max_age = num_of(value),
                    b"s-maxage" => s_maxage = num_of(value),
                    b"stale-while-revalidate" => fresh.swr = secs(),
                    b"stale-if-error" => fresh.sie = secs(),
                    _ => {}
                }
            }
        }
        if let Some(n) = s_maxage.or(max_age) {
            if n == 0 {
                return None;
            }
            ttl = Some(n);
        }
    }
    if ttl.is_none()
        && !ig.expires
        && by_header
        && let Some(v) = all(b"expires").next()
    {
        let t = std::str::from_utf8(v)
            .ok()
            .and_then(|s| crate::compress::httpdate_secs(s.trim()));
        match t {
            Some(t) if t > now => ttl = Some(t - now),
            // Expired or not a date: nginx does not store it.
            _ => return None,
        }
    }
    let ttl = match ttl {
        Some(t) => t,
        None => c.valid_for(status)?.as_secs(),
    };
    if ttl == 0 {
        return None;
    }
    fresh.expires = now.saturating_add(ttl);
    let tags: Names = all(b"cache-tag")
        .flat_map(|v| v.split(|&c| c == b',' || c == b' '))
        .map(<[u8]>::trim_ascii)
        .filter(|t| !t.is_empty())
        .map(Box::from)
        .collect();
    Some(Storable {
        fresh,
        vary: (!vary.is_empty()).then(|| vary.into()),
        tags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxelo_api::snapshot::v1 as ir;

    fn runtime(valid: Vec<ir::CacheValid>) -> Runtime {
        Runtime::build(&ir::Snapshot {
            cache_zones: vec![ir::CacheZone {
                id: "z".into(),
                path: "/tmp/x".into(),
                ..Default::default()
            }],
            sites: vec![ir::Site {
                routes: vec![ir::Route {
                    path: Some(ir::PathMatch {
                        kind: ir::path_match::Kind::Prefix as i32,
                        value: "/".into(),
                    }),
                    action: Some(ir::Action {
                        kind: Some(ir::action::Kind::Proxy(ir::ProxyAction::default())),
                    }),
                    cache: Some(ir::Cache {
                        valid,
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            upstreams: vec![ir::Upstream::default()],
            ..Default::default()
        })
        .unwrap()
    }

    fn decide(c: &Cache, status: u16, h: &[(&str, &str)]) -> Option<(u64, Option<Vec<String>>)> {
        let h: Vec<(&[u8], &[u8])> = h
            .iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
            .collect();
        storable(c, status, &h, 1000).map(|s| {
            (
                s.fresh.expires - 1000,
                s.vary.map(|v| {
                    v.iter()
                        .map(|n| String::from_utf8_lossy(n).into_owned())
                        .collect()
                }),
            )
        })
    }

    #[test]
    fn freshness_as_nginx() {
        let rt = runtime(vec![ir::CacheValid {
            seconds: 60,
            ..Default::default()
        }]);
        let c = rt.sites[0].routes[0].cache.as_deref().unwrap();
        assert_eq!(decide(c, 200, &[]), Some((60, None)));
        assert_eq!(decide(c, 404, &[]), None);
        assert_eq!(
            decide(c, 200, &[("Cache-Control", "max-age=5")]),
            Some((5, None))
        );
        assert_eq!(
            decide(
                c,
                200,
                &[("X-Accel-Expires", "7"), ("Cache-Control", "no-store")]
            ),
            Some((7, None))
        );
        assert_eq!(
            decide(c, 200, &[("Cache-Control", "private, max-age=9")]),
            None
        );
        assert_eq!(decide(c, 200, &[("Set-Cookie", "a=b")]), None);
        assert_eq!(decide(c, 200, &[("Vary", "*")]), None);
        assert_eq!(
            decide(c, 200, &[("Vary", "Accept-Encoding, X-A")]),
            Some((60, Some(vec!["accept-encoding".into(), "x-a".into()])))
        );
        assert_eq!(
            decide(c, 200, &[("Expires", "Thu, 01 Jan 1970 00:00:00 GMT")]),
            None
        );
    }

    #[test]
    fn entries_round_trip_and_purge() {
        let dir = std::env::temp_dir().join(format!("pxcache-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let zone = Zone {
            id: "z".into(),
            path: dir.clone(),
            levels: [1, 2].into(),
            limits: Mutex::new(Limits {
                max_size: 0,
                max_entries: 2,
                inactive: Duration::from_secs(600),
            }),
            index: Mutex::new(Index::default()),
            locks: Mutex::new(HashMap::new()),
        };
        let x = Exchange::new(
            "127.0.0.1:80".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let store = |key: &[u8], tag: &str| {
            let s = Storable {
                fresh: Fresh {
                    expires: now() + 60,
                    ..Fresh::default()
                },
                vary: None,
                tags: [Box::from(tag.as_bytes())].into(),
            };
            let mut p = zone
                .begin(key, &x, s, 200, b"Content-Type: text/plain\r\n")
                .unwrap();
            p.write(b"hello");
            zone.commit(p, true);
        };
        store(b"k1", "a");
        let (h, f) = zone.lookup(b"k1", &x);
        assert!(f.unwrap().fresh(now()));
        let (_, e) = zone.open(h).unwrap();
        assert_eq!((e.status, e.body_len), (200, 5));
        assert_eq!(e.header(b"content-type"), Some(&b"text/plain"[..]));
        let name = hex(&h);
        assert!(
            dir.join(&name[31..])
                .join(&name[29..31])
                .join(&name)
                .exists()
        );
        store(b"k2", "b");
        store(b"k3", "b");
        // max_entries 2: k1 went first.
        assert!(zone.lookup(b"k1", &x).1.is_none());
        let removed = zone.purge(&Purge {
            tags: vec!["b".into()],
            ..Default::default()
        });
        assert_eq!(removed, 2);
        store(b"k4", "c");
        // The loader finds what is on disk.
        let fresh = Zone {
            index: Mutex::new(Index::default()),
            locks: Mutex::new(HashMap::new()),
            limits: Mutex::new(zone.limits()),
            id: "z".into(),
            path: dir.clone(),
            levels: [1, 2].into(),
        };
        fresh.load();
        assert!(fresh.lookup(b"k4", &x).1.is_some());
        let _ = fs::remove_dir_all(&dir);
    }
}
