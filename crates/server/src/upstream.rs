//! Upstream state that outlives a request: load balancing, target limits,
//! passive and active health, sticky sessions, the request queue and idle
//! keepalive connections.

use std::cell::Cell;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use proxelo_snapshot::{Balancing, Upstream};
use tokio::net::TcpStream;
use tokio::sync::Notify;

use crate::worker;

/// Health and load of one target, shared by every worker and carried over
/// snapshot swaps by upstream ID and address.
#[derive(Default)]
pub(crate) struct Peer {
    /// Requests in progress, for least_conn, random two and max_conns.
    active: AtomicU32,
    /// Failures counted in the current fail_timeout window.
    fails: AtomicU32,
    /// Milliseconds since [`EPOCH`] of the last failure.
    failed_at: AtomicU64,
    /// Failing the active health check.
    check_down: AtomicBool,
    /// Probe results in a row that disagree with the current state.
    streak: AtomicU32,
    /// The last failed probe, while it is failing.
    check_error: Mutex<String>,
    /// Milliseconds since [`EPOCH`] when the target last came back from
    /// being down; slow start counts from here. 0: never.
    up_since: AtomicU64,
}

static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

fn now_ms() -> u64 {
    EPOCH.elapsed().as_millis() as u64
}

pub(crate) struct State {
    pub id: Box<str>,
    pools: Box<[Arc<Pool>]>,
    peers: Box<[Arc<Peer>]>,
    weights: Box<[i64]>,
    backup: Box<[bool]>,
    down: Box<[bool]>,
    max_conns: Box<[u32]>,
    slow_start_ms: Box<[u64]>,
    /// Index of each target's configured name among the distinct names;
    /// the addresses of one name share it.
    name_id: Box<[u32]>,
    /// Sticky route values.
    routes: Box<[Box<str>]>,
    /// Sticky cookie values: the target address's CRC-32 in hex.
    cookies: Box<[[u8; 8]]>,
    balancing: Balancing,
    /// Sum of the primary targets' weights, for the hash methods.
    total: i64,
    /// Consistent hash ring: point hash and name ID, sorted by hash.
    ring: Box<[(u32, u32)]>,
    max_fails: u32,
    fail_timeout_ms: u64,
    /// Smooth weighted round robin positions, one set per worker like nginx
    /// without a shared zone.
    current: Box<[Mutex<Box<[i64]>>]>,
    pub keepalive: bool,
    pub keepalive_requests: u32,
    pub keepalive_time: Duration,
    pub host: Box<str>,
    queue_size: u32,
    queue_timeout: Duration,
    /// Requests waiting in the queue.
    queued: AtomicU32,
    /// Signalled when a request releases a target with max_conns.
    freed: Notify,
    limited: bool,
    /// TLS to the targets: the connector, the name for SNI and verification,
    /// and whether SNI is sent.
    tls: Option<(openssl::ssl::SslConnector, Box<str>, bool)>,
}

/// State from the previous snapshot, so warm connections and health survive
/// a swap.
#[derive(Default)]
pub(crate) struct Reuse {
    /// By target address, idle limit and idle timeout.
    pub pools: HashMap<(SocketAddr, u32, Duration), Arc<Pool>>,
    /// By upstream ID and target address.
    pub peers: HashMap<(Box<str>, SocketAddr), Arc<Peer>>,
}

/// The target picked for one attempt. Counts as active until dropped.
pub(crate) struct Picked<'a> {
    pub index: usize,
    state: &'a State,
}

impl Drop for Picked<'_> {
    fn drop(&mut self) {
        self.state.peers[self.index]
            .active
            .fetch_sub(1, Ordering::Relaxed);
        if self.state.limited {
            self.state.freed.notify_one();
        }
    }
}

/// Target selection of one request across its attempts.
#[derive(Default)]
pub(crate) struct Choice {
    /// Targets already tried: bit i for target i < 64.
    pub tried: u64,
    /// The target a sticky session names, tried first.
    pub prefer: Option<usize>,
    /// Hash methods: the running hash, or the ring position.
    pub(crate) hash: u32,
    /// Hash: rehash count.
    pub(crate) rehash: u32,
    /// Hash and random methods: picks that hit an unavailable target; after
    /// 20 they fall back to round robin, as in nginx.
    pub(crate) tries: u32,
    pub(crate) started: bool,
}

const CRC_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

/// CRC-32 (IEEE), as nginx's ngx_crc32 and zlib.
#[derive(Clone, Copy)]
struct Crc(u32);

impl Crc {
    fn new() -> Self {
        Self(0xffff_ffff)
    }

    fn update(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = CRC_TABLE[((self.0 ^ u32::from(b)) & 0xff) as usize] ^ (self.0 >> 8);
        }
    }

    fn finish(self) -> u32 {
        self.0 ^ 0xffff_ffff
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut c = Crc::new();
    c.update(bytes);
    c.finish()
}

thread_local! {
    static RNG: Cell<u64> = Cell::new(std::collections::hash_map::RandomState::new().hash_one(0u8) | 1);
}

/// xorshift64: the random methods need spread, not secrecy.
pub(crate) fn rand() -> u64 {
    RNG.with(|r| {
        let mut x = r.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        r.set(x);
        x
    })
}

/// Splits `host:port` as nginx's consistent hash does: the port is the
/// digits after the last colon.
fn host_port(name: &str) -> (&[u8], &[u8]) {
    let b = name.as_bytes();
    let digits = b.iter().rev().take_while(|c| c.is_ascii_digit()).count();
    if digits > 0 && digits < b.len() && b[b.len() - digits - 1] == b':' {
        (&b[..b.len() - digits - 1], &b[b.len() - digits..])
    } else {
        (b, &[])
    }
}

/// 160 points per weight unit and target address, each the CRC-32 of
/// `host \0 port` and the previous point, as Cache::Memcached::Fast and
/// nginx `hash ... consistent`. Equal points keep the first.
fn ring(up: &Upstream, name_id: &[u32]) -> Box<[(u32, u32)]> {
    let mut points = Vec::new();
    for (i, t) in up.targets.iter().enumerate() {
        if t.backup {
            continue;
        }
        let (host, port) = host_port(&t.name);
        let mut base = Crc::new();
        base.update(host);
        base.update(&[0]);
        base.update(port);
        let mut prev = 0u32;
        for _ in 0..t.weight.max(1) * 160 {
            let mut h = base;
            h.update(&prev.to_le_bytes());
            prev = h.finish();
            points.push((prev, name_id[i]));
        }
    }
    points.sort_by_key(|p| p.0);
    points.dedup_by_key(|p| p.0);
    points.into()
}

impl State {
    /// `certs` are the snapshot's, for a client certificate. Fails when
    /// OpenSSL rejects the TLS settings.
    pub fn new(
        up: &Upstream,
        shards: usize,
        reuse: &Reuse,
        certs: &[proxelo_snapshot::Certificate],
    ) -> Result<Self, String> {
        let tls = match &up.tls {
            None => None,
            Some(t) => {
                let cert = t.certificate.map(|c| &certs[c as usize]);
                let c =
                    crate::tls::connector(t, cert).map_err(|e| format!("{}.tls: {e}", up.id))?;
                let name = if t.server_name.is_empty() {
                    up.host
                        .rsplit_once(':')
                        .map_or(&*up.host, |(h, _)| h)
                        .into()
                } else {
                    t.server_name.clone()
                };
                Some((c, name, t.sni))
            }
        };
        let pools = up
            .targets
            .iter()
            .map(|t| {
                let key = (t.addr, up.keepalive_idle, up.keepalive_timeout);
                reuse.pools.get(&key).cloned().unwrap_or_else(|| {
                    Arc::new(Pool::new(
                        t.addr,
                        up.keepalive_idle,
                        up.keepalive_timeout,
                        shards,
                    ))
                })
            })
            .collect();
        let peers = up
            .targets
            .iter()
            .map(|t| {
                reuse
                    .peers
                    .get(&(up.id.clone(), t.addr))
                    .cloned()
                    .unwrap_or_default()
            })
            .collect();
        let weights: Box<[i64]> = up.targets.iter().map(|t| i64::from(t.weight)).collect();
        let current = (0..shards)
            .map(|_| Mutex::new(vec![0; weights.len()].into()))
            .collect();
        let mut names: Vec<&str> = Vec::new();
        let name_id: Box<[u32]> = up
            .targets
            .iter()
            .map(|t| match names.iter().position(|n| **n == *t.name) {
                Some(i) => i as u32,
                None => {
                    names.push(&t.name);
                    names.len() as u32 - 1
                }
            })
            .collect();
        let ring = if up.balancing == Balancing::HashConsistent {
            ring(up, &name_id)
        } else {
            Box::default()
        };
        let cookies = up
            .targets
            .iter()
            .map(|t| {
                let mut v = [0u8; 8];
                let h = crc32(t.addr.to_string().as_bytes());
                for (i, b) in v.iter_mut().enumerate() {
                    *b = b"0123456789abcdef"[(h >> (28 - 4 * i) & 15) as usize];
                }
                v
            })
            .collect();
        // nginx does not track the health of a single server.
        let single = up.targets.len() == 1;
        Ok(Self {
            id: up.id.clone(),
            pools,
            peers,
            total: up
                .targets
                .iter()
                .filter(|t| !t.backup)
                .map(|t| i64::from(t.weight))
                .sum(),
            weights,
            backup: up.targets.iter().map(|t| t.backup).collect(),
            down: up.targets.iter().map(|t| t.down).collect(),
            max_conns: up.targets.iter().map(|t| t.max_conns).collect(),
            slow_start_ms: up
                .targets
                .iter()
                .map(|t| t.slow_start.as_millis() as u64)
                .collect(),
            limited: up.targets.iter().any(|t| t.max_conns > 0),
            name_id,
            routes: up.targets.iter().map(|t| t.route.clone()).collect(),
            cookies,
            balancing: up.balancing,
            ring,
            max_fails: if single { 0 } else { up.max_fails },
            fail_timeout_ms: up.fail_timeout.as_millis() as u64,
            current,
            keepalive: up.keepalive_idle > 0,
            keepalive_requests: up.keepalive_requests,
            keepalive_time: up.keepalive_time,
            host: up.host.clone(),
            queue_size: up.queue_size,
            queue_timeout: up.queue_timeout,
            queued: AtomicU32::new(0),
            freed: Notify::new(),
            tls,
        })
    }

    pub fn pools(&self) -> &[Arc<Pool>] {
        &self.pools
    }

    pub fn peers(&self) -> impl Iterator<Item = (SocketAddr, &Arc<Peer>)> {
        self.pools.iter().map(|p| p.addr).zip(self.peers.iter())
    }

    pub fn len(&self) -> usize {
        self.weights.len()
    }

    /// Not taking requests: marked down, failing the active check or down
    /// after max_fails failures, for fail_timeout after the last one (nginx
    /// max_fails, fail_timeout).
    fn available(&self, i: usize, now: u64) -> bool {
        let p = &self.peers[i];
        if self.down[i] || p.check_down.load(Ordering::Relaxed) {
            return false;
        }
        self.max_fails == 0
            || p.fails.load(Ordering::Relaxed) < self.max_fails
            || now.saturating_sub(p.failed_at.load(Ordering::Relaxed)) >= self.fail_timeout_ms
    }

    fn below_max_conns(&self, i: usize) -> bool {
        let m = self.max_conns[i];
        m == 0 || self.peers[i].active.load(Ordering::Relaxed) < m
    }

    fn untried(i: usize, tried: u64) -> bool {
        i >= 64 || tried >> i & 1 == 0
    }

    fn candidate(&self, i: usize, tried: u64, backup: bool, now: u64) -> bool {
        self.backup[i] == backup
            && Self::untried(i, tried)
            && self.available(i, now)
            && self.below_max_conns(i)
    }

    /// The weight now: during slow start it grows linearly from 1.
    fn weight(&self, i: usize, now: u64) -> i64 {
        let w = self.weights[i];
        let ss = self.slow_start_ms[i];
        let since = self.peers[i].up_since.load(Ordering::Relaxed);
        if ss == 0 || since == 0 {
            return w;
        }
        let t = now.saturating_sub(since);
        if t >= ss {
            w
        } else {
            (w * t as i64 / ss as i64).max(1)
        }
    }

    /// Whether another target could be tried after those in `tried`.
    pub fn has_next(&self, tried: u64) -> bool {
        let now = now_ms();
        (0..self.len())
            .any(|i| self.candidate(i, tried, false, now) || self.candidate(i, tried, true, now))
    }

    /// Whether a target would be free but for max_conns, so a request may
    /// wait in the queue.
    pub fn full(&self, tried: u64) -> bool {
        let now = now_ms();
        self.queue_size > 0
            && (0..self.len()).any(|i| Self::untried(i, tried) && self.available(i, now))
    }

    /// Waits in the queue until a target frees up or `deadline`. False when
    /// the queue is full or the wait timed out.
    pub async fn wait(&self, deadline: Option<tokio::time::Instant>) -> bool {
        if self.queued.fetch_add(1, Ordering::Relaxed) >= self.queue_size {
            self.queued.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        let deadline = deadline.unwrap_or_else(|| tokio::time::Instant::now() + self.queue_timeout);
        let ok = tokio::time::timeout_at(deadline, self.freed.notified())
            .await
            .is_ok();
        self.queued.fetch_sub(1, Ordering::Relaxed);
        ok
    }

    pub fn queue_deadline(&self) -> tokio::time::Instant {
        tokio::time::Instant::now() + self.queue_timeout
    }

    /// The target whose sticky cookie value is `v`.
    pub fn by_cookie(&self, v: &[u8]) -> Option<usize> {
        self.cookies.iter().position(|c| c == v)
    }

    pub fn cookie(&self, i: usize) -> &[u8; 8] {
        &self.cookies[i]
    }

    /// The first target with sticky route `v`.
    pub fn by_route(&self, v: &[u8]) -> Option<usize> {
        self.routes.iter().position(|r| r.as_bytes() == v)
    }

    /// Picks the next target. `key` is the client address bytes for
    /// ip_hash and the expanded hash key for the hash methods.
    pub fn pick(&self, c: &mut Choice, key: &[u8]) -> Option<Picked<'_>> {
        let now = now_ms();
        let i = self.choose(c, key, now)?;
        if i < 64 {
            c.tried |= 1 << i;
        }
        self.peers[i].active.fetch_add(1, Ordering::Relaxed);
        Some(Picked {
            index: i,
            state: self,
        })
    }

    fn choose(&self, c: &mut Choice, key: &[u8], now: u64) -> Option<usize> {
        if let Some(i) = c.prefer.take()
            && i < self.len()
            && self.candidate(i, c.tried, self.backup[i], now)
        {
            return Some(i);
        }
        if self.len() > 1 && self.total > 0 && c.tries <= 20 {
            let hashed = match self.balancing {
                Balancing::IpHash => self.ip_hash(c, key, now),
                Balancing::Hash if !key.is_empty() => self.hash(c, key, now),
                Balancing::HashConsistent if !key.is_empty() && !self.ring.is_empty() => {
                    self.chash(c, key, now)
                }
                Balancing::Random => self.random(c, now, false),
                Balancing::RandomTwo => self.random(c, now, true),
                _ => None,
            };
            if hashed.is_some() {
                return hashed;
            }
        }
        // Round robin, also what the hash methods fall back to.
        self.rr(c.tried, false, now, None)
            .or_else(|| self.rr(c.tried, true, now, None))
    }

    /// The primary target at `w` in the cumulative weights.
    fn walk(&self, mut w: i64) -> usize {
        for i in 0..self.len() {
            if self.backup[i] {
                continue;
            }
            if w < self.weights[i] {
                return i;
            }
            w -= self.weights[i];
        }
        0
    }

    /// Counts a pick of an unavailable target; false after 20.
    fn retry(c: &mut Choice) -> bool {
        c.tries += 1;
        c.tries <= 20
    }

    /// nginx ip_hash: the first three octets of IPv4 or all of IPv6.
    fn ip_hash(&self, c: &mut Choice, key: &[u8], now: u64) -> Option<usize> {
        if !c.started {
            c.hash = 89;
            c.started = true;
        }
        loop {
            for &b in key {
                c.hash = (c.hash * 113 + u32::from(b)) % 6271;
            }
            let i = self.walk(i64::from(c.hash) % self.total);
            if self.candidate(i, c.tried, false, now) {
                return Some(i);
            }
            if !Self::retry(c) {
                return None;
            }
        }
    }

    /// nginx hash: compatible with Cache::Memcached, the hash of the key
    /// (prefixed with the rehash count after the first pick) accumulates.
    fn hash(&self, c: &mut Choice, key: &[u8], now: u64) -> Option<usize> {
        loop {
            let mut crc = Crc::new();
            if c.rehash > 0 {
                let mut buf = [0u8; 10];
                let mut n = c.rehash;
                let mut at = buf.len();
                while n > 0 || at == buf.len() {
                    at -= 1;
                    buf[at] = b'0' + (n % 10) as u8;
                    n /= 10;
                }
                crc.update(&buf[at..]);
            }
            crc.update(key);
            c.hash = c.hash.wrapping_add((crc.finish() >> 16) & 0x7fff);
            c.rehash += 1;
            let i = self.walk(i64::from(c.hash) % self.total);
            if self.candidate(i, c.tried, false, now) {
                return Some(i);
            }
            if !Self::retry(c) {
                return None;
            }
        }
    }

    /// nginx hash consistent: the first ring point at or after the key's
    /// hash, then the following points; the addresses of the point's name
    /// share it by round robin.
    fn chash(&self, c: &mut Choice, key: &[u8], now: u64) -> Option<usize> {
        if !c.started {
            let h = crc32(key);
            c.hash = self.ring.partition_point(|p| p.0 < h) as u32;
            c.started = true;
        }
        loop {
            let name = self.ring[c.hash as usize % self.ring.len()].1;
            if let Some(i) = self.rr(c.tried, false, now, Some(name)) {
                return Some(i);
            }
            c.hash = c.hash.wrapping_add(1);
            if !Self::retry(c) {
                return None;
            }
        }
    }

    /// nginx random: a weighted random target; with `two`, the less loaded
    /// of two different ones (random two least_conn).
    fn random(&self, c: &mut Choice, now: u64, two: bool) -> Option<usize> {
        let one = |c: &mut Choice| loop {
            let i = self.walk((rand() % self.total as u64) as i64);
            if self.candidate(i, c.tried, false, now) {
                return Some(i);
            }
            if !Self::retry(c) {
                return None;
            }
        };
        let a = one(c)?;
        if !two {
            return Some(a);
        }
        let b = loop {
            match one(c) {
                Some(b) if b != a => break b,
                Some(_) => {
                    if !Self::retry(c) {
                        return Some(a);
                    }
                }
                None => return Some(a),
            }
        };
        let load = |i: usize| i64::from(self.peers[i].active.load(Ordering::Relaxed));
        // a/w(a) <= b/w(b) without division.
        if load(a) * self.weight(b, now) <= load(b) * self.weight(a, now) {
            Some(a)
        } else {
            Some(b)
        }
    }

    /// Smooth weighted round robin among the available primary or backup
    /// targets, only those of name `only` when set; with least_conn, among
    /// the ones with the fewest active requests per weight.
    fn rr(&self, tried: u64, backup: bool, now: u64, only: Option<u32>) -> Option<usize> {
        let n = self.len();
        let ok = |i: usize| {
            self.candidate(i, tried, backup, now) && only.is_none_or(|id| self.name_id[i] == id)
        };
        if n == 1 {
            return ok(0).then_some(0);
        }
        // Load a/w compared as a * w' against a' * w, without division.
        let load = |i: usize| {
            (
                i64::from(self.peers[i].active.load(Ordering::Relaxed)),
                self.weight(i, now),
            )
        };
        let less = |(a, w): (i64, i64), (b, v): (i64, i64)| a * v < b * w;
        let mut least: Option<(i64, i64)> = None;
        if self.balancing == Balancing::LeastConn {
            for i in (0..n).filter(|&i| ok(i)) {
                let l = load(i);
                if least.is_none_or(|m| less(l, m)) {
                    least = Some(l);
                }
            }
        }
        let shard = worker::id() % self.current.len();
        let mut cur = self.current[shard]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut total = 0;
        let mut best: Option<usize> = None;
        for i in 0..n {
            if !ok(i) {
                continue;
            }
            if let Some(m) = least
                && less(m, load(i))
            {
                continue;
            }
            let w = self.weight(i, now);
            cur[i] += w;
            total += w;
            if best.is_none_or(|b| cur[i] > cur[b]) {
                best = Some(i);
            }
        }
        if let Some(b) = best {
            cur[b] -= total;
        }
        best
    }

    /// Records a failed attempt (nginx: an error, a timeout or a status
    /// listed in proxy_next_upstream other than 403 and 404).
    pub fn failed(&self, i: usize) {
        if self.max_fails == 0 {
            return;
        }
        let p = &self.peers[i];
        let now = now_ms();
        let last = p.failed_at.swap(now, Ordering::Relaxed);
        if now.saturating_sub(last) >= self.fail_timeout_ms {
            p.fails.store(1, Ordering::Relaxed);
        } else {
            p.fails.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A successful response makes the target fully available again; one
    /// that was down starts its slow start.
    pub fn succeeded(&self, i: usize) {
        if self.max_fails != 0 {
            let p = &self.peers[i];
            if p.fails.swap(0, Ordering::Relaxed) >= self.max_fails {
                p.up_since.store(now_ms().max(1), Ordering::Relaxed);
            }
        }
    }

    /// Records an active health check probe of target `i`.
    pub fn probed(&self, i: usize, result: Result<(), String>, fails: u32, passes: u32) {
        let p = &self.peers[i];
        let down = p.check_down.load(Ordering::Relaxed);
        let mut error = p.check_error.lock().unwrap_or_else(|e| e.into_inner());
        match result {
            Ok(()) if down => {
                if p.streak.fetch_add(1, Ordering::Relaxed) + 1 >= passes {
                    p.streak.store(0, Ordering::Relaxed);
                    p.up_since.store(now_ms().max(1), Ordering::Relaxed);
                    p.check_down.store(false, Ordering::Relaxed);
                    error.clear();
                }
            }
            Ok(()) => {
                p.streak.store(0, Ordering::Relaxed);
                error.clear();
            }
            Err(e) => {
                if !down && p.streak.fetch_add(1, Ordering::Relaxed) + 1 >= fails {
                    p.streak.store(0, Ordering::Relaxed);
                    p.check_down.store(true, Ordering::Relaxed);
                } else if down {
                    p.streak.store(0, Ordering::Relaxed);
                }
                *error = e;
            }
        }
    }

    /// Whether target `i` takes requests, and why the active check fails it.
    pub fn health(&self, i: usize) -> (bool, String) {
        let p = &self.peers[i];
        let error = if p.check_down.load(Ordering::Relaxed) {
            p.check_error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        } else {
            String::new()
        };
        (self.available(i, now_ms()), error)
    }

    /// Targets currently down, for metrics.
    pub fn down(&self, i: usize) -> bool {
        !self.available(i, now_ms())
    }
}

struct Idle {
    stream: UpStream,
    since: Instant,
    opened: Instant,
    used: u32,
}

/// An upstream connection taken from or returned to a pool.
pub(crate) struct Conn {
    pub stream: UpStream,
    /// Requests it served.
    pub used: u32,
    pub opened: Instant,
}

/// Idle connections to one target, one LIFO stack per worker.
pub(crate) struct Pool {
    pub addr: SocketAddr,
    /// The HTTP/2 connection grpc requests to this target share.
    pub h2: tokio::sync::Mutex<Option<h2::client::SendRequest<bytes::Bytes>>>,
    max_idle: usize,
    timeout: Duration,
    shards: Box<[Mutex<Vec<Idle>>]>,
}

impl Pool {
    fn new(addr: SocketAddr, max_idle: u32, timeout: Duration, shards: usize) -> Self {
        let max_idle = max_idle as usize;
        Self {
            addr,
            h2: tokio::sync::Mutex::new(None),
            max_idle,
            timeout,
            shards: (0..shards)
                .map(|_| Mutex::new(Vec::with_capacity(max_idle)))
                .collect(),
        }
    }

    pub fn key(&self) -> (SocketAddr, u32, Duration) {
        (self.addr, self.max_idle as u32, self.timeout)
    }

    fn shard(&self) -> std::sync::MutexGuard<'_, Vec<Idle>> {
        self.shards[worker::id() % self.shards.len()]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Returns the most recently used idle connection that is still open.
    pub fn take(&self) -> Option<Conn> {
        let mut idle = self.shard();
        while let Some(c) = idle.pop() {
            if c.since.elapsed() < self.timeout && open(&c.stream) {
                return Some(Conn {
                    stream: c.stream,
                    used: c.used,
                    opened: c.opened,
                });
            }
        }
        None
    }

    /// Keeps `c` for reuse, closing the oldest idle connection when the
    /// worker already holds `max_idle`.
    pub fn put(&self, c: Conn) {
        if self.max_idle == 0 {
            return;
        }
        let mut idle = self.shard();
        if idle.len() == self.max_idle {
            idle.remove(0);
        }
        idle.push(Idle {
            stream: c.stream,
            since: Instant::now(),
            opened: c.opened,
            used: c.used,
        });
    }
}

/// An upstream connection: plain TCP or TLS (proxy_pass https://).
pub(crate) enum UpStream {
    Tcp(TcpStream),
    Tls(Box<tokio_openssl::SslStream<TcpStream>>),
}

impl UpStream {
    fn tcp(&self) -> &TcpStream {
        match self {
            Self::Tcp(s) => s,
            Self::Tls(s) => s.get_ref(),
        }
    }
}

impl tokio::io::AsyncRead for UpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => std::pin::Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for UpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => std::pin::Pin::new(&mut **s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            Self::Tls(s) => std::pin::Pin::new(&mut **s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => std::pin::Pin::new(&mut **s).poll_shutdown(cx),
        }
    }
}

/// Why a new upstream connection could not be made.
pub(crate) enum ConnectError {
    Failed,
    TimedOut,
}

impl State {
    /// Opens a connection to target `i`, with TLS when the upstream has it;
    /// `limit` bounds the TCP connect and the handshake together.
    pub async fn connect(
        &self,
        i: usize,
        limit: Duration,
        local: Option<SocketAddr>,
    ) -> Result<UpStream, ConnectError> {
        let addr = self.pools[i].addr;
        let run = async {
            let s = tcp_connect(addr, local)
                .await
                .map_err(|_| ConnectError::Failed)?;
            let _ = s.set_nodelay(true);
            let Some((connector, name, sni)) = &self.tls else {
                return Ok(UpStream::Tcp(s));
            };
            let mut cfg = connector.configure().map_err(|_| ConnectError::Failed)?;
            cfg.set_use_server_name_indication(*sni);
            let name = if name.is_empty() {
                addr.ip().to_string()
            } else {
                name.to_string()
            };
            let ssl = cfg.into_ssl(&name).map_err(|_| ConnectError::Failed)?;
            let mut tls =
                tokio_openssl::SslStream::new(ssl, s).map_err(|_| ConnectError::Failed)?;
            std::pin::Pin::new(&mut tls)
                .connect()
                .await
                .map_err(|_| ConnectError::Failed)?;
            Ok(UpStream::Tls(Box::new(tls)))
        };
        match tokio::time::timeout(limit, run).await {
            Ok(r) => r,
            Err(_) => Err(ConnectError::TimedOut),
        }
    }
}

/// Connects to `addr` from `local` (nginx proxy_bind), or from an address
/// the system chooses.
pub(crate) async fn tcp_connect(
    addr: SocketAddr,
    local: Option<SocketAddr>,
) -> std::io::Result<TcpStream> {
    let Some(local) = local else {
        return TcpStream::connect(addr).await;
    };
    let s = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    // A fixed port is shared by connections to different targets.
    if local.port() != 0 {
        s.set_reuseaddr(true)?;
    }
    s.bind(local)?;
    s.connect(addr).await
}

/// An idle connection has nothing to read. EOF means the upstream closed it,
/// and unsolicited bytes mean it can no longer be framed.
fn open(stream: &UpStream) -> bool {
    let mut b = [0u8; 1];
    matches!(stream.tcp().try_read(&mut b), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxelo_snapshot::{Target, Template};

    fn upstream(weights: &[u32], balancing: Balancing) -> Upstream {
        Upstream {
            id: "up".into(),
            targets: weights
                .iter()
                .enumerate()
                .map(|(i, &weight)| {
                    let addr = SocketAddr::from(([127, 0, 0, 1], 1000 + i as u16));
                    Target {
                        addr,
                        name: addr.to_string().into(),
                        weight,
                        backup: false,
                        down: false,
                        max_conns: 0,
                        slow_start: Duration::ZERO,
                        route: "".into(),
                    }
                })
                .collect(),
            balancing,
            hash_key: Template::default(),
            health_check: None,
            sticky: None,
            queue_size: 0,
            queue_timeout: Duration::from_secs(60),
            keepalive_time: Duration::from_secs(3600),
            tls: None,
            keepalive_idle: 0,
            keepalive_timeout: Duration::from_secs(60),
            keepalive_requests: 1000,
            host: "".into(),
            max_fails: 1,
            fail_timeout: Duration::from_secs(10),
        }
    }

    fn state(weights: &[u32], balancing: Balancing) -> State {
        State::new(&upstream(weights, balancing), 1, &Reuse::default(), &[]).unwrap()
    }

    fn pick(s: &State, tried: u64) -> Option<usize> {
        let mut c = Choice {
            tried,
            ..Default::default()
        };
        s.pick(&mut c, b"").map(|p| p.index)
    }

    fn pick_key(s: &State, key: &[u8]) -> usize {
        s.pick(&mut Choice::default(), key).unwrap().index
    }

    #[test]
    fn smooth_weighted_order() {
        // nginx's documented sequence for weights 5, 1, 1.
        let s = state(&[5, 1, 1], Balancing::RoundRobin);
        let seq: Vec<_> = (0..7).map(|_| pick(&s, 0).unwrap()).collect();
        assert_eq!(seq, [0, 0, 1, 0, 2, 0, 0]);
    }

    #[test]
    fn skips_tried() {
        let s = state(&[1, 1, 1], Balancing::RoundRobin);
        assert_eq!(pick(&s, 0b011), Some(2));
        assert_eq!(pick(&s, 0b111), None);
        let one = state(&[1], Balancing::RoundRobin);
        assert_eq!(pick(&one, 0), Some(0));
        assert_eq!(pick(&one, 1), None);
    }

    #[test]
    fn least_conn_prefers_idle_targets() {
        let s = state(&[1, 1, 1], Balancing::LeastConn);
        let mut c = Choice::default();
        let a = s.pick(&mut c, b"").unwrap();
        let b = s.pick(&mut Choice::default(), b"").unwrap();
        assert_ne!(a.index, b.index);
        let c = s.pick(&mut Choice::default(), b"").unwrap();
        assert!(c.index != a.index && c.index != b.index);
        // Only b's target is idle now.
        let freed = b.index;
        drop(b);
        assert_eq!(pick(&s, 0), Some(freed));
        drop((a, c));
    }

    #[test]
    fn failed_target_is_skipped() {
        let s = state(&[1, 1], Balancing::RoundRobin);
        s.failed(0);
        assert!((0..4).all(|_| pick(&s, 0) == Some(1)));
        s.succeeded(0);
        assert!((0..4).any(|_| pick(&s, 0) == Some(0)));
    }

    #[test]
    fn crc32_matches_zlib() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn ip_hash_is_stable_per_network() {
        let s = state(&[1, 1, 1, 1], Balancing::IpHash);
        let a = pick_key(&s, &[10, 0, 0]);
        assert!((0..8).all(|_| pick_key(&s, &[10, 0, 0]) == a));
        let spread: std::collections::HashSet<_> =
            (0..=255u8).map(|n| pick_key(&s, &[10, n, 0])).collect();
        assert!(spread.len() > 1);
        // The next pick of the same request moves on to another target.
        let mut c = Choice::default();
        let first = s.pick(&mut c, &[10, 0, 0]).unwrap().index;
        assert_ne!(s.pick(&mut c, &[10, 0, 0]).unwrap().index, first);
    }

    #[test]
    fn hash_follows_the_key_and_skips_down_targets() {
        let s = state(&[1, 1, 1], Balancing::Hash);
        let a = pick_key(&s, b"/user/42");
        assert!((0..8).all(|_| pick_key(&s, b"/user/42") == a));
        s.failed(a);
        let b = pick_key(&s, b"/user/42");
        assert_ne!(a, b);
        assert!((0..8).all(|_| pick_key(&s, b"/user/42") == b));
    }

    #[test]
    fn consistent_hash_moves_few_keys() {
        let three = state(&[1, 1, 1], Balancing::HashConsistent);
        let four = state(&[1, 1, 1, 1], Balancing::HashConsistent);
        let keys: Vec<String> = (0..1000).map(|i| format!("key{i}")).collect();
        let moved = keys
            .iter()
            .filter(|k| pick_key(&three, k.as_bytes()) != pick_key(&four, k.as_bytes()))
            .count();
        // About a quarter of the keys go to the new target; none move
        // between the old ones.
        assert!((150..400).contains(&moved), "moved {moved}");
        assert!(keys.iter().all(|k| {
            let b = pick_key(&four, k.as_bytes());
            b == 3 || b == pick_key(&three, k.as_bytes())
        }));
    }

    #[test]
    fn random_spreads_by_weight() {
        let s = state(&[3, 1], Balancing::Random);
        let first = (0..4000).filter(|_| pick(&s, 0) == Some(0)).count();
        assert!((2700..3300).contains(&first), "first {first}");
    }

    #[test]
    fn random_two_prefers_the_less_loaded() {
        let s = state(&[1, 1], Balancing::RandomTwo);
        let busy = s.pick(&mut Choice::default(), b"").unwrap();
        assert!((0..20).all(|_| pick(&s, 0) != Some(busy.index)));
    }

    #[test]
    fn max_conns_limits_and_queue_signals() {
        let mut up = upstream(&[1], Balancing::RoundRobin);
        up.targets[0].max_conns = 1;
        up.queue_size = 1;
        let s = State::new(&up, 1, &Reuse::default(), &[]).unwrap();
        let held = s.pick(&mut Choice::default(), b"").unwrap();
        assert!(s.pick(&mut Choice::default(), b"").is_none());
        assert!(s.full(0));
        drop(held);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        // The release stored a wakeup for the next waiter.
        assert!(rt.block_on(s.wait(None)));
        assert!(s.pick(&mut Choice::default(), b"").is_some());
    }

    #[test]
    fn down_and_sticky_preference() {
        let mut up = upstream(&[1, 1, 1], Balancing::RoundRobin);
        up.targets[1].down = true;
        up.targets[2].route = "c".into();
        let s = State::new(&up, 1, &Reuse::default(), &[]).unwrap();
        assert!((0..6).all(|_| pick(&s, 0) != Some(1)));
        let mut c = Choice {
            prefer: s.by_route(b"c"),
            ..Default::default()
        };
        assert_eq!(s.pick(&mut c, b"").map(|p| p.index), Some(2));
        let mut c = Choice {
            prefer: s.by_cookie(s.cookie(0)),
            ..Default::default()
        };
        assert_eq!(s.pick(&mut c, b"").map(|p| p.index), Some(0));
    }

    #[test]
    fn active_check_takes_a_target_out_and_slow_start_brings_it_back() {
        let mut up = upstream(&[4, 4], Balancing::RoundRobin);
        up.targets[0].slow_start = Duration::from_secs(60);
        let s = State::new(&up, 1, &Reuse::default(), &[]).unwrap();
        s.probed(0, Err("refused".into()), 2, 1);
        assert!(s.health(0).0);
        s.probed(0, Err("refused".into()), 2, 1);
        assert_eq!(s.health(0), (false, "refused".into()));
        assert!((0..4).all(|_| pick(&s, 0) == Some(1)));
        s.probed(0, Ok(()), 2, 1);
        assert!(s.health(0).0);
        // Back with weight 1 of 4: the other target takes most requests.
        let first = (0..40).filter(|_| pick(&s, 0) == Some(0)).count();
        assert!(first <= 10, "first {first}");
    }

    #[test]
    fn host_port_split() {
        assert_eq!(
            host_port("a.example:8080"),
            (&b"a.example"[..], &b"8080"[..])
        );
        assert_eq!(host_port("[::1]:80"), (&b"[::1]"[..], &b"80"[..]));
        assert_eq!(host_port("a.example"), (&b"a.example"[..], &b""[..]));
    }
}
