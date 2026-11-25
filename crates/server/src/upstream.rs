//! Upstream state that outlives a request: load balancer positions, active
//! request counts, passive health and idle keepalive connections.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use proxelo_snapshot::Upstream;
use tokio::net::TcpStream;

use crate::worker;

/// Health and load of one target, shared by every worker and carried over
/// snapshot swaps by upstream ID and address.
#[derive(Default)]
pub(crate) struct Peer {
    /// Requests in progress, for least_conn.
    active: AtomicU32,
    /// Failures counted in the current fail_timeout window.
    fails: AtomicU32,
    /// Milliseconds since [`EPOCH`] of the last failure.
    failed_at: AtomicU64,
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
    least_conn: bool,
    max_fails: u32,
    fail_timeout_ms: u64,
    /// Smooth weighted round robin positions, one set per worker like nginx
    /// without a shared zone.
    current: Box<[Mutex<Box<[i64]>>]>,
    pub keepalive: bool,
    pub keepalive_requests: u32,
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
    peer: &'a Peer,
}

impl Drop for Picked<'_> {
    fn drop(&mut self) {
        self.peer.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl State {
    pub fn new(up: &Upstream, shards: usize, reuse: &Reuse) -> Self {
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
        // nginx does not track the health of a single server.
        let single = up.targets.len() == 1;
        Self {
            id: up.id.clone(),
            pools,
            peers,
            weights,
            backup: up.targets.iter().map(|t| t.backup).collect(),
            least_conn: up.least_conn,
            max_fails: if single { 0 } else { up.max_fails },
            fail_timeout_ms: up.fail_timeout.as_millis() as u64,
            current,
            keepalive: up.keepalive_idle > 0,
            keepalive_requests: up.keepalive_requests,
        }
    }

    pub fn pools(&self) -> &[Arc<Pool>] {
        &self.pools
    }

    pub fn peers(&self) -> impl Iterator<Item = (SocketAddr, &Arc<Peer>)> {
        self.pools.iter().map(|p| p.addr).zip(self.peers.iter())
    }

    /// A target is down after max_fails failures, for fail_timeout after the
    /// last one (nginx max_fails, fail_timeout).
    fn available(&self, i: usize, now: u64) -> bool {
        if self.max_fails == 0 {
            return true;
        }
        let p = &self.peers[i];
        p.fails.load(Ordering::Relaxed) < self.max_fails
            || now.saturating_sub(p.failed_at.load(Ordering::Relaxed)) >= self.fail_timeout_ms
    }

    fn candidate(&self, i: usize, tried: u64, backup: bool, now: u64) -> bool {
        self.backup[i] == backup && !(i < 64 && tried >> i & 1 == 1) && self.available(i, now)
    }

    /// Whether another target could be tried after those in `tried`.
    pub fn has_next(&self, tried: u64) -> bool {
        let now = now_ms();
        (0..self.weights.len())
            .any(|i| self.candidate(i, tried, false, now) || self.candidate(i, tried, true, now))
    }

    /// Picks the next target among the available primary ones, or the
    /// backups when none is left, skipping targets set in `tried`. Targets
    /// past the 64th cannot be excluded and may be picked again.
    pub fn pick(&self, tried: u64) -> Option<Picked<'_>> {
        let now = now_ms();
        let i = self
            .pick_in(tried, false, now)
            .or_else(|| self.pick_in(tried, true, now))?;
        let peer = &*self.peers[i];
        peer.active.fetch_add(1, Ordering::Relaxed);
        Some(Picked { index: i, peer })
    }

    fn pick_in(&self, tried: u64, backup: bool, now: u64) -> Option<usize> {
        let n = self.weights.len();
        if n == 1 {
            return self.candidate(0, tried, backup, now).then_some(0);
        }
        // least_conn: only the targets with the fewest active requests per
        // weight take part; round robin breaks the tie, as in nginx.
        // Load a/w compared as a * w' against a' * w, without division.
        let load = |i: usize| {
            (
                i64::from(self.peers[i].active.load(Ordering::Relaxed)),
                self.weights[i],
            )
        };
        let less = |(a, w): (i64, i64), (b, v): (i64, i64)| a * v < b * w;
        let mut least: Option<(i64, i64)> = None;
        if self.least_conn {
            for i in (0..n).filter(|&i| self.candidate(i, tried, backup, now)) {
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
            if !self.candidate(i, tried, backup, now) {
                continue;
            }
            if let Some(m) = least
                && less(m, load(i))
            {
                continue;
            }
            cur[i] += self.weights[i];
            total += self.weights[i];
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

    /// A successful response makes the target fully available again.
    pub fn succeeded(&self, i: usize) {
        if self.max_fails != 0 {
            self.peers[i].fails.store(0, Ordering::Relaxed);
        }
    }

    /// Targets currently down, for metrics.
    pub fn down(&self, i: usize) -> bool {
        !self.available(i, now_ms())
    }
}

struct Idle {
    stream: TcpStream,
    since: Instant,
    used: u32,
}

/// Idle connections to one target, one LIFO stack per worker.
pub(crate) struct Pool {
    pub addr: SocketAddr,
    max_idle: usize,
    timeout: Duration,
    shards: Box<[Mutex<Vec<Idle>>]>,
}

impl Pool {
    fn new(addr: SocketAddr, max_idle: u32, timeout: Duration, shards: usize) -> Self {
        let max_idle = max_idle as usize;
        Self {
            addr,
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

    /// Returns the most recently used idle connection that is still open,
    /// with the number of requests it served.
    pub fn take(&self) -> Option<(TcpStream, u32)> {
        let mut idle = self.shard();
        while let Some(c) = idle.pop() {
            if c.since.elapsed() < self.timeout && open(&c.stream) {
                return Some((c.stream, c.used));
            }
        }
        None
    }

    /// Keeps `stream`, which has served `used` requests, for reuse, closing
    /// the oldest idle connection when the worker already holds `max_idle`.
    pub fn put(&self, stream: TcpStream, used: u32) {
        if self.max_idle == 0 {
            return;
        }
        let mut idle = self.shard();
        if idle.len() == self.max_idle {
            idle.remove(0);
        }
        idle.push(Idle {
            stream,
            since: Instant::now(),
            used,
        });
    }
}

/// An idle connection has nothing to read. EOF means the upstream closed it,
/// and unsolicited bytes mean it can no longer be framed.
fn open(stream: &TcpStream) -> bool {
    let mut b = [0u8; 1];
    matches!(stream.try_read(&mut b), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxelo_snapshot::Target;

    fn state(weights: &[u32], least_conn: bool) -> State {
        let up = Upstream {
            id: "up".into(),
            targets: weights
                .iter()
                .enumerate()
                .map(|(i, &weight)| Target {
                    addr: SocketAddr::from(([127, 0, 0, 1], 1000 + i as u16)),
                    weight,
                    backup: false,
                })
                .collect(),
            least_conn,
            keepalive_idle: 0,
            keepalive_timeout: Duration::from_secs(60),
            keepalive_requests: 1000,
            max_fails: 1,
            fail_timeout: Duration::from_secs(10),
        };
        State::new(&up, 1, &Reuse::default())
    }

    fn pick(s: &State, tried: u64) -> Option<usize> {
        s.pick(tried).map(|p| p.index)
    }

    #[test]
    fn smooth_weighted_order() {
        // nginx's documented sequence for weights 5, 1, 1.
        let s = state(&[5, 1, 1], false);
        let seq: Vec<_> = (0..7).map(|_| pick(&s, 0).unwrap()).collect();
        assert_eq!(seq, [0, 0, 1, 0, 2, 0, 0]);
    }

    #[test]
    fn skips_tried() {
        let s = state(&[1, 1, 1], false);
        assert_eq!(pick(&s, 0b011), Some(2));
        assert_eq!(pick(&s, 0b111), None);
        let one = state(&[1], false);
        assert_eq!(pick(&one, 0), Some(0));
        assert_eq!(pick(&one, 1), None);
    }

    #[test]
    fn least_conn_prefers_idle_targets() {
        let s = state(&[1, 1, 1], true);
        let a = s.pick(0).unwrap();
        let b = s.pick(0).unwrap();
        assert_ne!(a.index, b.index);
        let c = s.pick(0).unwrap();
        assert!(c.index != a.index && c.index != b.index);
        // Only b's target is idle now.
        let freed = b.index;
        drop(b);
        assert_eq!(s.pick(0).map(|p| p.index), Some(freed));
        drop((a, c));
    }

    #[test]
    fn failed_target_is_skipped() {
        let s = state(&[1, 1], false);
        s.failed(0);
        assert!((0..4).all(|_| pick(&s, 0) == Some(1)));
        s.succeeded(0);
        assert!((0..4).any(|_| pick(&s, 0) == Some(0)));
    }
}
