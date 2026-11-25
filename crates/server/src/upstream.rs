//! Upstream state that outlives a request: load balancer positions and idle
//! keepalive connections.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use proxelo_snapshot::Upstream;
use tokio::net::TcpStream;

use crate::worker;

/// How long an idle upstream connection is kept (nginx `keepalive_timeout`
/// in an upstream block).
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) struct State {
    pools: Box<[Arc<Pool>]>,
    weights: Box<[i64]>,
    /// Smooth weighted round robin positions, one set per worker like nginx
    /// without a shared zone.
    current: Box<[Mutex<Box<[i64]>>]>,
    pub keepalive: bool,
}

/// Pools from the previous snapshot by target address and idle limit, so
/// warm connections survive a snapshot swap.
pub(crate) type Reuse = HashMap<(SocketAddr, u32), Arc<Pool>>;

impl State {
    pub fn new(up: &Upstream, shards: usize, reuse: &Reuse) -> Self {
        let pools = up
            .targets
            .iter()
            .map(|t| {
                reuse
                    .get(&(t.addr, up.keepalive_idle))
                    .cloned()
                    .unwrap_or_else(|| Arc::new(Pool::new(t.addr, up.keepalive_idle, shards)))
            })
            .collect();
        let weights: Box<[i64]> = up.targets.iter().map(|t| i64::from(t.weight)).collect();
        let current = (0..shards)
            .map(|_| Mutex::new(vec![0; weights.len()].into()))
            .collect();
        Self {
            pools,
            weights,
            current,
            keepalive: up.keepalive_idle > 0,
        }
    }

    pub fn pools(&self) -> &[Arc<Pool>] {
        &self.pools
    }

    /// Picks the next target with nginx's smooth weighted round robin,
    /// skipping targets set in `tried`. Targets past the 64th cannot be
    /// excluded and may be picked again.
    pub fn pick(&self, tried: u64) -> Option<usize> {
        let n = self.weights.len();
        if n == 1 {
            return (tried & 1 == 0).then_some(0);
        }
        let shard = worker::id() % self.current.len();
        let mut cur = self.current[shard]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut total = 0;
        let mut best: Option<usize> = None;
        for i in 0..n {
            if i < 64 && tried >> i & 1 == 1 {
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
}

struct Idle {
    stream: TcpStream,
    since: Instant,
}

/// Idle connections to one target, one LIFO stack per worker.
pub(crate) struct Pool {
    pub addr: SocketAddr,
    max_idle: usize,
    shards: Box<[Mutex<Vec<Idle>>]>,
}

impl Pool {
    fn new(addr: SocketAddr, max_idle: u32, shards: usize) -> Self {
        let max_idle = max_idle as usize;
        Self {
            addr,
            max_idle,
            shards: (0..shards)
                .map(|_| Mutex::new(Vec::with_capacity(max_idle)))
                .collect(),
        }
    }

    fn shard(&self) -> std::sync::MutexGuard<'_, Vec<Idle>> {
        self.shards[worker::id() % self.shards.len()]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Returns the most recently used idle connection that is still open.
    pub fn take(&self) -> Option<TcpStream> {
        let mut idle = self.shard();
        while let Some(c) = idle.pop() {
            if c.since.elapsed() < IDLE_TIMEOUT && open(&c.stream) {
                return Some(c.stream);
            }
        }
        None
    }

    /// Keeps `stream` for reuse, closing the oldest idle connection when the
    /// worker already holds `max_idle` of them.
    pub fn put(&self, stream: TcpStream) {
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

    fn state(weights: &[u32]) -> State {
        let up = Upstream {
            targets: weights
                .iter()
                .enumerate()
                .map(|(i, &weight)| Target {
                    addr: SocketAddr::from(([127, 0, 0, 1], 1000 + i as u16)),
                    weight,
                })
                .collect(),
            keepalive_idle: 0,
        };
        State::new(&up, 1, &Reuse::new())
    }

    #[test]
    fn smooth_weighted_order() {
        // nginx's documented sequence for weights 5, 1, 1.
        let s = state(&[5, 1, 1]);
        let seq: Vec<_> = (0..7).map(|_| s.pick(0).unwrap()).collect();
        assert_eq!(seq, [0, 0, 1, 0, 2, 0, 0]);
    }

    #[test]
    fn skips_tried() {
        let s = state(&[1, 1, 1]);
        assert_eq!(s.pick(0b011), Some(2));
        assert_eq!(s.pick(0b111), None);
        let one = state(&[1]);
        assert_eq!(one.pick(0), Some(0));
        assert_eq!(one.pick(1), None);
    }
}
