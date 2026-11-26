//! nginx limit_req and limit_conn. Zone state is shared by every worker, as
//! nginx keeps it in shared memory, and carried over snapshot swaps by zone
//! ID.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use foldhash::fast::FixedState;
use proxelo_snapshot::{ConnZone, RateZone, Runtime};

use crate::exchange::Exchange;
use crate::vars::expand;

const NIL: u32 = u32::MAX;

/// Milliseconds on a monotonic clock that starts far from zero, so a node
/// stamped 0 reads as idle for a long time, like nginx's `last = 0`.
fn now_ms() -> i64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    let base = *BASE.get_or_init(Instant::now);
    base.elapsed().as_millis() as i64 + 1_000_000_000
}

struct Node {
    key: Box<[u8]>,
    /// Thousandths of a request over the rate.
    excess: i64,
    last: i64,
    /// Requests holding this node between lookup and accounting.
    count: u32,
    prev: u32,
    next: u32,
}

/// Keys in least recently used order, as nginx's zone queue.
#[derive(Default)]
struct Lru {
    index: HashMap<Box<[u8]>, u32, FixedState>,
    nodes: Vec<Node>,
    free: Vec<u32>,
    /// Most recently used.
    head: u32,
    tail: u32,
}

impl Lru {
    fn new() -> Self {
        Self {
            head: NIL,
            tail: NIL,
            ..Default::default()
        }
    }

    fn len(&self) -> usize {
        self.index.len()
    }

    fn unlink(&mut self, i: u32) {
        let (prev, next) = (self.nodes[i as usize].prev, self.nodes[i as usize].next);
        match prev {
            NIL => self.head = next,
            p => self.nodes[p as usize].next = next,
        }
        match next {
            NIL => self.tail = prev,
            n => self.nodes[n as usize].prev = prev,
        }
    }

    fn push_front(&mut self, i: u32) {
        self.nodes[i as usize].prev = NIL;
        self.nodes[i as usize].next = self.head;
        match self.head {
            NIL => self.tail = i,
            h => self.nodes[h as usize].prev = i,
        }
        self.head = i;
    }

    /// Finds `key` and marks it used.
    fn get(&mut self, key: &[u8]) -> Option<u32> {
        let i = *self.index.get(key)?;
        self.unlink(i);
        self.push_front(i);
        Some(i)
    }

    fn insert(&mut self, key: &[u8]) -> u32 {
        let node = Node {
            key: key.into(),
            excess: 0,
            last: 0,
            count: 0,
            prev: NIL,
            next: NIL,
        };
        let i = match self.free.pop() {
            Some(i) => {
                self.nodes[i as usize] = node;
                i
            }
            None => {
                self.nodes.push(node);
                (self.nodes.len() - 1) as u32
            }
        };
        self.index.insert(key.into(), i);
        self.push_front(i);
        i
    }

    fn remove(&mut self, i: u32) {
        self.unlink(i);
        let key = std::mem::take(&mut self.nodes[i as usize].key);
        self.index.remove(&key);
        self.free.push(i);
    }

    /// nginx ngx_http_limit_req_expire: with `n` 0 the oldest key goes
    /// unless a request holds it, then up to two more (one or two with `n`
    /// 1) that were idle for a minute and drained.
    fn expire(&mut self, rate: i64, now: i64, mut n: u32) {
        while n < 3 {
            let t = self.tail;
            if t == NIL {
                return;
            }
            let node = &self.nodes[t as usize];
            if node.count != 0 {
                return;
            }
            if n != 0 {
                let ms = (now - node.last).abs();
                if ms < 60_000 || node.excess - rate * ms / 1000 > 0 {
                    return;
                }
            }
            n += 1;
            self.remove(t);
        }
    }
}

fn elapsed(now: i64, last: i64) -> i64 {
    match now - last {
        ms if ms < -60_000 => 1,
        ms if ms < 0 => 0,
        ms => ms,
    }
}

pub(crate) struct RateState(Mutex<Lru>);

pub(crate) struct ConnState(Mutex<HashMap<Box<[u8]>, u32, FixedState>>);

/// The state of every zone of a snapshot, indexed like its zones.
pub(crate) struct Zones {
    rate: Box<[Arc<RateState>]>,
    conn: Box<[Arc<ConnState>]>,
}

impl Zones {
    /// Builds the state for `rt`, keeping that of zones `old` has by ID.
    pub fn new(rt: &Runtime, old: Option<(&Runtime, &Zones)>) -> Self {
        let rate = rt
            .rate_zones
            .iter()
            .map(|z| {
                old.and_then(|(ort, oz)| {
                    let i = ort.rate_zones.iter().position(|o| o.id == z.id)?;
                    Some(oz.rate[i].clone())
                })
                .unwrap_or_else(|| Arc::new(RateState(Mutex::new(Lru::new()))))
            })
            .collect();
        let conn = rt
            .conn_zones
            .iter()
            .map(|z| {
                old.and_then(|(ort, oz)| {
                    let i = ort.conn_zones.iter().position(|o| o.id == z.id)?;
                    Some(oz.conn[i].clone())
                })
                .unwrap_or_else(|| Arc::new(ConnState(Mutex::new(HashMap::default()))))
            })
            .collect();
        Self { rate, conn }
    }
}

/// What the rate limits decided.
pub(crate) enum Limited {
    Pass,
    Delay(Duration),
    Reject(u16),
}

enum Lookup {
    Busy,
    Ok(i64),
    /// Held until accounting.
    Again(u32),
}

fn lookup(state: &RateState, z: &RateZone, key: &[u8], now: i64, account: bool) -> Lookup {
    let rate = z.rate as i64;
    let mut l = state.0.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(i) = l.get(key) {
        let n = &mut l.nodes[i as usize];
        let ms = elapsed(now, n.last);
        let excess = (n.excess - rate * ms / 1000 + 1000).max(0);
        if excess > z.burst as i64 {
            return Lookup::Busy;
        }
        if account {
            n.excess = excess;
            if ms != 0 {
                n.last = now;
            }
            return Lookup::Ok(excess);
        }
        n.count += 1;
        return Lookup::Again(i);
    }
    l.expire(rate, now, 1);
    if l.len() >= z.max_keys {
        l.expire(rate, now, 0);
        if l.len() >= z.max_keys {
            return Lookup::Busy;
        }
    }
    let i = l.insert(key);
    let n = &mut l.nodes[i as usize];
    if account {
        n.last = now;
        Lookup::Ok(0)
    } else {
        n.count = 1;
        Lookup::Again(i)
    }
}

/// Releases the nodes held by earlier limits after a rejection.
fn unlock(zones: &Zones, held: &[(u32, u32)]) {
    for &(z, i) in held {
        let mut l = zones.rate[z as usize]
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        l.nodes[i as usize].count -= 1;
    }
}

/// Delay for `excess` over the zone's delay threshold.
fn delay_ms(z: &RateZone, excess: i64) -> i64 {
    let over = excess - z.delay as i64;
    if over <= 0 {
        0
    } else {
        over * 1000 / z.rate as i64
    }
}

/// nginx limit_req over `limits` (indexes into the runtime's rate zones),
/// in order. Requests whose key is empty are not counted by that limit.
pub(crate) fn rate(x: &mut Exchange, rt: &Runtime, zones: &Zones, limits: &[u32]) -> Limited {
    let now = now_ms();
    let mut held = std::mem::take(&mut x.rate_held);
    held.clear();
    let mut decided: Option<(u32, Lookup)> = None;
    for (n, &zi) in limits.iter().enumerate() {
        let z = &rt.rate_zones[zi as usize];
        expand(x, &z.key);
        if x.tmpl.is_empty() || x.tmpl.len() > 65535 {
            continue;
        }
        match lookup(
            &zones.rate[zi as usize],
            z,
            &x.tmpl,
            now,
            n == limits.len() - 1,
        ) {
            Lookup::Again(i) => held.push((zi, i)),
            other => {
                decided = Some((zi, other));
                break;
            }
        }
    }
    let result = match decided {
        None if held.is_empty() => Limited::Pass,
        Some((zi, Lookup::Busy)) => {
            unlock(zones, &held);
            let z = &rt.rate_zones[zi as usize];
            if z.dry_run {
                Limited::Pass
            } else {
                Limited::Reject(z.status)
            }
        }
        decided => {
            // nginx ngx_http_limit_req_account: the longest delay of any
            // limit, the decided one's from its excess, the held ones' from
            // their state now.
            let (mut max, mut dry) = match decided {
                Some((zi, Lookup::Ok(excess))) => {
                    let z = &rt.rate_zones[zi as usize];
                    (delay_ms(z, excess), z.dry_run)
                }
                _ => (0, false),
            };
            for &(zi, i) in &held {
                let z = &rt.rate_zones[zi as usize];
                let mut l = zones.rate[zi as usize]
                    .0
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let node = &mut l.nodes[i as usize];
                let ms = elapsed(now, node.last);
                let excess = (node.excess - z.rate as i64 * ms / 1000 + 1000).max(0);
                if ms != 0 {
                    node.last = now;
                }
                node.excess = excess;
                node.count -= 1;
                let d = delay_ms(z, excess);
                if d > max {
                    max = d;
                    dry = z.dry_run;
                }
            }
            if max == 0 || dry {
                Limited::Pass
            } else {
                Limited::Delay(Duration::from_millis(max as u64))
            }
        }
    };
    x.rate_held = held;
    result
}

/// A request counted by a connection zone until it ends.
pub(crate) struct Hold {
    zone: Arc<ConnState>,
    key: Box<[u8]>,
}

impl Drop for Hold {
    fn drop(&mut self) {
        let mut m = self.zone.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = m.get_mut(&self.key) {
            *c -= 1;
            if *c == 0 {
                m.remove(&self.key);
            }
        }
    }
}

/// nginx limit_conn over `limits`. Counted requests are added to `holds`,
/// which the caller drops when the request ends. `Err` is the status to
/// answer.
pub(crate) fn conn(
    x: &mut Exchange,
    rt: &Runtime,
    zones: &Zones,
    limits: &[u32],
    holds: &mut Vec<Hold>,
) -> Result<(), u16> {
    for &zi in limits {
        let z: &ConnZone = &rt.conn_zones[zi as usize];
        expand(x, &z.key);
        if x.tmpl.is_empty() || x.tmpl.len() > 255 {
            continue;
        }
        let state = &zones.conn[zi as usize];
        let mut m = state.0.lock().unwrap_or_else(|e| e.into_inner());
        let over = match m.get(&x.tmpl[..]) {
            Some(&c) => c >= z.max,
            None => m.len() >= z.max_keys,
        };
        if over {
            if z.dry_run {
                continue;
            }
            return Err(z.status);
        }
        *m.entry(x.tmpl[..].into()).or_insert(0) += 1;
        drop(m);
        holds.push(Hold {
            zone: state.clone(),
            key: x.tmpl[..].into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(rate_per_s: u64, burst: u32, delay: u32) -> RateZone {
        RateZone {
            id: "z".into(),
            key: proxelo_snapshot::Template::parse("k").unwrap(),
            rate: rate_per_s * 1000,
            burst: u64::from(burst) * 1000,
            delay: u64::from(delay) * 1000,
            status: 503,
            dry_run: false,
            max_keys: 2,
        }
    }

    #[test]
    fn leaky_bucket() {
        let z = zone(1, 2, 0);
        let s = RateState(Mutex::new(Lru::new()));
        let t = 2_000_000_000;
        assert!(matches!(lookup(&s, &z, b"a", t, true), Lookup::Ok(0)));
        // Two more fit in the burst, a third does not.
        assert!(matches!(lookup(&s, &z, b"a", t, true), Lookup::Ok(1000)));
        assert!(matches!(lookup(&s, &z, b"a", t, true), Lookup::Ok(2000)));
        assert!(matches!(lookup(&s, &z, b"a", t, true), Lookup::Busy));
        // A second drains one request.
        assert!(matches!(
            lookup(&s, &z, b"a", t + 1000, true),
            Lookup::Ok(2000)
        ));
        assert_eq!(delay_ms(&z, 2000), 2000);
        assert_eq!(delay_ms(&zone(1, 2, 1), 2000), 1000);
    }

    #[test]
    fn full_zone_drops_the_oldest_idle_key() {
        let z = zone(1, 0, 0);
        let s = RateState(Mutex::new(Lru::new()));
        let t = 2_000_000_000;
        assert!(matches!(lookup(&s, &z, b"a", t, true), Lookup::Ok(0)));
        assert!(matches!(lookup(&s, &z, b"b", t, true), Lookup::Ok(0)));
        // "a" is forced out to make room for "c".
        assert!(matches!(lookup(&s, &z, b"c", t, true), Lookup::Ok(0)));
        assert!(matches!(lookup(&s, &z, b"a", t, true), Lookup::Ok(0)));
        assert_eq!(s.0.lock().unwrap().len(), 2);
        // A held key is not dropped.
        let s = RateState(Mutex::new(Lru::new()));
        assert!(matches!(lookup(&s, &z, b"a", t, false), Lookup::Again(_)));
        assert!(matches!(lookup(&s, &z, b"b", t, false), Lookup::Again(_)));
        assert!(matches!(lookup(&s, &z, b"c", t, true), Lookup::Busy));
    }
}
