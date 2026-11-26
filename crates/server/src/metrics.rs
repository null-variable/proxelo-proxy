//! Prometheus metrics.
//!
//! Counters live in per-snapshot tables indexed like the snapshot's sites,
//! routes and upstream targets, so recording is an atomic add without lookup
//! or allocation. Labels are resource IDs and the status class; paths and
//! addresses of clients never become labels. Series are carried over a swap
//! by ID, so counters do not reset when the configuration changes.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use proxelo_snapshot::Runtime;

use crate::Server;

/// Latency buckets in seconds, as the Prometheus client defaults.
const BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

#[derive(Default)]
pub(crate) struct Histogram {
    buckets: [AtomicU64; BUCKETS.len()],
    count: AtomicU64,
    /// Microseconds.
    sum_us: AtomicU64,
}

impl Histogram {
    fn observe(&self, d: Duration) {
        let s = d.as_secs_f64();
        if let Some(i) = BUCKETS.iter().position(|&b| s <= b) {
            self.buckets[i].fetch_add(1, Ordering::Relaxed);
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_us
            .fetch_add(d.as_micros() as u64, Ordering::Relaxed);
    }

    fn write(&self, out: &mut String, name: &str, labels: &str) {
        let mut cum = 0;
        for (i, b) in BUCKETS.iter().enumerate() {
            cum += self.buckets[i].load(Ordering::Relaxed);
            let _ = writeln!(out, "{name}_bucket{{{labels},le=\"{b}\"}} {cum}");
        }
        let count = self.count.load(Ordering::Relaxed);
        let _ = writeln!(out, "{name}_bucket{{{labels},le=\"+Inf\"}} {count}");
        let sum = self.sum_us.load(Ordering::Relaxed) as f64 / 1e6;
        let _ = writeln!(out, "{name}_sum{{{labels}}} {sum}");
        let _ = writeln!(out, "{name}_count{{{labels}}} {count}");
    }
}

/// Requests of one site or route.
#[derive(Default)]
pub(crate) struct Requests {
    /// 1xx..5xx.
    by_class: [AtomicU64; 5],
    duration: Histogram,
}

impl Requests {
    fn record(&self, status: u16, d: Duration) {
        let class = usize::from(status / 100).clamp(1, 5) - 1;
        self.by_class[class].fetch_add(1, Ordering::Relaxed);
        self.duration.observe(d);
    }
}

#[derive(Default)]
pub(crate) struct TargetStats {
    responses: [AtomicU64; 5],
    failures: AtomicU64,
    response_time: Histogram,
}

/// Counters of one snapshot.
pub(crate) struct Table {
    sites: Box<[Arc<Requests>]>,
    /// Per site, per route number.
    routes: Box<[Box<[Arc<Requests>]>]>,
    /// Per upstream, per target.
    targets: Box<[Box<[Arc<TargetStats>]>]>,
}

/// Series by key, so a new snapshot continues the old counters.
#[derive(Default)]
struct Registry {
    sites: HashMap<Box<str>, Arc<Requests>>,
    routes: HashMap<(Box<str>, Box<str>), Arc<Requests>>,
    targets: HashMap<(Box<str>, String), Arc<TargetStats>>,
}

static REGISTRY: Mutex<Option<Registry>> = Mutex::new(None);

static CONNECTIONS_ACCEPTED: AtomicU64 = AtomicU64::new(0);
static CONNECTIONS_ACTIVE: AtomicU64 = AtomicU64::new(0);
static TLS_HANDSHAKE_ERRORS: AtomicU64 = AtomicU64::new(0);
static LOG_DROPPED: AtomicU64 = AtomicU64::new(0);
static REQUESTS: AtomicU64 = AtomicU64::new(0);
static SERVER_ERRORS: AtomicU64 = AtomicU64::new(0);
static UPSTREAM_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static UPSTREAM_FAILURES: AtomicU64 = AtomicU64::new(0);
static SWAPS: AtomicU64 = AtomicU64::new(0);
static SWAP_SECONDS_US: AtomicU64 = AtomicU64::new(0);

/// Process-wide traffic counters, reported to the control plane.
#[derive(Clone, Copy, Debug, Default)]
pub struct Totals {
    pub requests: u64,
    pub server_errors: u64,
    pub upstream_attempts: u64,
    pub upstream_failures: u64,
}

/// Requests and 5xx of one site or route since start.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Count {
    pub requests: u64,
    pub server_errors: u64,
}

/// Counters per resource since start, for every resource any snapshot had.
#[derive(Clone, Debug, Default)]
pub struct PerResource {
    /// By site ID.
    pub sites: Vec<(String, Count)>,
    /// By site ID and route ID.
    pub routes: Vec<(String, String, Count)>,
    /// By upstream ID and target address: attempts, failures.
    pub targets: Vec<(String, String, u64, u64)>,
}

impl Requests {
    fn count(&self) -> Count {
        Count {
            requests: self
                .by_class
                .iter()
                .map(|c| c.load(Ordering::Relaxed))
                .sum(),
            server_errors: self.by_class[4].load(Ordering::Relaxed),
        }
    }
}

/// Reads the per-resource counters. Resources without traffic are left out.
pub fn per_resource() -> PerResource {
    let guard = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    let mut out = PerResource::default();
    let Some(reg) = guard.as_ref() else {
        return out;
    };
    for (id, r) in &reg.sites {
        let c = r.count();
        if c.requests > 0 {
            out.sites.push((id.to_string(), c));
        }
    }
    for ((site, id), r) in &reg.routes {
        let c = r.count();
        if c.requests > 0 {
            out.routes.push((site.to_string(), id.to_string(), c));
        }
    }
    for ((up, addr), t) in &reg.targets {
        let ok: u64 = t.responses.iter().map(|c| c.load(Ordering::Relaxed)).sum();
        let failures = t.failures.load(Ordering::Relaxed);
        if ok + failures > 0 {
            out.targets
                .push((up.to_string(), addr.clone(), ok + failures, failures));
        }
    }
    out
}

/// Counters since start, across snapshots.
pub fn totals() -> Totals {
    Totals {
        requests: REQUESTS.load(Ordering::Relaxed),
        server_errors: SERVER_ERRORS.load(Ordering::Relaxed),
        upstream_attempts: UPSTREAM_ATTEMPTS.load(Ordering::Relaxed),
        upstream_failures: UPSTREAM_FAILURES.load(Ordering::Relaxed),
    }
}

pub(crate) fn connection_opened() {
    CONNECTIONS_ACCEPTED.fetch_add(1, Ordering::Relaxed);
    CONNECTIONS_ACTIVE.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn connection_closed() {
    CONNECTIONS_ACTIVE.fetch_sub(1, Ordering::Relaxed);
}

pub(crate) fn tls_handshake_error() {
    TLS_HANDSHAKE_ERRORS.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn log_dropped() {
    LOG_DROPPED.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn swapped(took: Duration) {
    SWAPS.fetch_add(1, Ordering::Relaxed);
    SWAP_SECONDS_US.store(took.as_micros() as u64, Ordering::Relaxed);
}

impl Table {
    pub fn new(rt: &Runtime) -> Self {
        let mut guard = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        let reg = guard.get_or_insert_with(Registry::default);
        let sites = rt
            .sites
            .iter()
            .map(|s| reg.sites.entry(s.id.clone()).or_default().clone())
            .collect();
        let routes = rt
            .sites
            .iter()
            .map(|s| {
                s.routes
                    .iter()
                    .map(|r| {
                        reg.routes
                            .entry((s.id.clone(), r.id.clone()))
                            .or_default()
                            .clone()
                    })
                    .collect()
            })
            .collect();
        let targets = rt
            .upstreams
            .iter()
            .map(|u| {
                u.targets
                    .iter()
                    .map(|t| {
                        reg.targets
                            .entry((u.id.clone(), t.addr.to_string()))
                            .or_default()
                            .clone()
                    })
                    .collect()
            })
            .collect();
        Self {
            sites,
            routes,
            targets,
        }
    }

    /// A finished request. `route` is the route number in the site.
    pub fn request(&self, site: u32, route: Option<u32>, status: u16, d: Duration) {
        REQUESTS.fetch_add(1, Ordering::Relaxed);
        if status >= 500 {
            SERVER_ERRORS.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(s) = self.sites.get(site as usize) {
            s.record(status, d);
        }
        if let Some(r) = route.and_then(|r| self.routes.get(site as usize)?.get(r as usize)) {
            r.record(status, d);
        }
    }

    pub fn upstream_response(&self, upstream: u32, target: usize, status: u16, d: Duration) {
        UPSTREAM_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        if let Some(t) = self.target(upstream, target) {
            let class = usize::from(status / 100).clamp(1, 5) - 1;
            t.responses[class].fetch_add(1, Ordering::Relaxed);
            t.response_time.observe(d);
        }
    }

    pub fn upstream_failure(&self, upstream: u32, target: usize) {
        UPSTREAM_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        UPSTREAM_FAILURES.fetch_add(1, Ordering::Relaxed);
        if let Some(t) = self.target(upstream, target) {
            t.failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn target(&self, upstream: u32, target: usize) -> Option<&TargetStats> {
        self.targets
            .get(upstream as usize)?
            .get(target)
            .map(|t| &**t)
    }
}

/// Label value escaping per the exposition format.
fn label(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// The metrics of `server` in Prometheus text format.
pub fn render(server: &Server) -> String {
    let active = server.active();
    let rt = &active.rt;
    let mut out = String::new();
    let classes = ["1xx", "2xx", "3xx", "4xx", "5xx"];

    let _ = writeln!(out, "# TYPE proxelo_snapshot_revision gauge");
    let _ = writeln!(out, "proxelo_snapshot_revision {}", rt.revision);
    let _ = writeln!(out, "# TYPE proxelo_snapshot_swaps_total counter");
    let _ = writeln!(
        out,
        "proxelo_snapshot_swaps_total {}",
        SWAPS.load(Ordering::Relaxed)
    );
    let _ = writeln!(out, "# TYPE proxelo_snapshot_swap_seconds gauge");
    let _ = writeln!(
        out,
        "proxelo_snapshot_swap_seconds {}",
        SWAP_SECONDS_US.load(Ordering::Relaxed) as f64 / 1e6
    );
    let _ = writeln!(out, "# TYPE proxelo_connections_accepted_total counter");
    let _ = writeln!(
        out,
        "proxelo_connections_accepted_total {}",
        CONNECTIONS_ACCEPTED.load(Ordering::Relaxed)
    );
    let _ = writeln!(out, "# TYPE proxelo_connections_active gauge");
    let _ = writeln!(
        out,
        "proxelo_connections_active {}",
        CONNECTIONS_ACTIVE.load(Ordering::Relaxed)
    );
    let _ = writeln!(out, "# TYPE proxelo_tls_handshake_errors_total counter");
    let _ = writeln!(
        out,
        "proxelo_tls_handshake_errors_total {}",
        TLS_HANDSHAKE_ERRORS.load(Ordering::Relaxed)
    );
    let _ = writeln!(out, "# TYPE proxelo_access_log_dropped_total counter");
    let _ = writeln!(
        out,
        "proxelo_access_log_dropped_total {}",
        LOG_DROPPED.load(Ordering::Relaxed)
    );

    let t = &active.metrics;
    let _ = writeln!(out, "# TYPE proxelo_requests_total counter");
    for (s, site) in rt.sites.iter().enumerate() {
        for (c, class) in classes.iter().enumerate() {
            let n = t.sites[s].by_class[c].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "proxelo_requests_total{{site=\"{}\",code=\"{class}\"}} {n}",
                label(&site.id)
            );
        }
    }
    let _ = writeln!(out, "# TYPE proxelo_request_duration_seconds histogram");
    for (s, site) in rt.sites.iter().enumerate() {
        t.sites[s].duration.write(
            &mut out,
            "proxelo_request_duration_seconds",
            &format!("site=\"{}\"", label(&site.id)),
        );
    }
    let _ = writeln!(out, "# TYPE proxelo_route_requests_total counter");
    for (s, site) in rt.sites.iter().enumerate() {
        for (r, route) in site.routes.iter().enumerate() {
            for (c, class) in classes.iter().enumerate() {
                let n = t.routes[s][r].by_class[c].load(Ordering::Relaxed);
                if n > 0 {
                    let _ = writeln!(
                        out,
                        "proxelo_route_requests_total{{site=\"{}\",route=\"{}\",code=\"{class}\"}} {n}",
                        label(&site.id),
                        label(&route.id)
                    );
                }
            }
        }
    }

    let _ = writeln!(out, "# TYPE proxelo_upstream_responses_total counter");
    let _ = writeln!(out, "# TYPE proxelo_upstream_failures_total counter");
    let _ = writeln!(out, "# TYPE proxelo_upstream_target_up gauge");
    let _ = writeln!(out, "# TYPE proxelo_upstream_response_seconds histogram");
    for (u, up) in rt.upstreams.iter().enumerate() {
        for (i, target) in up.targets.iter().enumerate() {
            let labels = format!("upstream=\"{}\",target=\"{}\"", label(&up.id), target.addr);
            let st = &t.targets[u][i];
            for (c, class) in classes.iter().enumerate() {
                let n = st.responses[c].load(Ordering::Relaxed);
                if n > 0 {
                    let _ = writeln!(
                        out,
                        "proxelo_upstream_responses_total{{{labels},code=\"{class}\"}} {n}"
                    );
                }
            }
            let _ = writeln!(
                out,
                "proxelo_upstream_failures_total{{{labels}}} {}",
                st.failures.load(Ordering::Relaxed)
            );
            let up_now = !active.upstreams[u].down(i);
            let _ = writeln!(
                out,
                "proxelo_upstream_target_up{{{labels}}} {}",
                u8::from(up_now)
            );
            st.response_time
                .write(&mut out, "proxelo_upstream_response_seconds", &labels);
        }
    }
    out
}
