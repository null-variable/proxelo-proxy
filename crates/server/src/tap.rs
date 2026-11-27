//! Live Tap: finished requests that match the control plane's filter are
//! collected and sent in batches. With no filter the check is one atomic
//! load per request; matching and copying only happen while tapping.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use proxelo_api::distrib::v1::{TapEvent, TapEvents, TapFilter, TapHeader};
use proxelo_snapshot::Cidr;

use crate::exchange::Exchange;

/// Events held between batches; more are counted as dropped.
const MAX_PENDING: usize = 1024;

struct Filter {
    id: String,
    sites: Box<[Box<str>]>,
    routes: Box<[Box<str>]>,
    cidrs: Box<[Cidr]>,
    sample: u64,
    max_per_second: u64,
    headers: Box<[Box<str>]>,
}

#[derive(Default)]
struct Pending {
    events: Vec<TapEvent>,
    dropped: u64,
    /// The second `sent` counts events in, for max_per_second.
    window: Option<Instant>,
    sent: u64,
}

struct Tap {
    on: AtomicBool,
    filter: ArcSwapOption<Filter>,
    seen: AtomicU64,
    pending: Mutex<Pending>,
}

static TAP: LazyLock<Tap> = LazyLock::new(|| Tap {
    on: AtomicBool::new(false),
    filter: ArcSwapOption::empty(),
    seen: AtomicU64::new(0),
    pending: Mutex::new(Pending::default()),
});

/// Replaces the filter; one without an ID stops tapping. Pending events of
/// the previous filter are dropped.
pub fn set_filter(f: TapFilter) {
    let tap = &*TAP;
    if f.id.is_empty() {
        tap.on.store(false, Ordering::Relaxed);
        tap.filter.store(None);
    } else {
        let cidrs = f.cidrs.iter().filter_map(|c| Cidr::parse(c).ok()).collect();
        tap.filter.store(Some(Arc::new(Filter {
            id: f.id,
            sites: f.site_ids.into_iter().map(Into::into).collect(),
            routes: f.route_ids.into_iter().map(Into::into).collect(),
            cidrs,
            sample: u64::from(f.sample.max(1)),
            max_per_second: if f.max_per_second == 0 {
                100
            } else {
                u64::from(f.max_per_second)
            },
            headers: f
                .headers
                .into_iter()
                .map(|h| h.to_ascii_lowercase().into())
                .collect(),
        })));
        tap.on.store(true, Ordering::Relaxed);
    }
    tap.seen.store(0, Ordering::Relaxed);
    *tap.pending.lock().unwrap_or_else(|e| e.into_inner()) = Pending::default();
}

/// Takes the events collected since the last call, `None` when there are
/// none and nothing was dropped.
pub fn take() -> Option<TapEvents> {
    let tap = &*TAP;
    let f = tap.filter.load_full()?;
    let mut p = tap.pending.lock().unwrap_or_else(|e| e.into_inner());
    if p.events.is_empty() && p.dropped == 0 {
        return None;
    }
    Some(TapEvents {
        tap_id: f.id.clone(),
        events: std::mem::take(&mut p.events),
        dropped: std::mem::take(&mut p.dropped),
    })
}

/// Records a finished request when it matches.
pub(crate) fn record(x: &Exchange, site: &str, route: Option<&str>) {
    let tap = &*TAP;
    if !tap.on.load(Ordering::Relaxed) {
        return;
    }
    let Some(f) = tap.filter.load_full() else {
        return;
    };
    if !f.sites.is_empty() && !f.sites.iter().any(|s| &**s == site) {
        return;
    }
    if !f.routes.is_empty() && !route.is_some_and(|r| f.routes.iter().any(|s| &**s == r)) {
        return;
    }
    if !f.cidrs.is_empty() && !f.cidrs.iter().any(|c| c.contains(x.peer.ip())) {
        return;
    }
    if !tap
        .seen
        .fetch_add(1, Ordering::Relaxed)
        .is_multiple_of(f.sample)
    {
        return;
    }
    let now = Instant::now();
    let mut p = tap.pending.lock().unwrap_or_else(|e| e.into_inner());
    if p.window
        .is_none_or(|w| now.duration_since(w).as_secs() >= 1)
    {
        p.window = Some(now);
        p.sent = 0;
    }
    if p.sent >= f.max_per_second || p.events.len() >= MAX_PENDING {
        p.dropped += 1;
        return;
    }
    p.sent += 1;
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let headers = f
        .headers
        .iter()
        .filter_map(|n| {
            x.request_header(n.as_bytes()).map(|v| TapHeader {
                name: n.to_string(),
                value: text(v),
            })
        })
        .collect();
    let time_us = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_micros()).unwrap_or(i64::MAX));
    p.events.push(TapEvent {
        time_us,
        site_id: site.to_owned(),
        route_id: route.unwrap_or_default().to_owned(),
        client: x.peer.ip().to_string(),
        method: text(proxelo_snapshot::Facts::method(x)),
        host: text(&x.host),
        uri: text(x.req.target.get(&x.head)),
        status: u32::from(x.sent.status),
        duration_us: u64::try_from(x.started.elapsed().as_micros()).unwrap_or(u64::MAX),
        upstream: x
            .sent
            .upstream_addr
            .map(|a| a.to_string())
            .unwrap_or_default(),
        upstream_status: u32::from(x.sent.upstream_status),
        bytes_sent: x.sent.bytes,
        headers,
        protocol: if x.h3 {
            "3"
        } else if x.h2 {
            "2"
        } else {
            "1.1"
        }
        .to_owned(),
        waf_rules: x.waf_rules.clone(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_and_limits() {
        let peer = "10.0.0.5:1234".parse().unwrap();
        let mut x = Exchange::new("127.0.0.1:80".parse().unwrap(), peer);
        x.sent.status = 200;
        set_filter(TapFilter {
            id: "t".into(),
            site_ids: vec!["site_a".into()],
            cidrs: vec!["10.0.0.0/8".into()],
            max_per_second: 2,
            ..Default::default()
        });
        record(&x, "site_b", None);
        for _ in 0..3 {
            record(&x, "site_a", Some("rt_1"));
        }
        let got = take().unwrap();
        assert_eq!((got.events.len(), got.dropped), (2, 1));
        assert_eq!(got.events[0].route_id, "rt_1");
        assert!(take().is_none());
        set_filter(TapFilter::default());
        record(&x, "site_a", None);
        assert!(take().is_none());
    }
}
