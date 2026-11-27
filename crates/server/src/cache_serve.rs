//! Response caching, as nginx proxy_cache: serving routes from the store
//! and filling it from upstream responses.

use std::sync::Arc;

use proxelo_http1::{HeaderKind, Method, push_u64};
use proxelo_snapshot::{Cache, Facts, HeaderOps, Proxy, Route};

use crate::Active;
use crate::cache::{Hash, Locked, Pending, Zone, now, storable};
use crate::conn::{Conn, KeepAlive, SEND_TIMEOUT};
use crate::exchange::Sent;
use crate::io::write_timeout;
use crate::range::{self, Answer, Span};
use crate::reply;

/// What became of a cached route's upstream response.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Took {
    /// Relayed to the client, and stored when it could be.
    Relayed,
    /// Not relayed: the stale entry answers instead.
    Stale,
    /// The upstream confirmed the stale entry with 304.
    Revalidated,
}

/// The cache side of a request that goes upstream.
pub(crate) struct Fill {
    zone: Arc<Zone>,
    key: Box<[u8]>,
    /// The response may be stored.
    store: bool,
    /// The expired entry being refreshed.
    stale: Option<Hash>,
    pending: Option<Pending>,
    /// The client gets nothing of the response (background update).
    pub silent: bool,
    /// The client asked HEAD; the body is fetched only to store it.
    pub head_only: bool,
    took: Took,
}

impl Fill {
    /// Copies body bytes into the entry being stored.
    pub(crate) fn tee(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        if let Some(p) = &mut self.pending {
            p.write(data);
        }
    }
}

/// Request headers left out upstream while filling: the cache asks for
/// whole, unconditional responses, or its own conditional one.
pub(crate) fn dropped_on_fill(name: &[u8]) -> bool {
    [
        &b"range"[..],
        b"if-range",
        b"if-none-match",
        b"if-modified-since",
        b"if-match",
        b"if-unmodified-since",
    ]
    .iter()
    .any(|n| name.eq_ignore_ascii_case(n))
}

/// Response headers not stored: per-connection ones and those the proxy
/// sets itself.
fn stored_header(kind: HeaderKind, name: &[u8]) -> bool {
    !(kind.is_hop_by_hop()
        || matches!(
            kind,
            HeaderKind::Date
                | HeaderKind::Server
                | HeaderKind::Internal
                | HeaderKind::ContentLength
                | HeaderKind::TransferEncoding
        )
        || name.eq_ignore_ascii_case(b"set-cookie"))
}

impl Conn {
    /// Proxies a route with a cache: answers from the store when it can,
    /// otherwise goes upstream and stores the response.
    pub(crate) async fn proxy_cached(
        &mut self,
        active: &Active,
        p: &Proxy,
        route: &Route,
        c: &Cache,
    ) -> Result<KeepAlive, u16> {
        let zone = active.caches[c.zone as usize].clone();
        let up = &active.rt.upstreams[p.upstream as usize];
        self.x.proxy_host.clear();
        match up.targets.first() {
            _ if !up.host.is_empty() => self.x.proxy_host.extend_from_slice(up.host.as_bytes()),
            Some(t) => self.x.proxy_host.extend_from_slice(t.name.as_bytes()),
            None => {}
        }
        crate::vars::expand(&mut self.x, &c.key);
        let key: Box<[u8]> = self.x.tmpl.as_slice().into();
        if key.is_empty() || key.contains(&b'\n') || !c.caches_method(self.x.method()) {
            return self.proxy(active, p, route).await;
        }
        let main = Zone::key_hash(&key);
        if c.bypass(&self.x) {
            self.x.cache_status = b"BYPASS";
            let store = !c.no_store(&self.x);
            return self
                .fetch(active, p, route, c, &zone, key, None, store, false)
                .await;
        }
        let mut waited = false;
        loop {
            let (hash, found) = zone.lookup(&key, &self.x);
            let now = now();
            if let Some(f) = found
                && f.fresh(now)
            {
                self.x.cache_status = b"HIT";
                match self.serve_entry(&zone, hash, &route.response_headers).await {
                    Some(keep) => return Ok(keep),
                    // Gone from disk: drop it and look again.
                    None => {
                        zone.remove(hash);
                        continue;
                    }
                }
            }
            let stale = found.map(|f| (hash, f));
            let mut guard = None;
            if c.lock || stale.is_some() {
                guard = zone.try_lock(main);
                if guard.is_none() {
                    // Another request is fetching this key.
                    if let Some((h, f)) = stale
                        && (c.stale.updating || f.within_swr(now))
                    {
                        self.x.cache_status = b"UPDATING";
                        if let Some(keep) =
                            self.serve_entry(&zone, h, &route.response_headers).await
                        {
                            return Ok(keep);
                        }
                    }
                    if c.lock && !waited {
                        match zone.lock(main, c.lock_timeout).await {
                            Locked::Held(g) => guard = Some(g),
                            Locked::Released => {
                                waited = true;
                                continue;
                            }
                            Locked::TimedOut => {
                                // nginx passes it upstream without storing.
                                self.x.cache_status = b"MISS";
                                return self
                                    .fetch(active, p, route, c, &zone, key, None, false, false)
                                    .await;
                            }
                        }
                    }
                }
            }
            let store = !c.no_store(&self.x) && zone.used(main, c.min_uses);
            // proxy_cache_background_update: the stale entry answers now and
            // the refresh runs afterwards, on this connection.
            if let Some((h, f)) = stale
                && guard.is_some()
                && c.background_update
                && (c.stale.updating || f.within_swr(now))
            {
                self.x.cache_status = b"UPDATING";
                if let Some(keep) = self.serve_entry(&zone, h, &route.response_headers).await {
                    let sent = self.x.sent.clone();
                    let _ = self
                        .fetch(active, p, route, c, &zone, key, Some(h), store, true)
                        .await;
                    // The log describes what the client got.
                    let u = std::mem::take(&mut self.x.sent);
                    self.x.sent = Sent {
                        upstream_addr: u.upstream_addr,
                        upstream_status: u.upstream_status,
                        upstream_connect: u.upstream_connect,
                        upstream_header: u.upstream_header,
                        upstream_response: u.upstream_response,
                        ..sent
                    };
                    self.x.cache_status = b"UPDATING";
                    return Ok(keep);
                }
            }
            self.x.cache_status = if stale.is_some() { b"EXPIRED" } else { b"MISS" };
            let stale = stale.map(|(h, _)| h);
            let r = self
                .fetch(active, p, route, c, &zone, key, stale, store, false)
                .await;
            drop(guard);
            return r;
        }
    }

    /// Goes upstream for a cached route; see [`Fill`].
    #[allow(clippy::too_many_arguments)]
    async fn fetch(
        &mut self,
        active: &Active,
        p: &Proxy,
        route: &Route,
        c: &Cache,
        zone: &Arc<Zone>,
        key: Box<[u8]>,
        stale: Option<Hash>,
        store: bool,
        silent: bool,
    ) -> Result<KeepAlive, u16> {
        self.x.cache_cond.clear();
        if c.revalidate
            && let Some(h) = stale
            && let Ok((_, e)) = zone.open(h)
        {
            for (have, send) in [
                (&b"etag"[..], &b"If-None-Match: "[..]),
                (b"last-modified", b"If-Modified-Since: "),
            ] {
                if let Some(v) = e.header(have) {
                    self.x.cache_cond.extend_from_slice(send);
                    self.x.cache_cond.extend_from_slice(v);
                    self.x.cache_cond.extend_from_slice(b"\r\n");
                }
            }
        }
        // proxy_cache_convert_head: a HEAD goes upstream as GET so the whole
        // response can be stored.
        let head_only = self.x.req.method == Method::Head && !c.keep_head;
        self.x.as_get_upstream = head_only;
        self.fill = Some(Box::new(Fill {
            zone: zone.clone(),
            key,
            store,
            stale,
            pending: None,
            silent,
            head_only,
            took: Took::Relayed,
        }));
        let r = self.proxy(active, p, route).await;
        let fill = *self.fill.take().expect("set above");
        self.x.cache_cond.clear();
        self.x.as_get_upstream = false;
        if let Some(pending) = fill.pending {
            zone.commit(pending, self.fill_done);
        }
        self.fill_done = false;
        if silent {
            return r;
        }
        match fill.took {
            Took::Stale | Took::Revalidated => {
                let h = fill.stale.expect("only with a stale entry");
                self.x.cache_status = if fill.took == Took::Stale {
                    b"STALE"
                } else {
                    b"REVALIDATED"
                };
                self.serve_entry(zone, h, &route.response_headers)
                    .await
                    .ok_or(502)
            }
            Took::Relayed => match r {
                Err(st) => {
                    // proxy_cache_use_stale error/timeout, stale-if-error.
                    let now = now();
                    let usable = fill.stale.filter(|&h| {
                        zone.fresh_of(h).is_some_and(|f| {
                            (st == 502 && c.stale.error)
                                || (st == 504 && c.stale.timeout)
                                || f.within_sie(now)
                        })
                    });
                    match usable {
                        Some(h) => {
                            self.x.cache_status = b"STALE";
                            self.serve_entry(zone, h, &route.response_headers)
                                .await
                                .ok_or(st)
                        }
                        None => Err(st),
                    }
                }
                ok => ok,
            },
        }
    }

    /// Called with the upstream response head in `resp` before it is
    /// relayed. Returns false when it is not relayed: a stale or
    /// revalidated entry answers instead, and the upstream connection is not
    /// reused.
    pub(crate) fn cache_head(&mut self, c: &Cache) -> bool {
        let Some(mut fill) = self.fill.take() else {
            return true;
        };
        let relay = self.decide_fill(&mut fill, c);
        self.fill = Some(fill);
        relay
    }

    fn decide_fill(&self, fill: &mut Fill, c: &Cache) -> bool {
        let status = self.resp.status;
        let now = now();
        let headers = self.resp_headers();
        if let Some(h) = fill.stale {
            if status == 304 && !self.x.cache_cond.is_empty() {
                // The 304's freshness, or the route's for a 200.
                if let Some(s) = storable(c, 200, &headers, now) {
                    fill.zone.refresh(h, s.fresh);
                }
                fill.took = Took::Revalidated;
                return false;
            }
            if c.stale.on_status(status) {
                fill.took = Took::Stale;
                return false;
            }
        }
        if !fill.store {
            return true;
        }
        let Some(s) = storable(c, status, &headers, now) else {
            return true;
        };
        let data = &self.ubuf.data;
        let mut head = Vec::with_capacity(512);
        for h in self.resp.headers.iter() {
            let name = h.name.get(data);
            if stored_header(h.kind, name) {
                head.extend_from_slice(name);
                head.extend_from_slice(b": ");
                head.extend_from_slice(h.value.get(data));
                head.extend_from_slice(b"\r\n");
            }
        }
        match fill.zone.begin(&fill.key, &self.x, s, status, &head) {
            Ok(p) => fill.pending = Some(p),
            Err(e) => eprintln!("cache {}: {e}", fill.zone.id),
        }
        true
    }

    /// Answers from a stored entry, with Range and conditional requests as
    /// nginx does for cached responses. `None` when the entry cannot be
    /// read; nothing was sent then.
    pub(crate) async fn serve_entry(
        &mut self,
        zone: &Zone,
        h: Hash,
        ops: &HeaderOps,
    ) -> Option<KeepAlive> {
        use std::io::{Seek, SeekFrom};
        let (mut file, e) = zone.open(h).ok()?;
        let len = e.body_len;
        let status = self.x.status(e.status);
        let etag = e.header(b"etag");
        let modified = e.header(b"last-modified");
        let not_modified = status == 200
            && match self.x.request_header(b"if-none-match") {
                Some(v) => v == b"*" || etag.is_some_and(|t| t == v),
                None => {
                    modified.is_some_and(|m| self.x.request_header(b"if-modified-since") == Some(m))
                }
            };
        let ranges = match self.x.request_header(b"range") {
            Some(v) if status == 200 && !not_modified && self.cached_if_range(etag, modified) => {
                range::parse(v, len)
            }
            _ => range::Ranges::WHOLE,
        };
        let status = match (ranges.answer, not_modified) {
            (_, true) => 304,
            (Answer::Unsatisfiable, _) => 416,
            (Answer::Partial, _) if ranges.parts().len() == 1 => 206,
            _ => status,
        };
        let parts: &[Span] = if status == 206 { ranges.parts() } else { &[] };
        let keep = self.x.req.keep_alive;
        self.extra(ops, status);
        let ops_extra = std::mem::take(&mut self.x.resp_extra);
        let out = &mut self.out;
        out.clear();
        reply::start(out, status, b"");
        for line in e.head.split_inclusive(|&c| c == b'\n') {
            let name = line.split(|&c| c == b':').next().unwrap_or_default();
            if !ops.is_empty() && ops.drops(name) {
                continue;
            }
            if status == 304 {
                // RFC 9110 §15.4.5: only validators and caching headers.
                let keep_line = [
                    &b"etag:"[..],
                    b"cache-control:",
                    b"expires:",
                    b"vary:",
                    b"content-location:",
                ]
                .iter()
                .any(|p| line.len() >= p.len() && line[..p.len()].eq_ignore_ascii_case(p));
                if !keep_line {
                    continue;
                }
            }
            out.extend_from_slice(line);
        }
        let body = match parts {
            [one] => one.end - one.start,
            _ if status == 304 || status == 416 => 0,
            _ => len,
        };
        if status == 416 {
            out.extend_from_slice(b"Content-Range: bytes */");
            push_u64(out, len);
            out.extend_from_slice(b"\r\n");
        }
        if status != 304 {
            out.extend_from_slice(b"Content-Length: ");
            push_u64(out, body);
            out.extend_from_slice(b"\r\n");
        }
        if let [one] = parts {
            out.extend_from_slice(b"Content-Range: bytes ");
            range::push_span(out, *one, len);
            out.extend_from_slice(b"\r\n");
        } else if status == 200 && e.header(b"accept-ranges").is_none() {
            out.extend_from_slice(b"Accept-Ranges: bytes\r\n");
        }
        reply::connection(out, keep, &ops_extra);
        out.extend_from_slice(b"\r\n");
        self.x.resp_extra = ops_extra;
        self.x.sent.status = status;
        self.x.sent.bytes = self.out.len() as u64;
        if self.x.req.method == Method::Head || body == 0 {
            return Some(self.respond(keep).await);
        }
        if keep && self.pump_body(crate::conn::Sink::Drop).await.is_err() {
            return Some(false);
        }
        self.x.sent.bytes += body;
        self.x.sent.body_bytes = body;
        let span = match parts {
            [one] => *one,
            _ => Span { start: 0, end: len },
        };
        let span = Span {
            start: e.body_offset + span.start,
            end: e.body_offset + span.end,
        };
        if file.seek(SeekFrom::Start(0)).is_err() || !self.send_span(&mut file, span).await {
            return Some(false);
        }
        if !self.out.is_empty() {
            return Some(
                write_timeout(&mut self.client, &self.out, SEND_TIMEOUT)
                    .await
                    .is_ok()
                    && keep,
            );
        }
        Some(keep)
    }

    /// The upstream response headers as name and value pairs.
    fn resp_headers(&self) -> Vec<(&[u8], &[u8])> {
        let data = &self.ubuf.data;
        self.resp
            .headers
            .iter()
            .map(|h| (h.name.get(data), h.value.get(data)))
            .collect()
    }

    /// nginx If-Range against a cached response's validators.
    fn cached_if_range(&self, etag: Option<&[u8]>, modified: Option<&[u8]>) -> bool {
        match self.x.request_header(b"if-range") {
            None => true,
            Some(v) if v.ends_with(b"\"") => etag == Some(v),
            Some(v) => modified == Some(v),
        }
    }
}
