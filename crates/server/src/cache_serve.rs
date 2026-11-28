//! Response caching, as nginx proxy_cache: serving routes from the store
//! and filling it from upstream responses.

use std::sync::Arc;

use proxelo_http1::{HeaderKind, Method, push_u64};
use proxelo_snapshot::{Cache, Facts, Proxy, Route};

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
/// sets itself, unless the route passes them on (nginx proxy_pass_header).
fn stored_header(kind: HeaderKind, name: &[u8], route: &Route) -> bool {
    let passed = matches!(
        kind,
        HeaderKind::Date | HeaderKind::Server | HeaderKind::Internal
    ) && route.edits.as_deref().is_some_and(|e| e.passes(name));
    passed
        || !(kind.is_hop_by_hop()
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
        let sliced = c.slice != 0
            && (self.x.req.method == Method::Get
                || (self.x.req.method == Method::Head && !c.keep_head));
        if sliced && !c.bypass(&self.x) {
            return self.proxy_sliced(active, p, route, c, &zone).await;
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
                match self.serve_entry(&zone, hash, route).await {
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
                        if let Some(keep) = self.serve_entry(&zone, h, route).await {
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
                if let Some(keep) = self.serve_entry(&zone, h, route).await {
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
        if silent {
            // The upstream request head; nothing of it is the client's.
            self.out.clear();
        }
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
                self.serve_entry(zone, h, route).await.ok_or(502)
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
                            self.serve_entry(zone, h, route).await.ok_or(st)
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
    pub(crate) fn cache_head(&mut self, c: &Cache, route: &Route) -> bool {
        let Some(mut fill) = self.fill.take() else {
            return true;
        };
        let relay = self.decide_fill(&mut fill, c, route);
        self.fill = Some(fill);
        relay
    }

    fn decide_fill(&self, fill: &mut Fill, c: &Cache, route: &Route) -> bool {
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
        // A slice is a 206; it is fresh as the whole 200 would be.
        let as_status = if status == 206 && c.slice != 0 {
            200
        } else {
            status
        };
        let Some(s) = storable(c, as_status, &headers, now) else {
            return true;
        };
        let data = &self.ubuf.data;
        let mut head = Vec::with_capacity(512);
        for h in self.resp.headers.iter() {
            let name = h.name.get(data);
            if stored_header(h.kind, name, route) {
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
        route: &Route,
    ) -> Option<KeepAlive> {
        let ops = &route.response_headers;
        use std::io::{Seek, SeekFrom};
        let (mut file, e) = zone.open(h).ok()?;
        let len = e.body_len;
        let status = self.x.status(e.status);
        let etag = e.header(b"etag");
        let modified = e.header(b"last-modified");
        let not_modified = status == 200
            && match self.x.main_header(b"if-none-match") {
                Some(v) => v == b"*" || etag.is_some_and(|t| t == v),
                None => {
                    modified.is_some_and(|m| self.x.main_header(b"if-modified-since") == Some(m))
                }
            };
        let ranges = match self.x.main_header(b"range") {
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
        let mut plan = if status == 304 || status == 416 {
            crate::filter::Plan::default()
        } else {
            let ct = e.header(b"content-type").unwrap_or_default().to_vec();
            let enc = e.header(b"content-encoding").is_some_and(|v| !v.is_empty());
            crate::filter::plan(&mut self.x, status, &ct, Some(len), enc)
        };
        // A body the filters change is sent whole.
        let (status, ranges) = if plan.reframe && status == 206 {
            (self.x.status(e.status), range::Ranges::WHOLE)
        } else {
            (status, ranges)
        };
        let parts: &[Span] = if status == 206 { ranges.parts() } else { &[] };
        let chunked = plan.reframe && crate::compress::chunked_for(&self.x);
        let head_only = self.x.req.method == Method::Head;
        let keep = self.x.req.keep_alive && (!plan.reframe || chunked || head_only);
        let etag_mode = plan.etag(false);
        let ctype = plan.ctype.take();
        self.extra(ops, status);
        let ops_extra = std::mem::take(&mut self.x.resp_extra);
        let out = &mut self.out;
        out.clear();
        // A stored Server or Date was passed on (nginx proxy_pass_header)
        // and replaces the proxy's own.
        reply::start_with(out, status, b"", e.header(b"server"), e.header(b"date"));
        for line in e.head.split_inclusive(|&c| c == b'\n') {
            let name = line.split(|&c| c == b':').next().unwrap_or_default();
            if (!ops.is_empty() && ops.drops(name))
                || name.eq_ignore_ascii_case(b"server")
                || name.eq_ignore_ascii_case(b"date")
            {
                continue;
            }
            let is = |n: &[u8]| name.eq_ignore_ascii_case(n);
            if (plan.reframe && is(b"accept-ranges"))
                || (plan.drop_validators && is(b"last-modified"))
            {
                continue;
            }
            if is(b"etag") && etag_mode != crate::filter::Etag::Keep {
                if etag_mode == crate::filter::Etag::Weak {
                    crate::filter::weak_etag(line, name.len(), out);
                }
                continue;
            }
            if is(b"content-type")
                && let Some(ct) = &ctype
            {
                out.extend_from_slice(b"Content-Type: ");
                out.extend_from_slice(ct);
                out.extend_from_slice(b"\r\n");
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
            // Stored as the upstream sent them: the route's edits apply.
            match line.iter().position(|&c| c == b':') {
                Some(i) if route.edits.is_some() => {
                    let value = line[i + 1..].trim_ascii();
                    crate::edits::push_line(&mut self.x, route.edits.as_deref(), name, value, out);
                }
                _ => out.extend_from_slice(line),
            }
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
        if plan.reframe {
            if chunked && !head_only {
                out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
            }
        } else if status != 304 {
            out.extend_from_slice(b"Content-Length: ");
            push_u64(out, body);
            out.extend_from_slice(b"\r\n");
        }
        if let [one] = parts {
            out.extend_from_slice(b"Content-Range: bytes ");
            range::push_span(out, *one, len);
            out.extend_from_slice(b"\r\n");
        } else if status == 200 && !plan.reframe && e.header(b"accept-ranges").is_none() {
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
        if plan.reframe {
            self.x.sent.bytes = 0;
            let span = Span {
                start: e.body_offset,
                end: e.body_offset + len,
            };
            let ok = self
                .send_filtered(&mut file, span, plan.chain(None), chunked)
                .await;
            return Some(ok && keep);
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
        if file.seek(SeekFrom::Start(0)).is_err()
            || !self.send_span(&mut file, span, plan.table()).await
        {
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
        match self.x.main_header(b"if-range") {
            None => true,
            Some(v) if v.ends_with(b"\"") => etag == Some(v),
            Some(v) => modified == Some(v),
        }
    }

    /// nginx slice: the response is fetched and stored in ranges of
    /// `c.slice` bytes, each its own entry keyed with $slice_range, and the
    /// client's request is answered from the slices it covers.
    async fn proxy_sliced(
        &mut self,
        active: &Active,
        p: &Proxy,
        route: &Route,
        c: &Cache,
        zone: &Arc<Zone>,
    ) -> Result<KeepAlive, u16> {
        let size = c.slice;
        // The first slice the client wants; slice 0 when the start is
        // relative to the unknown length.
        let first = self
            .x
            .main_header(b"range")
            .and_then(range_start)
            .map_or(0, |s| s / size);
        let (mut file, e) = self.slice(active, p, route, c, zone, first).await?;
        let Some((at, total)) = e.header(b"content-range").and_then(content_range) else {
            // The upstream ignored the Range: the entry is the whole response.
            drop(file);
            let h = zone.lookup(&self.slice_key(c), &self.x).0;
            return self.serve_entry(zone, h, route).await.ok_or(502);
        };
        if e.status != 206 || at != first * size {
            return Err(502);
        }
        let etag: Option<Box<[u8]>> = e.header(b"etag").map(Box::from);
        let ranges = match self.x.main_header(b"range") {
            Some(v) if self.cached_if_range(etag.as_deref(), e.header(b"last-modified")) => {
                range::parse(v, total)
            }
            _ => range::Ranges::WHOLE,
        };
        let not_modified = etag
            .as_deref()
            .is_some_and(|t| self.x.main_header(b"if-none-match") == Some(t));
        let (status, span) = match (ranges.answer, ranges.parts()) {
            _ if not_modified => (304, Span::default()),
            (Answer::Unsatisfiable, _) => (416, Span::default()),
            (Answer::Partial, [one]) => (206, *one),
            _ => (
                200,
                Span {
                    start: 0,
                    end: total,
                },
            ),
        };
        let ops = &route.response_headers;
        let keep = self.x.req.keep_alive;
        self.extra(ops, status);
        let ops_extra = std::mem::take(&mut self.x.resp_extra);
        let out = &mut self.out;
        out.clear();
        reply::start(out, status, b"");
        for line in e.head.split_inclusive(|&c| c == b'\n') {
            let name = line.split(|&c| c == b':').next().unwrap_or_default();
            if name.eq_ignore_ascii_case(b"content-range") || (!ops.is_empty() && ops.drops(name)) {
                continue;
            }
            out.extend_from_slice(line);
        }
        let body = span.end - span.start;
        match status {
            416 => {
                out.extend_from_slice(b"Content-Range: bytes */");
                push_u64(out, total);
                out.extend_from_slice(b"\r\n");
            }
            206 => {
                out.extend_from_slice(b"Content-Range: bytes ");
                range::push_span(out, span, total);
                out.extend_from_slice(b"\r\n");
            }
            _ => {}
        }
        if status != 304 {
            out.extend_from_slice(b"Content-Length: ");
            push_u64(out, body);
            out.extend_from_slice(b"\r\n");
        }
        if status == 200 && e.header(b"accept-ranges").is_none() {
            out.extend_from_slice(b"Accept-Ranges: bytes\r\n");
        }
        reply::connection(out, keep, &ops_extra);
        out.extend_from_slice(b"\r\n");
        self.x.resp_extra = ops_extra;
        self.x.sent.status = status;
        self.x.sent.bytes = self.out.len() as u64;
        self.x.cache_status = b"HIT";
        if self.x.req.method == Method::Head || body == 0 {
            return Ok(self.respond(keep).await);
        }
        if keep && self.pump_body(crate::conn::Sink::Drop).await.is_err() {
            return Ok(false);
        }
        self.x.sent.bytes += body;
        self.x.sent.body_bytes = body;
        let mut n = span.start / size;
        let mut entry = Some((file, e));
        while n * size < span.end {
            let (f, e) = match entry.take() {
                Some(fe) if n == first => fe,
                _ => match self.slice(active, p, route, c, zone, n).await {
                    Ok(fe) => fe,
                    // The head is out: only closing tells the client.
                    Err(_) => return Ok(false),
                },
            };
            file = f;
            // Every slice must be of the same response.
            let same = e.header(b"content-range").and_then(content_range)
                == Some((n * size, total))
                && e.header(b"etag").map(Box::from) == etag;
            if !same {
                return Ok(false);
            }
            let from = span.start.max(n * size) - n * size;
            let to = span.end.min((n + 1) * size).min(total) - n * size;
            if to > e.body_len {
                return Ok(false);
            }
            let part = Span {
                start: e.body_offset + from,
                end: e.body_offset + to,
            };
            if !self.send_span(&mut file, part, None).await {
                return Ok(false);
            }
            n += 1;
        }
        if !self.out.is_empty()
            && write_timeout(&mut self.client, &self.out, SEND_TIMEOUT)
                .await
                .is_err()
        {
            return Ok(false);
        }
        Ok(keep)
    }

    /// The cache key with the current $slice_range.
    fn slice_key(&mut self, c: &Cache) -> Box<[u8]> {
        crate::vars::expand(&mut self.x, &c.key);
        self.x.tmpl.as_slice().into()
    }

    /// Slice `n` of the response: from the store, or fetched upstream with
    /// a Range request and stored first.
    async fn slice(
        &mut self,
        active: &Active,
        p: &Proxy,
        route: &Route,
        c: &Cache,
        zone: &Arc<Zone>,
        n: u64,
    ) -> Result<(std::fs::File, crate::cache::Entry), u16> {
        let size = c.slice;
        self.x.slice_range.clear();
        self.x.slice_range.extend_from_slice(b"bytes=");
        push_u64(&mut self.x.slice_range, n * size);
        self.x.slice_range.push(b'-');
        push_u64(&mut self.x.slice_range, (n + 1) * size - 1);
        let key = self.slice_key(c);
        let main = Zone::key_hash(&key);
        for fetched in [false, true] {
            let (h, found) = zone.lookup(&key, &self.x);
            if found.is_some_and(|f| fetched || f.fresh(now()))
                && let Ok(fe) = zone.open(h)
            {
                return Ok(fe);
            }
            if fetched {
                break;
            }
            let guard = if c.lock {
                match zone.lock(main, c.lock_timeout).await {
                    Locked::Held(g) => Some(g),
                    // Another request stored it meanwhile, or gave up.
                    Locked::Released | Locked::TimedOut => None,
                }
            } else {
                None
            };
            let (h, found) = zone.lookup(&key, &self.x);
            if found.is_some_and(|f| f.fresh(now()))
                && let Ok(fe) = zone.open(h)
            {
                return Ok(fe);
            }
            self.x.cache_status = b"MISS";
            let store = !c.no_store(&self.x);
            self.fetch(active, p, route, c, zone, key.clone(), None, store, true)
                .await?;
            drop(guard);
        }
        Err(502)
    }
}

/// The first byte position of a single "bytes=N-" range; `None` for a
/// suffix range or one that does not parse.
fn range_start(v: &[u8]) -> Option<u64> {
    let v = v.trim_ascii();
    if v.len() < 6 || !v[..6].eq_ignore_ascii_case(b"bytes=") {
        return None;
    }
    let rest = v[6..].trim_ascii_start();
    let end = rest.iter().position(|c| !c.is_ascii_digit())?;
    std::str::from_utf8(&rest[..end]).ok()?.parse().ok()
}

/// "bytes S-E/L" into (S, L).
fn content_range(v: &[u8]) -> Option<(u64, u64)> {
    let v = std::str::from_utf8(v).ok()?.trim();
    let rest = v.strip_prefix("bytes ")?;
    let (span, total) = rest.split_once('/')?;
    let (start, _) = span.split_once('-')?;
    Some((start.trim().parse().ok()?, total.trim().parse().ok()?))
}
