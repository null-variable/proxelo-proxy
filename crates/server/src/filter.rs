//! Response filters, in nginx order after the headers filter: userid,
//! sub_filter and charset. They decide on the response head; the body then
//! streams through a [`Chain`] that ends with the compression encoder.

use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use proxelo_snapshot::{Charset, Filters, Recode, SubFilter, Userid, UseridMode};

use crate::compress::Coder;
use crate::exchange::Exchange;
use crate::vars::expand;

/// A Content-Type split as nginx reads it: the type before a `charset=`
/// parameter, and that charset without quotes.
pub(crate) struct ContentType<'a> {
    pub base: &'a [u8],
    pub charset: Option<&'a [u8]>,
}

pub(crate) fn split_type(v: &[u8]) -> ContentType<'_> {
    let mut i = 0;
    while let Some(off) = v[i..].iter().position(|&c| c == b';') {
        let semi = i + off;
        let mut p = semi + 1;
        while v.get(p) == Some(&b' ') {
            p += 1;
        }
        if p >= v.len() {
            break;
        }
        if v.len() - p >= 8 && v[p..p + 8].eq_ignore_ascii_case(b"charset=") {
            let mut cs = &v[p + 8..];
            if let Some(r) = cs.strip_prefix(b"\"") {
                cs = r;
            }
            if let Some(r) = cs.strip_suffix(b"\"") {
                cs = r;
            }
            return ContentType {
                base: &v[..semi],
                charset: Some(cs),
            };
        }
        i = p;
    }
    ContentType {
        base: v,
        charset: None,
    }
}

fn with_charset(base: &[u8], charset: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(base.len() + 10 + charset.len());
    v.extend_from_slice(base);
    v.extend_from_slice(b"; charset=");
    v.extend_from_slice(charset);
    v
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Etag {
    Keep,
    Weak,
    Drop,
}

/// How a complete response head is rewritten.
pub(crate) struct Edit<'a> {
    pub ctype: Option<&'a [u8]>,
    /// No Content-Length or Accept-Ranges.
    pub reframe: bool,
    pub etag: Etag,
    pub drop_modified: bool,
    /// Connection becomes close.
    pub close: bool,
}

/// Rewrites a complete head (ending with the empty line) by `e`, with the
/// lines `add` before the end.
pub(crate) fn edit_head(head: &[u8], e: &Edit<'_>, add: &[&[u8]], out: &mut Vec<u8>) {
    let body = head.strip_suffix(b"\r\n").unwrap_or(head);
    for line in body.split_inclusive(|&c| c == b'\n') {
        let name_end = line.iter().position(|&c| c == b':').unwrap_or(0);
        let name = &line[..name_end];
        let is = |n: &[u8]| name.eq_ignore_ascii_case(n);
        if (e.reframe && (is(b"content-length") || is(b"accept-ranges")))
            || (e.close && is(b"connection"))
            || (e.drop_modified && is(b"last-modified"))
        {
            continue;
        }
        if is(b"etag") {
            match e.etag {
                Etag::Keep => out.extend_from_slice(line),
                Etag::Weak => weak_etag(line, name_end, out),
                Etag::Drop => {}
            }
            continue;
        }
        if is(b"content-type")
            && let Some(ct) = e.ctype
        {
            out.extend_from_slice(b"Content-Type: ");
            out.extend_from_slice(ct);
            out.extend_from_slice(b"\r\n");
            continue;
        }
        out.extend_from_slice(line);
    }
    for a in add {
        out.extend_from_slice(a);
    }
    if e.close {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
}

/// nginx ngx_http_weak_etag: a strong ETag becomes W/; anything that is
/// not a quoted tag is dropped.
pub(crate) fn weak_etag(line: &[u8], name_end: usize, out: &mut Vec<u8>) {
    let v = line[name_end + 1..].trim_ascii();
    if v.starts_with(b"W/") {
        out.extend_from_slice(line);
    } else if v.starts_with(b"\"") {
        out.extend_from_slice(&line[..name_end]);
        out.extend_from_slice(b": W/");
        out.extend_from_slice(v);
        out.extend_from_slice(b"\r\n");
    }
}

/// What the filters do to one response.
#[derive(Default)]
pub(crate) struct Plan {
    /// The Content-Type to send instead.
    pub ctype: Option<Vec<u8>>,
    /// The body changes: no Content-Length or Accept-Ranges, and the
    /// response is not served in ranges.
    pub reframe: bool,
    /// Last-Modified and ETag are left out (sub_filter_last_modified off).
    pub drop_validators: bool,
    /// The ETag becomes weak (sub_filter_last_modified on).
    pub weak: bool,
    sub: Option<Sub>,
    recode: Option<Recoder>,
}

impl Plan {
    pub fn is_noop(&self) -> bool {
        self.ctype.is_none() && !self.reframe
    }

    /// What happens to the ETag when the body is also `encoded`.
    pub fn etag(&self, encoded: bool) -> Etag {
        if self.drop_validators {
            Etag::Drop
        } else if encoded || self.weak {
            Etag::Weak
        } else {
            Etag::Keep
        }
    }

    /// The body side with `coder`: gunzip runs before the filters and an
    /// encoder after them, as in nginx.
    pub fn chain(&mut self, coder: Option<Coder>) -> Chain {
        let (gunzip, coder) = match coder {
            Some(k @ Coder::Gunzip(_)) => (Some(k), None),
            k => (None, k),
        };
        Chain {
            gunzip,
            g: Vec::new(),
            sub: self.sub.take(),
            recode: self.recode.take(),
            coder,
            a: Vec::new(),
            b: Vec::new(),
        }
    }
}

/// Decides the filters for a response of the main request. `length` is
/// the body length when known, `encoded` whether it has a Content-Encoding.
pub(crate) fn plan(
    x: &mut Exchange,
    status: u16,
    ctype: &[u8],
    length: Option<u64>,
    encoded: bool,
) -> Plan {
    let mut p = Plan::default();
    let Some(f) = x.filters.clone() else {
        return p;
    };
    if let Some(s) = &f.sub
        && length != Some(0)
        && s.types.matches(ctype)
        && let Some(sub) = Sub::new(x, s)
    {
        p.sub = Some(sub);
        p.reframe = true;
        p.drop_validators = !s.last_modified;
        p.weak = s.last_modified;
    }
    if let Some(c) = &f.charset {
        charset(&f, c, status, ctype, encoded, &mut p);
    }
    p
}

/// nginx charset header filter.
fn charset(f: &Arc<Filters>, c: &Charset, status: u16, ct: &[u8], encoded: bool, p: &mut Plan) {
    if ct.is_empty() {
        return;
    }
    let t = split_type(ct);
    if t.charset.is_some() {
        if !c.override_charset {
            return;
        }
    } else if !c.types.matches(ct) {
        return;
    }
    let dst = &c.charset[..];
    // nginx sends no charset with a redirect.
    let redirect = matches!(status, 301 | 302);
    let src = match t.charset {
        Some(s) => s,
        None if c.source.is_empty() => {
            if !redirect {
                p.ctype = Some(with_charset(ct, dst));
            }
            return;
        }
        None => &c.source[..],
    };
    if !src.eq_ignore_ascii_case(dst) {
        // Only the configured source has a map to the destination; an
        // encoded body is passed as is.
        if !src.eq_ignore_ascii_case(&c.source) || encoded || c.recode.is_none() {
            return;
        }
        p.recode = Some(Recoder {
            f: Arc::clone(f),
            saved: [0; 4],
            saved_len: 0,
        });
        p.reframe = true;
    }
    p.ctype = Some(if redirect {
        t.base.to_vec()
    } else {
        with_charset(t.base, dst)
    });
}

/// sub_filter state for one response.
struct Sub {
    /// Lowercase matches with their replacements, in configuration order.
    pairs: Vec<(Vec<u8>, Vec<u8>)>,
    /// Pairs already applied, with `once`.
    used: Vec<bool>,
    once: bool,
    /// Lowercase first bytes of the matches.
    first: [bool; 256],
    /// Bytes held back because a match may start in them.
    held: Vec<u8>,
}

impl Sub {
    fn new(x: &mut Exchange, s: &SubFilter) -> Option<Self> {
        let mut pairs = Vec::with_capacity(s.pairs.len());
        for (m, r) in s.pairs.iter() {
            expand(x, m);
            if x.tmpl.is_empty() {
                continue;
            }
            let m = x.tmpl.to_ascii_lowercase();
            expand(x, r);
            pairs.push((m, x.tmpl.clone()));
        }
        if pairs.is_empty() {
            return None;
        }
        let mut first = [false; 256];
        for (m, _) in &pairs {
            first[usize::from(m[0])] = true;
        }
        Some(Self {
            used: vec![false; pairs.len()],
            pairs,
            once: !s.all,
            first,
            held: Vec::new(),
        })
    }

    fn done(&self) -> bool {
        self.once && self.used.iter().all(|&u| u)
    }

    /// Replaces in `data` and appends to `out`; with `last` nothing is
    /// held back.
    fn write(&mut self, data: &[u8], last: bool, out: &mut Vec<u8>) {
        if self.done() && self.held.is_empty() {
            out.extend_from_slice(data);
            return;
        }
        let mut buf = std::mem::take(&mut self.held);
        buf.extend_from_slice(data);
        let mut copied = 0;
        let mut i = 0;
        'scan: while i < buf.len() {
            if self.done() {
                break;
            }
            if !self.first[usize::from(buf[i].to_ascii_lowercase())] {
                i += 1;
                continue;
            }
            let rest = &buf[i..];
            let mut partial = false;
            for (k, (m, r)) in self.pairs.iter().enumerate() {
                if self.once && self.used[k] {
                    continue;
                }
                let n = m.len().min(rest.len());
                if !rest[..n]
                    .iter()
                    .zip(&m[..n])
                    .all(|(a, b)| a.to_ascii_lowercase() == *b)
                {
                    continue;
                }
                if n < m.len() {
                    if !last {
                        partial = true;
                        break;
                    }
                    continue;
                }
                out.extend_from_slice(&buf[copied..i]);
                out.extend_from_slice(r);
                self.used[k] = true;
                i += m.len();
                copied = i;
                continue 'scan;
            }
            if partial {
                out.extend_from_slice(&buf[copied..i]);
                buf.drain(..i);
                self.held = buf;
                return;
            }
            i += 1;
        }
        out.extend_from_slice(&buf[copied..]);
        buf.clear();
        self.held = buf;
    }
}

/// charset recoding state for one response.
struct Recoder {
    f: Arc<Filters>,
    /// An incomplete UTF-8 sequence at the end of the last chunk.
    saved: [u8; 4],
    saved_len: usize,
}

/// nginx ngx_utf8_decode: the code point and the bytes it took, `None`
/// for a sequence cut short. Invalid input is `u32::MAX`.
fn utf8_decode(p: &[u8]) -> Option<(u32, usize)> {
    let u = u32::from(p[0]);
    let (mut u, valid, len) = match u {
        0xf8.. => return Some((u32::MAX, 1)),
        0xf0.. => (u & 0x07, 0xffff, 3),
        0xe0.. => (u & 0x0f, 0x7ff, 2),
        0xc2.. => (u & 0x1f, 0x7f, 1),
        _ => return Some((u32::MAX, 1)),
    };
    if p.len() - 1 < len {
        return None;
    }
    for (k, &c) in p[1..=len].iter().enumerate() {
        if c < 0x80 {
            return Some((u32::MAX, k + 2));
        }
        u = (u << 6) | u32::from(c & 0x3f);
    }
    Some((if u > valid { u } else { u32::MAX }, len + 1))
}

impl Recoder {
    fn write(&mut self, data: &[u8], last: bool, out: &mut Vec<u8>) {
        let Some(c) = &self.f.charset else {
            out.extend_from_slice(data);
            return;
        };
        match c.recode.as_ref() {
            None => out.extend_from_slice(data),
            Some(Recode::Table(t)) => out.extend(data.iter().map(|&b| t[usize::from(b)])),
            Some(Recode::ToUtf8(t)) => {
                for &b in data {
                    match t[usize::from(b)] {
                        0 if b < 0x80 => out.push(b),
                        0 => out.push(b'?'),
                        cp => {
                            let ch = char::from_u32(cp).unwrap_or('?');
                            let mut tmp = [0; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
                        }
                    }
                }
            }
            Some(Recode::FromUtf8(m)) => {
                let joined;
                let src: &[u8] = if self.saved_len > 0 {
                    joined = [&self.saved[..self.saved_len], data].concat();
                    self.saved_len = 0;
                    &joined
                } else {
                    data
                };
                let mut i = 0;
                while i < src.len() {
                    let b = src[i];
                    if b < 0x80 {
                        out.push(b);
                        i += 1;
                        continue;
                    }
                    let Some((n, took)) = utf8_decode(&src[i..]) else {
                        if !last {
                            let rest = &src[i..];
                            self.saved[..rest.len()].copy_from_slice(rest);
                            self.saved_len = rest.len();
                        }
                        break;
                    };
                    i += took;
                    match m.get(&n) {
                        Some(&c) => out.push(c),
                        None if n > 0x10ffff => out.push(b'?'),
                        None => {
                            out.extend_from_slice(b"&#");
                            proxelo_http1::push_u64(out, n.into());
                            out.push(b';');
                        }
                    }
                }
            }
        }
    }
}

/// The body filters and the encoder after them.
pub(crate) struct Chain {
    gunzip: Option<Coder>,
    g: Vec<u8>,
    sub: Option<Sub>,
    recode: Option<Recoder>,
    coder: Option<Coder>,
    a: Vec<u8>,
    b: Vec<u8>,
}

impl Chain {
    /// Feeds body bytes; the output goes to the end of `out`.
    pub fn write(&mut self, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        self.run(data, false, out)
    }

    /// Ends the body.
    pub fn finish(mut self, out: &mut Vec<u8>) -> io::Result<()> {
        self.run(&[], true, out)?;
        match self.coder.take() {
            Some(k) => k.finish(out),
            None => Ok(()),
        }
    }

    fn run(&mut self, data: &[u8], last: bool, out: &mut Vec<u8>) -> io::Result<()> {
        let mut a = std::mem::take(&mut self.a);
        let mut b = std::mem::take(&mut self.b);
        let mut g = std::mem::take(&mut self.g);
        a.clear();
        g.clear();
        let mut cur: &[u8] = data;
        let had = self.gunzip.is_some();
        let pre = match self.gunzip.take() {
            Some(k) if last => k.finish(&mut g),
            Some(mut k) => {
                let r = k.write(cur, &mut g);
                self.gunzip = Some(k);
                r
            }
            None => Ok(()),
        };
        if had {
            cur = &g;
        }
        if let Err(e) = pre {
            self.a = a;
            self.b = b;
            self.g = g;
            return Err(e);
        }
        if let Some(s) = &mut self.sub {
            s.write(cur, last, &mut a);
            cur = &a;
        }
        if let Some(r) = &mut self.recode {
            b.clear();
            r.write(cur, last, &mut b);
            cur = &b;
        }
        let r = match &mut self.coder {
            Some(k) => k.write(cur, out),
            None => {
                out.extend_from_slice(cur);
                Ok(())
            }
        };
        self.a = a;
        self.b = b;
        self.g = g;
        r
    }
}

impl crate::conn::Conn {
    /// Runs the filters over a complete response built in `out` (`body`
    /// bytes after the head). Returns the new body length, whether the body
    /// still needs framing (its length changed) and whether the connection
    /// closes after it.
    pub(crate) fn filter_buffered(&mut self, status: u16, body: usize) -> (usize, bool, bool) {
        if self.x.filters.is_none() {
            return (body, false, false);
        }
        let head_end = self.out.len() - body;
        let head = &self.out[..head_end];
        let ctype = crate::compress::head_value(head, b"content-type")
            .unwrap_or_default()
            .to_vec();
        let length = crate::compress::head_value(head, b"content-length")
            .and_then(|v| std::str::from_utf8(v).ok()?.parse().ok());
        let encoded =
            crate::compress::head_value(head, b"content-encoding").is_some_and(|v| !v.is_empty());
        let mut p = plan(&mut self.x, status, &ctype, length, encoded);
        if p.is_noop() {
            return (body, false, false);
        }
        let head_only = self.x.req.method == proxelo_http1::Method::Head;
        let close = p.reframe && !head_only && !crate::compress::chunked_for(&self.x);
        let edit = Edit {
            ctype: p.ctype.as_deref(),
            reframe: p.reframe,
            etag: p.etag(false),
            drop_modified: p.drop_validators,
            close,
        };
        let mut out = std::mem::take(&mut self.zout);
        out.clear();
        edit_head(&self.out[..head_end], &edit, &[], &mut out);
        let start = out.len();
        if p.reframe && !head_only {
            let mut chain = p.chain(None);
            let r = chain
                .write(&self.out[head_end..], &mut out)
                .and_then(|()| chain.finish(&mut out));
            if r.is_err() {
                out.truncate(start);
            }
        } else {
            out.extend_from_slice(&self.out[head_end..]);
        }
        let n = out.len() - start;
        std::mem::swap(&mut self.out, &mut out);
        self.zout = out;
        (n, p.reframe && !head_only && !close, close)
    }

    /// Sends a complete body of `body` bytes at the end of `out` chunked:
    /// the filters changed its length.
    pub(crate) fn frame_buffered(&mut self, body: usize) {
        let head_end = self.out.len() - body;
        let mut out = std::mem::take(&mut self.zout);
        out.clear();
        out.extend_from_slice(&self.out[..head_end - 2]);
        out.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
        crate::compress::push_chunk(&mut out, &self.out[head_end..]);
        out.extend_from_slice(b"0\r\n\r\n");
        std::mem::swap(&mut self.out, &mut out);
        self.zout = out;
    }
}

/// nginx userid sequencers and start value, per process.
static SEQ_V1: AtomicU32 = AtomicU32::new(1);
static SEQ_V2: AtomicU32 = AtomicU32::new(0x0303_0302);
static START: OnceLock<u32> = OnceLock::new();

/// The cookie base64 alphabet with padding, decoding without it too.
const B64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

fn start_value() -> u32 {
    *START.get_or_init(|| {
        let us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_micros());
        ((us / 20) << 16) | (std::process::id() & 0xffff)
    })
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The userid state of one request.
#[derive(Default, Clone)]
pub(crate) struct Uid {
    pub checked: bool,
    /// The client's cookie value, when it decoded.
    pub cookie: Vec<u8>,
    pub got: Option<[u32; 4]>,
    pub set: Option<[u32; 4]>,
}

impl Uid {
    pub fn reset(&mut self) {
        self.checked = false;
        self.cookie.clear();
        self.got = None;
        self.set = None;
    }
}

/// Reads the client's cookie once (nginx ngx_http_userid_get_uid).
fn got(x: &mut Exchange, u: &Userid) {
    if x.uid.checked {
        return;
    }
    x.uid.checked = true;
    let mut cookie = std::mem::take(&mut x.uid.cookie);
    cookie.clear();
    if let Some(v) = x.cookie(&u.name) {
        cookie.extend_from_slice(v);
    }
    let mut raw = [0u8; 18];
    let ok = cookie.len() >= 22
        && B64
            .decode_slice(&cookie[..22], &mut raw)
            .is_ok_and(|n| n >= 16);
    if ok {
        let mut w = [0u32; 4];
        for (i, c) in raw[..16].chunks(4).enumerate() {
            // nginx prints the words as the host reads them.
            w[i] = u32::from_ne_bytes([c[0], c[1], c[2], c[3]]);
        }
        x.uid.got = Some(w);
    } else {
        cookie.clear();
    }
    x.uid.cookie = cookie;
}

/// nginx ngx_http_userid_create_uid: the uid to set, `None` when the
/// client's stays as it is.
fn create(x: &mut Exchange, u: &Userid) {
    if x.uid.set.is_some() {
        return;
    }
    if let Some(g) = x.uid.got {
        let marked = u.mark == 0
            || (x.uid.cookie.len() > 23 && x.uid.cookie[22] == u.mark && x.uid.cookie[23] == b'=');
        if !marked {
            x.uid.set = Some(g);
        }
        return;
    }
    let t = now() as u32;
    let w = if u.mode == UseridMode::V1 {
        let seq = SEQ_V1.fetch_add(0x100, Ordering::Relaxed);
        [u.service.unwrap_or(0), t, start_value(), seq]
    } else {
        let first = match u.service {
            Some(s) => u32::from_ne_bytes(s.to_be_bytes()),
            None => match x.local.ip() {
                std::net::IpAddr::V4(a) => u32::from_ne_bytes(a.octets()),
                std::net::IpAddr::V6(a) => {
                    let o = a.octets();
                    u32::from_ne_bytes([o[12], o[13], o[14], o[15]])
                }
            },
        };
        let seq = SEQ_V2
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |s| {
                let n = s.wrapping_add(0x100);
                Some(if n < 0x0303_0302 { 0x0303_0302 } else { n })
            })
            .unwrap_or(0x0303_0302);
        let be = |v: u32| u32::from_ne_bytes(v.to_be_bytes());
        [first, be(t), be(start_value()), be(seq)]
    };
    x.uid.set = Some(w);
}

/// Puts the Set-Cookie (and P3P) lines of the userid filter for the
/// response in `uid_lines`, which every response head carries.
pub(crate) fn userid_lines(x: &mut Exchange) {
    x.uid_lines.clear();
    let Some(f) = x.filters.clone() else { return };
    let Some(u) = &f.userid else { return };
    if u.mode == UseridMode::Log {
        return;
    }
    got(x, u);
    create(x, u);
    let Some(set) = x.uid.set else { return };
    let mut out = std::mem::take(&mut x.uid_lines);
    userid_cookie(x, u, set, &mut out);
    x.uid_lines = out;
}

fn userid_cookie(x: &Exchange, u: &Userid, set: [u32; 4], out: &mut Vec<u8>) {
    out.extend_from_slice(b"Set-Cookie: ");
    out.extend_from_slice(&u.name);
    out.push(b'=');
    if x.uid.got.is_none() || x.uid.got != Some(set) || x.uid.cookie.len() < 22 {
        let mut raw = [0u8; 16];
        for (i, w) in set.iter().enumerate() {
            raw[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
        }
        let start = out.len();
        let mut enc = [0u8; 24];
        let n = B64.encode_slice(raw, &mut enc).unwrap_or(0);
        out.extend_from_slice(&enc[..n]);
        if u.mark != 0 && out.len() >= start + 2 {
            let at = out.len() - 2;
            out[at] = u.mark;
        }
    } else {
        out.extend_from_slice(&x.uid.cookie[..22]);
        out.push(u.mark);
        out.push(b'=');
    }
    if u.expires_max {
        out.extend_from_slice(b"; expires=Thu, 31-Dec-37 23:55:55 GMT");
    } else if u.expires != 0 {
        out.extend_from_slice(b"; expires=");
        cookie_time(now() + u64::from(u.expires), out);
    }
    out.extend_from_slice(&u.domain);
    out.extend_from_slice(&u.path);
    out.extend_from_slice(&u.flags);
    out.extend_from_slice(b"\r\n");
    if !u.p3p.is_empty() {
        out.extend_from_slice(b"P3P: ");
        out.extend_from_slice(&u.p3p);
        out.extend_from_slice(b"\r\n");
    }
}

/// nginx ngx_http_cookie_time: `Thu, 01-Jan-70 00:00:00 GMT`, with a
/// four-digit year after 2037.
fn cookie_time(t: u64, out: &mut Vec<u8>) {
    let d = proxelo_http1::http_date(t);
    // "Thu, 01 Jan 1970 00:00:00 GMT"
    out.extend_from_slice(&d[..7]);
    out.push(b'-');
    out.extend_from_slice(&d[8..11]);
    out.push(b'-');
    let year = &d[12..16];
    if year > &b"2037"[..] {
        out.extend_from_slice(year);
    } else {
        out.extend_from_slice(&year[2..]);
    }
    out.extend_from_slice(&d[16..]);
}

/// `$uid_got` or `$uid_set`.
pub(crate) fn uid_var(x: &mut Exchange, set: bool, out: &mut Vec<u8>) {
    let Some(f) = x.filters.clone() else { return };
    let Some(u) = &f.userid else { return };
    got(x, u);
    let w = if set {
        if u.mode == UseridMode::Log {
            return;
        }
        create(x, u);
        x.uid.set
    } else {
        x.uid.got
    };
    let Some(w) = w else { return };
    out.extend_from_slice(&u.name);
    out.push(b'=');
    for v in w {
        let _ = io::Write::write_fmt(out, format_args!("{v:08X}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_types() {
        let t = split_type(b"text/html; charset=\"KOI8-R\"");
        assert_eq!(t.base, b"text/html");
        assert_eq!(t.charset, Some(&b"KOI8-R"[..]));
        let t = split_type(b"text/plain;  q=1; charset=utf-8");
        assert_eq!(t.base, b"text/plain;  q=1");
        assert_eq!(t.charset, Some(&b"utf-8"[..]));
        assert!(split_type(b"text/html").charset.is_none());
    }

    fn sub(pairs: &[(&str, &str)], once: bool) -> Sub {
        let pairs: Vec<_> = pairs
            .iter()
            .map(|(m, r)| (m.as_bytes().to_ascii_lowercase(), r.as_bytes().to_vec()))
            .collect();
        let mut first = [false; 256];
        for (m, _) in &pairs {
            first[usize::from(m[0])] = true;
        }
        Sub {
            used: vec![false; pairs.len()],
            pairs,
            once,
            first,
            held: Vec::new(),
        }
    }

    #[test]
    fn sub_filter_across_chunks() {
        let mut s = sub(&[("Hello", "Bye")], false);
        let mut out = Vec::new();
        for part in [&b"a hel"[..], b"lo b HELLO c hel"] {
            s.write(part, false, &mut out);
        }
        s.write(b"", true, &mut out);
        assert_eq!(out, b"a Bye b Bye c hel");
        let mut s = sub(&[("a", "1"), ("b", "2")], true);
        let mut out = Vec::new();
        s.write(b"abab", true, &mut out);
        assert_eq!(out, b"12ab");
    }

    #[test]
    fn utf8() {
        assert_eq!(utf8_decode("Ж".as_bytes()), Some((0x416, 2)));
        assert_eq!(utf8_decode(&[0xd0]), None);
        assert_eq!(utf8_decode(&[0x80]), Some((u32::MAX, 1)));
        assert_eq!(utf8_decode(&[0xc0, 0x80]), Some((u32::MAX, 1)));
    }

    #[test]
    fn cookie_times() {
        let mut out = Vec::new();
        cookie_time(0, &mut out);
        assert_eq!(out, b"Thu, 01-Jan-70 00:00:00 GMT");
        out.clear();
        cookie_time(2_240_524_800, &mut out);
        assert_eq!(out, b"Mon, 31-Dec-2040 00:00:00 GMT");
    }
}
