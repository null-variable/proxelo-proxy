use super::*;

fn req(raw: &[u8]) -> Result<Option<Request>, Error> {
    let mut r = Request::default();
    Ok(parse_request(raw, &mut r)?.then_some(r))
}

fn header<'a>(buf: &'a [u8], h: &Headers, name: &[u8]) -> Option<&'a [u8]> {
    h.iter()
        .find(|h| h.name.get(buf).eq_ignore_ascii_case(name))
        .map(|h| h.value.get(buf))
}

#[test]
fn parses_simple_get() {
    let raw = b"GET /a/b?x=1 HTTP/1.1\r\nHost: example.com\r\nX-Y:  z \r\n\r\n";
    let r = req(raw).unwrap().unwrap();
    assert_eq!(r.method, Method::Get);
    assert_eq!(r.target.get(raw), b"/a/b?x=1");
    assert_eq!(r.path.get(raw), b"/a/b");
    assert_eq!(r.host.unwrap().get(raw), b"example.com");
    assert_eq!(header(raw, &r.headers, b"x-y"), Some(&b"z"[..]));
    assert_eq!(r.body, Body::None);
    assert!(r.keep_alive);
    assert_eq!(r.head_len, raw.len());
}

#[test]
fn incomplete_head_needs_more() {
    let raw = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    for n in 0..raw.len() {
        assert_eq!(req(&raw[..n]).map(|r| r.is_some()), Ok(false), "len {n}");
    }
}

#[test]
fn accepts_bare_lf_and_leading_empty_lines() {
    let raw = b"\r\n\nGET / HTTP/1.1\nHost: a\n\n";
    let r = req(raw).unwrap().unwrap();
    assert_eq!(r.path.get(raw), b"/");
    assert_eq!(r.head_len, raw.len());
}

#[test]
fn absolute_form_overrides_host() {
    let raw = b"GET http://b.example/p?q HTTP/1.1\r\nHost: a.example\r\n\r\n";
    let r = req(raw).unwrap().unwrap();
    assert_eq!(r.host.unwrap().get(raw), b"b.example");
    assert_eq!(r.target.get(raw), b"/p?q");
    assert_eq!(r.path.get(raw), b"/p");
}

#[test]
fn framing() {
    let r = req(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 12\r\n\r\n")
        .unwrap()
        .unwrap();
    assert_eq!(r.body, Body::Length(12));
    let r = req(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: Chunked\r\n\r\n")
        .unwrap()
        .unwrap();
    assert_eq!(r.body, Body::Chunked);
    let r = req(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n")
        .unwrap()
        .unwrap();
    assert_eq!(r.body, Body::None);
}

#[test]
fn connection_semantics() {
    let r = req(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: Close\r\n\r\n")
        .unwrap()
        .unwrap();
    assert!(!r.keep_alive);
    let r = req(b"GET / HTTP/1.0\r\n\r\n").unwrap().unwrap();
    assert!(!r.keep_alive);
    assert!(r.host.is_none());
    let r = req(b"GET / HTTP/1.0\r\nConnection: x, keep-alive\r\n\r\n")
        .unwrap()
        .unwrap();
    assert!(r.keep_alive);
    let r = req(b"GET / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\n\r\n")
        .unwrap()
        .unwrap();
    assert!(r.expect_continue);
}

#[test]
fn rejects_smuggling_vectors() {
    for (raw, want) in [
        (&b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"[..], Error::BadRequest),
        (b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n", Error::BadRequest),
        (b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1, 1\r\n\r\n", Error::BadRequest),
        (b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +1\r\n\r\n", Error::BadRequest),
        (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n", Error::BadRequest),
        (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", Error::NotImplemented),
        (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", Error::NotImplemented),
        (b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n", Error::BadRequest),
        (b"GET / HTTP/1.1\r\nHost: a\r\nX: a\rb\r\n\r\n", Error::BadRequest),
        (b"GET / HTTP/1.1\r\nHost: a\r\nX: a\r\n b\r\n\r\n", Error::BadRequest),
        (b"GET / HTTP/1.1\r\nHost: a\r\nX : b\r\n\r\n", Error::BadRequest),
        (b"GET / HTTP/1.1\r\nHost: a\r\nX: \x00\r\n\r\n", Error::BadRequest),
        (b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", Error::BadRequest),
        (b"GET / HTTP/1.1\r\n\r\n", Error::BadRequest),
        (b"GET / HTTP/1.1\r\nHost: a/b\r\n\r\n", Error::BadRequest),
        (b"GET / HTTP/1.1\r\nHost: a..b\r\n\r\n", Error::BadRequest),
        (b"GET  / HTTP/1.1\r\nHost: a\r\n\r\n", Error::BadRequest),
        (b"GET /\x7f HTTP/1.1\r\nHost: a\r\n\r\n", Error::BadRequest),
        (b"GET foo HTTP/1.1\r\nHost: a\r\n\r\n", Error::BadRequest),
        (b"G(T / HTTP/1.1\r\nHost: a\r\n\r\n", Error::BadRequest),
        (b"GET / HTTP/2.0\r\nHost: a\r\n\r\n", Error::VersionNotSupported),
        (b"GET / HTTX/1.1\r\nHost: a\r\n\r\n", Error::BadRequest),
        (b"GET /\r\n\r\n", Error::BadRequest),
    ] {
        assert_eq!(req(raw).err(), Some(want), "{:?}", String::from_utf8_lossy(raw));
    }
}

#[test]
fn bare_cr_rejected_before_line_completes() {
    assert_eq!(req(b"GET / HTTP/1.1\rX").err(), Some(Error::BadRequest));
    assert_eq!(req(b"GET / HTTP/1.1\r").map(|r| r.is_some()), Ok(false));
}

#[test]
fn header_limit() {
    let mut raw = b"GET / HTTP/1.1\r\nHost: a\r\n".to_vec();
    for _ in 0..MAX_HEADERS {
        raw.extend_from_slice(b"X: y\r\n");
    }
    raw.extend_from_slice(b"\r\n");
    assert_eq!(req(&raw).err(), Some(Error::HeaderTooLarge));
}

#[test]
fn reuse_resets_state() {
    let mut r = Request::default();
    let a =
        b"POST http://x/ HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n";
    assert_eq!(parse_request(a, &mut r), Ok(true));
    let b = b"GET /y HTTP/1.1\r\nHost: b\r\n\r\n";
    assert_eq!(parse_request(b, &mut r), Ok(true));
    assert_eq!(r.host.unwrap().get(b), b"b");
    assert_eq!(r.body, Body::None);
    assert!(!r.expect_continue);
    assert_eq!(r.headers.len(), 1);
}

#[test]
fn header_kinds() {
    let raw =
        b"GET / HTTP/1.1\r\nHost: a\r\nX-Accel-Redirect: /x\r\nKeep-Alive: 5\r\nX-Accel: y\r\n\r\n";
    let r = req(raw).unwrap().unwrap();
    let kinds: Vec<_> = r.headers.iter().map(|h| h.kind).collect();
    assert_eq!(
        kinds,
        [
            HeaderKind::Host,
            HeaderKind::Internal,
            HeaderKind::KeepAlive,
            HeaderKind::Other
        ]
    );
    assert!(HeaderKind::KeepAlive.is_hop_by_hop());
    assert!(!HeaderKind::Host.is_hop_by_hop());
}

fn resp(raw: &[u8], head: bool) -> Result<Option<Response>, Error> {
    let mut r = Response::default();
    Ok(parse_response(raw, head, &mut r)?.then_some(r))
}

#[test]
fn parses_responses() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    let r = resp(raw, false).unwrap().unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.reason.get(raw), b"OK");
    assert_eq!(r.body, Body::Length(5));
    assert!(r.keep_alive);
    assert_eq!(r.head_len, raw.len() - 5);

    let r = resp(b"HTTP/1.1 200 OK\r\n\r\n", false).unwrap().unwrap();
    assert_eq!(r.body, Body::Close);
    assert!(!r.keep_alive);

    let r = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", true)
        .unwrap()
        .unwrap();
    assert_eq!(r.body, Body::None);
    assert!(r.keep_alive);

    for status in ["204 No Content", "304 Not Modified", "100 Continue"] {
        let raw = format!("HTTP/1.1 {status}\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(
            resp(raw.as_bytes(), false).unwrap().unwrap().body,
            Body::None
        );
    }

    let r = resp(b"HTTP/1.1 200\r\nTransfer-Encoding: chunked\r\n\r\n", false)
        .unwrap()
        .unwrap();
    assert_eq!(r.body, Body::Chunked);
    assert!(r.reason.is_empty());

    let r = resp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", false)
        .unwrap()
        .unwrap();
    assert_eq!(r.body, Body::Close);

    let r = resp(b"HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\n", false)
        .unwrap()
        .unwrap();
    assert!(!r.keep_alive);
}

#[test]
fn rejects_bad_responses() {
    for raw in [
        &b"HTTP/1.1 20 OK\r\n\r\n"[..],
        b"HTTP/1.1 2000 OK\r\n\r\n",
        b"HTTP/1.1 099 X\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        b"ICY 200 OK\r\n\r\n",
    ] {
        assert_eq!(
            resp(raw, false).err(),
            Some(Error::BadRequest),
            "{:?}",
            String::from_utf8_lossy(raw)
        );
    }
}

#[test]
fn number_formatting() {
    let mut v = Vec::new();
    push_u64(&mut v, 0);
    v.push(b' ');
    push_u64(&mut v, u64::MAX);
    v.push(b' ');
    push_hex(&mut v, 0);
    v.push(b' ');
    push_hex(&mut v, 0xbeef);
    assert_eq!(v, b"0 18446744073709551615 0 beef");
}

#[test]
fn request_line_completion() {
    assert!(!request_line_complete(b"\r\nGET /aaaa"));
    assert!(request_line_complete(b"GET / HTTP/1.1\r\nHost"));
}

/// Deterministic xorshift so the property tests below need no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Mutates valid messages byte by byte. The parser must never panic, every
/// span must stay inside the head, and a complete parse of a prefix must not
/// change once more bytes arrive.
#[test]
fn mutated_requests_parse_consistently() {
    const SEEDS: &[&[u8]] = &[
        b"GET /a?b HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc",
        b"POST http://h/p HTTP/1.1\r\nHost: y\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
    ];
    const ALPHABET: &[u8] = b" \t\r\n:/?%.HTTP1.0chunkedContent-Length\x00\x7f\xff";
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..20_000 {
        let mut msg = SEEDS[rng.below(SEEDS.len())].to_vec();
        for _ in 0..=rng.below(4) {
            let at = rng.below(msg.len() + 1);
            let c = ALPHABET[rng.below(ALPHABET.len())];
            match rng.below(3) {
                0 if at < msg.len() => msg[at] = c,
                1 if at < msg.len() => {
                    msg.remove(at);
                }
                _ => msg.insert(at, c),
            }
        }
        let mut whole = Request::default();
        let full = parse_request(&msg, &mut whole);
        if let Ok(true) = full {
            let head = &msg[..whole.head_len];
            let _ = (
                whole.target.get(head),
                whole.path.get(head),
                whole.method_span.get(head),
            );
            for h in whole.headers.iter() {
                let _ = (h.name.get(head), h.value.get(head));
            }
            // The head parses identically with nothing after it.
            let mut exact = Request::default();
            assert_eq!(parse_request(head, &mut exact), Ok(true), "{msg:?}");
            assert_eq!(exact.head_len, whole.head_len);
            assert_eq!(exact.body, whole.body);
        }
        for cut in 0..msg.len() {
            let mut part = Request::default();
            match parse_request(&msg[..cut], &mut part) {
                // An error on a prefix must also be an error on the whole.
                Err(_) => assert!(full.is_err(), "prefix {cut} of {msg:?}"),
                Ok(true) => assert_eq!(full.map(|_| whole.head_len), Ok(part.head_len)),
                Ok(false) => {}
            }
        }
    }
}

#[test]
fn chunked_split_matches_whole() {
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    for _ in 0..5_000 {
        let mut body = Vec::new();
        for _ in 0..rng.below(4) {
            let n = rng.below(20) + 1;
            push_hex(&mut body, n as u64);
            if rng.below(3) == 0 {
                body.extend_from_slice(b";x=y");
            }
            body.extend_from_slice(b"\r\n");
            body.extend((0..n).map(|i| b'a' + (i % 26) as u8));
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(b"0\r\n");
        if rng.below(2) == 0 {
            body.extend_from_slice(b"T: v\r\n");
        }
        body.extend_from_slice(b"\r\nNEXT");
        if rng.below(2) == 0 {
            let at = rng.below(body.len());
            body[at] = b"\r\n;0Zz \x00"[rng.below(8)];
        }

        let mut whole = ChunkedDecoder::new();
        let mut whole_data = Vec::new();
        let whole_res = whole.advance_with(&body, |r| whole_data.extend_from_slice(&body[r]));

        let mut split = ChunkedDecoder::new();
        let mut split_data = Vec::new();
        let mut pos = 0;
        let split_res = loop {
            let end = (pos + rng.below(7) + 1).min(body.len());
            let part = &body[pos..end];
            match split.advance_with(part, |r| split_data.extend_from_slice(&part[r])) {
                Ok(n) => {
                    pos += n;
                    if split.is_done() || end == body.len() {
                        break Ok(pos);
                    }
                }
                Err(e) => break Err(e),
            }
        };
        assert_eq!(whole_res, split_res, "{:?}", String::from_utf8_lossy(&body));
        if whole_res.is_ok() {
            assert_eq!(whole.is_done(), split.is_done());
            assert_eq!(whole_data, split_data);
        }
    }
}
