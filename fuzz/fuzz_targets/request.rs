#![no_main]

use libfuzzer_sys::fuzz_target;
use proxelo_http1::{Request, parse_request};

fuzz_target!(|data: &[u8]| {
    let mut req = Request::default();
    if let Ok(true) = parse_request(data, &mut req) {
        // Every span must lie inside the parsed head.
        assert!(req.head_len <= data.len());
        let head = &data[..req.head_len];
        let _ = req.target.get(head);
        let _ = req.path.get(head);
        let _ = req.method_span.get(head);
        if let Some(h) = req.host {
            let _ = h.get(head);
        }
        for h in req.headers.iter() {
            let _ = h.name.get(head);
            let _ = h.value.get(head);
        }
        // Parsing is a pure function of the bytes: a reused Request must
        // give the same result.
        let mut again = Request::default();
        parse_request(data, &mut again).unwrap();
        assert_eq!(again.head_len, req.head_len);
        assert_eq!(again.body, req.body);
    }
});
