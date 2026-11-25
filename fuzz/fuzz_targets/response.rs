#![no_main]

use libfuzzer_sys::fuzz_target;
use proxelo_http1::{Response, parse_response};

fuzz_target!(|data: &[u8]| {
    let Some((&head_request, data)) = data.split_first() else {
        return;
    };
    let mut resp = Response::default();
    if let Ok(true) = parse_response(data, head_request & 1 == 1, &mut resp) {
        assert!(resp.head_len <= data.len());
        let head = &data[..resp.head_len];
        let _ = resp.reason.get(head);
        for h in resp.headers.iter() {
            let _ = h.name.get(head);
            let _ = h.value.get(head);
        }
        assert!((100..1000).contains(&resp.status));
    }
});
