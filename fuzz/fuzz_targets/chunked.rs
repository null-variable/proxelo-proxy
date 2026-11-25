#![no_main]

use libfuzzer_sys::fuzz_target;
use proxelo_http1::ChunkedDecoder;

// Feeding the body in arbitrary pieces must give the same end position and
// data as feeding it whole.
fuzz_target!(|input: (Vec<u8>, Vec<u8>)| {
    let (body, cuts) = input;
    let mut whole = ChunkedDecoder::new();
    let mut whole_data = Vec::new();
    let whole_res = whole.advance_with(&body, |r| whole_data.extend_from_slice(&body[r]));

    let mut split = ChunkedDecoder::new();
    let mut split_data = Vec::new();
    let mut pos = 0;
    let mut split_res = Ok(0);
    for &c in cuts.iter().chain(std::iter::once(&u8::MAX)) {
        let end = (pos + usize::from(c) + 1).min(body.len());
        let part = &body[pos..end];
        match split.advance_with(part, |r| split_data.extend_from_slice(&part[r])) {
            Ok(n) => {
                pos += n;
                split_res = Ok(pos);
                if split.is_done() || end == body.len() {
                    break;
                }
            }
            Err(e) => {
                split_res = Err(e);
                break;
            }
        }
    }
    if pos < body.len() && !split.is_done() && split_res.is_ok() {
        // Ran out of cuts before the body; finish it in one piece.
        let part = &body[pos..];
        split_res = split
            .advance_with(part, |r| split_data.extend_from_slice(&part[r]))
            .map(|n| pos + n);
    }
    assert_eq!(whole_res, split_res);
    if whole_res.is_ok() {
        assert_eq!(whole.is_done(), split.is_done());
        assert_eq!(whole_data, split_data);
    }
});
