#![no_main]

use libfuzzer_sys::fuzz_target;
use proxelo_http1::normalize_path;

fuzz_target!(|raw: &[u8]| {
    let mut out = Vec::new();
    if normalize_path(raw, &mut out).is_ok() {
        // A normalized path is absolute, has no empty, `.` or `..` segments
        // and no NUL byte.
        assert_eq!(out.first(), Some(&b'/'));
        assert!(!out.windows(2).any(|w| w == b"//"));
        for seg in out.split(|&c| c == b'/') {
            assert!(seg != b"." && seg != b"..", "{out:?}");
        }
        assert!(!out.contains(&0));
    }
});
