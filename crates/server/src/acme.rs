//! ACME challenges the control plane hands down. The proxy
//! has no ACME client; it only answers what it is told to.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use arc_swap::ArcSwap;

const PREFIX: &[u8] = b"/.well-known/acme-challenge/";

/// Token to key authorization.
type Answers = HashMap<Box<[u8]>, Box<[u8]>>;

static HTTP: LazyLock<ArcSwap<Answers>> = LazyLock::new(|| ArcSwap::from_pointee(HashMap::new()));

/// Replaces the HTTP-01 answers: token to key authorization.
pub fn set_http_challenges(list: &[(String, String)]) {
    let map = list
        .iter()
        .map(|(t, k)| (t.as_bytes().into(), k.as_bytes().into()))
        .collect();
    HTTP.store(Arc::new(map));
}

/// The key authorization for a challenge path, appended to `out`.
pub(crate) fn http_answer(path: &[u8], out: &mut Vec<u8>) -> bool {
    let Some(token) = path.strip_prefix(PREFIX) else {
        return false;
    };
    let all = HTTP.load();
    match all.get(token) {
        Some(k) => {
            out.clear();
            out.extend_from_slice(k);
            true
        }
        None => false,
    }
}
