//! Header changes from HeaderOps: response headers (nginx add_header, with
//! proxy_hide_header for removals) and the request sent upstream
//! (proxy_set_header).

use proxelo_snapshot::{HeaderOps, HeaderValue};

use crate::exchange::Exchange;
use crate::reply;
use crate::vars::expand;

/// Statuses nginx's add_header applies to without `always`.
fn add_header_status(status: u16) -> bool {
    matches!(
        status,
        200 | 201 | 204 | 206 | 301 | 302 | 303 | 304 | 307 | 308
    )
}

fn push(x: &mut Exchange, out: &mut Vec<u8>, h: &HeaderValue) {
    expand(x, &h.value);
    // nginx skips a header whose value is empty.
    if x.tmpl.is_empty() {
        return;
    }
    out.extend_from_slice(&h.name);
    out.extend_from_slice(b": ");
    reply::push_header_value_lenient(out, &x.tmpl);
    out.extend_from_slice(b"\r\n");
}

/// Expands the set and add lines of `ops` for a response with `status` into
/// `x.resp_extra`.
pub(crate) fn response(x: &mut Exchange, ops: &HeaderOps, status: u16) {
    let mut out = std::mem::take(&mut x.resp_extra);
    out.clear();
    out.extend_from_slice(&x.alt_svc);
    let any = add_header_status(status);
    for h in ops.set.iter().chain(ops.add.iter()) {
        if any || h.always {
            push(x, &mut out, h);
        }
    }
    // The userid filter runs after add_header.
    out.extend_from_slice(&x.uid_lines);
    x.resp_extra = out;
}

/// Appends the set and add lines of `ops` for the upstream request to `out`.
/// The caller leaves out the original headers `ops.drops`.
pub(crate) fn request(x: &mut Exchange, ops: &HeaderOps, out: &mut Vec<u8>) {
    for h in ops.set.iter().chain(ops.add.iter()) {
        push(x, out, h);
    }
}
