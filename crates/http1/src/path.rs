//! URI path normalization with nginx semantics.
//!
//! nginx routes and serves files by the decoded, normalized path: `%XX` is
//! decoded, `//` is merged, `.` and `..` segments are resolved. A `..` above
//! the root is a 400. The query string is not part of the input.

use crate::Error;

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Writes the normalized form of `raw` into `out`, replacing its contents.
/// `out` keeps its capacity so a reused buffer does not allocate once warm.
pub fn normalize_path(raw: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    out.clear();
    if raw.first() != Some(&b'/') {
        return Err(Error::BadRequest);
    }
    let mut i = 0;
    while i < raw.len() {
        let mut c = raw[i];
        i += 1;
        if c == b'%' {
            let (Some(h), Some(l)) = (
                raw.get(i).copied().and_then(hex),
                raw.get(i + 1).copied().and_then(hex),
            ) else {
                return Err(Error::BadRequest);
            };
            c = h << 4 | l;
            i += 2;
        }
        if c == 0 {
            return Err(Error::BadRequest);
        }
        if c == b'/' {
            if out.last() == Some(&b'/') {
                continue;
            }
            if !resolve_dots(out)? {
                out.push(b'/');
            }
            continue;
        }
        out.push(c);
    }
    resolve_dots(out)?;
    Ok(())
}

/// Resolves a trailing `/.` or `/..` segment in `out`. Returns whether one was
/// resolved; `out` then ends with `/`.
fn resolve_dots(out: &mut Vec<u8>) -> Result<bool, Error> {
    if out.ends_with(b"/.") {
        out.pop();
        return Ok(true);
    }
    if out.ends_with(b"/..") {
        out.truncate(out.len() - 3);
        let Some(slash) = out.iter().rposition(|&c| c == b'/') else {
            return Err(Error::BadRequest);
        };
        out.truncate(slash + 1);
        return Ok(true);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(raw: &str) -> Result<String, Error> {
        let mut out = Vec::new();
        normalize_path(raw.as_bytes(), &mut out)?;
        Ok(String::from_utf8(out).unwrap())
    }

    #[test]
    fn normalizes() {
        for (raw, want) in [
            ("/", "/"),
            ("/a/b", "/a/b"),
            ("/a//b///c", "/a/b/c"),
            ("/a/./b/.", "/a/b/"),
            ("/a/b/../c", "/a/c"),
            ("/a/b/..", "/a/"),
            ("/a/..", "/"),
            ("/%61%2Fb", "/a/b"),
            ("/a%2f..%2fb", "/b"),
            ("/a/.b/..c", "/a/.b/..c"),
            ("/%20x", "/ x"),
        ] {
            assert_eq!(norm(raw).as_deref(), Ok(want), "{raw}");
        }
    }

    #[test]
    fn rejects() {
        for raw in ["", "a", "/..", "/a/../..", "/%2e%2e", "/%zz", "/%4", "/%00", "/(\0}"] {
            assert_eq!(norm(raw), Err(Error::BadRequest), "{raw}");
        }
    }
}
