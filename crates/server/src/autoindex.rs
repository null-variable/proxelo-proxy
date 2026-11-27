//! nginx autoindex (directory listings in HTML, JSON, JSONP or XML) and
//! random_index.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::time::UNIX_EPOCH;

use proxelo_http1::{Method, http_date, push_u64};

use proxelo_snapshot::{Autoindex, AutoindexFormat};

use crate::conn::{Conn, KeepAlive, keeps_alive};
use crate::exchange::Exchange;
use crate::reply;

/// Longest name shown in the HTML listing; longer ones end in "..>".
const NAME_LEN: usize = 50;

struct Entry {
    name: Vec<u8>,
    dir: bool,
    file: bool,
    mtime: i64,
    size: u64,
}

/// Reads the entries of `dir` as nginx lists them: dot files skipped,
/// symlinks followed (dangling ones listed as themselves), directories
/// first, then by name bytes.
fn entries(dir: &[u8]) -> Result<Vec<Entry>, u16> {
    let rd = fs::read_dir(OsStr::from_bytes(dir)).map_err(|e| status(&e))?;
    let mut out = Vec::new();
    for e in rd {
        let e = e.map_err(|_| 500u16)?;
        let name = e.file_name().as_bytes().to_vec();
        if name.first() == Some(&b'.') {
            continue;
        }
        let meta = match fs::metadata(e.path()) {
            Ok(m) => m,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => continue,
            Err(_) => match fs::symlink_metadata(e.path()) {
                Ok(m) => m,
                Err(_) => return Err(500),
            },
        };
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs() as i64);
        out.push(Entry {
            name,
            dir: meta.is_dir(),
            file: meta.is_file(),
            mtime,
            size: meta.len(),
        });
    }
    out.sort_by(|a, b| b.dir.cmp(&a.dir).then_with(|| a.name.cmp(&b.name)));
    Ok(out)
}

fn status(e: &io::Error) -> u16 {
    match e.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory | io::ErrorKind::InvalidFilename => {
            404
        }
        io::ErrorKind::PermissionDenied => 403,
        _ => 500,
    }
}

/// random_index: extends `path` with a random regular file of the directory
/// `root` + `path`. False when it has none or cannot be read.
pub(crate) fn random_file(x: &mut Exchange, root: &[u8]) -> bool {
    let dir = &mut x.scratch;
    dir.clear();
    dir.extend_from_slice(root);
    dir.extend_from_slice(&x.path);
    let Ok(rd) = fs::read_dir(OsStr::from_bytes(dir)) else {
        return false;
    };
    let names: Vec<Vec<u8>> = rd
        .filter_map(|e| {
            let e = e.ok()?;
            let name = e.file_name().as_bytes().to_vec();
            (name.first() != Some(&b'.') && fs::metadata(e.path()).ok()?.is_file()).then_some(name)
        })
        .collect();
    if names.is_empty() {
        return false;
    }
    let pick = &names[(crate::upstream::rand() % names.len() as u64) as usize];
    x.path.extend_from_slice(pick);
    true
}

/// nginx ngx_escape_html: <, >, & and ".
fn push_html(out: &mut Vec<u8>, s: &[u8]) {
    for &c in s {
        match c {
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'&' => out.extend_from_slice(b"&amp;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            _ => out.push(c),
        }
    }
}

/// nginx NGX_ESCAPE_URI_COMPONENT: everything but unreserved characters
/// and the sub-delimiters nginx leaves alone.
fn push_component(out: &mut Vec<u8>, s: &[u8]) {
    const TABLE: [u32; 8] = [
        0xffff_ffff,
        0xfc00_9fff,
        0x7800_0001,
        0xb800_0001,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
    ];
    for &c in s {
        if TABLE[usize::from(c >> 5)] & (1 << (c & 31)) != 0 {
            out.push(b'%');
            out.push(b"0123456789ABCDEF"[usize::from(c >> 4)]);
            out.push(b"0123456789ABCDEF"[usize::from(c & 15)]);
        } else {
            out.push(c);
        }
    }
}

/// nginx ngx_escape_json.
fn push_json(out: &mut Vec<u8>, s: &[u8]) {
    for &c in s {
        match c {
            b'\\' | b'"' => {
                out.push(b'\\');
                out.push(c);
            }
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            0..=0x1f => {
                out.extend_from_slice(b"\\u00");
                out.push(b'0' + (c >> 4));
                out.push(b"0123456789ABCDEF"[usize::from(c & 15)]);
            }
            _ => out.push(c),
        }
    }
}

/// Days since the epoch to (year, month, day).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn html(out: &mut Vec<u8>, uri: &[u8], list: &[Entry], ai: &Autoindex, offset: i64) {
    out.extend_from_slice(b"<html>\r\n<head><title>Index of ");
    push_html(out, uri);
    out.extend_from_slice(b"</title></head>\r\n<body>\r\n<h1>Index of ");
    push_html(out, uri);
    out.extend_from_slice(b"</h1><hr><pre><a href=\"../\">../</a>\r\n");
    for e in list {
        out.extend_from_slice(b"<a href=\"");
        push_component(out, &e.name);
        if e.dir {
            out.push(b'/');
        }
        out.extend_from_slice(b"\">");
        // Responses carry no charset, so nginx counts bytes, not
        // characters: names are cut and padded by byte length.
        let mut len = e.name.len();
        let shown = if len > NAME_LEN {
            &e.name[..NAME_LEN - 3]
        } else {
            &e.name[..]
        };
        push_html(out, shown);
        if len > NAME_LEN {
            out.extend_from_slice(b"..&gt;</a>");
        } else {
            if e.dir && NAME_LEN > len {
                out.push(b'/');
                len += 1;
            }
            out.extend_from_slice(b"</a>");
            out.resize(out.len() + NAME_LEN.saturating_sub(len), b' ');
        }
        out.push(b' ');
        let t = e.mtime + if ai.localtime { offset } else { 0 };
        let (y, m, d) = civil(t.div_euclid(86_400));
        let secs = t.rem_euclid(86_400);
        use std::io::Write as _;
        let _ = write!(
            out,
            "{d:02}-{}-{y} {:02}:{:02} ",
            MONTHS[m as usize - 1],
            secs / 3600,
            secs / 60 % 60
        );
        if ai.exact_size {
            if e.dir {
                out.extend_from_slice(b"                  -");
            } else {
                let _ = write!(out, "{:>19}", e.size);
            }
        } else if e.dir {
            out.extend_from_slice(b"      -");
        } else {
            let (size, scale) = approximate(e.size);
            match scale {
                Some(c) => {
                    let _ = write!(out, "{size:>6}{c}");
                }
                None => {
                    let _ = write!(out, " {size:>6}");
                }
            }
        }
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"</pre><hr></body>\r\n</html>\r\n");
}

/// autoindex_exact_size off: rounded to K, M or G.
fn approximate(len: u64) -> (u64, Option<char>) {
    const K: u64 = 1024;
    const M: u64 = K * K;
    const G: u64 = M * K;
    let round = |unit: u64| len / unit + u64::from(len % unit > unit / 2 - 1);
    if len > G - 1 {
        (round(G), Some('G'))
    } else if len > M - 1 {
        (round(M), Some('M'))
    } else if len > 9999 {
        (len / K + u64::from(len % K > 511), Some('K'))
    } else {
        (len, None)
    }
}

fn kind(e: &Entry) -> &'static [u8] {
    if e.dir {
        b"directory"
    } else if e.file {
        b"file"
    } else {
        b"other"
    }
}

fn json(out: &mut Vec<u8>, list: &[Entry], callback: Option<&[u8]>) {
    if let Some(cb) = callback {
        out.extend_from_slice(b"/* callback */\r\n");
        out.extend_from_slice(cb);
        out.push(b'(');
    }
    out.push(b'[');
    for (i, e) in list.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(b"\r\n{ \"name\":\"");
        push_json(out, &e.name);
        out.extend_from_slice(b"\", \"type\":\"");
        out.extend_from_slice(kind(e));
        out.extend_from_slice(b"\", \"mtime\":\"");
        out.extend_from_slice(&http_date(e.mtime.max(0) as u64));
        if e.file {
            out.extend_from_slice(b"\", \"size\":");
            push_u64(out, e.size);
        } else {
            out.push(b'"');
        }
        out.extend_from_slice(b" }");
    }
    out.extend_from_slice(b"\r\n]");
    if callback.is_some() {
        out.extend_from_slice(b");");
    }
}

fn xml(out: &mut Vec<u8>, list: &[Entry]) {
    use std::io::Write as _;
    out.extend_from_slice(b"<?xml version=\"1.0\"?>\r\n<list>\r\n");
    for e in list {
        let k = kind(e);
        out.push(b'<');
        out.extend_from_slice(k);
        let (y, m, d) = civil(e.mtime.div_euclid(86_400));
        let s = e.mtime.rem_euclid(86_400);
        let _ = write!(
            out,
            " mtime=\"{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            s / 3600,
            s / 60 % 60,
            s % 60
        );
        if e.file {
            out.extend_from_slice(b"\" size=\"");
            push_u64(out, e.size);
        }
        out.extend_from_slice(b"\">");
        push_html(out, &e.name);
        out.extend_from_slice(b"</");
        out.extend_from_slice(k);
        out.extend_from_slice(b">\r\n");
    }
    out.extend_from_slice(b"</list>\r\n");
}

/// The JSONP callback argument: `Ok(None)` without one, `Err` when it is
/// too long or has characters other than letters, digits, `_` and `.`.
fn callback(args: &[u8]) -> Result<Option<&[u8]>, ()> {
    let Some(v) = args
        .split(|&c| c == b'&')
        .find_map(|kv| kv.strip_prefix(b"callback="))
    else {
        return Ok(None);
    };
    if v.is_empty() {
        return Ok(None);
    }
    if v.len() > 128
        || !v
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b'.')
    {
        return Err(());
    }
    Ok(Some(v))
}

impl Conn {
    /// Answers with the listing of the directory in `scratch`.
    pub async fn send_autoindex(&mut self, ai: Autoindex) -> Result<KeepAlive, u16> {
        let mut format = ai.format;
        let mut cb = None;
        if format == AutoindexFormat::Jsonp {
            match callback(&self.x.args) {
                Ok(Some(c)) => cb = Some(c.to_vec()),
                Ok(None) => format = AutoindexFormat::Json,
                Err(()) => return Err(400),
            }
        }
        let list = entries(&self.x.scratch)?;
        let offset = if ai.localtime {
            i64::from(crate::worker::utc_offset())
        } else {
            0
        };
        let mut body = std::mem::take(&mut self.zout);
        body.clear();
        let ctype: &[u8] = match format {
            AutoindexFormat::Html => {
                html(&mut body, &self.x.path, &list, &ai, offset);
                b"text/html"
            }
            AutoindexFormat::Json => {
                json(&mut body, &list, None);
                b"application/json"
            }
            AutoindexFormat::Jsonp => {
                json(&mut body, &list, cb.as_deref());
                b"application/javascript"
            }
            AutoindexFormat::Xml => {
                xml(&mut body, &list);
                b"text/xml; charset=utf-8"
            }
        };
        // nginx streams the listing without a length: chunked to HTTP/1.1
        // clients, ended by closing for HTTP/1.0 ones.
        let status = self.x.status(200);
        let head = self.x.req.method == Method::Head;
        let chunked = crate::compress::chunked_for(&self.x);
        let keep = self.x.req.keep_alive && keeps_alive(status) && (chunked || head);
        let out = &mut self.out;
        out.clear();
        reply::start(out, status, b"");
        out.extend_from_slice(b"Content-Type: ");
        out.extend_from_slice(ctype);
        out.extend_from_slice(b"\r\n");
        if chunked && !head {
            out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }
        reply::connection(out, keep, &self.x.resp_extra);
        out.extend_from_slice(b"\r\n");
        let start = out.len();
        if !head {
            if chunked {
                crate::compress::push_chunk(out, &body);
                out.extend_from_slice(b"0\r\n\r\n");
            } else {
                out.extend_from_slice(&body);
            }
        }
        let n = out.len() - start;
        self.zout = body;
        self.x.sent.status = status;
        self.x.sent.bytes = self.out.len() as u64;
        self.x.sent.body_bytes = n as u64;
        Ok(self.respond(keep).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, dir: bool, size: u64) -> Entry {
        Entry {
            name: name.into(),
            dir,
            file: !dir,
            mtime: 1_700_000_000,
            size,
        }
    }

    #[test]
    fn html_matches_nginx_layout() {
        let list = [
            entry("sub", true, 4096),
            entry("a b<.txt", false, 12),
            entry(&"x".repeat(60), false, 20_000),
        ];
        let ai = Autoindex {
            format: AutoindexFormat::Html,
            localtime: false,
            exact_size: true,
        };
        let mut out = Vec::new();
        html(&mut out, b"/d/", &list, &ai, 0);
        let s = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = s.split("\r\n").collect();
        assert_eq!(lines[0], "<html>");
        assert_eq!(lines[1], "<head><title>Index of /d/</title></head>");
        assert_eq!(
            lines[3],
            "<h1>Index of /d/</h1><hr><pre><a href=\"../\">../</a>"
        );
        assert_eq!(
            lines[4],
            format!(
                "<a href=\"sub/\">sub/</a>{} 14-Nov-2023 22:13 {:>19}",
                " ".repeat(46),
                "-"
            )
        );
        assert_eq!(
            lines[5],
            format!(
                "<a href=\"a%20b%3C.txt\">a b&lt;.txt</a>{} 14-Nov-2023 22:13 {:>19}",
                " ".repeat(42),
                12
            )
        );
        assert!(lines[6].starts_with(&format!(
            "<a href=\"{0}\">{1}..&gt;</a> ",
            "x".repeat(60),
            "x".repeat(47)
        )));
        assert_eq!(lines[7], "</pre><hr></body>");
    }

    #[test]
    fn approximate_sizes_round_like_nginx() {
        assert_eq!(approximate(9999), (9999, None));
        assert_eq!(approximate(10_000), (10, Some('K')));
        assert_eq!(approximate(10_752), (11, Some('K')));
        assert_eq!(approximate(1024 * 1024), (1, Some('M')));
        assert_eq!(approximate(3 * 1024 * 1024 * 1024 / 2), (2, Some('G')));
    }

    #[test]
    fn json_and_xml() {
        let list = [entry("d", true, 0), entry("f\"1", false, 3)];
        let mut out = Vec::new();
        json(&mut out, &list, Some(b"cb"));
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "/* callback */\r\ncb([\r\n{ \"name\":\"d\", \"type\":\"directory\", \"mtime\":\"Tue, 14 Nov 2023 22:13:20 GMT\" },\r\n{ \"name\":\"f\\\"1\", \"type\":\"file\", \"mtime\":\"Tue, 14 Nov 2023 22:13:20 GMT\", \"size\":3 }\r\n]);"
        );
        let mut out = Vec::new();
        xml(&mut out, &list[1..]);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "<?xml version=\"1.0\"?>\r\n<list>\r\n<file mtime=\"2023-11-14T22:13:20Z\" size=\"3\">f&quot;1</file>\r\n</list>\r\n"
        );
        assert_eq!(callback(b"a=1&callback=x.y_2"), Ok(Some(&b"x.y_2"[..])));
        assert_eq!(callback(b"callback=a(b)"), Err(()));
        assert_eq!(callback(b"x=1"), Ok(None));
    }
}
