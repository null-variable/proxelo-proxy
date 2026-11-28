//! nginx ssi: server-side includes in response bodies.
//!
//! The body streams through a byte parser like nginx's; each complete
//! `<!--#command param="value" -->` runs in place, so an include's answer is
//! output where the command was. Variables, blocks and the captures of `if`
//! regexes are shared by a request and its subrequests ([`Shared`]); the
//! rest of the state (conditionals, `config`) is per response.

use std::future::Future;
use std::io::Write as _;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};

use jiff::Timestamp;
use jiff::tz::TimeZone;
use proxelo_snapshot::{Captures, Pattern, variable};

use crate::exchange::Exchange;

/// nginx NGX_HTTP_SSI_COMMAND_LEN, NGX_HTTP_SSI_PARAM_LEN and
/// NGX_HTTP_SSI_MAX_PARAMS.
const COMMAND_LEN: usize = 32;
const PARAM_LEN: usize = 32;
const MAX_PARAMS: usize = 16;
const START: &[u8; 5] = b"<!--#";
const ERRMSG: &[u8] = b"[an error occurred while processing the directive]";
const TIMEFMT: &[u8] = b"%A, %d-%b-%Y %H:%M:%S %Z";

/// What the main request and its subrequests see alike (nginx keeps it in
/// the main request's context).
#[derive(Default)]
pub(crate) struct Shared {
    /// Lowercase names; set by `set`, `include set=` and named captures.
    vars: Vec<(Vec<u8>, Vec<u8>)>,
    /// Defined by `block`; the first of a name is the one used.
    blocks: Vec<(Vec<u8>, Vec<u8>)>,
    /// `$0`..`$9` of the last `if` regex that matched.
    caps: Captures,
}

impl Shared {
    fn set(&mut self, name: &[u8], value: Vec<u8>) {
        match self.vars.iter_mut().find(|(k, _)| k == name) {
            Some((_, v)) => *v = value,
            None => self.vars.push((name.to_vec(), value)),
        }
    }
}

pub(crate) type SharedRef = Arc<Mutex<Shared>>;

fn lock(s: &SharedRef) -> MutexGuard<'_, Shared> {
    s.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Text,
    /// Matched `n` bytes of `<!--#`.
    Tag(usize),
    PreCommand,
    Command,
    PreParam,
    Param,
    PreEqual,
    PreValue,
    /// Inside a value quoted by the byte.
    Value(u8),
    /// After a backslash in a value.
    Quoted(u8),
    PostParam,
    End0,
    End1,
    Error,
    ErrorEnd0,
    ErrorEnd1,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Encoding {
    None,
    Url,
    Entity,
}

/// The `if` state a command needs (nginx NGX_HTTP_SSI_COND_IF and _ELSE):
/// `elif` and `else` only after an `if`, `endif` after either.
const COND_IF: u8 = 1;
const COND_ELSE: u8 = 2;

struct Command {
    name: &'static [u8],
    /// Names and whether each is mandatory.
    params: &'static [(&'static [u8], bool)],
    cond: u8,
    /// Runs inside a block (only `endblock`).
    block: bool,
}

const COMMANDS: &[Command] = &[
    Command {
        name: b"include",
        params: &[
            (b"virtual", false),
            (b"file", false),
            (b"wait", false),
            (b"set", false),
            (b"stub", false),
        ],
        cond: 0,
        block: false,
    },
    Command {
        name: b"echo",
        params: &[(b"var", true), (b"default", false), (b"encoding", false)],
        cond: 0,
        block: false,
    },
    Command {
        name: b"config",
        params: &[(b"errmsg", false), (b"timefmt", false)],
        cond: 0,
        block: false,
    },
    Command {
        name: b"set",
        params: &[(b"var", true), (b"value", true)],
        cond: 0,
        block: false,
    },
    Command {
        name: b"if",
        params: &[(b"expr", true)],
        cond: 0,
        block: false,
    },
    Command {
        name: b"elif",
        params: &[(b"expr", true)],
        cond: COND_IF,
        block: false,
    },
    Command {
        name: b"else",
        params: &[],
        cond: COND_IF,
        block: false,
    },
    Command {
        name: b"endif",
        params: &[],
        cond: COND_ELSE,
        block: false,
    },
    Command {
        name: b"block",
        params: &[(b"name", true)],
        cond: 0,
        block: false,
    },
    Command {
        name: b"endblock",
        params: &[],
        cond: 0,
        block: true,
    },
];

/// A command failed: its place gets the error message.
struct Failed;

fn fail(msg: std::fmt::Arguments<'_>) -> Failed {
    eprintln!("ssi: {msg}");
    Failed
}

/// The ssi filter of one response body.
pub(crate) struct Ssi {
    shared: SharedRef,
    silent: bool,
    value_len: usize,
    state: State,
    command: Vec<u8>,
    params: Vec<(Vec<u8>, Vec<u8>)>,
    /// Text is output (false in a branch not taken and in a block).
    output: bool,
    /// A branch of the current `if` was taken.
    chosen: bool,
    cond: u8,
    /// The block being defined, with its text so far.
    block: Option<(Vec<u8>, Vec<u8>)>,
    encoding: Encoding,
    errmsg: Vec<u8>,
    timefmt: Vec<u8>,
}

impl Ssi {
    /// The filter for a response of `x`, sharing the variables of its main
    /// request.
    pub fn new(x: &mut Exchange, conf: &proxelo_snapshot::Ssi) -> Self {
        let shared = Arc::clone(x.ssi.get_or_insert_with(SharedRef::default));
        Self::with(shared, conf.silent_errors, conf.value_length)
    }

    fn with(shared: SharedRef, silent: bool, value_len: usize) -> Self {
        Self {
            shared,
            silent,
            value_len,
            state: State::Text,
            command: Vec::new(),
            params: Vec::new(),
            output: true,
            chosen: false,
            cond: 0,
            block: None,
            encoding: Encoding::Entity,
            errmsg: ERRMSG.to_vec(),
            timefmt: TIMEFMT.to_vec(),
        }
    }

    /// Feeds body bytes of `x`; the output goes to the end of `out`. With
    /// `last`, the body ends after `data`.
    pub fn write<'a>(
        &'a mut self,
        x: &'a mut Exchange,
        data: &'a [u8],
        last: bool,
        out: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let mut i = 0;
            while i < data.len() {
                if self.state == State::Text {
                    let end = data[i..]
                        .iter()
                        .position(|&c| c == b'<')
                        .map_or(data.len(), |p| i + p);
                    self.text(&data[i..end], out);
                    if end < data.len() {
                        self.state = State::Tag(1);
                    }
                    i = end + 1;
                    continue;
                }
                let c = data[i];
                i += 1;
                match self.step(c, out) {
                    Step::Next => {}
                    Step::Run => {
                        if let Err(Failed) = self.run(x, out).await {
                            self.error(out);
                        }
                        self.params.clear();
                    }
                    Step::Failed => {
                        self.params.clear();
                        self.error(out);
                    }
                }
            }
            if last {
                if let State::Tag(n) = self.state {
                    self.text(&START[..n], out);
                }
                // nginx drops a command cut by the end of the body.
                self.state = State::Text;
                self.end_block();
            }
        })
    }

    fn text(&mut self, t: &[u8], out: &mut Vec<u8>) {
        if self.output {
            out.extend_from_slice(t);
        } else if let Some((_, b)) = &mut self.block {
            b.extend_from_slice(t);
        }
    }

    fn error(&self, out: &mut Vec<u8>) {
        if !self.silent {
            out.extend_from_slice(&self.errmsg);
        }
    }

    /// One byte of a tag or command (nginx ngx_http_ssi_parse).
    fn step(&mut self, c: u8, out: &mut Vec<u8>) -> Step {
        let space = matches!(c, b' ' | b'\r' | b'\n' | b'\t');
        self.state = match self.state {
            State::Text => unreachable!("text is consumed in bulk"),
            State::Tag(n) if c == START[n] => {
                if n + 1 == START.len() {
                    State::PreCommand
                } else {
                    State::Tag(n + 1)
                }
            }
            State::Tag(n) => {
                self.text(&START[..n], out);
                if c == b'<' {
                    State::Tag(1)
                } else {
                    self.text(&[c], out);
                    State::Text
                }
            }
            State::PreCommand if space => State::PreCommand,
            State::PreCommand => {
                self.command.clear();
                self.command.push(c);
                self.params.clear();
                State::Command
            }
            State::Command if space => State::PreParam,
            State::Command if c == b'-' => State::End0,
            State::Command if self.command.len() == COMMAND_LEN => {
                fail(format_args!("the {:?} command is too long", self.name()));
                State::Error
            }
            State::Command => {
                self.command.push(c);
                State::Command
            }
            State::PreParam if space => State::PreParam,
            State::PreParam if c == b'-' => State::End0,
            State::PreParam if self.params.len() == MAX_PARAMS => {
                fail(format_args!("too many {:?} parameters", self.name()));
                State::Error
            }
            State::PreParam => {
                self.params.push((vec![c], Vec::new()));
                State::Param
            }
            State::Param if space => State::PreEqual,
            State::Param if c == b'=' => State::PreValue,
            State::Param if c == b'-' => self.unexpected(c, State::ErrorEnd0),
            State::Param => {
                let key = &mut self.params.last_mut().expect("a parameter").0;
                if key.len() == PARAM_LEN {
                    fail(format_args!("too long parameter in {:?}", self.name()));
                    State::Error
                } else {
                    key.push(c);
                    State::Param
                }
            }
            State::PreEqual if space => State::PreEqual,
            State::PreEqual if c == b'=' => State::PreValue,
            State::PreEqual | State::PreValue if c == b'-' => self.unexpected(c, State::ErrorEnd0),
            State::PreEqual => self.unexpected(c, State::Error),
            State::PreValue if space => State::PreValue,
            State::PreValue if c == b'"' || c == b'\'' => State::Value(c),
            State::PreValue => self.unexpected(c, State::Error),
            State::Value(q) if c == q => State::PostParam,
            State::Value(q) | State::Quoted(q) => {
                let next = if c == b'\\' && self.state == State::Value(q) {
                    State::Quoted(q)
                } else {
                    State::Value(q)
                };
                let value = &mut self.params.last_mut().expect("a parameter").1;
                if value.len() == self.value_len {
                    fail(format_args!("too long value in {:?}", self.name()));
                    State::Error
                } else {
                    value.push(c);
                    next
                }
            }
            State::PostParam if space => State::PreParam,
            State::PostParam if c == b'-' => State::End0,
            State::End0 if c == b'-' => State::End1,
            State::PostParam | State::End0 => self.unexpected(c, State::Error),
            State::End1 if c == b'>' => {
                self.state = State::Text;
                return Step::Run;
            }
            State::End1 => self.unexpected(c, State::Error),
            State::Error if c == b'-' => State::ErrorEnd0,
            State::ErrorEnd0 if c == b'-' => State::ErrorEnd1,
            State::ErrorEnd1 if c == b'>' => {
                self.state = State::Text;
                return Step::Failed;
            }
            State::Error | State::ErrorEnd0 | State::ErrorEnd1 => State::Error,
        };
        Step::Next
    }

    fn name(&self) -> String {
        String::from_utf8_lossy(&self.command).into_owned()
    }

    fn unexpected(&self, c: u8, then: State) -> State {
        fail(format_args!(
            "unexpected {:?} symbol in {:?} command",
            char::from(c),
            self.name()
        ));
        then
    }

    /// Runs the command just parsed.
    async fn run(&mut self, x: &mut Exchange, out: &mut Vec<u8>) -> Result<(), Failed> {
        let Some(cmd) = COMMANDS.iter().find(|c| c.name == self.command) else {
            if self.output {
                return Err(fail(format_args!("invalid command {:?}", self.name())));
            }
            return Ok(());
        };
        if !self.output && !cmd.block {
            if let Some((_, b)) = &mut self.block {
                // Kept as text, to run when the block is output.
                b.extend_from_slice(b"<!--#");
                b.extend_from_slice(&self.command);
                for (k, v) in &self.params {
                    b.push(b' ');
                    b.extend_from_slice(k);
                    b.extend_from_slice(b"=\"");
                    b.extend_from_slice(v);
                    b.push(b'"');
                }
                b.extend_from_slice(b" -->");
                return Ok(());
            }
            if cmd.cond == 0 {
                return Ok(());
            }
        }
        if cmd.cond != 0 && (self.cond == 0 || self.cond > cmd.cond) {
            return Err(fail(format_args!("invalid context of {:?}", self.name())));
        }
        let mut at = [None::<usize>; 5];
        for (i, (k, _)) in self.params.iter().enumerate() {
            let Some(j) = cmd.params.iter().position(|(n, _)| n == k) else {
                return Err(fail(format_args!(
                    "invalid parameter name {:?} in {:?}",
                    String::from_utf8_lossy(k),
                    self.name()
                )));
            };
            if at[j].replace(i).is_some() {
                return Err(fail(format_args!(
                    "duplicate {:?} parameter in {:?}",
                    String::from_utf8_lossy(k),
                    self.name()
                )));
            }
        }
        for (j, (n, mandatory)) in cmd.params.iter().enumerate() {
            if *mandatory && at[j].is_none() {
                return Err(fail(format_args!(
                    "mandatory {:?} parameter is absent in {:?}",
                    String::from_utf8_lossy(n),
                    self.name()
                )));
            }
        }
        let params = std::mem::take(&mut self.params);
        let p = |j: usize| at[j].map(|i| &params[i].1[..]);
        let r = match cmd.name {
            b"include" => self.include(x, [p(0), p(1), p(2), p(3), p(4)], out).await,
            b"echo" => self.echo(x, p(0).unwrap_or_default(), p(1), p(2), out),
            b"config" => {
                if let Some(t) = p(1) {
                    self.timefmt = t.to_vec();
                }
                if let Some(e) = p(0) {
                    self.errmsg = e.to_vec();
                }
                Ok(())
            }
            b"set" => {
                let value = self.evaluate(x, p(1).unwrap_or_default(), false)?;
                let name = p(0).unwrap_or_default().to_ascii_lowercase();
                lock(&self.shared).set(&name, value);
                Ok(())
            }
            b"if" | b"elif" => self.when(x, p(0).unwrap_or_default(), cmd.name == b"if"),
            b"else" => {
                self.output = !self.chosen;
                self.cond = COND_ELSE;
                Ok(())
            }
            b"endif" => {
                self.output = true;
                self.chosen = false;
                self.cond = 0;
                Ok(())
            }
            b"block" => {
                self.block = Some((p(0).unwrap_or_default().to_vec(), Vec::new()));
                self.output = false;
                Ok(())
            }
            _ => {
                self.end_block();
                self.output = true;
                Ok(())
            }
        };
        self.params = params;
        r
    }

    fn end_block(&mut self) {
        if let Some(b) = self.block.take() {
            lock(&self.shared).blocks.push(b);
        }
    }

    /// `include`: `params` are virtual, file, wait, set and stub.
    async fn include(
        &mut self,
        x: &mut Exchange,
        params: [Option<&[u8]>; 5],
        out: &mut Vec<u8>,
    ) -> Result<(), Failed> {
        let [uri, file, wait, set, stub] = params;
        let uri = match (uri, file) {
            (Some(_), Some(_)) => {
                return Err(fail(format_args!(
                    "inclusion may be either virtual or file"
                )));
            }
            (None, None) => return Err(fail(format_args!("no parameter in \"include\""))),
            (Some(u), None) | (None, Some(u)) => u,
        };
        if set.is_some() && stub.is_some() {
            return Err(fail(format_args!(
                "\"set\" and \"stub\" cannot be used together"
            )));
        }
        if let Some(w) = wait {
            if file.is_some() {
                return Err(fail(format_args!("\"wait\" cannot be used with file")));
            }
            // Includes always run in order, so waiting changes nothing.
            if !w.eq_ignore_ascii_case(b"yes") && !w.eq_ignore_ascii_case(b"no") {
                return Err(fail(format_args!(
                    "invalid value {:?} in the \"wait\" parameter",
                    String::from_utf8_lossy(w)
                )));
            }
        }
        let uri = self.evaluate(x, uri, true)?;
        let Some((path, args)) = unsafe_uri(&uri) else {
            return Err(fail(format_args!(
                "unsafe URI {:?} was detected",
                String::from_utf8_lossy(&uri)
            )));
        };
        let block = match stub {
            None => None,
            Some(name) => {
                let s = lock(&self.shared);
                match s.blocks.iter().find(|(n, _)| n == name) {
                    Some((_, b)) => Some(b.clone()),
                    None => {
                        return Err(fail(format_args!(
                            "\"stub\"={:?} for \"include\" not found",
                            String::from_utf8_lossy(name)
                        )));
                    }
                }
            }
        };
        let name = set.map(<[u8]>::to_ascii_lowercase);
        if let Some(n) = &name {
            let mut s = lock(&self.shared);
            if !s.vars.iter().any(|(k, _)| k == n) {
                s.vars.push((n.clone(), Vec::new()));
            }
        }
        let Some(r) = crate::subrequest::run(x, b"GET", &path, &args, None).await else {
            return Err(fail(format_args!(
                "subrequest {:?} failed",
                String::from_utf8_lossy(&uri)
            )));
        };
        if let Some(n) = name {
            // nginx keeps the variable as it was after an error.
            if r.status < 300 {
                lock(&self.shared).set(&n, r.body);
            }
            return Ok(());
        }
        match block {
            // The handler output nothing: the block stands in, run as a
            // document of its own.
            Some(b) if r.paged || r.body.is_empty() => {
                let mut inner = Self::with(Arc::clone(&self.shared), self.silent, self.value_len);
                inner.write(x, &b, true, out).await;
            }
            _ => out.extend_from_slice(&r.body),
        }
        Ok(())
    }

    fn echo(
        &mut self,
        x: &mut Exchange,
        name: &[u8],
        default: Option<&[u8]>,
        encoding: Option<&[u8]>,
        out: &mut Vec<u8>,
    ) -> Result<(), Failed> {
        let mut v = Vec::new();
        let value: &[u8] = if self.lookup(x, &name.to_ascii_lowercase(), &mut v) {
            &v
        } else {
            default.unwrap_or(b"(none)")
        };
        if value.is_empty() {
            return Ok(());
        }
        match encoding {
            None => {}
            Some(b"none") => self.encoding = Encoding::None,
            Some(b"url") => self.encoding = Encoding::Url,
            Some(b"entity") => self.encoding = Encoding::Entity,
            Some(e) => {
                fail(format_args!(
                    "unknown encoding {:?} in the \"echo\" command",
                    String::from_utf8_lossy(e)
                ));
            }
        }
        match self.encoding {
            Encoding::None => out.extend_from_slice(value),
            Encoding::Url => escape_url(value, out),
            Encoding::Entity => escape_html(value, out),
        }
        Ok(())
    }

    /// `if` and `elif` (nginx ngx_http_ssi_if).
    fn when(&mut self, x: &mut Exchange, expr: &[u8], is_if: bool) -> Result<(), Failed> {
        if is_if && self.cond != 0 {
            return Err(fail(format_args!(
                "the \"if\" command inside the \"if\" command"
            )));
        }
        if self.chosen {
            self.output = false;
            return Ok(());
        }
        let invalid = || {
            fail(format_args!(
                "invalid expression in {:?}",
                String::from_utf8_lossy(expr)
            ))
        };
        let mut e = expr.to_vec();
        let mut p = 0;
        while p < e.len() {
            let c = e[p].to_ascii_lowercase();
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || b"${}_\"'".contains(&c)) {
                break;
            }
            e[p] = c;
            p += 1;
        }
        let left = self.evaluate(x, &e[..p], false)?;
        while e.get(p) == Some(&b' ') {
            p += 1;
        }
        let hit = if p == e.len() {
            !left.is_empty()
        } else {
            let negative = if e[p] == b'=' {
                p += 1;
                false
            } else if e[p..].starts_with(b"!=") {
                p += 2;
                true
            } else {
                return Err(invalid());
            };
            while e.get(p) == Some(&b' ') {
                p += 1;
            }
            let mut last = e.len();
            let regex = p + 1 < last && e[p] == b'/';
            if regex {
                if e[last - 1] != b'/' {
                    return Err(invalid());
                }
                last -= 1;
                p += 1;
            } else if e[p..].starts_with(b"\\/") {
                p += 1;
            }
            let right = self.evaluate(x, &e[p..last], false)?;
            let matched = if regex {
                self.regex(&right, &left)?
            } else {
                left == right
            };
            matched != negative
        };
        self.output = hit;
        self.chosen = hit;
        self.cond = COND_IF;
        Ok(())
    }

    /// Matches `subject` against `pattern`; a match sets the captures and
    /// the named groups as variables.
    fn regex(&self, pattern: &[u8], subject: &[u8]) -> Result<bool, Failed> {
        let re = std::str::from_utf8(pattern)
            .map_err(|e| e.to_string())
            .and_then(Pattern::compile)
            .map_err(|e| fail(format_args!("{e}")))?;
        let mut caps = Captures::default();
        let matched = re
            .captures(subject, &mut caps)
            .map_err(|_| fail(format_args!("regex {:?} failed", re.source())))?;
        if matched {
            let mut s = lock(&self.shared);
            for (i, n) in re.names().iter().enumerate() {
                if let Some(n) = n {
                    let v = caps.get(i).unwrap_or_default().to_vec();
                    s.set(&n.to_ascii_lowercase().into_bytes(), v);
                }
            }
            s.caps = caps;
        }
        Ok(matched)
    }

    /// Appends the value of variable `name` (lowercase) to `out`; `false`
    /// when it has none.
    fn lookup(&self, x: &mut Exchange, name: &[u8], out: &mut Vec<u8>) -> bool {
        {
            let s = lock(&self.shared);
            if let [d @ b'0'..=b'9'] = name
                && usize::from(d - b'0') < s.caps.len()
            {
                out.extend_from_slice(s.caps.get(usize::from(d - b'0')).unwrap_or_default());
                return true;
            }
            if let Some((_, v)) = s.vars.iter().find(|(k, _)| k == name) {
                out.extend_from_slice(v);
                return true;
            }
        }
        match name {
            b"date_local" => self.date(false, out),
            b"date_gmt" => self.date(true, out),
            _ => {
                let Some(p) = std::str::from_utf8(name)
                    .ok()
                    .and_then(|n| variable(n, &x.lookups))
                else {
                    return false;
                };
                crate::vars::part(x, &p, out)
            }
        }
    }

    /// `$date_local` and `$date_gmt` by `timefmt`.
    fn date(&self, gmt: bool, out: &mut Vec<u8>) -> bool {
        let now = Timestamp::now();
        if self.timefmt == b"%s" {
            proxelo_http1::push_u64(out, now.as_second().max(0) as u64);
            return true;
        }
        // C strftime names UTC "GMT" for gmtime.
        let mut fmt = Vec::with_capacity(self.timefmt.len());
        let mut i = 0;
        while i < self.timefmt.len() {
            match &self.timefmt[i..] {
                [b'%', b'Z', ..] if gmt => {
                    fmt.extend_from_slice(b"GMT");
                    i += 2;
                }
                [b'%', c, ..] => {
                    fmt.extend_from_slice(&[b'%', *c]);
                    i += 2;
                }
                [c, ..] => {
                    fmt.push(*c);
                    i += 1;
                }
                [] => unreachable!(),
            }
        }
        let tz = if gmt {
            TimeZone::UTC
        } else {
            crate::worker::zone().clone()
        };
        let start = out.len();
        if write!(out, "{}", now.to_zoned_datetime(tz).strftime(&fmt)).is_err() {
            out.truncate(start);
        }
        true
    }

    /// nginx ngx_http_ssi_evaluate_string: expands `$name` and `${name}`
    /// and drops the backslash before `\ ' " $`. With `prefix`, a relative
    /// result is made relative to the directory of the current URI.
    fn evaluate(&self, x: &mut Exchange, text: &[u8], prefix: bool) -> Result<Vec<u8>, Failed> {
        let invalid = || {
            fail(format_args!(
                "invalid variable name in {:?}",
                String::from_utf8_lossy(text)
            ))
        };
        let mut out = Vec::with_capacity(text.len());
        // Whether the first non-empty part starts with '/'.
        let mut rooted = None;
        let mut i = 0;
        while i < text.len() {
            let start = out.len();
            if text[i] == b'$' {
                i += 1;
                let braced = text.get(i) == Some(&b'{');
                if braced {
                    i += 1;
                }
                let begin = i;
                while i < text.len() && (text[i].is_ascii_alphanumeric() || text[i] == b'_') {
                    i += 1;
                }
                let name = text[begin..i].to_ascii_lowercase();
                if braced {
                    if text.get(i) != Some(&b'}') {
                        return Err(fail(format_args!(
                            "the closing bracket in {:?} variable is missing",
                            String::from_utf8_lossy(&name)
                        )));
                    }
                    i += 1;
                }
                if name.is_empty() {
                    return Err(invalid());
                }
                self.lookup(x, &name, &mut out);
            } else {
                let mut quoted = false;
                while i < text.len() {
                    let c = text[i];
                    if !quoted {
                        if c == b'\\' {
                            quoted = true;
                            i += 1;
                            continue;
                        }
                        if c == b'$' {
                            break;
                        }
                    } else {
                        quoted = false;
                        if !b"\\'\"$".contains(&c) {
                            out.push(b'\\');
                        }
                    }
                    out.push(c);
                    i += 1;
                }
            }
            if rooted.is_none() && out.len() > start {
                rooted = Some(out[start] == b'/');
            }
        }
        if prefix
            && rooted == Some(false)
            && let Some(slash) = x.path.iter().rposition(|&c| c == b'/')
        {
            out.splice(0..0, x.path[..=slash].iter().copied());
        }
        Ok(out)
    }
}

enum Step {
    Next,
    Run,
    Failed,
}

/// nginx ngx_http_parse_unsafe_uri: the decoded path and the arguments of
/// an include, or `None` for a URI that is empty, leaves the root with `..`
/// or holds a NUL.
fn unsafe_uri(uri: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if uri.first().is_none_or(|&c| c == b'?') {
        return None;
    }
    let (path, args) = match uri.iter().position(|&c| c == b'?') {
        Some(q) => (&uri[..q], &uri[q + 1..]),
        None => (uri, &b""[..]),
    };
    let unsafe_path = |p: &[u8]| {
        p.contains(&0)
            || p == b".."
            || p.starts_with(b"../")
            || p.ends_with(b"/..")
            || p.windows(4).any(|w| w == b"/../")
    };
    if unsafe_path(path) {
        return None;
    }
    let path = if path.contains(&b'%') {
        let d = unescape(path);
        if unsafe_path(&d) {
            return None;
        }
        d
    } else {
        path.to_vec()
    };
    Some((path, args.to_vec()))
}

/// Decodes `%XX`; a `%` without two hex digits stays.
fn unescape(v: &[u8]) -> Vec<u8> {
    let hex = |c: Option<&u8>| c.and_then(|&c| (c as char).to_digit(16));
    let mut out = Vec::with_capacity(v.len());
    let mut i = 0;
    while i < v.len() {
        if v[i] == b'%'
            && let (Some(h), Some(l)) = (hex(v.get(i + 1)), hex(v.get(i + 2)))
        {
            out.push((h << 4 | l) as u8);
            i += 3;
            continue;
        }
        out.push(v[i]);
        i += 1;
    }
    out
}

/// nginx ngx_escape_html.
fn escape_html(v: &[u8], out: &mut Vec<u8>) {
    for &c in v {
        match c {
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'&' => out.extend_from_slice(b"&amp;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            c => out.push(c),
        }
    }
}

/// nginx ngx_escape_uri with NGX_ESCAPE_HTML.
fn escape_url(v: &[u8], out: &mut Vec<u8>) {
    for &c in v {
        if c <= b' ' || c >= 0x7f || b"\"#%'<>\\^`{|}".contains(&c) {
            out.push(b'%');
            out.push(b"0123456789ABCDEF"[usize::from(c >> 4)]);
            out.push(b"0123456789ABCDEF"[usize::from(c & 15)]);
        } else {
            out.push(c);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange(path: &str) -> Exchange {
        let mut x = Exchange::new(
            "127.0.0.1:80".parse().unwrap(),
            "127.0.0.1:9".parse().unwrap(),
        );
        x.path = path.as_bytes().to_vec();
        x
    }

    fn ssi(x: &mut Exchange) -> Ssi {
        let shared = Arc::clone(x.ssi.get_or_insert_with(SharedRef::default));
        Ssi::with(shared, false, 256)
    }

    /// Feeds `doc` split at every position, so tags cut across writes
    /// parse the same.
    fn run(doc: &str) -> String {
        let mut whole = None;
        for cut in 0..=doc.len() {
            let mut x = exchange("/dir/page.html");
            let mut s = ssi(&mut x);
            let mut out = Vec::new();
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            rt.block_on(async {
                s.write(&mut x, &doc.as_bytes()[..cut], false, &mut out)
                    .await;
                s.write(&mut x, &doc.as_bytes()[cut..], true, &mut out)
                    .await;
            });
            let out = String::from_utf8(out).unwrap();
            match &whole {
                None => whole = Some(out),
                Some(w) => assert_eq!(w, &out, "cut at {cut}"),
            }
        }
        whole.unwrap()
    }

    #[test]
    fn passes_text_and_lookalikes() {
        assert_eq!(
            run("a <b> <!- <!-- x --> <<!--"),
            "a <b> <!- <!-- x --> <<!--"
        );
    }

    #[test]
    fn echo_set_and_encodings() {
        assert_eq!(
            run(concat!(
                r#"<!--#set var="v" value="<a&b> $uri \$x \q" -->"#,
                r#"[<!--#echo var="V" -->]"#,
                r#"[<!--#echo var="none" -->][<!--#echo var="none" default="d" -->]"#,
                r#"[<!--#echo var="v" encoding="url" -->]"#,
                r#"[<!--#echo var="v" -->]"#,
                r#"[<!--#echo var="v" encoding="none" -->]"#,
            )),
            concat!(
                "[&lt;a&amp;b&gt; /dir/page.html $x \\q]",
                "[(none)][d]",
                "[%3Ca&b%3E%20/dir/page.html%20$x%20%5Cq]",
                "[%3Ca&b%3E%20/dir/page.html%20$x%20%5Cq]",
                "[<a&b> /dir/page.html $x \\q]",
            )
        );
    }

    #[test]
    fn conditionals() {
        let doc = |expr: &str| {
            run(&format!(
                r#"<!--#set var="a" value="xyz" --><!--#if expr="{expr}" -->1<!--#elif expr="$a = xyz" -->2<!--#else -->3<!--#endif -->."#
            ))
        };
        assert_eq!(doc("$a"), "1.");
        assert_eq!(doc("$nope"), "2.");
        assert_eq!(doc("$a != xyz"), "2.");
        assert_eq!(doc("$A = /^x(?<mid>.)/"), "1.");
        assert_eq!(
            run(
                r#"<!--#if expr="$nope" -->1<!--#elif expr="$nope" -->2<!--#else -->3<!--#endif -->."#
            ),
            "3."
        );
        // Captures and named groups of the regex.
        assert_eq!(
            run(
                r#"<!--#set var="a" value="xyz" --><!--#if expr="$a = /^x(?<mid>.)(.)/" --><!--#echo var="mid" --><!--#echo var="2" --><!--#endif -->"#
            ),
            "yz"
        );
        // Commands in a branch not taken do not run.
        assert_eq!(
            run(
                r#"<!--#if expr="" --><!--#set var="a" value="1" --><!--#bogus --><!--#endif --><!--#echo var="a" -->"#
            ),
            "(none)"
        );
    }

    #[test]
    fn errors() {
        let e = "[an error occurred while processing the directive]";
        for bad in [
            r#"<!--#bogus -->"#,
            r#"<!--#echo -->"#,
            r#"<!--#echo var="a" var="b" -->"#,
            r#"<!--#echo nope="a" -->"#,
            r#"<!--#echo var=a -->"#,
            r#"<!--#else -->"#,
            r#"<!--#if expr="a" --><!--#if expr="b" -->"#,
            r#"<!--#if expr="a ~ b" -->"#,
            r#"<!--#set var="a" value="${a" -->"#,
            r#"<!--#set var="a" value="$" -->"#,
            r#"<!--#include -->"#,
            r#"<!--#include virtual="/a" file="/b" -->"#,
            r#"<!--#include virtual="/a" wait="maybe" -->"#,
            r#"<!--#include virtual="../a" -->"#,
            r#"<!--#include virtual="/a" stub="none" -->"#,
        ] {
            assert!(run(bad).starts_with(e), "{bad}: {}", run(bad));
        }
        assert_eq!(run(r#"<!--#config errmsg="E" --><!--#bogus -->"#), "E");
        let long = format!(r#"<!--#echo var="{}" -->"#, "a".repeat(257));
        assert_eq!(run(&long), e);
    }

    #[test]
    fn blocks_keep_their_commands() {
        let mut x = exchange("/");
        let mut s = ssi(&mut x);
        let mut out = Vec::new();
        let doc = r#"<!--#block name="b" -->x<!--#echo var="v" -->y<!--#endblock -->z"#;
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(s.write(&mut x, doc.as_bytes(), true, &mut out));
        assert_eq!(out, b"z");
        let shared = lock(&s.shared);
        assert_eq!(shared.blocks[0].0, b"b");
        assert_eq!(shared.blocks[0].1, br#"x<!--#echo var="v" -->y"#);
    }

    #[test]
    fn prefixes_relative_includes() {
        let mut x = exchange("/dir/page.html");
        let s = ssi(&mut x);
        let eval = |x: &mut Exchange, t: &str| s.evaluate(x, t.as_bytes(), true).ok().unwrap();
        assert_eq!(eval(&mut x, "a.html"), b"/dir/a.html");
        assert_eq!(eval(&mut x, "/a.html"), b"/a.html");
        assert_eq!(eval(&mut x, "$uri"), b"/dir/page.html");
        assert_eq!(eval(&mut x, "$nope/a"), b"/a");
    }

    #[test]
    fn rejects_unsafe_uris() {
        assert_eq!(
            unsafe_uri(b"/a%20b?x=1").unwrap(),
            (b"/a b".to_vec(), b"x=1".to_vec())
        );
        for bad in [
            &b""[..],
            b"?a",
            b"..",
            b"../a",
            b"/a/../b",
            b"/a/..",
            b"/a/%2e%2e/b",
            b"/a\0",
        ] {
            assert!(unsafe_uri(bad).is_none(), "{bad:?}");
        }
        assert!(unsafe_uri(b"/a..b/..c").is_some());
    }
}
