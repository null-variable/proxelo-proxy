//! Route conditions: methods, headers, query arguments and a CEL expression,
//! checked after the path picked a route.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};

use cel::{Context, Env, Program, Value};
use proxelo_api::snapshot::v1::{self as ir, value_match};

use crate::runtime::{MatchError, Pattern};

/// What conditions read from a request.
pub trait Facts {
    /// Uppercase method as sent.
    fn method(&self) -> &[u8];
    /// Normalized path after rewrites.
    fn path(&self) -> &[u8];
    /// Request target as sent.
    fn uri(&self) -> &[u8];
    /// Query string without `?`.
    fn args(&self) -> &[u8];
    /// Lowercase host without port, empty when the request has none.
    fn host(&self) -> &[u8];
    fn scheme(&self) -> &[u8];
    fn remote_addr(&self) -> IpAddr;
    /// Calls `f` with each header name and value in request order until it
    /// returns true; returns whether it did.
    fn find_header(&self, f: &mut dyn FnMut(&[u8], &[u8]) -> bool) -> bool;
}

/// The conditions of one route. All must hold.
#[derive(Debug)]
pub struct Cond {
    methods: Box<[Box<[u8]>]>,
    headers: Box<[ValueMatch]>,
    query: Box<[ValueMatch]>,
    expr: Option<Expr>,
}

#[derive(Debug)]
struct ValueMatch {
    /// Lowercase for headers.
    name: Box<[u8]>,
    op: Op,
}

#[derive(Debug)]
enum Op {
    Present,
    Absent,
    Equals(Box<[u8]>),
    Prefix(Box<[u8]>),
    Suffix(Box<[u8]>),
    Contains(Box<[u8]>),
    Regex(Pattern),
}

pub struct Expr {
    source: Box<str>,
    program: Program,
}

impl Expr {
    /// Compiles a CEL expression over `request`.
    pub(crate) fn compile(source: &str) -> Result<Self, String> {
        let program = ENV.compile(source).map_err(|e| e.to_string())?;
        Ok(Self {
            source: source.into(),
            program,
        })
    }

    /// Whether the expression is true for the request; an evaluation error
    /// is false.
    pub fn eval(&self, f: &dyn Facts) -> bool {
        let mut ctx = Context::with_env(Arc::clone(&ENV));
        ctx.add_variable_from_value("request", request(f));
        matches!(self.program.execute(&ctx), Ok(Value::Bool(true)))
    }
}

impl std::fmt::Debug for Expr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Expr({:?})", self.source)
    }
}

/// The CEL environment of route expressions: the standard library and the
/// network extension (`cidr`, `ip`), as the control plane checks them with.
static ENV: LazyLock<Arc<Env>> = LazyLock::new(|| {
    let mut env = Env::stdlib();
    env.add_extension(cel::extensions::network)
        .expect("the network extension registers once");
    Arc::new(env)
});

impl Cond {
    /// Builds the conditions of `r`, `None` when it has none. Errors name the
    /// field below the route.
    pub(crate) fn build(r: &ir::Route) -> Result<Option<Self>, (String, String)> {
        if r.methods.is_empty() && r.headers.is_empty() && r.query.is_empty() && r.expr.is_empty() {
            return Ok(None);
        }
        let expr = if r.expr.is_empty() {
            None
        } else {
            Some(Expr::compile(&r.expr).map_err(|e| ("expr".to_string(), e))?)
        };
        Ok(Some(Self {
            methods: r.methods.iter().map(|m| m.as_bytes().into()).collect(),
            headers: value_matches(&r.headers, "headers", true)?,
            query: value_matches(&r.query, "query", false)?,
            expr,
        }))
    }

    /// Whether every condition holds for the request.
    pub fn holds(&self, f: &dyn Facts) -> Result<bool, MatchError> {
        if !self.methods.is_empty() && !self.methods.iter().any(|m| **m == *f.method()) {
            return Ok(false);
        }
        for h in &self.headers {
            let mut err = None;
            let mut seen = false;
            let found = f.find_header(&mut |name, value| {
                if !name.eq_ignore_ascii_case(&h.name) {
                    return false;
                }
                seen = true;
                h.op.test(value).unwrap_or_else(|e| {
                    err = Some(e);
                    true
                })
            });
            if let Some(e) = err {
                return Err(e);
            }
            if !h.op.holds(seen, found) {
                return Ok(false);
            }
        }
        for q in &self.query {
            let mut seen = false;
            let mut found = false;
            for (name, value) in args(f.args()) {
                if name == &*q.name {
                    seen = true;
                    if q.op.test(value)? {
                        found = true;
                        break;
                    }
                }
            }
            if !q.op.holds(seen, found) {
                return Ok(false);
            }
        }
        if let Some(e) = &self.expr {
            // An evaluation error, such as a missing map key, is no match.
            return Ok(e.eval(f));
        }
        Ok(true)
    }
}

fn value_matches(
    ms: &[ir::ValueMatch],
    field: &str,
    lower: bool,
) -> Result<Box<[ValueMatch]>, (String, String)> {
    ms.iter()
        .enumerate()
        .map(|(i, m)| {
            let at = format!("{field}[{i}]");
            let v = || m.value.as_bytes().into();
            let op = match m.op() {
                value_match::Op::Unspecified => {
                    return Err((format!("{at}.op"), "unspecified".to_string()));
                }
                value_match::Op::Present => Op::Present,
                value_match::Op::Absent => Op::Absent,
                value_match::Op::Equals => Op::Equals(v()),
                value_match::Op::Prefix => Op::Prefix(v()),
                value_match::Op::Suffix => Op::Suffix(v()),
                value_match::Op::Contains => Op::Contains(v()),
                value_match::Op::Regex => Op::Regex(
                    Pattern::new(&m.value, false).map_err(|e| (format!("{at}.value"), e))?,
                ),
            };
            if m.name.is_empty() {
                return Err((format!("{at}.name"), "empty".to_string()));
            }
            let name = if lower {
                m.name.to_ascii_lowercase()
            } else {
                m.name.clone()
            };
            Ok(ValueMatch {
                name: name.into_bytes().into(),
                op,
            })
        })
        .collect()
}

impl Op {
    /// Whether one value satisfies a value operator. Presence operators are
    /// decided by [`Op::holds`].
    fn test(&self, v: &[u8]) -> Result<bool, MatchError> {
        Ok(match self {
            Self::Present | Self::Absent => true,
            Self::Equals(x) => v == &**x,
            Self::Prefix(x) => v.starts_with(x),
            Self::Suffix(x) => v.ends_with(x),
            Self::Contains(x) => x.is_empty() || v.windows(x.len()).any(|w| w == &**x),
            Self::Regex(p) => p.is_match(v)?,
        })
    }

    /// `seen`: the name occurs; `found`: a value passed [`Op::test`].
    fn holds(&self, seen: bool, found: bool) -> bool {
        match self {
            Self::Absent => !seen,
            _ => found,
        }
    }
}

/// `name=value` pairs of a query string; a pair without `=` has an empty
/// value.
fn args(q: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    q.split(|&c| c == b'&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| match kv.iter().position(|&c| c == b'=') {
            Some(i) => (&kv[..i], &kv[i + 1..]),
            None => (kv, &b""[..]),
        })
}

fn text(b: &[u8]) -> Value {
    String::from_utf8_lossy(b).into_owned().into()
}

/// The `request` variable: a map with the fields of proxelo.expr.v1.Request.
fn request(f: &dyn Facts) -> HashMap<String, Value> {
    let mut headers: HashMap<String, String> = HashMap::new();
    f.find_header(&mut |name, value| {
        let value = String::from_utf8_lossy(value);
        headers
            .entry(String::from_utf8_lossy(name).to_ascii_lowercase())
            .and_modify(|v| {
                v.push_str(", ");
                v.push_str(&value);
            })
            .or_insert_with(|| value.into_owned());
        false
    });
    let mut query: HashMap<String, Value> = HashMap::new();
    for (name, value) in args(f.args()) {
        query
            .entry(String::from_utf8_lossy(name).into_owned())
            .or_insert_with(|| text(value));
    }
    let headers: HashMap<String, Value> = headers.into_iter().map(|(k, v)| (k, v.into())).collect();
    HashMap::from([
        ("method".to_string(), text(f.method())),
        ("path".to_string(), text(f.path())),
        ("uri".to_string(), text(f.uri())),
        ("args".to_string(), text(f.args())),
        ("host".to_string(), text(f.host())),
        ("scheme".to_string(), text(f.scheme())),
        (
            "remote_addr".to_string(),
            f.remote_addr().to_string().into(),
        ),
        ("headers".to_string(), headers.into()),
        ("query".to_string(), query.into()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Req {
        method: &'static str,
        args: &'static str,
        headers: Vec<(&'static str, &'static str)>,
    }

    impl Facts for Req {
        fn method(&self) -> &[u8] {
            self.method.as_bytes()
        }
        fn path(&self) -> &[u8] {
            b"/a"
        }
        fn uri(&self) -> &[u8] {
            b"/a"
        }
        fn args(&self) -> &[u8] {
            self.args.as_bytes()
        }
        fn host(&self) -> &[u8] {
            b"example.com"
        }
        fn scheme(&self) -> &[u8] {
            b"http"
        }
        fn remote_addr(&self) -> IpAddr {
            IpAddr::from([10, 1, 2, 3])
        }
        fn find_header(&self, f: &mut dyn FnMut(&[u8], &[u8]) -> bool) -> bool {
            self.headers
                .iter()
                .any(|(n, v)| f(n.as_bytes(), v.as_bytes()))
        }
    }

    fn vm(name: &str, op: value_match::Op, value: &str) -> ir::ValueMatch {
        ir::ValueMatch {
            name: name.into(),
            op: op as i32,
            value: value.into(),
        }
    }

    fn cond(r: ir::Route) -> Cond {
        Cond::build(&r).unwrap().unwrap()
    }

    #[test]
    fn conditions() {
        let req = Req {
            method: "GET",
            args: "v=2&flag&v=3",
            headers: vec![("X-Canary", "1"), ("Accept", "text/html")],
        };
        let yes = [
            ir::Route {
                methods: vec!["POST".into(), "GET".into()],
                ..Default::default()
            },
            ir::Route {
                headers: vec![vm("x-canary", value_match::Op::Equals, "1")],
                ..Default::default()
            },
            ir::Route {
                headers: vec![vm("X-Other", value_match::Op::Absent, "")],
                query: vec![
                    vm("flag", value_match::Op::Present, ""),
                    vm("v", value_match::Op::Equals, "3"),
                ],
                ..Default::default()
            },
            ir::Route {
                headers: vec![vm("accept", value_match::Op::Regex, "^text/")],
                ..Default::default()
            },
            ir::Route {
                expr: r#"cidr("10.0.0.0/8").containsIP(ip(request.remote_addr)) && request.headers["x-canary"] == "1" && request.query.v == "2""#.into(),
                ..Default::default()
            },
        ];
        for r in yes {
            assert_eq!(cond(r.clone()).holds(&req), Ok(true), "{r:?}");
        }
        let no = [
            ir::Route {
                methods: vec!["POST".into()],
                ..Default::default()
            },
            ir::Route {
                headers: vec![vm("x-canary", value_match::Op::Absent, "")],
                ..Default::default()
            },
            ir::Route {
                query: vec![vm("V", value_match::Op::Present, "")],
                ..Default::default()
            },
            // A missing key is an evaluation error, which is no match.
            ir::Route {
                expr: r#"request.headers["x-none"] == "1""#.into(),
                ..Default::default()
            },
        ];
        for r in no {
            assert_eq!(cond(r.clone()).holds(&req), Ok(false), "{r:?}");
        }
        assert!(
            Cond::build(&ir::Route {
                expr: "request.(".into(),
                ..Default::default()
            })
            .is_err()
        );
    }
}
