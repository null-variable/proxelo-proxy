//! Lookup variables: nginx map, geo and split_clients.
//!
//! A lookup expands its source template and finds the value in a table built
//! once per snapshot. Serving evaluates them through the request's variable
//! cache; this module only holds the tables and answers lookups.

use std::collections::HashMap;
use std::net::IpAddr;

use foldhash::fast::FixedState;
use proxelo_api::snapshot::v1::{self as ir, lookup, lookup_map_entry};

use crate::access::Cidr;
use crate::runtime::{Captures, MatchError, Pattern};
use crate::template::{self, Template};

type Map<V> = HashMap<Box<[u8]>, V, FixedState>;
/// Networks of one prefix length: masked address to value index.
type Prefixes<A> = (u8, HashMap<A, u32, FixedState>);

/// One lookup variable.
#[derive(Debug)]
pub struct Lookup {
    pub name: Box<str>,
    /// Empty for geo means the client address.
    pub source: Template,
    pub table: Table,
}

#[derive(Debug)]
pub enum Table {
    Map(MapTable),
    Geo(GeoTable),
    Split(SplitTable),
}

/// nginx map.
#[derive(Debug)]
pub struct MapTable {
    /// Lowercase keys.
    exact: Map<Template>,
    /// hostnames: `*.name` and `.name`, keyed by `name`.
    head: Map<Template>,
    /// hostnames: `.name`, which also matches `name`.
    head_self: Map<Template>,
    /// hostnames: `name.*`, keyed by `name`.
    tail: Map<Template>,
    regex: Box<[(Pattern, Template)]>,
    pub default: Template,
    pub hostnames: bool,
}

impl MapTable {
    /// The value for `key`, which must be lowercase when `lower` is the
    /// lowercased form. A regex match leaves its groups in `caps`, as nginx
    /// does, so the value can use them.
    pub fn find(
        &self,
        key: &[u8],
        lower: &[u8],
        caps: &mut Captures,
    ) -> Result<&Template, MatchError> {
        let lower = if self.hostnames {
            lower.strip_suffix(b".").unwrap_or(lower)
        } else {
            lower
        };
        if let Some(v) = self.exact.get(lower) {
            return Ok(v);
        }
        if self.hostnames && !lower.is_empty() {
            if let Some(v) = self.head_self.get(lower) {
                return Ok(v);
            }
            for (i, _) in lower.iter().enumerate().filter(|&(_, &b)| b == b'.') {
                if let Some(v) = self.head.get(&lower[i + 1..]) {
                    return Ok(v);
                }
            }
            for (i, _) in lower.iter().enumerate().rev().filter(|&(_, &b)| b == b'.') {
                if let Some(v) = self.tail.get(&lower[..i]) {
                    return Ok(v);
                }
            }
        }
        // nginx tries regexes only for a non-empty value.
        if !key.is_empty() {
            for (re, v) in &self.regex {
                if re.captures(key, caps)? {
                    return Ok(v);
                }
            }
        }
        Ok(&self.default)
    }
}

/// nginx geo with CIDRs: the longest prefix that contains the address.
#[derive(Debug)]
pub struct GeoTable {
    /// Per prefix length, longest first: masked address to value index.
    v4: Box<[Prefixes<u32>]>,
    v6: Box<[Prefixes<u128>]>,
    values: Box<[Box<[u8]>]>,
    pub default: Box<[u8]>,
}

fn mask4(a: u32, bits: u8) -> u32 {
    a & u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0)
}

fn mask6(a: u128, bits: u8) -> u128 {
    a & u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0)
}

impl GeoTable {
    /// The value for `ip`. IPv4-mapped IPv6 addresses look up as IPv4.
    pub fn find(&self, ip: IpAddr) -> &[u8] {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        let found = match ip {
            IpAddr::V4(a) => {
                let a = u32::from(a);
                self.v4.iter().find_map(|(bits, m)| m.get(&mask4(a, *bits)))
            }
            IpAddr::V6(a) => {
                let a = u128::from(a);
                self.v6.iter().find_map(|(bits, m)| m.get(&mask6(a, *bits)))
            }
        };
        found.map_or(&self.default, |&i| &self.values[i as usize])
    }

    /// The value for a source that is not an address: nginx looks up
    /// 255.255.255.255 (INADDR_NONE).
    pub fn find_none(&self) -> &[u8] {
        self.find(IpAddr::V4(std::net::Ipv4Addr::BROADCAST))
    }
}

/// nginx split_clients.
#[derive(Debug)]
pub struct SplitTable {
    /// Upper bound of each part's hash range, 0 for the rest.
    parts: Box<[(u32, Box<[u8]>)]>,
}

impl SplitTable {
    /// The part `hash` falls in; empty when the percentages do not cover it.
    pub fn find(&self, hash: u32) -> &[u8] {
        self.parts
            .iter()
            .find(|(bound, _)| hash < *bound || *bound == 0)
            .map_or(&[][..], |(_, v)| v)
    }
}

/// MurmurHash2 as nginx computes it for split_clients.
pub fn murmur2(data: &[u8]) -> u32 {
    const M: u32 = 0x5bd1_e995;
    let mut h = data.len() as u32;
    let (chunks, rest) = data.as_chunks::<4>();
    for c in chunks {
        let mut k = u32::from_le_bytes(*c);
        k = k.wrapping_mul(M);
        k ^= k >> 24;
        k = k.wrapping_mul(M);
        h = h.wrapping_mul(M) ^ k;
    }
    if !rest.is_empty() {
        if rest.len() >= 3 {
            h ^= u32::from(rest[2]) << 16;
        }
        if rest.len() >= 2 {
            h ^= u32::from(rest[1]) << 8;
        }
        h ^= u32::from(rest[0]);
        h = h.wrapping_mul(M);
    }
    h ^= h >> 13;
    h = h.wrapping_mul(M);
    h ^ (h >> 15)
}

/// `(field, error)` for the caller to place.
type Invalid = (String, String);

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// The lookups and their names, which templates resolve against.
pub(crate) type Built = (Box<[Lookup]>, Box<[Box<str>]>);

/// Builds the lookups in order. Each may use only the ones before it.
pub(crate) fn build(list: &[ir::Lookup]) -> Result<Built, Invalid> {
    let mut names: Vec<Box<str>> = Vec::with_capacity(list.len());
    let mut out = Vec::with_capacity(list.len());
    for (i, l) in list.iter().enumerate() {
        let at = |f: &str| format!("lookups[{i}].{f}");
        if !valid_name(&l.name) {
            return Err((
                at("name"),
                "must be lowercase letters, digits and '_'".into(),
            ));
        }
        if template::is_builtin(&l.name) {
            return Err((at("name"), format!("${} is a built-in variable", l.name)));
        }
        if names.iter().any(|n| **n == *l.name) {
            return Err((at("name"), format!("${} is defined twice", l.name)));
        }
        let tmpl = |s: &str, f: &str| Template::parse_in(s, &names).map_err(|e| (at(f), e));
        let source = tmpl(&l.source, "source")?;
        let table = match &l.kind {
            Some(lookup::Kind::Map(m)) => {
                if l.source.is_empty() {
                    return Err((at("source"), "must not be empty".into()));
                }
                let mut t = MapTable {
                    exact: Map::default(),
                    head: Map::default(),
                    head_self: Map::default(),
                    tail: Map::default(),
                    regex: Box::default(),
                    default: tmpl(&m.default, "map.default")?,
                    hostnames: m.hostnames,
                };
                let mut regex = Vec::new();
                for (e, entry) in m.entries.iter().enumerate() {
                    let f = format!("map.entries[{e}]");
                    let value = tmpl(&entry.value, &format!("{f}.value"))?;
                    match entry.kind() {
                        lookup_map_entry::Kind::Exact | lookup_map_entry::Kind::Unspecified => {
                            let key = entry.key.to_ascii_lowercase();
                            let put = |map: &mut Map<Template>, k: &str, v: Template| {
                                // nginx keeps the first of duplicate keys.
                                map.entry(k.as_bytes().into()).or_insert(v);
                            };
                            if !m.hostnames {
                                put(&mut t.exact, &key, value);
                            } else if let Some(name) = key.strip_prefix("*.") {
                                put(&mut t.head, name, value);
                            } else if let Some(name) = key.strip_suffix(".*") {
                                put(&mut t.tail, name, value);
                            } else if let Some(name) = key.strip_prefix('.') {
                                put(&mut t.head, name, value.clone());
                                put(&mut t.head_self, name, value);
                            } else {
                                put(&mut t.exact, &key, value);
                            }
                        }
                        kind => {
                            let caseless = kind == lookup_map_entry::Kind::RegexCi;
                            let re = Pattern::new(&entry.key, caseless)
                                .map_err(|e| (at(&format!("{f}.key")), e))?;
                            regex.push((re, value));
                        }
                    }
                }
                t.regex = regex.into();
                Table::Map(t)
            }
            Some(lookup::Kind::Geo(g)) => {
                let mut v4: Vec<Prefixes<u32>> = Vec::new();
                let mut v6: Vec<Prefixes<u128>> = Vec::new();
                let mut values = Vec::with_capacity(g.entries.len());
                for (e, entry) in g.entries.iter().enumerate() {
                    let c = Cidr::parse(&entry.cidr)
                        .map_err(|err| (at(&format!("geo.entries[{e}].cidr")), err))?;
                    let idx = values.len() as u32;
                    values.push(entry.value.as_bytes().into());
                    let bits = c.bits();
                    // nginx: a later duplicate network replaces the value.
                    match c.addr() {
                        IpAddr::V4(a) => {
                            let k = mask4(u32::from(a), bits);
                            match v4.iter_mut().find(|(b, _)| *b == bits) {
                                Some((_, m)) => _ = m.insert(k, idx),
                                None => v4.push((bits, [(k, idx)].into_iter().collect())),
                            }
                        }
                        IpAddr::V6(a) => {
                            let k = mask6(u128::from(a), bits);
                            match v6.iter_mut().find(|(b, _)| *b == bits) {
                                Some((_, m)) => _ = m.insert(k, idx),
                                None => v6.push((bits, [(k, idx)].into_iter().collect())),
                            }
                        }
                    }
                }
                v4.sort_by_key(|p| std::cmp::Reverse(p.0));
                v6.sort_by_key(|p| std::cmp::Reverse(p.0));
                Table::Geo(GeoTable {
                    v4: v4.into(),
                    v6: v6.into(),
                    values: values.into(),
                    default: g.default.as_bytes().into(),
                })
            }
            Some(lookup::Kind::Split(s)) => {
                if l.source.is_empty() {
                    return Err((at("source"), "must not be empty".into()));
                }
                // As nginx computes the bounds: cumulative shares of the
                // 32-bit hash space; the part reaching 100% takes the rest.
                let mut sum = 0u32;
                let mut last = 0u32;
                let mut parts = Vec::with_capacity(s.parts.len());
                for (p, part) in s.parts.iter().enumerate() {
                    sum = if part.basis_points == 0 {
                        10_000
                    } else {
                        sum.saturating_add(part.basis_points)
                    };
                    if sum > 10_000 {
                        return Err((
                            at(&format!("split.parts[{p}]")),
                            "percentages add up to more than 100%".into(),
                        ));
                    }
                    let bound = if sum == 10_000 {
                        0
                    } else {
                        last = last.wrapping_add(
                            (u64::from(part.basis_points) * 0xffff_ffff / 10_000) as u32,
                        );
                        last
                    };
                    parts.push((bound, part.value.as_bytes().into()));
                }
                Table::Split(SplitTable {
                    parts: parts.into(),
                })
            }
            None => return Err((at("kind"), "missing".into())),
        };
        names.push(l.name.as_str().into());
        out.push(Lookup {
            name: l.name.as_str().into(),
            source,
            table,
        });
    }
    Ok((out.into(), names.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::Part;

    fn map(entries: Vec<ir::LookupMapEntry>, hostnames: bool) -> ir::Lookup {
        ir::Lookup {
            name: "m".into(),
            source: "$host".into(),
            kind: Some(lookup::Kind::Map(ir::LookupMap {
                entries,
                default: "none".into(),
                hostnames,
            })),
        }
    }

    fn entry(kind: lookup_map_entry::Kind, key: &str, value: &str) -> ir::LookupMapEntry {
        ir::LookupMapEntry {
            kind: kind.into(),
            key: key.into(),
            value: value.into(),
        }
    }

    fn lit(t: &Template) -> String {
        t.parts()
            .iter()
            .map(|p| match p {
                Part::Lit(l) => String::from_utf8_lossy(l).into_owned(),
                other => format!("{other:?}"),
            })
            .collect()
    }

    #[test]
    fn map_order() {
        use lookup_map_entry::Kind::*;
        let (ls, _) = build(&[map(
            vec![
                entry(Regex, "^/a/(.*)$", "re:$1"),
                entry(Exact, "/A/x", "exact"),
                entry(RegexCi, "^/B", "ci"),
            ],
            false,
        )])
        .unwrap();
        let Table::Map(t) = &ls[0].table else {
            panic!()
        };
        let mut caps = Captures::default();
        let mut find = |k: &str| {
            let v = t
                .find(k.as_bytes(), k.to_ascii_lowercase().as_bytes(), &mut caps)
                .unwrap();
            lit(v)
        };
        assert_eq!(find("/a/x"), "exact");
        assert!(find("/a/y").starts_with("re:"));
        assert_eq!(find("/b/1"), "ci");
        assert_eq!(find(""), "none");
        assert_eq!(find("/c"), "none");
    }

    #[test]
    fn map_hostnames() {
        use lookup_map_entry::Kind::Exact;
        let (ls, _) = build(&[map(
            vec![
                entry(Exact, "example.com", "exact"),
                entry(Exact, "*.example.com", "star"),
                entry(Exact, ".example.org", "dot"),
                entry(Exact, "www.example.*", "tail"),
            ],
            true,
        )])
        .unwrap();
        let Table::Map(t) = &ls[0].table else {
            panic!()
        };
        let mut caps = Captures::default();
        let mut find = |k: &str| lit(t.find(k.as_bytes(), k.as_bytes(), &mut caps).unwrap());
        assert_eq!(find("example.com."), "exact");
        assert_eq!(find("a.b.example.com"), "star");
        assert_eq!(find("example.org"), "dot");
        assert_eq!(find("x.example.org"), "dot");
        assert_eq!(find("www.example.net"), "tail");
        assert_eq!(find("other"), "none");
    }

    #[test]
    fn geo_longest_prefix() {
        let geo = |cidr: &str, value: &str| ir::LookupGeoEntry {
            cidr: cidr.into(),
            value: value.into(),
        };
        let (ls, _) = build(&[ir::Lookup {
            name: "g".into(),
            source: String::new(),
            kind: Some(lookup::Kind::Geo(ir::LookupGeo {
                entries: vec![
                    geo("10.0.0.0/8", "ten"),
                    geo("10.1.0.0/16", "ten-one"),
                    geo("2001:db8::/32", "doc"),
                    geo("255.255.255.255", "none"),
                ],
                default: "other".into(),
            })),
        }])
        .unwrap();
        let Table::Geo(t) = &ls[0].table else {
            panic!()
        };
        let f = |ip: &str| String::from_utf8_lossy(t.find(ip.parse().unwrap())).into_owned();
        assert_eq!(f("10.1.2.3"), "ten-one");
        assert_eq!(f("10.2.0.1"), "ten");
        assert_eq!(f("::ffff:10.1.0.1"), "ten-one");
        assert_eq!(f("2001:db8::1"), "doc");
        assert_eq!(f("192.0.2.1"), "other");
        assert_eq!(t.find_none(), b"none");
    }

    #[test]
    fn split_matches_nginx() {
        // Values of nginx's ngx_murmur_hash2.
        assert_eq!(murmur2(b""), 0);
        assert_eq!(murmur2(b"a"), 0x92685f5e);
        assert_eq!(murmur2(b"abcd"), 0x26873021);
        assert_eq!(murmur2(b"abcde"), 0x5f09a8de);
        assert_eq!(murmur2(b"127.0.0.1AAA"), 0xb5fc5e4b);
        let part = |bp: u32, v: &str| ir::LookupSplitPart {
            basis_points: bp,
            value: v.into(),
        };
        let (ls, _) = build(&[ir::Lookup {
            name: "s".into(),
            source: "$remote_addr".into(),
            kind: Some(lookup::Kind::Split(ir::LookupSplit {
                parts: vec![part(5000, "a"), part(2500, "b"), part(0, "c")],
            })),
        }])
        .unwrap();
        let Table::Split(t) = &ls[0].table else {
            panic!()
        };
        assert_eq!(t.find(0), b"a");
        assert_eq!(t.find(0x7fff_fffe), b"a");
        assert_eq!(t.find(0x8000_0000), b"b");
        assert_eq!(t.find(u32::MAX), b"c");
    }

    #[test]
    fn names_and_order() {
        let mut l = map(vec![], false);
        l.name = "host".into();
        assert!(build(&[l]).is_err());
        let a = ir::Lookup {
            name: "a".into(),
            source: "$b".into(),
            ..map(vec![], false)
        };
        let b = ir::Lookup {
            name: "b".into(),
            source: "$a".into(),
            ..map(vec![], false)
        };
        // $b is not defined before a.
        assert!(build(&[a, b.clone()]).is_err());
        let a = ir::Lookup {
            name: "a".into(),
            ..map(vec![], false)
        };
        let (_, names) = build(&[a, b]).unwrap();
        assert_eq!(names.len(), 2);
    }
}
