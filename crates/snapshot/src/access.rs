//! The runtime form of the access settings: real_ip, request and connection
//! limits, allow/deny rules, basic auth and forward auth.

use std::net::IpAddr;
use std::time::Duration;

use proxelo_api::snapshot::v1 as ir;

use crate::template::Template;

/// Keys a limit zone keeps when the snapshot gives none.
const DEFAULT_MAX_KEYS: u32 = 16384;

/// An address block. A bare address is a block of one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    bits: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (a, bits) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (s, None),
        };
        let addr: IpAddr = a.parse().map_err(|_| format!("{s:?} is not an address"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let bits = match bits {
            None => max,
            Some(b) => b
                .parse::<u8>()
                .ok()
                .filter(|&b| b <= max)
                .ok_or_else(|| format!("{s:?} has a bad prefix length"))?,
        };
        Ok(Self { addr, bits })
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn bits(&self) -> u8 {
        self.bits
    }

    /// Whether `ip` is in the block. An IPv4-mapped IPv6 address matches as
    /// IPv4, as nginx does.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.bits)).unwrap_or(0);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.bits))
                    .unwrap_or(0);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

/// nginx realip: the client address a trusted proxy reports.
#[derive(Debug)]
pub struct RealIp {
    pub from: Box<[Cidr]>,
    /// Lowercase header name.
    pub header: Box<[u8]>,
    pub recursive: bool,
}

impl RealIp {
    pub fn trusted(&self, ip: IpAddr) -> bool {
        self.from.iter().any(|c| c.contains(ip))
    }
}

/// A leaky bucket per key (nginx limit_req_zone and limit_req).
#[derive(Debug)]
pub struct RateZone {
    pub id: Box<str>,
    pub key: Template,
    /// Requests per 1000 seconds, as nginx keeps it.
    pub rate: u64,
    /// In thousandths of a request, like nginx's excess.
    pub burst: u64,
    pub delay: u64,
    pub status: u16,
    pub dry_run: bool,
    pub max_keys: usize,
}

/// Requests in progress per key (nginx limit_conn_zone and limit_conn).
#[derive(Debug)]
pub struct ConnZone {
    pub id: Box<str>,
    pub key: Template,
    pub max: u32,
    pub status: u16,
    pub dry_run: bool,
    pub max_keys: usize,
}

#[derive(Debug)]
pub struct AccessRule {
    pub allow: bool,
    /// `None`: every client.
    pub cidr: Option<Cidr>,
}

#[derive(Debug)]
pub struct BasicAuth {
    /// The quoted realm as sent in WWW-Authenticate.
    pub challenge: Box<[u8]>,
    pub users: Box<[BasicUser]>,
}

#[derive(Debug)]
pub struct BasicUser {
    pub name: Box<[u8]>,
    pub hash: Box<str>,
}

#[derive(Debug)]
pub struct ForwardAuth {
    pub upstream: u32,
    pub uri: Template,
    pub timeout: Duration,
    /// Lowercase names.
    pub copy_headers: Box<[Box<[u8]>]>,
}

/// The access settings of one route, in nginx phase order.
#[derive(Debug, Default)]
pub struct Access {
    pub rate_limits: Box<[u32]>,
    pub conn_limits: Box<[u32]>,
    pub rules: Box<[AccessRule]>,
    pub basic_auth: Option<BasicAuth>,
    pub jwt: Option<crate::auth::Jwt>,
    pub oidc: Option<crate::auth::Oidc>,
    pub forward_auth: Option<ForwardAuth>,
}

impl Access {
    pub fn is_empty(&self) -> bool {
        self.rate_limits.is_empty()
            && self.conn_limits.is_empty()
            && self.rules.is_empty()
            && self.basic_auth.is_none()
            && self.jwt.is_none()
            && self.oidc.is_none()
            && self.forward_auth.is_none()
    }

    /// nginx allow/deny: the first rule that matches decides.
    pub fn allows(&self, ip: IpAddr) -> bool {
        allowed(&self.rules, ip)
    }
}

/// Response throttling of one request (nginx limit_rate, limit_rate_after).
#[derive(Debug, Clone, Copy)]
pub struct Bandwidth {
    /// Bytes per second.
    pub rate: u64,
    pub after: u64,
}

fn status(s: u32) -> Result<u16, String> {
    match s {
        0 => Ok(503),
        400..=599 => Ok(s as u16),
        _ => Err("must be 400-599".into()),
    }
}

fn max_keys(n: u32) -> usize {
    (if n == 0 { DEFAULT_MAX_KEYS } else { n }) as usize
}

/// `(field, error)` for the caller to place.
type Invalid = (String, String);

pub(crate) fn rate_zone(z: &ir::RateZone, names: &[Box<str>]) -> Result<RateZone, Invalid> {
    if z.rate_milli == 0 {
        return Err(("rate_milli".into(), "must be positive".into()));
    }
    Ok(RateZone {
        id: z.id.as_str().into(),
        key: Template::parse_in(&z.key, names).map_err(|e| ("key".to_string(), e))?,
        rate: z.rate_milli,
        burst: u64::from(z.burst) * 1000,
        delay: u64::from(z.delay) * 1000,
        status: status(z.status).map_err(|e| ("status".to_string(), e))?,
        dry_run: z.dry_run,
        max_keys: max_keys(z.max_keys),
    })
}

pub(crate) fn conn_zone(z: &ir::ConnZone, names: &[Box<str>]) -> Result<ConnZone, Invalid> {
    if z.max == 0 {
        return Err(("max".into(), "must be positive".into()));
    }
    Ok(ConnZone {
        id: z.id.as_str().into(),
        key: Template::parse_in(&z.key, names).map_err(|e| ("key".to_string(), e))?,
        max: z.max,
        status: status(z.status).map_err(|e| ("status".to_string(), e))?,
        dry_run: z.dry_run,
        max_keys: max_keys(z.max_keys),
    })
}

pub(crate) fn real_ip(r: &ir::RealIp) -> Result<RealIp, Invalid> {
    let from = r
        .from
        .iter()
        .enumerate()
        .map(|(i, c)| Cidr::parse(c).map_err(|e| (format!("from[{i}]"), e)))
        .collect::<Result<_, _>>()?;
    let header = if r.header.is_empty() {
        "x-real-ip"
    } else {
        &r.header
    };
    Ok(RealIp {
        from,
        header: header.to_ascii_lowercase().into_bytes().into(),
        recursive: r.recursive,
    })
}

/// nginx allow and deny rules, in order.
pub(crate) fn rules(rules: &[ir::AccessRule]) -> Result<Box<[AccessRule]>, Invalid> {
    rules
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let cidr = if r.cidr.is_empty() {
                None
            } else {
                Some(Cidr::parse(&r.cidr).map_err(|e| (format!("rules[{i}].cidr"), e))?)
            };
            Ok(AccessRule {
                allow: r.allow,
                cidr,
            })
        })
        .collect()
}

/// nginx allow/deny over `rules`: the first rule that matches decides.
pub fn allowed(rules: &[AccessRule], ip: IpAddr) -> bool {
    rules
        .iter()
        .find(|r| r.cidr.is_none_or(|c| c.contains(ip)))
        .is_none_or(|r| r.allow)
}

pub(crate) fn access(
    a: &ir::Access,
    rate_zones: usize,
    conn_zones: usize,
    upstreams: usize,
    names: &[Box<str>],
) -> Result<Access, Invalid> {
    if let Some(i) = a.rate_limits.iter().position(|&z| z as usize >= rate_zones) {
        return Err((format!("rate_limits[{i}]"), "no such rate zone".into()));
    }
    if let Some(i) = a.conn_limits.iter().position(|&z| z as usize >= conn_zones) {
        return Err((
            format!("conn_limits[{i}]"),
            "no such connection zone".into(),
        ));
    }
    let rules = rules(&a.rules)?;
    let basic_auth = a.basic_auth.as_ref().map(|b| {
        let mut challenge = b"Basic realm=\"".to_vec();
        challenge.extend(
            b.realm
                .bytes()
                .filter(|&c| c >= b' ' && c != 0x7f && c != b'"'),
        );
        challenge.push(b'"');
        BasicAuth {
            challenge: challenge.into(),
            users: b
                .users
                .iter()
                .map(|u| BasicUser {
                    name: u.name.as_bytes().into(),
                    hash: u.hash.as_str().into(),
                })
                .collect(),
        }
    });
    let forward_auth = match &a.forward_auth {
        None => None,
        Some(f) => {
            if f.upstream as usize >= upstreams {
                return Err(("forward_auth.upstream".into(), "no such upstream".into()));
            }
            Some(ForwardAuth {
                upstream: f.upstream,
                uri: Template::parse_in(&f.uri, names)
                    .map_err(|e| ("forward_auth.uri".to_string(), e))?,
                timeout: Duration::from_millis(if f.timeout_ms == 0 {
                    60_000
                } else {
                    f.timeout_ms.into()
                }),
                copy_headers: f
                    .copy_headers
                    .iter()
                    .map(|h| h.to_ascii_lowercase().into_bytes().into())
                    .collect(),
            })
        }
    };
    Ok(Access {
        rate_limits: a.rate_limits.clone().into(),
        conn_limits: a.conn_limits.clone().into(),
        rules,
        basic_auth,
        jwt: a
            .jwt
            .as_ref()
            .map(|j| crate::auth::jwt(j, names))
            .transpose()?,
        oidc: a.oidc.as_ref().map(crate::auth::oidc).transpose()?,
        forward_auth,
    })
}

pub(crate) fn bandwidth(b: &ir::Bandwidth) -> Option<Bandwidth> {
    (b.rate > 0).then_some(Bandwidth {
        rate: b.rate,
        after: b.after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_match() {
        let c = Cidr::parse("10.1.0.0/16").unwrap();
        assert!(c.contains("10.1.2.3".parse().unwrap()));
        assert!(!c.contains("10.2.0.1".parse().unwrap()));
        assert!(c.contains("::ffff:10.1.0.9".parse().unwrap()));
        let one = Cidr::parse("2001:db8::1").unwrap();
        assert!(one.contains("2001:db8::1".parse().unwrap()));
        assert!(!one.contains("2001:db8::2".parse().unwrap()));
        assert!(
            Cidr::parse("0.0.0.0/0")
                .unwrap()
                .contains("1.2.3.4".parse().unwrap())
        );
        for bad in ["10.0.0.0/33", "x", "10.0.0.0/"] {
            assert!(Cidr::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn first_rule_decides() {
        let a = access(
            &ir::Access {
                rules: vec![
                    ir::AccessRule {
                        allow: false,
                        cidr: "192.168.1.1".into(),
                    },
                    ir::AccessRule {
                        allow: true,
                        cidr: "192.168.1.0/24".into(),
                    },
                    ir::AccessRule {
                        allow: false,
                        cidr: String::new(),
                    },
                ],
                ..Default::default()
            },
            0,
            0,
            0,
            &[],
        )
        .unwrap();
        assert!(!a.allows("192.168.1.1".parse().unwrap()));
        assert!(a.allows("192.168.1.2".parse().unwrap()));
        assert!(!a.allows("10.0.0.1".parse().unwrap()));
        assert!(Access::default().allows("10.0.0.1".parse().unwrap()));
    }
}
