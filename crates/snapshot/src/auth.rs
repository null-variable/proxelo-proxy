//! Runtime form of the token and single sign-on access policies: JWT
//! (nginx auth_jwt) and OpenID Connect (nginx Plus auth_oidc).

use std::fmt;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Public};
use openssl::rsa::Rsa;
use proxelo_api::snapshot::v1 as ir;
use serde_json::Value;

use crate::template::Template;

type Invalid = (String, String);

/// An http or https URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub https: bool,
    pub host: Box<str>,
    pub port: u16,
    /// Path and query, starting with "/".
    pub target: Box<str>,
}

impl Url {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (https, rest) = if let Some(r) = s.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = s.strip_prefix("http://") {
            (false, r)
        } else {
            return Err("must be an http or https URL".into());
        };
        let (authority, target) = match rest.find(['/', '?']) {
            Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], &rest[i..]),
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.contains('@') {
            return Err("must not carry credentials".into());
        }
        let (host, port) = match authority.strip_prefix('[') {
            Some(v6) => {
                let end = v6.find(']').ok_or("bad IPv6 host")?;
                let port = v6[end + 1..].strip_prefix(':');
                (&v6[..end], port)
            }
            None => match authority.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            },
        };
        if host.is_empty()
            || host
                .bytes()
                .any(|c| !(c.is_ascii_alphanumeric() || b".-_:".contains(&c)))
        {
            return Err("bad host".into());
        }
        let port = match port {
            Some(p) => p.parse().map_err(|_| "bad port")?,
            None if https => 443,
            None => 80,
        };
        if target.bytes().any(|c| c <= b' ' || c == 0x7f || c == b'#') {
            return Err("bad path".into());
        }
        let target = if target.starts_with('?') {
            format!("/{target}")
        } else {
            target.to_owned()
        };
        Ok(Self {
            https,
            host: host.to_ascii_lowercase().into(),
            port,
            target: target.into(),
        })
    }

    /// The Host header value.
    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.to_string()
        };
        if self.port == if self.https { 443 } else { 80 } {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = if self.https { "https" } else { "http" };
        write!(f, "{scheme}://{}{}", self.authority(), self.target)
    }
}

/// The key material of a JSON Web Key.
#[derive(Clone)]
pub enum KeyKind {
    Rsa(PKey<Public>),
    /// With the curve's JWS algorithm: ES256, ES384 or ES512.
    Ec(PKey<Public>, &'static str),
    /// Ed25519 or Ed448, for EdDSA.
    Okp(PKey<Public>),
    Hmac(Box<[u8]>),
}

/// A verification key of a JSON Web Key Set.
#[derive(Clone)]
pub struct Key {
    pub kid: Box<str>,
    /// Empty: any algorithm the key type allows.
    pub alg: Box<str>,
    pub kind: KeyKind,
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match &self.kind {
            KeyKind::Rsa(_) => "RSA",
            KeyKind::Ec(_, alg) => alg,
            KeyKind::Okp(_) => "OKP",
            KeyKind::Hmac(_) => "oct",
        };
        write!(f, "Key({kind} kid={:?} alg={:?})", self.kid, self.alg)
    }
}

impl Key {
    /// Whether the key can verify a token signed with `alg`.
    pub fn suits(&self, alg: &str) -> bool {
        if !self.alg.is_empty() && *self.alg != *alg {
            return false;
        }
        match &self.kind {
            KeyKind::Rsa(_) => matches!(
                alg,
                "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512"
            ),
            KeyKind::Ec(_, a) => *a == alg,
            KeyKind::Okp(_) => alg == "EdDSA",
            KeyKind::Hmac(_) => matches!(alg, "HS256" | "HS384" | "HS512"),
        }
    }
}

fn b64(v: &Value, field: &str) -> Result<Vec<u8>, String> {
    let s = v
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{field} is missing"))?;
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|_| format!("{field} is not base64url"))
}

fn num(v: &Value, field: &str) -> Result<BigNum, String> {
    BigNum::from_slice(&b64(v, field)?).map_err(|e| e.to_string())
}

fn key(v: &Value) -> Result<Option<Key>, String> {
    if v.get("use")
        .and_then(Value::as_str)
        .is_some_and(|u| u != "sig")
    {
        return Ok(None);
    }
    let text = |f: &str| v.get(f).and_then(Value::as_str).unwrap_or_default();
    let kind = match text("kty") {
        "RSA" => {
            let rsa = Rsa::from_public_components(num(v, "n")?, num(v, "e")?)
                .map_err(|e| e.to_string())?;
            KeyKind::Rsa(PKey::from_rsa(rsa).map_err(|e| e.to_string())?)
        }
        "EC" => {
            let (nid, alg) = match text("crv") {
                "P-256" => (Nid::X9_62_PRIME256V1, "ES256"),
                "P-384" => (Nid::SECP384R1, "ES384"),
                "P-521" => (Nid::SECP521R1, "ES512"),
                c => return Err(format!("unknown curve {c:?}")),
            };
            let group = EcGroup::from_curve_name(nid).map_err(|e| e.to_string())?;
            let (x, y) = (num(v, "x")?, num(v, "y")?);
            let ec = EcKey::from_public_key_affine_coordinates(&group, &x, &y)
                .map_err(|e| e.to_string())?;
            ec.check_key().map_err(|_| "point is not on the curve")?;
            KeyKind::Ec(PKey::from_ec_key(ec).map_err(|e| e.to_string())?, alg)
        }
        "OKP" => {
            let id = match text("crv") {
                "Ed25519" => Id::ED25519,
                "Ed448" => Id::ED448,
                // X25519 and X448 do not sign.
                _ => return Ok(None),
            };
            KeyKind::Okp(
                PKey::public_key_from_raw_bytes(&b64(v, "x")?, id).map_err(|e| e.to_string())?,
            )
        }
        "oct" => KeyKind::Hmac(b64(v, "k")?.into()),
        _ => return Ok(None),
    };
    Ok(Some(Key {
        kid: text("kid").into(),
        alg: text("alg").into(),
        kind,
    }))
}

/// The signing keys of a JSON Web Key Set (RFC 7517). Keys for encryption
/// and of unknown types are left out.
pub fn parse_jwks(json: &[u8]) -> Result<Vec<Key>, String> {
    let v: Value = serde_json::from_slice(json).map_err(|e| e.to_string())?;
    // A single key is accepted as well as a set.
    let keys = match v.get("keys") {
        Some(Value::Array(a)) => a.as_slice(),
        Some(_) => return Err("keys is not an array".into()),
        None => std::slice::from_ref(&v),
    };
    let mut out = Vec::with_capacity(keys.len());
    for (i, k) in keys.iter().enumerate() {
        if let Some(k) = key(k).map_err(|e| format!("keys[{i}]: {e}"))? {
            out.push(k);
        }
    }
    Ok(out)
}

/// nginx auth_jwt.
#[derive(Debug)]
pub struct Jwt {
    /// The WWW-Authenticate value for a request without a token.
    pub challenge: Box<[u8]>,
    /// `None`: the Bearer credentials of the Authorization header.
    pub token: Option<Template>,
    pub keys: Box<[Key]>,
    pub jwks_url: Option<Url>,
    pub key_cache: Duration,
    pub issuer: Box<str>,
    pub audiences: Box<[Box<str>]>,
    pub leeway: u64,
}

/// Session cookie values are signed with this.
pub type SessionKey = [u8; 32];

/// OpenID Connect sign-in.
#[derive(Debug)]
pub struct Oidc {
    /// Without a trailing "/".
    pub issuer: Box<str>,
    /// The discovery document.
    pub discovery: Url,
    pub client_id: Box<str>,
    pub client_secret: Box<str>,
    /// A path, answered on the request's origin, or an absolute URL.
    pub redirect_uri: Box<str>,
    /// The path part of `redirect_uri`, which is the callback.
    pub callback: Box<[u8]>,
    /// Space separated, with "openid".
    pub scope: Box<str>,
    pub cookie: Box<str>,
    pub session_timeout: Duration,
    pub logout: Box<[u8]>,
    pub post_logout_uri: Box<str>,
    pub key: SessionKey,
}

fn quoted(realm: &str) -> Vec<u8> {
    realm
        .bytes()
        .filter(|&c| c >= b' ' && c != 0x7f && c != b'"' && c != b'\\')
        .collect()
}

pub(crate) fn jwt(j: &ir::Jwt, names: &[Box<str>]) -> Result<Jwt, Invalid> {
    let mut challenge = b"Bearer realm=\"".to_vec();
    challenge.extend(quoted(if j.realm.is_empty() {
        "proxelo"
    } else {
        &j.realm
    }));
    challenge.push(b'"');
    let token = if j.token.is_empty() {
        None
    } else {
        Some(Template::parse_in(&j.token, names).map_err(|e| ("jwt.token".to_string(), e))?)
    };
    let keys = if j.jwks.is_empty() {
        Vec::new()
    } else {
        parse_jwks(&j.jwks).map_err(|e| ("jwt.jwks".to_string(), e))?
    };
    let jwks_url = if j.jwks_url.is_empty() {
        None
    } else {
        Some(Url::parse(&j.jwks_url).map_err(|e| ("jwt.jwks_url".to_string(), e))?)
    };
    if keys.is_empty() && jwks_url.is_none() {
        return Err(("jwt.jwks".into(), "no signing keys and no jwks_url".into()));
    }
    Ok(Jwt {
        challenge: challenge.into(),
        token,
        keys: keys.into(),
        jwks_url,
        key_cache: Duration::from_secs(if j.key_cache_s == 0 {
            3600
        } else {
            j.key_cache_s.into()
        }),
        issuer: j.issuer.as_str().into(),
        audiences: j.audiences.iter().map(|a| a.as_str().into()).collect(),
        leeway: j.leeway_s.into(),
    })
}

fn cookie_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
}

pub(crate) fn oidc(o: &ir::Oidc) -> Result<Oidc, Invalid> {
    let err = |f: &str, e: &str| (format!("oidc.{f}"), e.to_string());
    let issuer = o.issuer.trim_end_matches('/');
    let discovery = Url::parse(&format!("{issuer}/.well-known/openid-configuration"))
        .map_err(|e| err("issuer", &e))?;
    if o.client_id.is_empty() {
        return Err(err("client_id", "is required"));
    }
    let redirect_uri = if o.redirect_uri.is_empty() {
        "/oidc_callback"
    } else {
        &o.redirect_uri
    };
    let callback: Box<[u8]> = if redirect_uri.starts_with('/') {
        redirect_uri.as_bytes().into()
    } else {
        let u = Url::parse(redirect_uri).map_err(|e| err("redirect_uri", &e))?;
        let path = u.target.split('?').next().unwrap_or("/");
        path.as_bytes().into()
    };
    if callback.contains(&b'?') || callback.iter().any(|&c| c <= b' ') {
        return Err(err("redirect_uri", "must be a path without a query"));
    }
    let cookie = if o.cookie.is_empty() {
        "proxelo_oidc"
    } else {
        &o.cookie
    };
    if !cookie_name(cookie) {
        return Err(err("cookie", "is not a cookie name"));
    }
    let mut scopes: Vec<&str> = o.scopes.iter().map(String::as_str).collect();
    if !scopes.contains(&"openid") {
        scopes.insert(0, "openid");
    }
    if scopes
        .iter()
        .any(|s| s.is_empty() || s.bytes().any(|c| c <= b' ' || c == b'"' || c == b'\\'))
    {
        return Err(err("scopes", "bad scope"));
    }
    for (f, v) in [
        ("logout_uri", &o.logout_uri),
        ("post_logout_uri", &o.post_logout_uri),
    ] {
        if v.bytes().any(|c| c <= b' ' || c == 0x7f) {
            return Err(err(f, "bad URI"));
        }
    }
    // The session key depends on the client's secret, so sessions end when
    // it changes.
    let mut seed = b"proxelo-oidc-session\0".to_vec();
    seed.extend_from_slice(issuer.as_bytes());
    seed.push(0);
    seed.extend_from_slice(o.client_id.as_bytes());
    seed.push(0);
    seed.extend_from_slice(o.client_secret.as_bytes());
    let key = openssl::sha::sha256(&seed);
    Ok(Oidc {
        issuer: issuer.into(),
        discovery,
        client_id: o.client_id.as_str().into(),
        client_secret: o.client_secret.as_str().into(),
        redirect_uri: redirect_uri.into(),
        callback,
        scope: scopes.join(" ").into(),
        cookie: cookie.into(),
        session_timeout: Duration::from_secs(if o.session_timeout_s == 0 {
            8 * 3600
        } else {
            o.session_timeout_s.into()
        }),
        logout: o.logout_uri.as_bytes().into(),
        post_logout_uri: o.post_logout_uri.as_str().into(),
        key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = Url::parse("https://Login.Example.com/realms/a?x=1").unwrap();
        assert_eq!(
            (u.https, &*u.host, u.port, &*u.target),
            (true, "login.example.com", 443, "/realms/a?x=1")
        );
        assert_eq!(u.authority(), "login.example.com");
        let u = Url::parse("http://[::1]:8080").unwrap();
        assert_eq!((&*u.host, u.port, &*u.target), ("::1", 8080, "/"));
        assert_eq!(u.to_string(), "http://[::1]:8080/");
        assert!(Url::parse("ftp://a").is_err());
        assert!(Url::parse("https://u:p@a/").is_err());
    }

    #[test]
    fn jwks() {
        let keys = parse_jwks(
            br#"{"keys":[
              {"kty":"oct","kid":"h","k":"c2VjcmV0"},
              {"kty":"EC","crv":"P-256","use":"enc","x":"","y":""},
              {"kty":"OKP","crv":"X25519","x":"AA"},
              {"kty":"OKP","crv":"Ed25519","kid":"e","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
            ]}"#,
        )
        .unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys[0].suits("HS256") && !keys[0].suits("RS256"));
        assert!(keys[1].suits("EdDSA"));
        assert!(parse_jwks(br#"{"keys":[{"kty":"RSA","n":"!"}]}"#).is_err());
    }
}
