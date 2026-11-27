//! nginx auth_jwt: JWS signature, time and audience checks, key sets
//! fetched by URL, and the `$jwt_claim_<name>` and `$jwt_header_<name>`
//! variables.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Signer, Verifier};
use proxelo_snapshot::{Jwt, Key, KeyKind, Url, parse_jwks};
use serde_json::Value;

use crate::exchange::Exchange;

/// A token with an unknown kid fetches the key set again at most this often.
const REFETCH: Duration = Duration::from_secs(10);

/// The decoded parts of a verified token.
#[derive(Debug)]
pub(crate) struct Verified {
    pub header: Value,
    pub claims: Value,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Invalid {
    /// Not three base64url parts of JSON.
    Malformed,
    /// No key verifies the signature.
    Signature,
    /// Expired, not yet valid, or the wrong issuer or audience.
    Claims,
}

struct Fetched {
    keys: Arc<[Key]>,
    at: Instant,
}

/// Key sets fetched by URL, shared by every snapshot that names the URL.
static KEYS: LazyLock<Mutex<HashMap<String, Fetched>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The keys at `url`, fetched when not cached for `ttl`, or when `stale`
/// asks for a fresh copy and the last fetch is older than [`REFETCH`].
pub(crate) async fn remote_keys(url: &Url, ttl: Duration, stale: bool) -> Option<Arc<[Key]>> {
    let k = url.to_string();
    let cached = {
        let map = KEYS.lock().unwrap_or_else(|e| e.into_inner());
        map.get(&k).map(|f| (f.keys.clone(), f.at.elapsed()))
    };
    if let Some((keys, age)) = &cached
        && *age < ttl
        && (!stale || *age < REFETCH)
    {
        return Some(keys.clone());
    }
    match fetch_keys(url).await {
        Ok(keys) => {
            let keys: Arc<[Key]> = keys.into();
            KEYS.lock().unwrap_or_else(|e| e.into_inner()).insert(
                k,
                Fetched {
                    keys: keys.clone(),
                    at: Instant::now(),
                },
            );
            Some(keys)
        }
        // A failed refresh keeps the keys we had.
        Err(_) => cached.map(|(keys, _)| keys),
    }
}

async fn fetch_keys(url: &Url) -> Result<Vec<Key>, String> {
    let r = crate::fetch::fetch(url, None, None).await?;
    if r.status != 200 {
        return Err(format!("{url}: status {}", r.status));
    }
    parse_jwks(&r.body)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn json_part(s: &[u8]) -> Result<Value, Invalid> {
    let raw = URL_SAFE_NO_PAD.decode(s).map_err(|_| Invalid::Malformed)?;
    let v: Value = serde_json::from_slice(&raw).map_err(|_| Invalid::Malformed)?;
    if v.is_object() {
        Ok(v)
    } else {
        Err(Invalid::Malformed)
    }
}

fn digest(alg: &str) -> MessageDigest {
    match &alg[2..] {
        "384" => MessageDigest::sha384(),
        "512" => MessageDigest::sha512(),
        _ => MessageDigest::sha256(),
    }
}

/// Whether `key` signed `input` with `sig` under `alg`.
fn verifies(key: &Key, alg: &str, input: &[u8], sig: &[u8]) -> bool {
    let result = match &key.kind {
        KeyKind::Hmac(secret) => (|| {
            let pkey = PKey::hmac(secret)?;
            let mut s = Signer::new(digest(alg), &pkey)?;
            let mac = s.sign_oneshot_to_vec(input)?;
            Ok::<_, openssl::error::ErrorStack>(
                mac.len() == sig.len() && openssl::memcmp::eq(&mac, sig),
            )
        })(),
        KeyKind::Rsa(pkey) => (|| {
            let mut v = Verifier::new(digest(alg), pkey)?;
            if alg.starts_with("PS") {
                v.set_rsa_padding(Padding::PKCS1_PSS)?;
                v.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
                v.set_rsa_mgf1_md(digest(alg))?;
            }
            v.verify_oneshot(sig, input)
        })(),
        KeyKind::Ec(pkey, _) => (|| {
            // JWS carries r and s as fixed-size big-endian halves.
            if sig.is_empty() || !sig.len().is_multiple_of(2) {
                return Ok(false);
            }
            let (r, s) = sig.split_at(sig.len() / 2);
            let der =
                EcdsaSig::from_private_components(BigNum::from_slice(r)?, BigNum::from_slice(s)?)?
                    .to_der()?;
            let mut v = Verifier::new(digest(alg), pkey)?;
            v.verify_oneshot(&der, input)
        })(),
        KeyKind::Okp(pkey) => (|| {
            let mut v = Verifier::new_without_digest(pkey)?;
            v.verify_oneshot(sig, input)
        })(),
    };
    result.unwrap_or(false)
}

/// Checks the signature of `token` against `keys`. `Err(Signature)` with
/// `unknown_kid` set when no key carries the token's kid.
pub(crate) fn verify(token: &[u8], keys: &[&[Key]]) -> Result<Verified, (Invalid, bool)> {
    let mut parts = token.split(|&c| c == b'.');
    let (Some(h), Some(c), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err((Invalid::Malformed, false));
    };
    let header = json_part(h).map_err(|e| (e, false))?;
    let claims = json_part(c).map_err(|e| (e, false))?;
    let sig = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| (Invalid::Malformed, false))?;
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or("none");
    if !matches!(
        alg,
        "HS256"
            | "HS384"
            | "HS512"
            | "RS256"
            | "RS384"
            | "RS512"
            | "PS256"
            | "PS384"
            | "PS512"
            | "ES256"
            | "ES384"
            | "ES512"
            | "EdDSA"
    ) {
        return Err((Invalid::Signature, false));
    }
    // Critical extensions are not understood (RFC 7515 §4.1.11).
    if header.get("crit").is_some() {
        return Err((Invalid::Malformed, false));
    }
    let kid = header.get("kid").and_then(Value::as_str);
    let input = &token[..h.len() + 1 + c.len()];
    let mut known = false;
    for k in keys.iter().flat_map(|k| k.iter()) {
        if kid.is_some_and(|kid| !k.kid.is_empty() && *k.kid != *kid) || !k.suits(alg) {
            continue;
        }
        known = true;
        if verifies(k, alg, input, &sig) {
            return Ok(Verified { header, claims });
        }
    }
    Err((Invalid::Signature, !known))
}

/// The exp, nbf, iss and aud checks.
pub(crate) fn check_claims(
    claims: &Value,
    issuer: &str,
    audiences: &[impl AsRef<str>],
    leeway: u64,
) -> Result<(), Invalid> {
    let now = now();
    let time = |name: &str| match claims.get(name) {
        None => Ok(None),
        Some(v) => v.as_f64().map(|t| Some(t as u64)).ok_or(Invalid::Claims),
    };
    if time("exp")?.is_some_and(|exp| now >= exp.saturating_add(leeway)) {
        return Err(Invalid::Claims);
    }
    if time("nbf")?.is_some_and(|nbf| now.saturating_add(leeway) < nbf) {
        return Err(Invalid::Claims);
    }
    if !issuer.is_empty() && claims.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Err(Invalid::Claims);
    }
    if !audiences.is_empty() {
        let ok = match claims.get("aud") {
            Some(Value::String(a)) => audiences.iter().any(|w| w.as_ref() == a),
            Some(Value::Array(list)) => list
                .iter()
                .filter_map(Value::as_str)
                .any(|a| audiences.iter().any(|w| w.as_ref() == a)),
            _ => false,
        };
        if !ok {
            return Err(Invalid::Claims);
        }
    }
    Ok(())
}

/// Runs `j` against the request. `Err(401)` carries the challenge in
/// `x.auth_header`.
pub(crate) async fn check(x: &mut Exchange, j: &Jwt) -> Result<(), u16> {
    let token = match &j.token {
        Some(t) => {
            crate::vars::expand(x, t);
            x.tmpl.clone()
        }
        None => bearer(x).map(<[u8]>::to_vec).unwrap_or_default(),
    };
    let fail = |x: &mut Exchange, error: Option<&[u8]>| {
        x.auth_header.clear();
        x.auth_header.extend_from_slice(b"WWW-Authenticate: ");
        x.auth_header.extend_from_slice(&j.challenge);
        if let Some(e) = error {
            x.auth_header.extend_from_slice(b", error=\"");
            x.auth_header.extend_from_slice(e);
            x.auth_header.push(b'"');
        }
        x.auth_header.extend_from_slice(b"\r\n");
        Err(401)
    };
    if token.is_empty() {
        return fail(x, None);
    }
    let remote = match &j.jwks_url {
        Some(u) => remote_keys(u, j.key_cache, false).await,
        None => None,
    };
    let empty: Arc<[Key]> = Arc::new([]);
    let remote = remote.unwrap_or(empty);
    let mut result = verify(&token, &[&j.keys, &remote]);
    if let (Err((Invalid::Signature, true)), Some(u)) = (&result, &j.jwks_url) {
        // The key set may have rotated.
        if let Some(fresh) = remote_keys(u, j.key_cache, true).await {
            result = verify(&token, &[&j.keys, &fresh]);
        }
    }
    let v = match result {
        Ok(v) => v,
        Err(_) => return fail(x, Some(b"invalid_token")),
    };
    if check_claims(&v.claims, &j.issuer, &j.audiences, j.leeway).is_err() {
        return fail(x, Some(b"invalid_token"));
    }
    x.jwt = Some(Box::new(v));
    Ok(())
}

/// The credentials of `Authorization: Bearer <token>`.
fn bearer(x: &Exchange) -> Option<&[u8]> {
    let v = x.request_header(b"authorization")?.trim_ascii();
    let (scheme, rest) = v.split_at(v.iter().position(|&c| c == b' ')?);
    scheme
        .eq_ignore_ascii_case(b"bearer")
        .then(|| rest.trim_ascii())
}

/// Appends a claim or header field as nginx does: strings as they are,
/// arrays of strings joined with ",", anything else as JSON.
pub(crate) fn render(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::String(s) => out.extend_from_slice(s.as_bytes()),
        Value::Array(a) if a.iter().all(Value::is_string) => {
            for (i, s) in a.iter().filter_map(Value::as_str).enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(s.as_bytes());
            }
        }
        Value::Null => {}
        v => out.extend_from_slice(v.to_string().as_bytes()),
    }
}

/// The value of `name` in a JSON object, as text.
pub(crate) fn field(obj: &Value, name: &[u8], out: &mut Vec<u8>) {
    if let Some(v) = std::str::from_utf8(name).ok().and_then(|n| obj.get(n)) {
        render(v, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hs256(secret: &[u8], header: &str, claims: &str) -> Vec<u8> {
        let mut t = URL_SAFE_NO_PAD.encode(header).into_bytes();
        t.push(b'.');
        t.extend_from_slice(URL_SAFE_NO_PAD.encode(claims).as_bytes());
        let pkey = PKey::hmac(secret).unwrap();
        let mac = Signer::new(MessageDigest::sha256(), &pkey)
            .unwrap()
            .sign_oneshot_to_vec(&t)
            .unwrap();
        t.push(b'.');
        t.extend_from_slice(URL_SAFE_NO_PAD.encode(mac).as_bytes());
        t
    }

    #[test]
    fn hmac_and_claims() {
        let keys = parse_jwks(br#"{"keys":[{"kty":"oct","kid":"a","k":"c2VjcmV0"}]}"#).unwrap();
        let t = hs256(
            b"secret",
            r#"{"alg":"HS256","kid":"a"}"#,
            r#"{"sub":"u1","aud":["x","y"],"exp":99999999999}"#,
        );
        let v = verify(&t, &[&keys]).unwrap();
        assert_eq!(v.claims["sub"], "u1");
        assert!(check_claims(&v.claims, "", &["y"], 0).is_ok());
        assert_eq!(check_claims(&v.claims, "", &["z"], 0), Err(Invalid::Claims));
        assert_eq!(
            check_claims(&v.claims, "iss", &[] as &[&str], 0),
            Err(Invalid::Claims)
        );
        let mut out = Vec::new();
        field(&v.claims, b"aud", &mut out);
        assert_eq!(out, b"x,y");

        let bad = hs256(b"other", r#"{"alg":"HS256"}"#, "{}");
        assert_eq!(
            verify(&bad, &[&keys]).unwrap_err(),
            (Invalid::Signature, false)
        );
        let unknown = hs256(b"secret", r#"{"alg":"HS256","kid":"b"}"#, "{}");
        assert_eq!(
            verify(&unknown, &[&keys]).unwrap_err(),
            (Invalid::Signature, true)
        );
        let none = hs256(b"secret", r#"{"alg":"none"}"#, "{}");
        assert!(verify(&none, &[&keys]).is_err());
        let old = hs256(b"secret", r#"{"alg":"HS256"}"#, r#"{"exp":1000}"#);
        let v = verify(&old, &[&keys]).unwrap();
        assert_eq!(
            check_claims(&v.claims, "", &[] as &[&str], 0),
            Err(Invalid::Claims)
        );
    }

    #[test]
    fn ecdsa_and_eddsa() {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();
        let (mut x, mut y) = (BigNum::new().unwrap(), BigNum::new().unwrap());
        ec.public_key()
            .affine_coordinates(&group, &mut x, &mut y, &mut ctx)
            .unwrap();
        let jwk = format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(x.to_vec_padded(32).unwrap()),
            URL_SAFE_NO_PAD.encode(y.to_vec_padded(32).unwrap())
        );
        let keys = parse_jwks(jwk.as_bytes()).unwrap();
        let mut t = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#).into_bytes();
        t.push(b'.');
        t.extend_from_slice(URL_SAFE_NO_PAD.encode("{}").as_bytes());
        let digest = openssl::sha::sha256(&t);
        let sig = EcdsaSig::sign(&digest, &ec).unwrap();
        let mut raw = sig.r().to_vec_padded(32).unwrap();
        raw.extend(sig.s().to_vec_padded(32).unwrap());
        t.push(b'.');
        t.extend_from_slice(URL_SAFE_NO_PAD.encode(raw).as_bytes());
        assert!(verify(&t, &[&keys]).is_ok());

        let ed = PKey::generate_ed25519().unwrap();
        let jwk = format!(
            r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(ed.raw_public_key().unwrap())
        );
        let keys = parse_jwks(jwk.as_bytes()).unwrap();
        let mut t = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA"}"#).into_bytes();
        t.push(b'.');
        t.extend_from_slice(URL_SAFE_NO_PAD.encode(r#"{"a":1}"#).as_bytes());
        let sig = Signer::new_without_digest(&ed)
            .unwrap()
            .sign_oneshot_to_vec(&t)
            .unwrap();
        t.push(b'.');
        t.extend_from_slice(URL_SAFE_NO_PAD.encode(sig).as_bytes());
        let v = verify(&t, &[&keys]).unwrap();
        let mut out = Vec::new();
        field(&v.claims, b"a", &mut out);
        assert_eq!(out, b"1");
    }
}
