//! OpenID Connect sign-in (authorization code flow with PKCE, nginx Plus
//! auth_oidc): sessions in a signed cookie, `$oidc_sub` and `$oidc_email`.
//!
//! A request without a session is answered 302 to the provider with a
//! signed, short-lived state cookie holding state, nonce, PKCE verifier and
//! the original target. The callback exchanges the code, verifies the ID
//! token, sets the session cookie and redirects back.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use proxelo_snapshot::{Oidc, SessionKey, Url};
use serde_json::{Value, json};

use crate::exchange::Exchange;
use crate::fetch::{fetch, push_query, query_arg};

/// Provider metadata is fetched again after this.
const METADATA_TTL: Duration = Duration::from_secs(3600);
/// How long a sign-in may take.
const STATE_TTL: u64 = 600;
/// Clock skew allowed on ID tokens.
const LEEWAY: u64 = 60;

#[derive(Clone)]
struct Provider {
    authorization: Url,
    token: Url,
    jwks: Url,
    end_session: Option<Url>,
}

static PROVIDERS: LazyLock<Mutex<HashMap<String, (Provider, Instant)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

async fn provider(o: &Oidc) -> Result<Provider, String> {
    let k = o.discovery.to_string();
    if let Some((p, at)) = PROVIDERS.lock().unwrap_or_else(|e| e.into_inner()).get(&k)
        && at.elapsed() < METADATA_TTL
    {
        return Ok(p.clone());
    }
    let r = fetch(&o.discovery, None, None).await?;
    if r.status != 200 {
        return Err(format!("{}: status {}", o.discovery, r.status));
    }
    let v: Value = serde_json::from_slice(&r.body).map_err(|e| e.to_string())?;
    // OpenID Connect Discovery 1.0 §4.3: the issuer must match.
    if v.get("issuer")
        .and_then(Value::as_str)
        .map(|i| i.trim_end_matches('/'))
        != Some(&*o.issuer)
    {
        return Err("discovery issuer does not match".into());
    }
    let url = |f: &str| {
        v.get(f)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("discovery has no {f}"))
            .and_then(Url::parse)
    };
    let p = Provider {
        authorization: url("authorization_endpoint")?,
        token: url("token_endpoint")?,
        jwks: url("jwks_uri")?,
        end_session: url("end_session_endpoint").ok(),
    };
    PROVIDERS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(k, (p.clone(), Instant::now()));
    Ok(p)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn mac(key: &SessionKey, data: &[u8]) -> Vec<u8> {
    PKey::hmac(key)
        .and_then(|k| Signer::new(MessageDigest::sha256(), &k)?.sign_oneshot_to_vec(data))
        .unwrap_or_default()
}

/// `base64url(json).base64url(hmac)`.
fn seal(key: &SessionKey, v: &Value) -> String {
    let body = URL_SAFE_NO_PAD.encode(v.to_string());
    let sig = URL_SAFE_NO_PAD.encode(mac(key, body.as_bytes()));
    format!("{body}.{sig}")
}

/// The JSON of a sealed value with a valid signature and an exp in the
/// future.
fn open(key: &SessionKey, s: &[u8]) -> Option<Value> {
    let dot = s.iter().position(|&c| c == b'.')?;
    let (body, sig) = (&s[..dot], &s[dot + 1..]);
    let sig = URL_SAFE_NO_PAD.decode(sig).ok()?;
    let want = mac(key, body);
    if want.len() != sig.len() || !openssl::memcmp::eq(&want, &sig) {
        return None;
    }
    let v: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body).ok()?).ok()?;
    (v.get("exp")?.as_u64()? > now()).then_some(v)
}

/// 256 random bits, base64url. `None` when OpenSSL has no randomness:
/// there is no safe sign-in then.
fn random() -> Option<String> {
    let mut b = [0u8; 32];
    openssl::rand::rand_bytes(&mut b).ok()?;
    Some(URL_SAFE_NO_PAD.encode(b))
}

fn state_cookie(o: &Oidc) -> String {
    format!("{}_auth", o.cookie)
}

fn set_cookie(x: &mut Exchange, name: &str, value: &str, max_age: Option<u64>) {
    x.auth_header.extend_from_slice(b"Set-Cookie: ");
    x.auth_header.extend_from_slice(name.as_bytes());
    x.auth_header.push(b'=');
    x.auth_header.extend_from_slice(value.as_bytes());
    x.auth_header
        .extend_from_slice(b"; Path=/; HttpOnly; SameSite=Lax");
    if x.tls.is_some() {
        x.auth_header.extend_from_slice(b"; Secure");
    }
    if let Some(a) = max_age {
        x.auth_header.extend_from_slice(b"; Max-Age=");
        proxelo_http1::push_u64(&mut x.auth_header, a);
    }
    x.auth_header.extend_from_slice(b"\r\n");
}

/// Answers 302 to `location`, with the cookies already in `auth_header`.
fn redirect(x: &mut Exchange, location: &[u8]) -> Result<(), u16> {
    x.auth_header.extend_from_slice(b"Location: ");
    crate::reply::push_header_value(&mut x.auth_header, location);
    x.auth_header.extend_from_slice(b"\r\n");
    Err(302)
}

/// The redirect URI for this request: absolute as configured, or the
/// request's origin with the configured path.
fn redirect_uri(x: &Exchange, o: &Oidc) -> Vec<u8> {
    let mut out = Vec::new();
    if o.redirect_uri.starts_with('/') {
        crate::reply::push_origin(&mut out, x.tls.is_some(), &x.host, x.local);
    }
    out.extend_from_slice(o.redirect_uri.as_bytes());
    out
}

/// Runs the sign-in for the request. `Err(302)` and `Err(401)` carry their
/// header lines in `x.auth_header`.
pub(crate) async fn check(x: &mut Exchange, o: &Oidc) -> Result<(), u16> {
    x.auth_header.clear();
    if x.path == *o.callback {
        return callback(x, o).await;
    }
    if !o.logout.is_empty() && x.path == *o.logout {
        return logout(x, o).await;
    }
    if let Some(v) = x.cookie(o.cookie.as_bytes()).and_then(|c| open(&o.key, c)) {
        let text = |f: &str| v.get(f).and_then(Value::as_str).unwrap_or_default();
        x.oidc_sub.clear();
        x.oidc_sub.extend_from_slice(text("sub").as_bytes());
        x.oidc_email.clear();
        x.oidc_email.extend_from_slice(text("email").as_bytes());
        return Ok(());
    }
    let p = provider(o).await.map_err(|_| 500u16)?;
    let (Some(state), Some(nonce), Some(verifier)) = (random(), random(), random()) else {
        return Err(500);
    };
    let target = String::from_utf8_lossy(x.req.target.get(&x.head)).into_owned();
    let sealed = seal(
        &o.key,
        &json!({
            "state": state,
            "nonce": nonce,
            "verifier": verifier,
            "to": if target.starts_with('/') { target } else { "/".into() },
            "exp": now() + STATE_TTL,
        }),
    );
    set_cookie(x, &state_cookie(o), &sealed, Some(STATE_TTL));
    let challenge = URL_SAFE_NO_PAD.encode(openssl::sha::sha256(verifier.as_bytes()));
    let mut loc = p.authorization.to_string().into_bytes();
    loc.push(if p.authorization.target.contains('?') {
        b'&'
    } else {
        b'?'
    });
    loc.extend_from_slice(b"response_type=code&client_id=");
    push_query(&mut loc, o.client_id.as_bytes());
    loc.extend_from_slice(b"&redirect_uri=");
    push_query(&mut loc, &redirect_uri(x, o));
    loc.extend_from_slice(b"&scope=");
    push_query(&mut loc, o.scope.as_bytes());
    loc.extend_from_slice(b"&state=");
    loc.extend_from_slice(state.as_bytes());
    loc.extend_from_slice(b"&nonce=");
    loc.extend_from_slice(nonce.as_bytes());
    loc.extend_from_slice(b"&code_challenge=");
    loc.extend_from_slice(challenge.as_bytes());
    loc.extend_from_slice(b"&code_challenge_method=S256");
    redirect(x, &loc)
}

async fn callback(x: &mut Exchange, o: &Oidc) -> Result<(), u16> {
    let Some(st) = x
        .cookie(state_cookie(o).as_bytes())
        .and_then(|c| open(&o.key, c))
    else {
        return Err(401);
    };
    let field = |f: &str| st.get(f).and_then(Value::as_str).unwrap_or_default();
    let state = query_arg(&x.args, b"state").unwrap_or_default();
    let want = field("state").as_bytes();
    if state.len() != want.len() || !openssl::memcmp::eq(&state, want) {
        return Err(401);
    }
    let Some(code) = query_arg(&x.args, b"code") else {
        // The provider answered with an error (RFC 6749 §4.1.2.1).
        return Err(401);
    };
    let p = provider(o).await.map_err(|_| 500u16)?;
    let mut form = b"grant_type=authorization_code&code=".to_vec();
    push_query(&mut form, &code);
    form.extend_from_slice(b"&redirect_uri=");
    push_query(&mut form, &redirect_uri(x, o));
    form.extend_from_slice(b"&code_verifier=");
    form.extend_from_slice(field("verifier").as_bytes());
    // RFC 6749 §2.3.1: client_secret_basic, the form-encoded id and secret.
    let auth = if o.client_secret.is_empty() {
        form.extend_from_slice(b"&client_id=");
        push_query(&mut form, o.client_id.as_bytes());
        None
    } else {
        let mut creds = Vec::new();
        push_query(&mut creds, o.client_id.as_bytes());
        creds.push(b':');
        push_query(&mut creds, o.client_secret.as_bytes());
        Some(format!("Basic {}", STANDARD.encode(creds)))
    };
    let r = fetch(&p.token, Some(&form), auth.as_deref())
        .await
        .map_err(|_| 502u16)?;
    if r.status != 200 {
        return Err(401);
    }
    let tokens: Value = serde_json::from_slice(&r.body).map_err(|_| 502u16)?;
    let id_token = tokens
        .get("id_token")
        .and_then(Value::as_str)
        .ok_or(502u16)?;
    let mut keys = crate::jwt::remote_keys(&p.jwks, METADATA_TTL, false).await;
    let mut verified = keys
        .as_deref()
        .map(|k| crate::jwt::verify(id_token.as_bytes(), &[k]));
    if let Some(Err((crate::jwt::Invalid::Signature, true))) = verified {
        keys = crate::jwt::remote_keys(&p.jwks, METADATA_TTL, true).await;
        verified = keys
            .as_deref()
            .map(|k| crate::jwt::verify(id_token.as_bytes(), &[k]));
    }
    let Some(Ok(v)) = verified else {
        return Err(401);
    };
    if crate::jwt::check_claims(&v.claims, &o.issuer, &[&*o.client_id], LEEWAY).is_err()
        || v.claims.get("nonce").and_then(Value::as_str) != Some(field("nonce"))
    {
        return Err(401);
    }
    let text = |f: &str| v.claims.get(f).and_then(Value::as_str).unwrap_or_default();
    let timeout = o.session_timeout.as_secs();
    let session = seal(
        &o.key,
        &json!({ "sub": text("sub"), "email": text("email"), "exp": now() + timeout }),
    );
    let to = field("to").to_owned();
    set_cookie(x, &o.cookie, &session, Some(timeout));
    set_cookie(x, &state_cookie(o), "", Some(0));
    redirect(x, to.as_bytes())
}

async fn logout(x: &mut Exchange, o: &Oidc) -> Result<(), u16> {
    set_cookie(x, &o.cookie, "", Some(0));
    let end = provider(o).await.ok().and_then(|p| p.end_session);
    let mut loc = Vec::new();
    match end {
        Some(e) => {
            loc.extend_from_slice(e.to_string().as_bytes());
            loc.push(if e.target.contains('?') { b'&' } else { b'?' });
            loc.extend_from_slice(b"client_id=");
            push_query(&mut loc, o.client_id.as_bytes());
            if !o.post_logout_uri.is_empty() {
                loc.extend_from_slice(b"&post_logout_redirect_uri=");
                push_query(&mut loc, o.post_logout_uri.as_bytes());
            }
        }
        None if !o.post_logout_uri.is_empty() => {
            loc.extend_from_slice(o.post_logout_uri.as_bytes());
        }
        None => loc.push(b'/'),
    }
    redirect(x, &loc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_values() {
        let key = [7u8; 32];
        let s = seal(&key, &json!({"sub": "a", "exp": now() + 10}));
        assert_eq!(open(&key, s.as_bytes()).unwrap()["sub"], "a");
        assert!(open(&[8u8; 32], s.as_bytes()).is_none());
        let mut bad = s.clone().into_bytes();
        bad[2] ^= 1;
        assert!(open(&key, &bad).is_none());
        let old = seal(&key, &json!({"sub": "a", "exp": 1}));
        assert!(open(&key, old.as_bytes()).is_none());
    }
}
