//! JWT and OpenID Connect access policies end to end, against a scripted
//! provider.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use proxelo_api::snapshot::v1::{
    self as ir, Access, Action, HostMatch, Jwt, Listener, Oidc, PathMatch, ReturnAction, Route,
    Site, action, host_match, path_match,
};
use proxelo_server::{Listeners, Server};
use proxelo_snapshot::Runtime;

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

fn jwks() -> String {
    format!(
        r#"{{"keys":[{{"kty":"oct","kid":"k1","alg":"HS256","k":"{}"}}]}}"#,
        URL_SAFE_NO_PAD.encode(SECRET)
    )
}

fn sign(claims: &str) -> String {
    let mut t = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","kid":"k1","typ":"JWT"}"#);
    t.push('.');
    t.push_str(&URL_SAFE_NO_PAD.encode(claims));
    let pkey = PKey::hmac(SECRET).unwrap();
    let mac = Signer::new(MessageDigest::sha256(), &pkey)
        .unwrap()
        .sign_oneshot_to_vec(t.as_bytes())
        .unwrap();
    t.push('.');
    t.push_str(&URL_SAFE_NO_PAD.encode(mac));
    t
}

fn answer(text: &str, access: Access) -> Route {
    Route {
        path: Some(PathMatch {
            kind: path_match::Kind::Prefix as i32,
            value: "/".into(),
        }),
        action: Some(Action {
            kind: Some(action::Kind::Return(ReturnAction {
                status: 200,
                text: text.into(),
            })),
        }),
        access: Some(access),
        ..Default::default()
    }
}

fn start(route: Route) -> SocketAddr {
    let addr = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let snap = ir::Snapshot {
        revision: 1,
        listeners: vec![Listener {
            address: addr.to_string(),
            ..Default::default()
        }],
        sites: vec![Site {
            listeners: vec![0],
            hostnames: vec![HostMatch {
                kind: host_match::Kind::Exact as i32,
                value: "example.com".into(),
            }],
            routes: vec![route],
            ..Default::default()
        }],
        ..Default::default()
    };
    proxelo_snapshot::validate(&snap).unwrap();
    let rt = Runtime::build(&snap).unwrap();
    let server = Server::new(Runtime::empty(), 2);
    let workers = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let mut listeners = Listeners::new(vec![workers.handle().clone()], false);
    listeners.apply(&server, rt).unwrap();
    std::mem::forget(listeners);
    std::mem::forget(workers);
    addr
}

/// Sends one request and returns the head and body.
fn get(addr: SocketAddr, target: &str, headers: &str) -> (String, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "GET {target} HTTP/1.1\r\nHost: example.com\r\n{headers}Connection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    (head.to_owned(), body.to_owned())
}

fn header<'a>(head: &'a str, name: &str) -> Vec<&'a str> {
    head.lines()
        .filter_map(|l| l.split_once(": "))
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
        .collect()
}

#[test]
fn jwt_policy() {
    let addr = start(answer(
        "sub=$jwt_claim_sub roles=$jwt_claim_roles kid=$jwt_header_kid",
        Access {
            jwt: Some(Jwt {
                realm: "api".into(),
                jwks: jwks().into_bytes(),
                audiences: vec!["svc".into()],
                ..Default::default()
            }),
            ..Default::default()
        },
    ));
    let (head, _) = get(addr, "/", "");
    assert!(head.starts_with("HTTP/1.1 401"), "{head}");
    assert_eq!(header(&head, "www-authenticate"), ["Bearer realm=\"api\""]);

    let good = sign(r#"{"sub":"u1","aud":"svc","roles":["a","b"],"exp":99999999999}"#);
    let (head, body) = get(addr, "/", &format!("Authorization: Bearer {good}\r\n"));
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, "sub=u1 roles=a,b kid=k1");

    for bad in [
        sign(r#"{"sub":"u1","aud":"other"}"#),
        sign(r#"{"sub":"u1","aud":"svc","exp":1}"#),
        format!("{}x", &good[..good.len() - 1]),
    ] {
        let (head, _) = get(addr, "/", &format!("Authorization: Bearer {bad}\r\n"));
        assert!(head.starts_with("HTTP/1.1 401"), "{head}");
        assert_eq!(
            header(&head, "www-authenticate"),
            ["Bearer realm=\"api\", error=\"invalid_token\""]
        );
    }
}

/// A provider with discovery, keys and a token endpoint that issues an ID
/// token for code "c1" with the nonce it was last sent.
fn provider() -> (String, Arc<Mutex<String>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let issuer = format!("http://{}", l.local_addr().unwrap());
    let nonce = Arc::new(Mutex::new(String::new()));
    let (iss, n) = (issuer.clone(), nonce.clone());
    thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            let mut raw = Vec::new();
            let mut b = [0u8; 4096];
            while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                let k = s.read(&mut b).unwrap();
                if k == 0 {
                    break;
                }
                raw.extend_from_slice(&b[..k]);
            }
            let text = String::from_utf8_lossy(&raw).to_string();
            let line = text.lines().next().unwrap_or_default().to_owned();
            let body = if line.starts_with("GET /.well-known/openid-configuration") {
                format!(
                    r#"{{"issuer":"{iss}","authorization_endpoint":"{iss}/authorize","token_endpoint":"{iss}/token","jwks_uri":"{iss}/jwks","end_session_endpoint":"{iss}/logout"}}"#
                )
            } else if line.starts_with("GET /jwks") {
                jwks()
            } else if line.starts_with("POST /token") {
                let ok = text.contains("code=c1")
                    && text.contains("code_verifier=")
                    && text.contains("Authorization: Basic ");
                if ok {
                    let id = sign(&format!(
                        r#"{{"iss":"{iss}","aud":"app","sub":"user-7","email":"u@example.com","nonce":"{}","exp":99999999999}}"#,
                        n.lock().unwrap()
                    ));
                    format!(r#"{{"id_token":"{id}","token_type":"Bearer"}}"#)
                } else {
                    let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
                    continue;
                }
            } else {
                let _ = s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                continue;
            };
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (issuer, nonce)
}

fn query<'a>(url: &'a str, name: &str) -> &'a str {
    url.split(['?', '&'])
        .find_map(|kv| kv.strip_prefix(name).and_then(|v| v.strip_prefix('=')))
        .unwrap()
}

#[test]
fn oidc_policy() {
    let (issuer, nonce) = provider();
    let addr = start(answer(
        "sub=$oidc_sub email=$oidc_email",
        Access {
            oidc: Some(Oidc {
                issuer: issuer.clone(),
                client_id: "app".into(),
                client_secret: "s3cret".into(),
                logout_uri: "/logout".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
    ));
    // Not signed in: off to the provider, with the sign-in state in a cookie.
    let (head, _) = get(addr, "/app/page?x=1", "");
    assert!(head.starts_with("HTTP/1.1 302"), "{head}");
    let loc = header(&head, "location")[0];
    assert!(loc.starts_with(&format!(
        "{issuer}/authorize?response_type=code&client_id=app"
    )));
    assert_eq!(query(loc, "code_challenge_method"), "S256");
    assert_eq!(
        query(loc, "redirect_uri"),
        format!("http%3A%2F%2Fexample.com%3A{}%2Foidc_callback", addr.port())
    );
    let state = query(loc, "state").to_owned();
    *nonce.lock().unwrap() = query(loc, "nonce").to_owned();
    let auth_cookie = header(&head, "set-cookie")[0]
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert!(auth_cookie.starts_with("proxelo_oidc_auth="));

    // A forged state is refused.
    let (head, _) = get(
        addr,
        "/oidc_callback?code=c1&state=forged",
        &format!("Cookie: {auth_cookie}\r\n"),
    );
    assert!(head.starts_with("HTTP/1.1 401"), "{head}");

    // The callback signs in and goes back where the user was going.
    let (head, _) = get(
        addr,
        &format!("/oidc_callback?code=c1&state={state}"),
        &format!("Cookie: {auth_cookie}\r\n"),
    );
    assert!(head.starts_with("HTTP/1.1 302"), "{head}");
    assert_eq!(header(&head, "location"), ["/app/page?x=1"]);
    let session = header(&head, "set-cookie")
        .into_iter()
        .find(|c| c.starts_with("proxelo_oidc="))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();

    let (head, body) = get(addr, "/app/page", &format!("Cookie: {session}\r\n"));
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, "sub=user-7 email=u@example.com");

    // Logout clears the session and goes to the provider.
    let (head, _) = get(addr, "/logout", &format!("Cookie: {session}\r\n"));
    assert!(head.starts_with("HTTP/1.1 302"), "{head}");
    assert!(header(&head, "location")[0].starts_with(&format!("{issuer}/logout?client_id=app")));
    assert!(header(&head, "set-cookie")[0].starts_with("proxelo_oidc=; "));
}
