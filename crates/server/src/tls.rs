//! TLS termination with OpenSSL.
//!
//! Every TLS listener gets a set of contexts built with the snapshot: one per
//! certificate its sites use, all with the listener's protocol settings. The
//! handshake starts on the default certificate's context; the SNI callback
//! finds the site for the name exactly like the Host lookup does and moves
//! the handshake to that site's certificate. ACME TLS-ALPN-01 challenges are
//! answered from the ALPN callback, which runs before the certificate is
//! sent.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use arc_swap::ArcSwap;
use openssl::dh::Dh;
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{
    AlpnError, NameType, SniError, SslConnector, SslContext, SslContextBuilder, SslMethod,
    SslOptions, SslRef, SslSessionCacheMode, SslVerifyMode, SslVersion,
};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509, X509VerifyResult};
use proxelo_snapshot::{Certificate, ClientAuthMode, ListenerTls, Runtime, UpstreamTls};

/// The ACME protocol of TLS-ALPN-01 (RFC 8737).
const ACME_TLS: &[u8] = b"acme-tls/1";

/// TLS-ALPN-01 certificates by lowercase name. Replaced as a whole by the
/// control plane; read by handshakes.
static TLS_CHALLENGES: LazyLock<ArcSwap<HashMap<Box<str>, AcmeCert>>> =
    LazyLock::new(|| ArcSwap::from_pointee(HashMap::new()));

pub(crate) struct AcmeCert {
    chain: Box<[X509]>,
    key: PKey<Private>,
}

/// Replaces the TLS-ALPN-01 challenge certificates. Entries that do not
/// parse are skipped and reported.
pub fn set_tls_challenges(list: &[(String, String, String)]) -> Vec<String> {
    let mut map = HashMap::new();
    let mut errors = Vec::new();
    for (name, chain, key) in list {
        match Certificate::parse(name, chain.as_bytes(), key.as_bytes()) {
            Ok(c) => {
                map.insert(
                    name.to_ascii_lowercase().into(),
                    AcmeCert {
                        chain: c.chain,
                        key: c.key,
                    },
                );
            }
            Err(e) => errors.push(format!("tls-alpn-01 {name}: {e}")),
        }
    }
    TLS_CHALLENGES.store(Arc::new(map));
    errors
}

/// The TLS contexts of one listener.
pub(crate) struct Acceptor {
    /// Handshakes start here: the default certificate, or none.
    base: SslContext,
}

impl Acceptor {
    pub fn ssl(&self) -> Result<openssl::ssl::Ssl, ErrorStack> {
        openssl::ssl::Ssl::new(&self.base)
    }
}

fn version(v: u16) -> SslVersion {
    match v {
        0x0301 => SslVersion::TLS1,
        0x0302 => SslVersion::TLS1_1,
        0x0304 => SslVersion::TLS1_3,
        _ => SslVersion::TLS1_2,
    }
}

/// Adds the PEM certificates in `pem` to the context's trust store.
fn trust(b: &mut SslContextBuilder, pem: &str) -> Result<Vec<X509>, ErrorStack> {
    let certs = X509::stack_from_pem(pem.as_bytes())?;
    let mut store = X509StoreBuilder::new()?;
    for c in &certs {
        store.add_cert(c.clone())?;
    }
    b.set_verify_cert_store(store.build())?;
    Ok(certs)
}

fn context(
    t: &ListenerTls,
    http2: bool,
    cert: Option<&Certificate>,
) -> Result<SslContextBuilder, ErrorStack> {
    let mut b = SslContextBuilder::new(SslMethod::tls_server())?;
    b.set_min_proto_version(Some(version(t.min_version)))?;
    b.set_max_proto_version(Some(version(t.max_version)))?;
    b.set_cipher_list(&t.ciphers)?;
    if !t.ciphersuites.is_empty() {
        b.set_ciphersuites(&t.ciphersuites)?;
    }
    if !t.groups.is_empty() {
        b.set_groups_list(&t.groups)?;
    }
    if !t.dh_params.is_empty() {
        let dh = Dh::params_from_pem(t.dh_params.as_bytes())?;
        b.set_tmp_dh(&dh)?;
    }
    // nginx: no renegotiation, no compression.
    let mut opts = SslOptions::NO_RENEGOTIATION | SslOptions::NO_COMPRESSION;
    if t.prefer_server_ciphers {
        opts |= SslOptions::CIPHER_SERVER_PREFERENCE;
    }
    if !t.session_tickets {
        opts |= SslOptions::NO_TICKET;
    }
    b.set_options(opts);
    if t.session_cache_size == 0 {
        b.set_session_cache_mode(SslSessionCacheMode::OFF);
    } else {
        b.set_session_cache_mode(SslSessionCacheMode::SERVER);
        b.set_session_cache_size(i32::try_from(t.session_cache_size).unwrap_or(i32::MAX));
    }
    // Session IDs and tickets are bound to the listener's settings.
    b.set_session_id_context(b"proxelo")?;
    if let Some(ca) = &t.client_auth {
        // The verdict is read after the handshake: a missing or bad
        // certificate is answered with 400, as nginx does.
        b.set_verify_callback(SslVerifyMode::PEER, |_, _| true);
        b.set_verify_depth(ca.depth);
        if !ca.ca.is_empty() {
            for c in trust(&mut b, &ca.ca)? {
                b.add_client_ca(&c)?;
            }
        }
    }
    if let Some(c) = cert {
        b.set_certificate(&c.chain[0])?;
        for extra in &c.chain[1..] {
            b.add_extra_chain_cert(extra.clone())?;
        }
        b.set_private_key(&c.key)?;
        b.check_private_key()?;
    }
    b.set_alpn_select_callback(move |ssl, client| alpn(ssl, client, http2));
    Ok(b)
}

/// Picks h2 when the listener has HTTP/2 and the client offers it, then
/// http/1.1. A client offering acme-tls/1 for a name with a challenge gets
/// the challenge certificate.
fn alpn<'a>(ssl: &mut SslRef, client: &'a [u8], http2: bool) -> Result<&'a [u8], AlpnError> {
    let offered = |p: &[u8]| protocols(client).find(|&o| o == p);
    if let Some(p) = offered(ACME_TLS) {
        let name = ssl
            .servername(NameType::HOST_NAME)
            .map(str::to_ascii_lowercase)
            .ok_or(AlpnError::ALERT_FATAL)?;
        let all = TLS_CHALLENGES.load();
        let c = all.get(name.as_str()).ok_or(AlpnError::ALERT_FATAL)?;
        ssl.set_certificate(&c.chain[0])
            .and_then(|()| ssl.set_private_key(&c.key))
            .map_err(|_| AlpnError::ALERT_FATAL)?;
        return Ok(p);
    }
    if http2 && let Some(p) = offered(b"h2") {
        return Ok(p);
    }
    offered(b"http/1.1").ok_or(AlpnError::NOACK)
}

/// Splits an ALPN protocol list (length-prefixed names).
fn protocols(mut list: &[u8]) -> impl Iterator<Item = &[u8]> {
    std::iter::from_fn(move || {
        let (&n, rest) = list.split_first()?;
        let n = usize::from(n);
        if rest.len() < n {
            return None;
        }
        let (p, rest) = rest.split_at(n);
        list = rest;
        Some(p)
    })
}

/// Builds the acceptors of every TLS listener in `rt`, indexed like
/// `rt.listeners`. Fails when OpenSSL rejects a setting or certificate, so a
/// snapshot that cannot serve TLS is refused before it is swapped in.
pub(crate) fn build(rt: &Arc<Runtime>) -> Result<Box<[Option<Acceptor>]>, String> {
    rt.listeners
        .iter()
        .enumerate()
        .map(|(li, l)| {
            let Some(t) = &l.tls else {
                return Ok(None);
            };
            let err = |e: ErrorStack| format!("listeners[{li}].tls: {e}");
            // A context per certificate any site of this listener offers.
            let mut by_cert: HashMap<u32, SslContext> = HashMap::new();
            for site in rt
                .sites
                .iter()
                .filter(|s| s.listeners.contains(&(li as u32)))
            {
                if let Some(&c) = site.certificates.first()
                    && let std::collections::hash_map::Entry::Vacant(v) = by_cert.entry(c)
                {
                    let ctx =
                        context(t, l.http2, Some(&rt.certificates[c as usize])).map_err(err)?;
                    v.insert(ctx.build());
                }
            }
            let default = t.default_certificate.map(|c| &rt.certificates[c as usize]);
            let mut base = context(t, l.http2, default).map_err(err)?;
            let rt = Arc::clone(rt);
            let has_default = default.is_some();
            base.set_servername_callback(move |ssl, _alert| {
                let Some(name) = ssl.servername(NameType::HOST_NAME) else {
                    return if has_default {
                        Ok(())
                    } else {
                        Err(SniError::ALERT_FATAL)
                    };
                };
                let name = name.trim_end_matches('.').to_ascii_lowercase();
                let cert = match rt.listeners[li].site(Some(name.as_bytes())) {
                    Ok(Some(s)) => rt.sites[s as usize].certificates.first().copied(),
                    _ => None,
                };
                match cert.and_then(|c| by_cert.get(&c)) {
                    Some(ctx) => ssl.set_ssl_context(ctx).map_err(|_| SniError::ALERT_FATAL),
                    // A challenge-only name has no site certificate yet.
                    None if has_default || TLS_CHALLENGES.load().contains_key(name.as_str()) => {
                        Ok(())
                    }
                    None => Err(SniError::ALERT_FATAL),
                }
            });
            Ok(Some(Acceptor { base: base.build() }))
        })
        .collect()
}

/// Builds the contexts `build` would, without the SNI wiring, so OpenSSL's
/// verdict on settings and certificates is known without serving.
pub(crate) fn check(rt: &Runtime) -> Result<(), String> {
    for (li, l) in rt.listeners.iter().enumerate() {
        let Some(t) = &l.tls else {
            continue;
        };
        let err = |e: ErrorStack| format!("listeners[{li}].tls: {e}");
        context(
            t,
            l.http2,
            t.default_certificate.map(|c| &rt.certificates[c as usize]),
        )
        .map_err(err)?;
        for site in rt
            .sites
            .iter()
            .filter(|s| s.listeners.contains(&(li as u32)))
        {
            if let Some(&c) = site.certificates.first() {
                context(t, l.http2, Some(&rt.certificates[c as usize])).map_err(err)?;
            }
        }
    }
    Ok(())
}

/// The client certificate check of a connection ($ssl_client_verify).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ClientVerify {
    /// Not requested, or requested and not sent ("NONE").
    #[default]
    None,
    Success,
    /// Sent and not valid ("FAILED:<reason>").
    Failed(X509VerifyResult),
}

/// What the request variables know about the TLS connection.
#[derive(Debug, Clone, Default)]
pub(crate) struct TlsInfo {
    pub protocol: &'static str,
    pub cipher: &'static str,
    /// Lowercase SNI name, empty without one.
    pub server_name: Box<[u8]>,
    pub session_reused: bool,
    /// Whether the listener asked for a certificate, and how.
    pub client_auth: Option<ClientAuthMode>,
    pub verify: ClientVerify,
    /// The client certificate's subject and issuer (RFC 2253) and serial
    /// in hex, when one was sent.
    pub client_subject: Box<str>,
    pub client_issuer: Box<str>,
    pub client_serial: Box<str>,
    /// PEM of the client certificate.
    pub client_cert: Box<str>,
}

fn rfc2253(name: &openssl::x509::X509NameRef) -> String {
    // Most specific first, comma separated.
    name.entries()
        .collect::<Vec<_>>()
        .iter()
        .rev()
        .map(|e| {
            let key = e.object().nid().short_name().unwrap_or("?");
            let value = e.data().to_string().unwrap_or_default();
            format!("{key}={value}")
        })
        .collect::<Vec<_>>()
        .join(",")
}

impl TlsInfo {
    pub fn of(ssl: &SslRef, client_auth: Option<ClientAuthMode>) -> Self {
        let mut info = Self {
            protocol: ssl.version_str(),
            cipher: ssl.current_cipher().map_or("", |c| c.name()),
            server_name: ssl
                .servername(NameType::HOST_NAME)
                .map(|n| n.to_ascii_lowercase().into_bytes().into())
                .unwrap_or_default(),
            session_reused: ssl.session_reused(),
            client_auth,
            ..Self::default()
        };
        if let Some(c) = ssl.peer_certificate() {
            let r = ssl.verify_result();
            info.verify = match client_auth {
                Some(ClientAuthMode::OptionalNoCa) => ClientVerify::Success,
                _ if r == X509VerifyResult::OK => ClientVerify::Success,
                _ => ClientVerify::Failed(r),
            };
            info.client_subject = rfc2253(c.subject_name()).into();
            info.client_issuer = rfc2253(c.issuer_name()).into();
            info.client_serial = c
                .serial_number()
                .to_bn()
                .and_then(|b| b.to_hex_str().map(|h| h.to_string()))
                .unwrap_or_default()
                .into();
            info.client_cert = c
                .to_pem()
                .ok()
                .and_then(|p| String::from_utf8(p).ok())
                .unwrap_or_default()
                .into();
        }
        info
    }

    /// nginx answers a request on a connection whose client certificate
    /// failed with 400 ("495"), and one without a required certificate
    /// with 400 ("496").
    pub fn client_error(&self) -> Option<u16> {
        match (self.client_auth, self.verify) {
            (Some(_), ClientVerify::Failed(_)) => Some(495),
            (Some(ClientAuthMode::Require), ClientVerify::None) => Some(496),
            _ => None,
        }
    }
}

/// The connector of an upstream with TLS: its settings, trust store and
/// client certificate.
pub(crate) fn connector(
    t: &UpstreamTls,
    cert: Option<&Certificate>,
) -> Result<SslConnector, ErrorStack> {
    let mut b = SslConnector::builder(SslMethod::tls_client())?;
    b.set_min_proto_version(Some(version(t.min_version)))?;
    b.set_max_proto_version(Some(version(t.max_version)))?;
    b.set_cipher_list(&t.ciphers)?;
    if !t.ciphersuites.is_empty() {
        b.set_ciphersuites(&t.ciphersuites)?;
    }
    if t.verify {
        b.set_verify(SslVerifyMode::PEER);
        b.set_verify_depth(t.depth);
        if !t.ca.is_empty() {
            trust(&mut b, &t.ca)?;
        }
    } else {
        // nginx proxy_ssl_verify off.
        b.set_verify(SslVerifyMode::NONE);
    }
    if let Some(c) = cert {
        b.set_certificate(&c.chain[0])?;
        for extra in &c.chain[1..] {
            b.add_extra_chain_cert(extra.clone())?;
        }
        b.set_private_key(&c.key)?;
    }
    Ok(b.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_list() {
        let list = b"\x02h2\x08http/1.1";
        let v: Vec<_> = protocols(list).collect();
        assert_eq!(v, [&b"h2"[..], b"http/1.1"]);
        assert_eq!(protocols(b"\x05ab").count(), 0);
    }
}
