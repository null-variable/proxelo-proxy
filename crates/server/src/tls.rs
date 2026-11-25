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
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{
    AlpnError, NameType, SniError, SslContext, SslContextBuilder, SslMethod, SslOptions, SslRef,
    SslVersion,
};
use openssl::x509::X509;
use proxelo_snapshot::{Certificate, ListenerTls, Runtime};

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

fn context(
    t: &ListenerTls,
    http2: bool,
    cert: Option<&Certificate>,
) -> Result<SslContextBuilder, ErrorStack> {
    let mut b = SslContextBuilder::new(SslMethod::tls_server())?;
    b.set_min_proto_version(Some(version(t.min_version)))?;
    b.set_cipher_list(&t.ciphers)?;
    // nginx: ssl_prefer_server_ciphers off, session tickets on, no
    // renegotiation.
    b.set_options(SslOptions::NO_RENEGOTIATION | SslOptions::NO_COMPRESSION);
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

/// What the request variables know about the TLS connection.
#[derive(Debug, Clone, Default)]
pub(crate) struct TlsInfo {
    pub protocol: &'static str,
    pub cipher: &'static str,
    /// Lowercase SNI name, empty without one.
    pub server_name: Box<[u8]>,
}

impl TlsInfo {
    pub fn of(ssl: &SslRef) -> Self {
        Self {
            protocol: ssl.version_str(),
            cipher: ssl.current_cipher().map_or("", |c| c.name()),
            server_name: ssl
                .servername(NameType::HOST_NAME)
                .map(|n| n.to_ascii_lowercase().into_bytes().into())
                .unwrap_or_default(),
        }
    }
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
