//! Password hashes in the formats nginx's auth_basic_user_file accepts:
//! its own `$apr1$`, `{PLAIN}`, `{SHA}` and `{SSHA}`, and what glibc crypt()
//! takes on common systems (`$1$`, `$5$`, `$6$`, bcrypt).

use openssl::base64;
use openssl::hash::{Hasher, MessageDigest, hash};
use openssl::memcmp;

/// Whether `password` matches `stored`. An unknown format never matches.
pub(crate) fn verify(password: &[u8], stored: &str) -> bool {
    if let Some(rest) = stored.strip_prefix("{PLAIN}") {
        return eq(password, rest.as_bytes());
    }
    if let Some(rest) = stored.strip_prefix("{SHA}") {
        let Ok(want) = base64::decode_block(rest) else {
            return false;
        };
        return hash(MessageDigest::sha1(), password).is_ok_and(|d| eq(&d, &want));
    }
    if let Some(rest) = stored.strip_prefix("{SSHA}") {
        let Ok(raw) = base64::decode_block(rest) else {
            return false;
        };
        if raw.len() <= 20 {
            return false;
        }
        let (want, salt) = raw.split_at(20);
        let digest = Hasher::new(MessageDigest::sha1()).and_then(|mut h| {
            h.update(password)?;
            h.update(salt)?;
            h.finish()
        });
        return digest.is_ok_and(|d| eq(&d, want));
    }
    for magic in ["$apr1$", "$1$"] {
        if let Some(rest) = stored.strip_prefix(magic) {
            return md5_crypt(password, magic.as_bytes(), rest.as_bytes())
                .is_some_and(|h| eq(&h, stored.as_bytes()));
        }
    }
    if stored.starts_with("$5$") || stored.starts_with("$6$") {
        use sha_crypt::{PasswordVerifier, ShaCrypt};
        return ShaCrypt::default()
            .verify_password(password, stored)
            .is_ok();
    }
    if stored.starts_with("$2") {
        return bcrypt::verify(password, stored).unwrap_or(false);
    }
    false
}

fn eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && memcmp::eq(a, b)
}

/// Poul-Henning Kamp's MD5 crypt with `magic` (`$1$` or Apache's `$apr1$`),
/// as nginx ngx_crypt_apr1. `rest` is what follows the magic.
fn md5_crypt(key: &[u8], magic: &[u8], rest: &[u8]) -> Option<Vec<u8>> {
    let end = rest
        .iter()
        .take(8)
        .position(|&c| c == b'$')
        .unwrap_or(rest.len().min(8));
    let salt = &rest[..end];
    let md5 = || Hasher::new(MessageDigest::md5()).ok();
    let finish = |mut h: Hasher| -> Option<[u8; 16]> { h.finish().ok()?[..].try_into().ok() };

    let mut ctx1 = md5()?;
    ctx1.update(key).ok()?;
    ctx1.update(salt).ok()?;
    ctx1.update(key).ok()?;
    let alt = finish(ctx1)?;

    let mut ctx = md5()?;
    ctx.update(key).ok()?;
    ctx.update(magic).ok()?;
    ctx.update(salt).ok()?;
    let mut n = key.len();
    while n > 0 {
        ctx.update(&alt[..n.min(16)]).ok()?;
        n = n.saturating_sub(16);
    }
    let mut i = key.len();
    while i > 0 {
        if i & 1 == 1 {
            ctx.update(&[0]).ok()?;
        } else {
            ctx.update(&key[..1]).ok()?;
        }
        i >>= 1;
    }
    let mut fin = finish(ctx)?;
    for i in 0..1000 {
        let mut c = md5()?;
        if i & 1 == 1 {
            c.update(key).ok()?;
        } else {
            c.update(&fin).ok()?;
        }
        if i % 3 != 0 {
            c.update(salt).ok()?;
        }
        if i % 7 != 0 {
            c.update(key).ok()?;
        }
        if i & 1 == 1 {
            c.update(&fin).ok()?;
        } else {
            c.update(key).ok()?;
        }
        fin = finish(c)?;
    }

    const ITOA64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::with_capacity(magic.len() + salt.len() + 23);
    out.extend_from_slice(magic);
    out.extend_from_slice(salt);
    out.push(b'$');
    let mut to64 = |mut v: u32, n: usize| {
        for _ in 0..n {
            out.push(ITOA64[(v & 0x3f) as usize]);
            v >>= 6;
        }
    };
    let f = |i: usize| u32::from(fin[i]);
    to64((f(0) << 16) | (f(6) << 8) | f(12), 4);
    to64((f(1) << 16) | (f(7) << 8) | f(13), 4);
    to64((f(2) << 16) | (f(8) << 8) | f(14), 4);
    to64((f(3) << 16) | (f(9) << 8) | f(15), 4);
    to64((f(4) << 16) | (f(10) << 8) | f(5), 4);
    to64(f(11), 2);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::verify;

    #[test]
    fn formats() {
        // Hashes of "secret" made by openssl passwd and htpasswd.
        let good = [
            "{PLAIN}secret",
            "{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=",
            "$apr1$abcdefgh$h9FWgUz3n9YxylKLlR5SQ/",
            "$1$abcdefgh$cHJi5PXp/ki/ktXzqlk6I1",
            "{SSHA}gVK8WC9YyFT1gMsQHTGCgT3sSv5zYWx0",
            "$5$abcdefgh$gruCpC7VkOTspMQTTSAR8mtlO9Upms.fwqE5y16JVM.",
            "$6$abcdefgh$ltjgWl6579NluT/Vi1nwEvcil.G5Nbc4NiXZaNGStk8PSwGfQv72N2CKPPrVACtLtip/cZ/1GM/O6IND4WQhG.",
            "$2y$05$0rZ3ipm6pINXF94AfJT13.rbaa29UNTnr6jKca3MfVhIMlNWxScne",
        ];
        for h in good {
            assert!(verify(b"secret", h), "{h}");
            assert!(!verify(b"secreT", h), "{h}");
        }
        assert!(!verify(b"secret", "secret"));
        assert!(!verify(b"secret", "{SHA}!!"));
    }
}
