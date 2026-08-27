//! The token format, and what makes a presented one acceptable.
//!
//! No I/O: minting produces bytes and a hash, verification compares them. What
//! a row looks like is [`infra`](super::infra)'s business.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// What every keyway token starts with, so one that turns up in a log or a
/// repository names the system it opens without anybody having to recognise
/// the shape.
pub const PREFIX: &str = "kw";

/// The public half. Not a secret: it is the lookup key, and what an audit row
/// names.
///
/// Rendered as HEX rather than base64url, which is the whole reason the format
/// is unambiguous: `-` is the separator, base64url contains `-`, and an id
/// carrying one would split in the wrong place and fail to verify against its
/// own hash. Hex cannot, so the first `-` after the prefix is always the
/// separator.
const ID_BYTES: usize = 8;

/// The secret half.
const SECRET_BYTES: usize = 32;

/// Long enough for "eso — payment-bot prod", short enough that the list stays
/// a list.
pub const MAX_NAME: usize = 80;

/// One issued token as a caller sees it. The plaintext is deliberately absent:
/// it exists once, in the response that created it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Token {
    pub id: String,
    #[serde(skip_serializing)]
    pub subject: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used: Option<DateTime<Utc>>,
}

/// One issued token as storage holds it — the hash included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredToken {
    pub id: String,
    pub hash: Vec<u8>,
    pub subject: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used: Option<DateTime<Utc>>,
}

impl StoredToken {
    /// Whether the secret half presented is this token's, and it is still
    /// live.
    ///
    /// # Errors
    ///
    /// [`Rejected`] saying which, for a log line. A caller reports all of them
    /// identically.
    pub fn admits(&self, secret: &str, now: DateTime<Utc>) -> Result<(), Rejected> {
        if !constant_time_eq(&self.hash, &hash_secret(secret)) {
            return Err(Rejected::WrongSecret);
        }
        if self.expires_at.is_some_and(|expiry| expiry <= now) {
            return Err(Rejected::Expired);
        }
        Ok(())
    }
}

/// Why a presented token was not accepted.
///
/// Distinguished here so a log line can say what happened, never so a response
/// can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejected {
    /// Not `kw-<id>-<secret>`.
    Malformed,
    /// No token with that id.
    Unknown,
    /// The id exists but the secret half does not match.
    WrongSecret,
    /// Past its expiry.
    Expired,
}

/// A newly minted token: the row, and the plaintext that will never exist
/// again.
pub struct Minted {
    pub token: Token,
    /// Zeroized on drop. It goes into one response body and nowhere else.
    pub plaintext: Zeroizing<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("a name is required, up to {max} characters")]
    NameRequired { max: usize },
    #[error("generating a token: {0}")]
    Rng(String),
}

/// Generates a token for `subject`.
///
/// Returns what to store and what to show once. `created_at` is left to
/// storage, which is the only thing that can say when the row was written.
///
/// # Errors
///
/// When the name is empty or too long, or the random source fails.
pub fn mint(
    subject: &str,
    name: &str,
    expires_at: Option<DateTime<Utc>>,
) -> Result<(StoredToken, Zeroizing<String>), Error> {
    let name = name.trim();
    // Required, not defaulted to something like "token": the name is the only
    // thing that answers "can I delete this one" in six months, and a list of
    // identical defaults answers nothing.
    if name.is_empty() || name.len() > MAX_NAME {
        return Err(Error::NameRequired { max: MAX_NAME });
    }

    let id = random_hex(ID_BYTES)?;
    let secret = Zeroizing::new(random_b64(SECRET_BYTES)?);

    Ok((
        StoredToken {
            id: id.clone(),
            hash: hash_secret(&secret),
            subject: subject.to_owned(),
            name: name.to_owned(),
            created_at: DateTime::<Utc>::MIN_UTC,
            expires_at,
            last_used: None,
        },
        Zeroizing::new(format!("{PREFIX}-{id}-{}", *secret)),
    ))
}

/// Splits `kw-<id>-<secret>`.
///
/// On the FIRST `-` after the prefix, which is only unambiguous because the id
/// is hex. The secret half is base64url and may well contain `-`; that is
/// fine, since everything after the separator is the secret.
#[must_use]
pub fn split(presented: &str) -> Option<(&str, &str)> {
    let rest = presented.strip_prefix(PREFIX)?.strip_prefix('-')?;
    let (id, secret) = rest.split_once('-')?;
    if id.is_empty() || secret.is_empty() || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some((id, secret))
}

fn hash_secret(secret: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.finalize().to_vec()
}

/// Compares in time independent of where the first difference is, so a caller
/// cannot learn a hash a byte at a time.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn random_b64(bytes: usize) -> Result<String, Error> {
    let mut raw = Zeroizing::new(vec![0_u8; bytes]);
    getrandom::fill(&mut raw).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(BASE64URL.encode(&*raw))
}

fn random_hex(bytes: usize) -> Result<String, Error> {
    use std::fmt::Write as _;
    let mut raw = vec![0_u8; bytes];
    getrandom::fill(&mut raw).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(raw
        .iter()
        .fold(String::with_capacity(bytes * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minted() -> (StoredToken, Zeroizing<String>) {
        mint("alice", "eso prod", None).expect("mints")
    }

    #[test]
    fn a_minted_token_verifies_against_its_own_hash() {
        let (stored, plaintext) = minted();
        let (id, secret) = split(&plaintext).expect("splits");

        assert_eq!(id, stored.id);
        assert!(stored.admits(secret, Utc::now()).is_ok());
    }

    #[test]
    fn another_secret_does_not_verify() {
        let (stored, _) = minted();
        assert_eq!(
            stored.admits("wrong", Utc::now()),
            Err(Rejected::WrongSecret)
        );
    }

    #[test]
    fn an_expired_token_is_refused_even_with_the_right_secret() {
        let (mut stored, plaintext) = minted();
        stored.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        let (_, secret) = split(&plaintext).unwrap();

        assert_eq!(stored.admits(secret, Utc::now()), Err(Rejected::Expired));
    }

    #[test]
    fn a_token_with_no_expiry_never_expires() {
        // Deliberate, for the caller this exists for: an expiry on the
        // credential a reconcile loop presents is an outage scheduled for a
        // day nobody picked.
        let (stored, plaintext) = minted();
        let (_, secret) = split(&plaintext).unwrap();

        let far_future = Utc::now() + chrono::Duration::days(3650);
        assert!(stored.admits(secret, far_future).is_ok());
    }

    #[test]
    fn a_name_is_required() {
        assert!(matches!(
            mint("alice", "   ", None),
            Err(Error::NameRequired { .. })
        ));
        assert!(matches!(
            mint("alice", &"x".repeat(MAX_NAME + 1), None),
            Err(Error::NameRequired { .. })
        ));
    }

    #[test]
    fn the_plaintext_is_url_safe() {
        // A token goes into env vars, YAML and URLs. A `/` or `+` in it is a
        // bug report from somebody whose CI mangled it.
        for _ in 0..32 {
            let (_, plaintext) = minted();
            assert!(
                plaintext
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "{} is not url-safe",
                *plaintext
            );
        }
    }

    #[test]
    fn every_minted_token_verifies_against_its_own_hash() {
        // A REGRESSION TEST, and it has to loop. The id was base64url once,
        // which contains `-` — the same character that separates the halves.
        // Roughly one token in three split in the wrong place and could not be
        // used at all, and a single round trip missed it two times in three.
        for _ in 0..512 {
            let (stored, plaintext) = minted();
            let (id, secret) = split(&plaintext).expect("splits");
            assert_eq!(id, stored.id, "{}", *plaintext);
            assert!(
                stored.admits(secret, Utc::now()).is_ok(),
                "{} did not verify",
                *plaintext
            );
        }
    }

    #[test]
    fn an_id_never_contains_the_separator() {
        for _ in 0..512 {
            let (stored, _) = minted();
            assert!(
                !stored.id.contains('-'),
                "{} would split in the wrong place",
                stored.id
            );
        }
    }

    #[test]
    fn tokens_do_not_repeat() {
        let (first, _) = minted();
        let (second, _) = minted();
        assert_ne!(first.id, second.id);
        assert_ne!(first.hash, second.hash);
    }

    #[test]
    fn something_that_is_not_a_token_does_not_split() {
        for bad in [
            "",
            "kw",
            "kw-",
            "kw-onlyid",
            "kw--secret",
            "kw-id-",
            "lkr-id-secret",
            "hunter2",
        ] {
            assert!(split(bad).is_none(), "{bad:?} should not split");
        }
    }

    #[test]
    fn a_secret_containing_a_dash_survives_the_split() {
        // The secret half is base64url and may contain `-`; everything after
        // the first separator is the secret.
        let (id, secret) = split("kw-aa-bb-cc").expect("splits");
        assert_eq!(id, "aa");
        assert_eq!(secret, "bb-cc");
    }

    #[test]
    fn an_id_that_is_not_hex_is_refused() {
        // Nothing keyway minted looks like this, so it is a probe.
        assert!(split("kw-zzz-secret").is_none());
    }

    #[test]
    fn comparison_rejects_a_different_length() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"abc", b"abc"));
    }
}
