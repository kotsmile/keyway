//! Sealing payloads for keyway's own Store.
//!
//! This is the one backend where keyway holds a value at all, so it is the one
//! place a mistake here loses secrets rather than merely metadata. AES-256-GCM,
//! a fresh random nonce per version, and the key id recorded beside the
//! ciphertext so a rotated deployment can still open what it wrote last year.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// AES-256-GCM's nonce is 96 bits.
const NONCE_LEN: usize = 12;

/// A sealed payload, as a row stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// Which key sealed this. Recorded per version rather than per Store, so
    /// rotating the active key does not make yesterday's versions unreadable.
    pub key_id: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("key {key_id:?} is not configured; a version sealed with it cannot be opened")]
    UnknownKey { key_id: String },
    #[error("key {key_id:?} is not 32 bytes of base64: {reason}")]
    BadKey { key_id: String, reason: String },
    /// Deliberately says nothing about why. A caller distinguishing "wrong
    /// key" from "tampered" learns something from a failure, and there is
    /// nothing useful they could do with it.
    #[error("the payload could not be opened")]
    Unopenable,
    #[error("generating a nonce: {0}")]
    Rng(String),
}

/// The keys a Store can open payloads with, and the one it seals new ones
/// under.
///
/// More than one because rotation is not an instant: the active key seals
/// everything new, and the retired ones stay configured for exactly as long as
/// a version sealed under them still exists.
pub struct Keyring {
    active: String,
    keys: BTreeMap<String, Zeroizing<Vec<u8>>>,
}

/// Names the ids and nothing else. A derived Debug would put key material in
/// the first panic message or tracing span that touched a Keyring.
impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyring")
            .field("active", &self.active)
            .field("key_ids", &self.keys.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Keyring {
    /// Builds a keyring from base64 keys.
    ///
    /// # Errors
    ///
    /// When a key is not 32 bytes of base64, or the active id names a key that
    /// was not given.
    pub fn new(
        active: impl Into<String>,
        keys: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, Error> {
        let active = active.into();
        let mut decoded = BTreeMap::new();
        for (id, material) in keys {
            decoded.insert(id.clone(), decode_key(&id, &material)?);
        }
        if !decoded.contains_key(&active) {
            return Err(Error::UnknownKey { key_id: active });
        }
        Ok(Self {
            active,
            keys: decoded,
        })
    }

    /// The id new payloads are sealed under.
    #[must_use]
    pub fn active_id(&self) -> &str {
        &self.active
    }

    /// Seals a payload under the active key.
    ///
    /// `aad` is bound into the tag — pass the secret's identity, so a
    /// ciphertext lifted from one row into another fails to open rather than
    /// silently revealing the wrong secret's value.
    ///
    /// # Errors
    ///
    /// When the system random source fails.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Sealed, Error> {
        let cipher = self.cipher(&self.active)?;

        let mut nonce = [0_u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|e| Error::Rng(e.to_string()))?;

        let ciphertext = cipher
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::Unopenable)?;

        Ok(Sealed {
            key_id: self.active.clone(),
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    /// Opens a sealed payload with whichever key sealed it.
    ///
    /// # Errors
    ///
    /// When the recorded key is not configured, or the payload does not
    /// authenticate.
    pub fn open(&self, sealed: &Sealed, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let cipher = self.cipher(&sealed.key_id)?;
        let nonce: [u8; NONCE_LEN] = sealed
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| Error::Unopenable)?;
        let plaintext = cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &sealed.ciphertext,
                    aad,
                },
            )
            .map_err(|_| Error::Unopenable)?;
        Ok(Zeroizing::new(plaintext))
    }

    fn cipher(&self, id: &str) -> Result<Aes256Gcm, Error> {
        let material = self.keys.get(id).ok_or_else(|| Error::UnknownKey {
            key_id: id.to_owned(),
        })?;
        let key = Key::<Aes256Gcm>::try_from(material.as_slice()).map_err(|_| Error::BadKey {
            key_id: id.to_owned(),
            reason: "not 32 bytes".to_owned(),
        })?;
        Ok(Aes256Gcm::new(&key))
    }
}

fn decode_key(id: &str, material: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let raw = BASE64.decode(material.trim()).map_err(|e| Error::BadKey {
        key_id: id.to_owned(),
        reason: e.to_string(),
    })?;
    if raw.len() != 32 {
        return Err(Error::BadKey {
            key_id: id.to_owned(),
            reason: format!("decoded to {} bytes, not 32", raw.len()),
        });
    }
    Ok(Zeroizing::new(raw))
}

/// The bytes a secret's identity contributes to the tag.
#[must_use]
pub fn aad(store: &str, name: &str, version: &str) -> Vec<u8> {
    format!("{store}/{name}@{version}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const KEY_B: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

    fn ring(active: &str, keys: &[(&str, &str)]) -> Keyring {
        Keyring::new(
            active,
            keys.iter()
                .map(|(id, k)| ((*id).to_owned(), (*k).to_owned())),
        )
        .expect("a valid keyring")
    }

    #[test]
    fn a_payload_round_trips() {
        let ring = ring("v1", &[("v1", KEY_A)]);
        let aad = aad("local", "db-creds", "1");

        let sealed = ring.seal(b"hunter2", &aad).unwrap();
        assert_eq!(&*ring.open(&sealed, &aad).unwrap(), b"hunter2");
    }

    #[test]
    fn the_ciphertext_does_not_contain_the_plaintext() {
        let ring = ring("v1", &[("v1", KEY_A)]);
        let sealed = ring.seal(b"hunter2", b"aad").unwrap();
        assert!(!sealed.ciphertext.windows(7).any(|w| w == b"hunter2"));
    }

    #[test]
    fn two_seals_of_one_value_differ() {
        // A fresh nonce per version. Equal ciphertexts would tell an observer
        // with read access to the table which secrets share a value.
        let ring = ring("v1", &[("v1", KEY_A)]);
        let first = ring.seal(b"same", b"aad").unwrap();
        let second = ring.seal(b"same", b"aad").unwrap();

        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn a_tampered_ciphertext_will_not_open() {
        let ring = ring("v1", &[("v1", KEY_A)]);
        let mut sealed = ring.seal(b"hunter2", b"aad").unwrap();
        sealed.ciphertext[0] ^= 0x01;

        assert!(matches!(ring.open(&sealed, b"aad"), Err(Error::Unopenable)));
    }

    #[test]
    fn a_ciphertext_moved_to_another_secret_will_not_open() {
        // The identity is bound into the tag, so a row lifted from one secret
        // into another fails rather than revealing the wrong value.
        let ring = ring("v1", &[("v1", KEY_A)]);
        let sealed = ring
            .seal(b"hunter2", &aad("local", "db-creds", "1"))
            .unwrap();

        assert!(matches!(
            ring.open(&sealed, &aad("local", "api-key", "1")),
            Err(Error::Unopenable)
        ));
    }

    #[test]
    fn a_version_sealed_under_a_retired_key_still_opens() {
        // The whole point of recording key_id per version: rotating the active
        // key must not make yesterday's payloads unreadable.
        let old = ring("v1", &[("v1", KEY_A)]);
        let sealed = old.seal(b"hunter2", b"aad").unwrap();
        assert_eq!(sealed.key_id, "v1");

        let rotated = ring("v2", &[("v1", KEY_A), ("v2", KEY_B)]);
        assert_eq!(&*rotated.open(&sealed, b"aad").unwrap(), b"hunter2");
        assert_eq!(
            rotated.seal(b"new", b"aad").unwrap().key_id,
            "v2",
            "new payloads use the active key"
        );
    }

    #[test]
    fn dropping_a_key_that_is_still_in_use_is_reported_as_such() {
        let old = ring("v1", &[("v1", KEY_A)]);
        let sealed = old.seal(b"hunter2", b"aad").unwrap();

        let without = ring("v2", &[("v2", KEY_B)]);
        assert!(matches!(
            without.open(&sealed, b"aad"),
            Err(Error::UnknownKey { .. })
        ));
    }

    #[test]
    fn an_active_id_naming_no_key_is_refused_at_construction() {
        // Caught at boot rather than on the first write.
        let error = Keyring::new("v2", [("v1".to_owned(), KEY_A.to_owned())]).unwrap_err();
        assert!(matches!(error, Error::UnknownKey { .. }));
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        let short = BASE64.encode([0_u8; 16]);
        let error = Keyring::new("v1", [("v1".to_owned(), short)]).unwrap_err();
        let Error::BadKey { reason, .. } = error else {
            panic!("expected a bad key");
        };
        assert!(reason.contains("16 bytes"), "reason was {reason:?}");
    }

    #[test]
    fn a_key_that_is_not_base64_is_refused() {
        let error = Keyring::new("v1", [("v1".to_owned(), "not base64!".to_owned())]).unwrap_err();
        assert!(matches!(error, Error::BadKey { .. }));
    }

    #[test]
    fn a_truncated_nonce_is_refused_rather_than_panicking() {
        let ring = ring("v1", &[("v1", KEY_A)]);
        let mut sealed = ring.seal(b"hunter2", b"aad").unwrap();
        sealed.nonce.truncate(4);
        assert!(matches!(ring.open(&sealed, b"aad"), Err(Error::Unopenable)));
    }
}
