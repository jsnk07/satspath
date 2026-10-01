//! Key continuity (trust-on-first-use pinning) for resolved profiles.
//!
//! A profile signature only proves that *some* key signed the profile. On its
//! own it cannot stop key substitution: anyone who can answer resolution for
//! `alice@example.com` (a compromised `.well-known` host, a MITM on an
//! unpinned transport, a Nostr identity the attacker controls) can serve a
//! profile for Alice's alias, self-signed with the attacker's key, and it will
//! verify.
//!
//! This module binds an identifier to the identity key the wallet has already
//! trusted for it:
//!
//! * **First contact** — the key is pinned (TOFU) and the caller is told so.
//! * **Same key** — accepted, unless the profile's `sequence` is lower than the
//!   highest one already seen (a replayed older copy, e.g. pre-revocation).
//! * **Different key** — accepted only with a valid [`KeyRotation`] that was
//!   authorized by the pinned key and accepted by the new one. Anything else is
//!   rejected with [`SatsPathError::UnauthorizedKeyReplacement`].
//!
//! [`PinnedResolver`] applies this to any [`ProfileResolver`], so every
//! command that resolves an alias gets the same guarantee.
//!
//! [`KeyRotation`]: crate::rotation::KeyRotation

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::crypto::verify_signed_profile;
use crate::peer_registry::hash_identifier;
use crate::privacy::identifier_hash;
use crate::resolver::ProfileResolver;
use crate::{Result, SatsPathError, SignedPaymentProfile};

/// File name of the pin store inside the `.satspath/` directory.
pub const KNOWN_KEYS_FILE: &str = "known_keys.json";

/// The identity key a wallet trusts for one identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedKey {
    /// Hex-encoded compressed secp256k1 identity public key.
    pub identity_pubkey: String,
    /// Highest profile `sequence` seen for this key (0 when unsequenced).
    pub sequence: u64,
    /// Unix time the identifier was first pinned.
    pub first_seen: i64,
    /// Unix time this pin was last updated.
    pub updated_at: i64,
}

/// Outcome of a key-continuity check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyContinuity {
    /// No key was trusted for this identifier yet; the key has now been pinned.
    FirstUse,
    /// The resolved key is the key already trusted for this identifier.
    Matches,
    /// The key changed with a valid rotation authorized by the trusted key.
    Rotated { previous_pubkey: String },
    /// The identifier has no SatsPath identity key to pin (BIP-353 names).
    NotApplicable,
}

/// Storage for pinned identity keys. Keys are looked up by identifier; the raw
/// identifier is never persisted (see [`hash_identifier`]).
pub trait TrustedKeyStore: Send + Sync {
    fn trusted_key(&self, identifier: &str) -> Result<Option<TrustedKey>>;
    fn pin_key(&self, identifier: &str, key: TrustedKey) -> Result<()>;
}

/// Decide whether `signed` keeps key continuity with `pinned`.
///
/// Does not mutate anything; see [`PinnedResolver`] for the full flow.
pub fn check_key_continuity(
    alias: &str,
    pinned: Option<&TrustedKey>,
    signed: &SignedPaymentProfile,
) -> Result<KeyContinuity> {
    let Some(pinned) = pinned else {
        return Ok(KeyContinuity::FirstUse);
    };
    let profile = &signed.profile;
    let sequence = profile.sequence.unwrap_or(0);

    if profile.identity_pubkey == pinned.identity_pubkey {
        if sequence < pinned.sequence {
            return Err(SatsPathError::ValidationError(format!(
                "stale profile for {alias}: sequence {sequence} is older than the \
                 already-seen sequence {} (possible replay of an outdated profile)",
                pinned.sequence
            )));
        }
        return Ok(KeyContinuity::Matches);
    }

    // The key changed. Only a rotation authorized by the pinned key is allowed.
    let authorized = match &profile.rotation {
        Some(rotation) => {
            rotation.previous_pubkey == pinned.identity_pubkey
                && rotation.new_pubkey == profile.identity_pubkey
                && rotation.identifier_hash == identifier_hash(&profile.alias)
                && rotation.sequence == sequence
                && sequence > pinned.sequence
                && rotation.verify()?
        }
        None => false,
    };

    if authorized {
        Ok(KeyContinuity::Rotated {
            previous_pubkey: pinned.identity_pubkey.clone(),
        })
    } else {
        Err(SatsPathError::UnauthorizedKeyReplacement)
    }
}

/// Wraps a resolver and enforces key continuity on every result.
pub struct PinnedResolver<R> {
    inner: R,
    store: Arc<dyn TrustedKeyStore>,
}

impl<R: ProfileResolver + Send + Sync> PinnedResolver<R> {
    pub fn new(inner: R, store: Arc<dyn TrustedKeyStore>) -> Self {
        Self { inner, store }
    }

    /// Resolve `alias`, verify the signature, and enforce key continuity.
    /// Pins the key on first use and follows authorized rotations.
    pub async fn resolve_with_continuity(
        &self,
        alias: &str,
    ) -> Result<(SignedPaymentProfile, KeyContinuity)> {
        let signed = self.inner.resolve_alias(alias).await?;

        // BIP-353 names resolve to DNS payment instructions, not to a
        // SatsPath identity key, so there is nothing to pin.
        if alias.trim().starts_with('₿') {
            return Ok((signed, KeyContinuity::NotApplicable));
        }

        // Never pin (or compare against) a key whose signature does not verify.
        if !verify_signed_profile(&signed)? {
            return Err(SatsPathError::InvalidSignature);
        }

        let pinned = self.store.trusted_key(alias)?;
        let continuity = check_key_continuity(alias, pinned.as_ref(), &signed)?;

        let now = chrono::Utc::now().timestamp();
        let sequence = signed.profile.sequence.unwrap_or(0);
        let updated = TrustedKey {
            identity_pubkey: signed.profile.identity_pubkey.clone(),
            sequence: pinned
                .as_ref()
                .filter(|p| p.identity_pubkey == signed.profile.identity_pubkey)
                .map_or(sequence, |p| p.sequence.max(sequence)),
            first_seen: pinned.as_ref().map_or(now, |p| p.first_seen),
            updated_at: now,
        };
        if pinned.as_ref() != Some(&updated) {
            self.store.pin_key(alias, updated)?;
        }

        Ok((signed, continuity))
    }
}

#[async_trait]
impl<R: ProfileResolver + Send + Sync> ProfileResolver for PinnedResolver<R> {
    async fn resolve_alias(&self, alias: &str) -> Result<SignedPaymentProfile> {
        self.resolve_with_continuity(alias)
            .await
            .map(|(signed, _)| signed)
    }
}

// ─── Stores ─────────────────────────────────────────────────────────────────────

/// In-memory pin store (tests, or when no `.satspath/` directory exists).
#[derive(Default)]
pub struct MemoryKeyStore {
    keys: Mutex<HashMap<String, TrustedKey>>,
}

impl MemoryKeyStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TrustedKeyStore for MemoryKeyStore {
    fn trusted_key(&self, identifier: &str) -> Result<Option<TrustedKey>> {
        let keys = self.keys.lock().map_err(lock_poisoned)?;
        Ok(keys.get(&hash_identifier(identifier)).cloned())
    }

    fn pin_key(&self, identifier: &str, key: TrustedKey) -> Result<()> {
        let mut keys = self.keys.lock().map_err(lock_poisoned)?;
        keys.insert(hash_identifier(identifier), key);
        Ok(())
    }
}

/// File-backed pin store at `.satspath/known_keys.json`.
pub struct FileKeyStore {
    path: PathBuf,
    keys: Mutex<HashMap<String, TrustedKey>>,
}

impl FileKeyStore {
    /// Open (or prepare to create) the pin store inside `dir`.
    pub fn open(dir: &Path) -> Result<Self> {
        let path = dir.join(KNOWN_KEYS_FILE);
        let keys = if path.exists() {
            serde_json::from_str(&std::fs::read_to_string(&path)?)?
        } else {
            HashMap::new()
        };
        Ok(Self {
            path,
            keys: Mutex::new(keys),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl TrustedKeyStore for FileKeyStore {
    fn trusted_key(&self, identifier: &str) -> Result<Option<TrustedKey>> {
        let keys = self.keys.lock().map_err(lock_poisoned)?;
        Ok(keys.get(&hash_identifier(identifier)).cloned())
    }

    fn pin_key(&self, identifier: &str, key: TrustedKey) -> Result<()> {
        let mut keys = self.keys.lock().map_err(lock_poisoned)?;
        keys.insert(hash_identifier(identifier), key);
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Write-then-rename so a crash never leaves a truncated pin file.
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&*keys)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

fn lock_poisoned<T>(_: std::sync::PoisonError<T>) -> SatsPathError {
    SatsPathError::RegistryError("key pin store lock poisoned".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_identity_keypair, sign_profile};
    use crate::profile::{PaymentMethod, PaymentProfile};
    use crate::rotation::KeyRotation;
    use secp256k1::SecretKey;

    fn profile(alias: &str, pubkey: &str, sequence: u64) -> PaymentProfile {
        PaymentProfile {
            alias: alias.into(),
            identity_pubkey: pubkey.into(),
            methods: vec![PaymentMethod::Lightning {
                label: "LN".into(),
                lnurl: None,
                lightning_address: Some(alias.into()),
                bolt12: None,
                receiver_pubkey: None,
            }],
            updated_at: 1_700_000_000,
            expires_at: None,
            sequence: Some(sequence),
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: vec![],
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
        }
    }

    fn keypair() -> (String, SecretKey) {
        let kp = generate_identity_keypair();
        (hex::encode(kp.public_key.serialize()), kp.secret_key)
    }

    fn pin(pubkey: &str, sequence: u64) -> TrustedKey {
        TrustedKey {
            identity_pubkey: pubkey.into(),
            sequence,
            first_seen: 0,
            updated_at: 0,
        }
    }

    const ALICE: &str = "alice@example.com";

    #[test]
    fn first_use_and_match() {
        let (pk, sk) = keypair();
        let signed = sign_profile(profile(ALICE, &pk, 1), &sk).unwrap();
        assert_eq!(
            check_key_continuity(ALICE, None, &signed).unwrap(),
            KeyContinuity::FirstUse
        );
        assert_eq!(
            check_key_continuity(ALICE, Some(&pin(&pk, 1)), &signed).unwrap(),
            KeyContinuity::Matches
        );
    }

    #[test]
    fn substituted_key_rejected() {
        let (alice_pk, _) = keypair();
        let (evil_pk, evil_sk) = keypair();
        let evil = sign_profile(profile(ALICE, &evil_pk, 9), &evil_sk).unwrap();
        assert!(matches!(
            check_key_continuity(ALICE, Some(&pin(&alice_pk, 1)), &evil),
            Err(SatsPathError::UnauthorizedKeyReplacement)
        ));
    }

    #[test]
    fn stale_sequence_rejected() {
        let (pk, sk) = keypair();
        let old = sign_profile(profile(ALICE, &pk, 2), &sk).unwrap();
        assert!(check_key_continuity(ALICE, Some(&pin(&pk, 5)), &old).is_err());
    }

    fn rotated(
        old: (&str, &SecretKey),
        new: (&str, &SecretKey),
        claimed_previous: &str,
        sequence: u64,
    ) -> SignedPaymentProfile {
        let rotation = KeyRotation::create(
            identifier_hash(ALICE),
            claimed_previous.into(),
            old.1,
            new.0.into(),
            new.1,
            "prev-event".into(),
            sequence,
        )
        .unwrap();
        let mut p = profile(ALICE, new.0, sequence);
        p.rotation = Some(rotation);
        sign_profile(p, new.1).unwrap()
    }

    #[test]
    fn authorized_rotation_accepted() {
        let (old_pk, old_sk) = keypair();
        let (new_pk, new_sk) = keypair();
        let signed = rotated((&old_pk, &old_sk), (&new_pk, &new_sk), &old_pk, 2);
        assert_eq!(
            check_key_continuity(ALICE, Some(&pin(&old_pk, 1)), &signed).unwrap(),
            KeyContinuity::Rotated {
                previous_pubkey: old_pk.clone()
            }
        );
    }

    #[test]
    fn rotation_not_from_pinned_key_rejected() {
        let (alice_pk, _) = keypair();
        let (evil_old_pk, evil_old_sk) = keypair();
        let (evil_pk, evil_sk) = keypair();
        // Valid rotation, but it starts from a key the wallet never trusted.
        let signed = rotated(
            (&evil_old_pk, &evil_old_sk),
            (&evil_pk, &evil_sk),
            &evil_old_pk,
            2,
        );
        assert!(check_key_continuity(ALICE, Some(&pin(&alice_pk, 1)), &signed).is_err());
        // Claiming the pinned key as previous without its signature also fails.
        let forged = rotated(
            (&evil_old_pk, &evil_old_sk),
            (&evil_pk, &evil_sk),
            &alice_pk,
            2,
        );
        assert!(check_key_continuity(ALICE, Some(&pin(&alice_pk, 1)), &forged).is_err());
    }

    #[test]
    fn file_store_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = FileKeyStore::open(dir.path()).unwrap();
            store.pin_key("Alice@Example.com", pin("02aa", 3)).unwrap();
        }
        let store = FileKeyStore::open(dir.path()).unwrap();
        assert_eq!(store.trusted_key(ALICE).unwrap(), Some(pin("02aa", 3)));
        let raw = std::fs::read_to_string(store.path()).unwrap();
        assert!(
            !raw.contains("alice"),
            "raw identifier must not be persisted"
        );
    }
}
