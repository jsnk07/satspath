use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::errors::{Result, SatsPathError};
use crate::privacy::{canonical_identifier, identifier_hash, validate_ascii_identifier};
use crate::profile::SignedPaymentProfile;

const REGISTRY_FILE: &str = "registry.json";

#[derive(Debug, Serialize, Deserialize, Default)]
struct RegistryData {
    profiles: HashMap<String, SignedPaymentProfile>,
}

/// Local file-backed registry of signed payment profiles.
///
/// In production this would be replaced with BIP-353, Nostr, or a
/// decentralized registry. For the hackathon prototype it persists to
/// `.satspath/registry.json` on disk.
pub struct Registry {
    path: PathBuf,
    data: RegistryData,
}

impl Registry {
    /// Open (or create) the registry at `dir/registry.json`.
    pub fn open(dir: &Path) -> Result<Self> {
        let path = dir.join(REGISTRY_FILE);
        let data = if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            serde_json::from_str(&raw)?
        } else {
            RegistryData::default()
        };
        Ok(Registry { path, data })
    }

    fn save(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.data)
            .map_err(|e| SatsPathError::SerializationError(e.to_string()))?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(tmp, &self.path)?;
        Ok(())
    }

    pub fn validate_profile_write(
        requested_alias: &str,
        signed: &SignedPaymentProfile,
    ) -> Result<()> {
        validate_ascii_identifier(requested_alias)?;
        validate_ascii_identifier(&signed.profile.alias)?;
        let requested = canonical_identifier(requested_alias);
        let profile_alias = canonical_identifier(&signed.profile.alias);
        if requested != profile_alias || signed.profile.alias != profile_alias {
            return Err(SatsPathError::RegistryError(
                "canonical profile alias does not match requested registry key".into(),
            ));
        }
        crate::validation::validate_compressed_pubkey(&signed.profile.identity_pubkey)?;
        crate::crypto::check_profile_expiry(&signed.profile)?;
        let canonical = crate::crypto::canonical_profile_bytes(&signed.profile)?;
        let canonical_text = std::str::from_utf8(&canonical)
            .map_err(|e| SatsPathError::SerializationError(e.to_string()))?;
        crate::validation::assert_no_private_material(canonical_text)?;
        if !crate::crypto::verify_signed_profile(signed)? {
            return Err(SatsPathError::InvalidSignature);
        }
        Ok(())
    }

    /// Register a signed profile. Fails if the alias is already taken.
    pub fn register_profile(&mut self, signed: SignedPaymentProfile) -> Result<()> {
        let requested = signed.profile.alias.clone();
        self.register_profile_for(&requested, signed)
    }

    pub fn register_profile_for(
        &mut self,
        requested_alias: &str,
        signed: SignedPaymentProfile,
    ) -> Result<()> {
        Self::validate_profile_write(requested_alias, &signed)?;
        let alias = canonical_identifier(&signed.profile.alias);
        let key = identifier_hash(&alias);
        if self.data.profiles.contains_key(&key) || self.data.profiles.contains_key(&alias) {
            return Err(SatsPathError::AliasAlreadyRegistered(alias));
        }
        self.data.profiles.insert(key, signed);
        self.save()
    }

    /// Update (overwrite) an existing profile entry.
    pub fn update_profile(&mut self, signed: SignedPaymentProfile) -> Result<()> {
        let requested = signed.profile.alias.clone();
        self.update_profile_for(&requested, signed)
    }

    pub fn update_profile_for(
        &mut self,
        requested_alias: &str,
        signed: SignedPaymentProfile,
    ) -> Result<()> {
        Self::validate_profile_write(requested_alias, &signed)?;
        let alias = canonical_identifier(&signed.profile.alias);
        let key = identifier_hash(&alias);

        // SEC-03: Downgrade Attack Mitigation
        // Ensure we do not overwrite a newer profile with an older one.
        if let Some(existing) = self
            .data
            .profiles
            .get(&key)
            .or_else(|| self.data.profiles.get(&alias))
        {
            if signed.profile.identity_pubkey != existing.profile.identity_pubkey {
                let rotation = signed
                    .profile
                    .rotation
                    .as_ref()
                    .ok_or(SatsPathError::UnauthorizedKeyReplacement)?;
                if rotation.previous_pubkey != existing.profile.identity_pubkey
                    || rotation.new_pubkey != signed.profile.identity_pubkey
                    || rotation.identifier_hash != identifier_hash(&alias)
                    || rotation.sequence != signed.profile.sequence.unwrap_or(0)
                    || rotation.sequence != existing.profile.sequence.unwrap_or(0).saturating_add(1)
                    || rotation.previous_event_hash.is_empty()
                    || !rotation.verify()?
                {
                    return Err(SatsPathError::InvalidRotation(
                        "rotation must be authorized by the old key and accepted by the new key"
                            .into(),
                    ));
                }
            } else if signed.profile.rotation.is_some() {
                return Err(SatsPathError::InvalidRotation(
                    "rotation proof supplied without an identity key change".into(),
                ));
            }
            if signed.profile.updated_at < existing.profile.updated_at {
                return Err(SatsPathError::RegistryError(format!(
                    "Update rejected: incoming profile is older (updated_at: {}) than existing profile (updated_at: {})",
                    signed.profile.updated_at, existing.profile.updated_at
                )));
            }

            // SEC-03c: Sequence Number Check (Replay Protection)
            // Each update must have a strictly higher sequence number
            if let (Some(new_seq), Some(existing_seq)) =
                (signed.profile.sequence, existing.profile.sequence)
            {
                if new_seq <= existing_seq {
                    return Err(SatsPathError::RegistryError(format!(
                        "Update rejected: sequence number {} not greater than existing {}",
                        new_seq, existing_seq
                    )));
                }
            } else if signed.profile.sequence.is_some() && existing.profile.sequence.is_none() {
                // Allow adding sequence to an old profile without sequence
            } else if signed.profile.sequence.is_none() && existing.profile.sequence.is_some() {
                // Reject removing sequence once it's been added
                return Err(SatsPathError::RegistryError(
                    "Update rejected: cannot remove sequence number once added".into(),
                ));
            }
        }

        self.data.profiles.insert(key, signed);
        self.save()
    }

    pub fn resolve_alias(&self, alias: &str) -> Result<&SignedPaymentProfile> {
        let canonical = canonical_identifier(alias);
        let key = identifier_hash(&canonical);
        let profile = self
            .data
            .profiles
            .get(&key)
            .or_else(|| self.data.profiles.get(&canonical))
            .ok_or_else(|| SatsPathError::AliasNotFound(canonical.clone()))?;

        if profile.profile.revoked {
            return Err(SatsPathError::ProfileRevoked(canonical));
        }

        Ok(profile)
    }

    /// Check whether an alias is already registered.
    pub fn is_registered(&self, alias: &str) -> bool {
        let canonical = canonical_identifier(alias);
        self.data
            .profiles
            .contains_key(&identifier_hash(&canonical))
            || self.data.profiles.contains_key(&canonical)
    }

    /// Return all registered aliases.
    pub fn all_aliases(&self) -> Vec<&str> {
        self.data.profiles.keys().map(String::as_str).collect()
    }
}

use crate::resolver::ProfileResolver;
use async_trait::async_trait;

#[async_trait]
impl ProfileResolver for Registry {
    async fn resolve_alias(&self, alias: &str) -> Result<SignedPaymentProfile> {
        // We clone to return an owned value, as ProfileResolver returns owned data
        let signed = self.resolve_alias(alias).cloned()?;
        // SEC-01: enforce profile expiry before returning.
        crate::crypto::check_profile_expiry(&signed.profile)?;
        Ok(signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_identity_keypair, sign_profile};
    use crate::profile::{PaymentMethod, PaymentProfile};

    fn make_signed(alias: &str) -> SignedPaymentProfile {
        let kp = generate_identity_keypair();
        let pubkey_hex = hex::encode(kp.public_key.serialize());
        let profile = PaymentProfile {
            alias: alias.to_string(),
            identity_pubkey: pubkey_hex,
            methods: vec![PaymentMethod::Lightning {
                label: "LN".into(),
                lightning_address: Some(alias.to_string()),
                lnurl: None,
                bolt12: None,
                receiver_pubkey: None,
            }],
            updated_at: 1_700_000_000,
            expires_at: None,
            sequence: None,
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: Vec::new(),
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
        };
        sign_profile(profile, &kp.secret_key).unwrap()
    }

    #[test]
    fn register_and_resolve() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = Registry::open(dir.path()).unwrap();
        let signed = make_signed("alice@example.com");
        reg.register_profile(signed).unwrap();
        let resolved = reg.resolve_alias("alice@example.com").unwrap();
        assert_eq!(resolved.profile.alias, "alice@example.com");
    }

    #[test]
    fn duplicate_registration_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = Registry::open(dir.path()).unwrap();
        reg.register_profile(make_signed("bob@example.com"))
            .unwrap();
        let err = reg
            .register_profile(make_signed("bob@example.com"))
            .unwrap_err();
        assert!(matches!(err, SatsPathError::AliasAlreadyRegistered(_)));
    }

    #[test]
    fn missing_alias_fails() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Registry::open(dir.path()).unwrap();
        let err = reg.resolve_alias("ghost@example.com").unwrap_err();
        assert!(matches!(err, SatsPathError::AliasNotFound(_)));
    }

    #[test]
    fn is_registered_check() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = Registry::open(dir.path()).unwrap();
        assert!(!reg.is_registered("carol@example.com"));
        reg.register_profile(make_signed("carol@example.com"))
            .unwrap();
        assert!(reg.is_registered("carol@example.com"));
    }

    #[test]
    fn registry_persists_across_opens() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut reg = Registry::open(dir.path()).unwrap();
            reg.register_profile(make_signed("persist@example.com"))
                .unwrap();
        }
        let reg2 = Registry::open(dir.path()).unwrap();
        assert!(reg2.is_registered("persist@example.com"));
    }

    #[test]
    fn invalid_profile_never_reaches_disk() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = Registry::open(dir.path()).unwrap();
        let mut signed = make_signed("invalid@example.com");
        signed.signature = "00".repeat(64);
        assert!(matches!(
            reg.register_profile(signed),
            Err(SatsPathError::InvalidSignature)
        ));
        assert!(!reg.is_registered("invalid@example.com"));
    }

    #[test]
    fn canonical_requested_alias_must_match() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = Registry::open(dir.path()).unwrap();
        let signed = make_signed("alice@example.com");
        assert!(reg
            .register_profile_for("mallory@example.com", signed)
            .is_err());
    }

    #[test]
    fn self_signed_replacement_key_is_rejected_without_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = Registry::open(dir.path()).unwrap();
        let mut original = make_signed("alice@example.com");
        original.profile.sequence = Some(1);
        let original_key = generate_identity_keypair();
        original.profile.identity_pubkey = hex::encode(original_key.public_key.serialize());
        original = sign_profile(original.profile, &original_key.secret_key).unwrap();
        reg.register_profile(original).unwrap();

        let attacker = generate_identity_keypair();
        let mut malicious = make_signed("alice@example.com").profile;
        malicious.identity_pubkey = hex::encode(attacker.public_key.serialize());
        malicious.sequence = Some(2);
        malicious.updated_at += 1;
        let malicious = sign_profile(malicious, &attacker.secret_key).unwrap();
        assert!(matches!(
            reg.update_profile(malicious),
            Err(SatsPathError::UnauthorizedKeyReplacement)
        ));
    }
}
