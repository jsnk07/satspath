pub mod ark;
pub mod bip321;
#[cfg(feature = "std")]
pub mod bip321_handoff;
pub mod bip353;
pub mod bip353_publish;
pub mod codec;
pub mod crypto;
pub mod dns;
pub mod errors;
pub mod execution;
pub mod ownership;
pub mod peer_registry;
pub mod platform;
pub mod pointer;
pub mod privacy;
pub mod profile;
pub mod registry;
pub mod rotation;
pub mod split;
pub mod transparency;
pub mod validation;

#[cfg(feature = "std")]
pub mod resolver;
#[cfg(feature = "std")]
pub mod resolvers;
#[cfg(feature = "std")]
pub mod ssrf;

pub use ark::{
    ark_ownership_challenge, validate_ark_receive_pointer, validate_ark_server_url,
    verify_ark_ownership_proof, ArkIntentStatus, ArkOwnershipProof, ArkPaymentIntent,
    ArkReceivePointer, ArkRouteKind, ClientValidationReport,
};
pub use bip321::{parse_bip321, Bip321Instruction, ParsedBip321Uri};
pub use bip353::{
    parse_bip353_name, resolve_bip353, resolve_bip353_with, verify_bip353_ownership, Bip353Name,
    Bip353Resolution, DnsTxtRecord, DnsTxtResolver, DnssecPolicy, DohTxtResolver,
    MockDnsTxtResolver,
};
pub use bip353_publish::{
    assert_public_payment_instruction, authorize_dns_update, chunk_txt, dns_update_challenge,
    plan_cname_delegation, plan_direct_txt, DnsPublisher, DnsUpdateAudit, DnsUpdateAuth,
    MockDnsPublisher, PublishingPlan,
};
pub use crypto::{
    fingerprint_pubkey, generate_identity_keypair, generate_nonce, sign_message, sign_profile,
    verify_message_signature, verify_signed_profile, IdentityKeypair,
};
pub use dns::{DnsDescriptor, DnsError};
pub use errors::{Result, SatsPathError};
pub use execution::{
    ExecutionGatePolicy, ExecutionMode, MockWalletExecutor, OnchainReceipt, PaymentReceipt,
    WalletExecutor,
};
pub use ownership::{
    attach_signature_proof, attach_well_known_proof, build_manual_attestation,
    build_signature_attestation, evaluate_method_trust, evaluate_method_trust_for_profile,
    ownership_challenge_message, pubkey_controls_address, stored_status_for_method,
    upsert_method_verification, validate_method_verification, validate_ownership_proof,
    verify_method_verification, well_known_url_for_method, well_known_url_of, MethodTrust,
    MethodVerification, OwnershipProof, ProofType, TrustTier, VerificationStatus,
};
pub use peer_registry::{
    canonicalize_identifier, display_hint, hash_identifier, LocalPeerRegistry, MockPeerRegistry,
    PeerPointers, PeerRecord, PeerRegistryBackend,
};
pub use platform::{
    EmailChallenge, EmailVerifier, ProfilePublisher, PublishReceipt, VerifiedIdentifier,
};
pub use pointer::{BitcoinNetwork, PaymentPointer};
pub use privacy::{canonical_identifier, identifier_hash, validate_ascii_identifier};
pub use profile::{
    Bolt12Offer, ClaimNotification, ClaimPolicy, Invite, InviteRecord, InviteStatus, PaymentMethod,
    PaymentProfile, PaymentRequest, SignedPaymentProfile,
};
pub use rotation::{
    apply_key_rotation, get_effective_identity_pubkey, is_rotation_valid, rotate_identity_key,
    verify_key_rotation, KeyRotation,
};
pub use split::{SplitPaymentRequest, SplitRecipient};
pub use transparency::next_identifier_sequence;
#[cfg(feature = "std")]
pub use transparency::TransactionalTransparencyStore;
pub use transparency::{
    BitcoinAnchor as TransparencyBitcoinAnchor, CheckpointStore, ConsistencyStatus,
    IdentifierAttestation, IdentifierVerificationMethod, MerkleConsistencyProof,
    MerkleInclusionProof, NameAction, NameEvent, OperatorKeyRotation, PinnedCheckpoint,
    TransparencyCheckpoint, TransparencyError, TransparencyLog, TransparencyLogIdentity,
    TransparencyStatus, TrustedVerifier,
};

#[cfg(feature = "std")]
pub mod invite_store;
#[cfg(feature = "std")]
pub use invite_store::{InviteStore, INVITES_FILE};

#[cfg(feature = "std")]
pub use resolver::{
    verify_payment_method_states, ChainResolver, PaymentMethodVerificationState, ProfileResolver,
    ResolvedTransparentProfile, ResolverSource, VerificationStates,
};
#[cfg(feature = "std")]
pub use resolvers::{bip353::Bip353Resolver, http::HttpResolver, nostr::NostrResolver};

pub use validation::validate_silent_payment_address;

/// Validate that a string looks like a Lightning Address (user@domain).
pub fn is_valid_lightning_address(s: &str) -> bool {
    validation::validate_lightning_address(s).is_ok()
}

/// Create an invite for an unregistered alias, signed by the sender.
pub fn create_invite(
    alias: &str,
    amount_sats: u64,
    sender_secret_key: Option<&secp256k1::SecretKey>,
    ttl_seconds: i64,
) -> Invite {
    let now = chrono::Utc::now().timestamp();
    let alias_hash = crate::privacy::identifier_hash(alias);
    let invite_id = uuid::Uuid::new_v4().to_string();
    let claim_url = format!(
        "https://satspath.local/claim?invite_id={}&alias_hash={}&amount={}",
        invite_id,
        &alias_hash[..16],
        amount_sats
    );

    // Build the message to sign: includes all critical invite fields
    let message = format!(
        "SatsPath Invite v1\nalias_hash={alias_hash}\namount_sats={amount_sats}\ncreated_at={now}\nexpires_at={}",
        now + ttl_seconds
    );

    let (sender_signature, sender_pubkey) = if let Some(sk) = sender_secret_key {
        let secp = secp256k1::Secp256k1::new();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, sk);
        let sig = crate::crypto::sign_message(&message, sk);
        (Some(sig), Some(hex::encode(pubkey.serialize())))
    } else {
        (None, None)
    };

    Invite {
        alias_hash,
        amount_sats,
        created_at: now,
        expires_at: now + ttl_seconds,
        claim_url,
        warning: "The receiver must claim this payment by generating their own keys locally. \
                  SatsPath never holds or generates keys on behalf of users."
            .into(),
        sender_signature,
        sender_pubkey,
        invite_id: Some(invite_id),
    }
}

/// Verify an invite's signature and expiry.
pub fn verify_invite(invite: &Invite) -> Result<bool> {
    let now = chrono::Utc::now().timestamp();

    // Check expiry
    if now >= invite.expires_at {
        return Err(SatsPathError::RegistryError("invite expired".into()));
    }

    // If no signature, can't verify sender identity
    let Some(signature) = &invite.sender_signature else {
        return Ok(false);
    };
    let Some(pubkey) = &invite.sender_pubkey else {
        return Ok(false);
    };

    // Reconstruct the signed message
    let message = format!(
        "SatsPath Invite v1\nalias_hash={}\namount_sats={}\ncreated_at={}\nexpires_at={}",
        invite.alias_hash, invite.amount_sats, invite.created_at, invite.expires_at
    );

    crate::crypto::verify_message_signature(&message, signature, pubkey)
}

pub fn create_invite_record(
    identifier: &str,
    amount_sats: u64,
    memo: Option<String>,
    sender_fingerprint: String,
    ttl_seconds: i64,
) -> InviteRecord {
    let now = chrono::Utc::now().timestamp();
    InviteRecord {
        invite_id: uuid::Uuid::new_v4().to_string(),
        identifier_hash: privacy::identifier_hash(identifier),
        display_hint: privacy::mask_identifier(identifier),
        amount_sats,
        memo,
        sender_fingerprint,
        status: InviteStatus::Created,
        created_at: now,
        expires_at: now + ttl_seconds,
        sender_pubkey: None,
        sender_signature: None,
        claimed_at: None,
        claimed_profile_pubkey: None,
    }
}

/// Create a signed invite record with cryptographic sender attribution.
pub fn create_signed_invite_record(
    identifier: &str,
    amount_sats: u64,
    memo: Option<String>,
    sender_fingerprint: String,
    ttl_seconds: i64,
    sender_secret_key: Option<&secp256k1::SecretKey>,
) -> InviteRecord {
    let now = chrono::Utc::now().timestamp();
    let identifier_hash = privacy::identifier_hash(identifier);
    let expires_at = now + ttl_seconds;

    let (sender_signature, sender_pubkey) = if let Some(sk) = sender_secret_key {
        let secp = secp256k1::Secp256k1::new();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, sk);
        let message = format!(
            "SatsPath Invite v1\nalias_hash={identifier_hash}\namount_sats={amount_sats}\ncreated_at={now}\nexpires_at={expires_at}"
        );
        let sig = crate::crypto::sign_message(&message, sk);
        (Some(sig), Some(hex::encode(pubkey.serialize())))
    } else {
        (None, None)
    };

    InviteRecord {
        invite_id: uuid::Uuid::new_v4().to_string(),
        identifier_hash,
        display_hint: privacy::mask_identifier(identifier),
        amount_sats,
        memo,
        sender_fingerprint,
        status: InviteStatus::Created,
        created_at: now,
        expires_at,
        sender_pubkey,
        sender_signature,
        claimed_at: None,
        claimed_profile_pubkey: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_user_invite_record_contains_no_private_material() {
        let invite = create_invite_record(
            "someone@gmail.com",
            1_000,
            Some("coffee".into()),
            "sender-fp".into(),
            600,
        );
        assert_eq!(invite.status, InviteStatus::Created);
        assert_eq!(invite.display_hint, "s***@gmail.com");
        assert!(!format!("{invite:?}").contains("seed"));
        assert!(!format!("{invite:?}").contains("xprv"));
        assert!(invite.expires_at > invite.created_at);
        assert!(invite.claimed_at.is_none());
        assert!(invite.claimed_profile_pubkey.is_none());
    }

    #[test]
    fn create_signed_invite_record_and_verify_roundtrip() {
        let secp = secp256k1::Secp256k1::new();
        let secret = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret);
        let pubkey_hex = hex::encode(pubkey.serialize());

        let record = create_signed_invite_record(
            "bob@example.com",
            25_000,
            Some("Pizza".into()),
            pubkey_hex.clone(),
            3600,
            Some(&secret),
        );

        assert_eq!(record.sender_pubkey.as_deref(), Some(pubkey_hex.as_str()));
        assert!(record.sender_signature.is_some());

        let message = format!(
            "SatsPath Invite v1\nalias_hash={}\namount_sats={}\ncreated_at={}\nexpires_at={}",
            record.identifier_hash, record.amount_sats, record.created_at, record.expires_at
        );
        let valid = crypto::verify_message_signature(
            &message,
            record.sender_signature.as_deref().unwrap(),
            record.sender_pubkey.as_deref().unwrap(),
        )
        .expect("verification should run");
        assert!(valid);
    }
}
