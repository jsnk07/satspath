//! Security regression — Finding #3: the resolution / pay path must enforce
//! key continuity.
//!
//! An attacker who can answer resolution for the victim's alias (operate the
//! `.well-known` host, win the resolver race, MITM a transport, publish a
//! Nostr profile under an identity they control) serves a profile for
//! `alice@example.com` self-signed with their own key. The signature verifies,
//! so the resolution result must be bound to the key the wallet already trusts
//! for that alias — not only to the alias string.
//!
//! No network I/O: the attacker is an in-process resolver.

use std::sync::Arc;

use async_trait::async_trait;
use secp256k1::SecretKey;

use satspath_core::crypto::{generate_identity_keypair, sign_profile, verify_signed_profile};
use satspath_core::key_pins::{KeyContinuity, MemoryKeyStore, PinnedResolver};
use satspath_core::privacy::identifier_hash;
use satspath_core::profile::{PaymentMethod, PaymentProfile};
use satspath_core::resolver::{ChainResolver, ProfileResolver};
use satspath_core::rotation::KeyRotation;
use satspath_core::{Result, SatsPathError, SignedPaymentProfile};

const ALICE: &str = "alice@example.com";

fn keypair() -> (String, SecretKey) {
    let kp = generate_identity_keypair();
    (hex::encode(kp.public_key.serialize()), kp.secret_key)
}

fn profile(pubkey: &str, lightning_address: &str, sequence: u64) -> PaymentProfile {
    PaymentProfile {
        alias: ALICE.into(),
        identity_pubkey: pubkey.into(),
        methods: vec![PaymentMethod::Lightning {
            label: "LN".into(),
            lnurl: None,
            lightning_address: Some(lightning_address.into()),
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

/// Answers every resolution with a fixed profile (honest server or attacker).
struct FixedResolver(SignedPaymentProfile);

#[async_trait]
impl ProfileResolver for FixedResolver {
    async fn resolve_alias(&self, _alias: &str) -> Result<SignedPaymentProfile> {
        Ok(self.0.clone())
    }
}

fn wallet_resolver(
    answer: SignedPaymentProfile,
    store: &Arc<MemoryKeyStore>,
) -> PinnedResolver<ChainResolver> {
    PinnedResolver::new(
        ChainResolver::new().push(FixedResolver(answer)),
        store.clone(),
    )
}

#[tokio::test]
async fn resolution_result_must_be_bound_to_trusted_key() {
    let store = Arc::new(MemoryKeyStore::new());

    // The wallet has paid Alice before and has seen her real key, K_alice.
    let (alice_pk, alice_sk) = keypair();
    let honest = sign_profile(profile(&alice_pk, "alice@blink.sv", 1), &alice_sk).unwrap();
    let (first, continuity) = wallet_resolver(honest, &store)
        .resolve_with_continuity(ALICE)
        .await
        .expect("first contact resolves");
    assert_eq!(first.profile.identity_pubkey, alice_pk);
    assert_eq!(continuity, KeyContinuity::FirstUse);

    // The attacker answers the next resolution with a profile for Alice's
    // alias, self-signed with K_evil and pointing at the attacker's wallet.
    let (evil_pk, evil_sk) = keypair();
    let evil = sign_profile(profile(&evil_pk, "attacker@evil.example", 2), &evil_sk).unwrap();
    assert!(
        verify_signed_profile(&evil).unwrap(),
        "precondition: the attacker's self-signature is valid"
    );

    match wallet_resolver(evil, &store).resolve_alias(ALICE).await {
        Ok(resolved) => assert_eq!(
            resolved.profile.identity_pubkey, alice_pk,
            "resolution silently switched {ALICE} from K_alice to K_evil"
        ),
        Err(e) => assert!(
            matches!(e, SatsPathError::UnauthorizedKeyReplacement),
            "expected UnauthorizedKeyReplacement, got {e}"
        ),
    }
}

#[tokio::test]
async fn authorized_rotation_is_followed() {
    let store = Arc::new(MemoryKeyStore::new());
    let (old_pk, old_sk) = keypair();
    let (new_pk, new_sk) = keypair();

    let before = sign_profile(profile(&old_pk, "alice@blink.sv", 1), &old_sk).unwrap();
    wallet_resolver(before, &store)
        .resolve_alias(ALICE)
        .await
        .unwrap();

    let rotation = KeyRotation::create(
        identifier_hash(ALICE),
        old_pk.clone(),
        &old_sk,
        new_pk.clone(),
        &new_sk,
        "prev-event".into(),
        2,
    )
    .unwrap();
    let mut rotated = profile(&new_pk, "alice@blink.sv", 2);
    rotated.rotation = Some(rotation);
    let rotated = sign_profile(rotated, &new_sk).unwrap();

    let (resolved, continuity) = wallet_resolver(rotated, &store)
        .resolve_with_continuity(ALICE)
        .await
        .expect("a rotation authorized by the trusted key is accepted");
    assert_eq!(resolved.profile.identity_pubkey, new_pk);
    assert_eq!(
        continuity,
        KeyContinuity::Rotated {
            previous_pubkey: old_pk.clone()
        }
    );

    // The pin moved: the new key keeps resolving, the old key is now refused.
    let same_key = sign_profile(profile(&new_pk, "alice@blink.sv", 2), &new_sk).unwrap();
    assert!(wallet_resolver(same_key, &store)
        .resolve_alias(ALICE)
        .await
        .is_ok());
    let old_key = sign_profile(profile(&old_pk, "alice@blink.sv", 3), &old_sk).unwrap();
    assert!(matches!(
        wallet_resolver(old_key, &store).resolve_alias(ALICE).await,
        Err(SatsPathError::UnauthorizedKeyReplacement)
    ));
}

#[tokio::test]
async fn replayed_older_profile_is_rejected() {
    let store = Arc::new(MemoryKeyStore::new());
    let (pk, sk) = keypair();
    let current = sign_profile(profile(&pk, "alice@blink.sv", 5), &sk).unwrap();
    let stale = sign_profile(profile(&pk, "alice@old-wallet.sv", 3), &sk).unwrap();

    wallet_resolver(current, &store)
        .resolve_alias(ALICE)
        .await
        .unwrap();
    assert!(
        wallet_resolver(stale, &store)
            .resolve_alias(ALICE)
            .await
            .is_err(),
        "an older, validly signed copy must not replace a newer one"
    );
}
