//! Security regression — Finding #4: revocation must be enforced off the
//! transparency path.
//!
//! When an owner's key is compromised they publish a correctly signed profile
//! with `revoked = true`. Every resolution path must treat that as a hard stop:
//! the HTTP resolver, and the resolver chain used by `pay`/`preview`/`quote`
//! regardless of which transport produced the profile.

use async_trait::async_trait;
use mockito::Server;

use satspath_core::crypto::{generate_identity_keypair, sign_profile};
use satspath_core::profile::{PaymentMethod, PaymentProfile};
use satspath_core::resolver::{ChainResolver, ProfileResolver};
use satspath_core::resolvers::http::HttpResolver;
use satspath_core::{Result, SatsPathError, SignedPaymentProfile};

fn signed_profile(alias: &str, revoked: bool) -> SignedPaymentProfile {
    let kp = generate_identity_keypair();
    let profile = PaymentProfile {
        alias: alias.to_string(),
        identity_pubkey: hex::encode(kp.public_key.serialize()),
        methods: vec![PaymentMethod::Lightning {
            label: "LN".into(),
            lnurl: None,
            lightning_address: Some(alias.to_string()),
            bolt12: None,
            receiver_pubkey: None,
        }],
        updated_at: 1_700_000_000,
        expires_at: None,
        sequence: Some(2),
        preferences: vec![],
        nonce: None,
        rotation: None,
        method_verifications: vec![],
        hybrid_pubkey: None,
        pqc_required: false,
        revoked,
    };
    sign_profile(profile, &kp.secret_key).expect("sign")
}

#[tokio::test]
async fn http_resolver_must_reject_revoked_profile() {
    let mut server = Server::new_async().await;
    let revoked = signed_profile("alice@example.com", true);
    let _mock = server
        .mock("GET", "/.well-known/satspath/alice")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&revoked).unwrap())
        .create_async()
        .await;

    let url = format!("{}/.well-known/satspath/alice", server.url());
    let result = HttpResolver::new().resolve_from_url(&url).await;

    assert!(
        result.is_err(),
        "a correctly signed profile with revoked = true must be rejected, got {:?}",
        result.map(|p| p.profile.alias)
    );
}

/// Serves a fixed profile for any alias, standing in for any transport.
struct FixedResolver(SignedPaymentProfile);

#[async_trait]
impl ProfileResolver for FixedResolver {
    async fn resolve_alias(&self, _alias: &str) -> Result<SignedPaymentProfile> {
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn resolver_chain_must_reject_revoked_profile_from_any_transport() {
    let chain = ChainResolver::new()
        .push(FixedResolver(signed_profile("alice@example.com", true)))
        // An older, non-revoked copy served further down the chain must not
        // be reached: revocation is a hard stop, not a "try the next one".
        .push(FixedResolver(signed_profile("alice@example.com", false)));

    let result = chain.resolve_alias("alice@example.com").await;
    assert!(
        matches!(result, Err(SatsPathError::ProfileRevoked(_))),
        "revoked profile must stop resolution, got {:?}",
        result.map(|p| p.profile.revoked)
    );
}

#[tokio::test]
async fn non_revoked_profile_still_resolves() {
    let mut server = Server::new_async().await;
    let ok = signed_profile("bob@example.com", false);
    let _mock = server
        .mock("GET", "/.well-known/satspath/bob")
        .with_status(200)
        .with_body(serde_json::to_string(&ok).unwrap())
        .create_async()
        .await;

    let url = format!("{}/.well-known/satspath/bob", server.url());
    assert!(HttpResolver::new().resolve_from_url(&url).await.is_ok());
}
