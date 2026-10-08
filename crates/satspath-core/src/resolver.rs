use async_trait::async_trait;

use crate::privacy::canonical_identifier;
use crate::{Result, SatsPathError, SignedPaymentProfile};
use serde::{Deserialize, Serialize};

use crate::transparency::{
    IdentifierAttestation, MerkleConsistencyProof, MerkleInclusionProof, NameEvent,
    TransparencyCheckpoint,
};
use crate::{MethodTrust, TrustTier};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResolverSource {
    LocalRegistry,
    Http,
    Bip353,
    Nostr,
    P2p,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationStates {
    pub profile_signature_verified: bool,
    pub identifier_verified: bool,
    pub key_continuity_verified: bool,
    pub transparency_inclusion_verified: bool,
    pub checkpoint_binding_verified: bool,
    pub checkpoint_consistency_verified: bool,
    pub operator_continuity_verified: bool,
    pub payment_methods_verified: bool,
    pub payment_method_states: Vec<PaymentMethodVerificationState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMethodVerificationState {
    pub descriptor: String,
    pub verified: bool,
    pub trust_tier: Option<TrustTier>,
    pub reason: String,
}

pub fn verify_payment_method_states(
    profile: &crate::PaymentProfile,
    now: i64,
) -> Vec<PaymentMethodVerificationState> {
    profile
        .methods
        .iter()
        .map(|method| {
            let descriptor = method.ownership_descriptor();
            let matches = profile
                .method_verifications
                .iter()
                .filter(|proof| proof.method_descriptor == descriptor)
                .count();
            if matches > 1 {
                return PaymentMethodVerificationState {
                    descriptor,
                    verified: false,
                    trust_tier: None,
                    reason: "duplicate ownership proofs".into(),
                };
            }
            match crate::evaluate_method_trust_for_profile(profile, method, now, None) {
                MethodTrust::Verified(tier) => PaymentMethodVerificationState {
                    descriptor,
                    verified: true,
                    trust_tier: Some(tier),
                    reason: format!("valid {} ownership proof", tier.label()),
                },
                MethodTrust::SelfAsserted => PaymentMethodVerificationState {
                    descriptor,
                    verified: false,
                    trust_tier: Some(TrustTier::SelfAsserted),
                    reason: "self-attestation is not independent ownership proof".into(),
                },
                MethodTrust::NeedsNetworkCheck(tier) => PaymentMethodVerificationState {
                    descriptor,
                    verified: false,
                    trust_tier: Some(tier),
                    reason: "domain proof requires fresh network verification".into(),
                },
                MethodTrust::Unverified => PaymentMethodVerificationState {
                    descriptor,
                    verified: false,
                    trust_tier: None,
                    reason: "ownership proof missing or bound to another descriptor".into(),
                },
                MethodTrust::Expired => PaymentMethodVerificationState {
                    descriptor,
                    verified: false,
                    trust_tier: None,
                    reason: "ownership proof expired".into(),
                },
                MethodTrust::Invalid(reason) => PaymentMethodVerificationState {
                    descriptor,
                    verified: false,
                    trust_tier: None,
                    reason,
                },
            }
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedTransparentProfile {
    pub signed_profile: SignedPaymentProfile,
    pub latest_event: NameEvent,
    pub inclusion_proof: MerkleInclusionProof,
    pub checkpoint: TransparencyCheckpoint,
    pub consistency_proof: Option<MerkleConsistencyProof>,
    pub identifier_attestation: Option<IdentifierAttestation>,
    pub resolver_source: ResolverSource,
    pub verification: VerificationStates,
}

/// A resolver capable of resolving a SatsPath alias to a `SignedPaymentProfile`.
///
/// Implementations could be local (e.g. `LocalRegistryResolver`) or remote
/// (e.g. `HttpResolver` for NIP-05 style public resolution).
#[async_trait]
pub trait ProfileResolver {
    /// Attempt to resolve the alias to a signed profile.
    ///
    /// # Returns
    /// - `Ok(SignedPaymentProfile)` if the alias is found.
    /// - `Err(SatsPathError::AliasNotFound)` if the alias is explicitly not found.
    /// - `Err(SatsPathError::NetworkError)` (or similar) on fetch failure.
    async fn resolve_alias(&self, alias: &str) -> Result<SignedPaymentProfile>;
}

/// A composite resolver that queries a chain of resolvers in order.
pub struct ChainResolver {
    resolvers: Vec<Box<dyn ProfileResolver + Send + Sync>>,
}

impl ChainResolver {
    pub fn new() -> Self {
        Self {
            resolvers: Vec::new(),
        }
    }

    pub fn push<R: ProfileResolver + Send + Sync + 'static>(mut self, resolver: R) -> Self {
        self.resolvers.push(Box::new(resolver));
        self
    }
}

impl Default for ChainResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProfileResolver for ChainResolver {
    /// Try each resolver in order. A substituted alias or a revoked profile stops the chain.
    async fn resolve_alias(&self, alias: &str) -> Result<SignedPaymentProfile> {
        let requested_canonical = canonical_identifier(alias);
        for resolver in &self.resolvers {
            match resolver.resolve_alias(alias).await {
                Ok(profile) => {
                    // SEC-02: Profile Substitution Attack mitigation
                    let returned_canonical = canonical_identifier(&profile.profile.alias);
                    if returned_canonical != requested_canonical {
                        // A resolver returned a valid profile but for a DIFFERENT user.
                        // Fail hard to prevent funds from being routed to the attacker.
                        return Err(SatsPathError::AliasNotFound(format!(
                            "security failure: requested {}, but got profile for {}",
                            requested_canonical, returned_canonical
                        )));
                    }
                    // SEC-03: revocation is enforced for every transport, not
                    // only the ones that remember to check it. A revoked result
                    // is a hard stop — never fall through to another resolver,
                    // which could be serving an older, non-revoked copy.
                    if profile.profile.revoked {
                        return Err(SatsPathError::ProfileRevoked(returned_canonical));
                    }
                    return Ok(profile);
                }
                Err(SatsPathError::AliasNotFound(_)) => continue,
                Err(SatsPathError::NetworkError(_)) => continue,
                Err(e) => return Err(e),
            }
        }

        Err(SatsPathError::AliasNotFound(alias.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_identity_keypair, sign_profile};
    use crate::profile::{PaymentMethod, PaymentProfile};

    struct MockResolver {
        should_succeed: bool,
        returned_alias: Option<String>,
    }

    #[async_trait]
    impl ProfileResolver for MockResolver {
        async fn resolve_alias(&self, alias: &str) -> Result<SignedPaymentProfile> {
            if self.should_succeed {
                let kp = generate_identity_keypair();
                let pubkey_hex = hex::encode(kp.public_key.serialize());
                let profile_alias = self
                    .returned_alias
                    .clone()
                    .unwrap_or_else(|| alias.to_string());
                let profile = PaymentProfile {
                    alias: profile_alias.clone(),
                    identity_pubkey: pubkey_hex,
                    methods: vec![PaymentMethod::Lightning {
                        label: "LN".into(),
                        lightning_address: Some(profile_alias),
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
                Ok(sign_profile(profile, &kp.secret_key).unwrap())
            } else {
                Err(SatsPathError::AliasNotFound(alias.to_string()))
            }
        }
    }

    #[tokio::test]
    async fn chain_resolver_success() {
        let chain = ChainResolver::new()
            .push(MockResolver {
                should_succeed: false,
                returned_alias: None,
            })
            .push(MockResolver {
                should_succeed: true,
                returned_alias: None,
            });

        let res = chain.resolve_alias("test@domain.com").await;
        assert!(res.is_ok());
        assert_eq!(res.unwrap().profile.alias, "test@domain.com");
    }

    #[tokio::test]
    async fn chain_resolver_failure() {
        let chain = ChainResolver::new()
            .push(MockResolver {
                should_succeed: false,
                returned_alias: None,
            })
            .push(MockResolver {
                should_succeed: false,
                returned_alias: None,
            });

        let res = chain.resolve_alias("test@domain.com").await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn chain_resolver_rejects_substituted_alias() {
        // We ask the mock resolver to succeed, which always returns a profile
        // for "test@domain.com".
        let chain = ChainResolver::new().push(MockResolver {
            should_succeed: true,
            returned_alias: Some("test@domain.com".to_string()),
        });

        // But we request "alice@domain.com".
        // The resolver will return "test@domain.com", which should trigger
        // the SEC-02 Profile Substitution Attack mitigation.
        let res = chain.resolve_alias("alice@domain.com").await;

        assert!(res.is_err());
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("security failure"),
            "Expected security failure message, got: {}",
            err
        );
        assert!(err.contains("alice@domain.com"));
        assert!(err.contains("test@domain.com"));
    }
}
