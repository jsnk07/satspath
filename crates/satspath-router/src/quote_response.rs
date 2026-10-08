//! The UX/backend **quote response contract**.
//!
//! One call — [`quote`] — resolves a recipient, verifies the signed profile,
//! checks expiry, selects a route, and builds a payment payload, returning a
//! single JSON-serializable [`QuoteResponse`] the frontend can render directly
//! by matching on `status`. The backend owns all protocol complexity.
//!
//! # Safety
//!
//! Responses carry **public data only**: payment profiles, public keys,
//! addresses, Lightning Addresses, LNURL/BOLT11 pointers, BIP-21 URIs, Ark
//! pointers, and invites. No funds are moved, nothing is signed or broadcast,
//! and no private key, seed, xprv, macaroon, cert, or secret is ever included —
//! [`build_qr_payload`] additionally screens payloads for private material.

use serde::{Deserialize, Serialize};

use satspath_core::{
    create_invite,
    crypto::{check_profile_expiry, fingerprint_pubkey, verify_signed_profile},
    profile::PaymentProfile,
    registry::Registry,
    resolver::{ChainResolver, ProfileResolver},
    resolvers::{bip353::Bip353Resolver, http::HttpResolver, nostr::NostrResolver},
    validation::assert_no_private_material,
    Invite, PaymentMethod, SatsPathError,
};

use crate::fees::FeeEstimate;
use crate::lightning::{fetch_invoice, fetch_lnurl_metadata};
use crate::router::{select_route, select_route_with_fees, RouteRequest};

/// Public, frontend-facing description of the recipient.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuoteRecipient {
    pub alias: String,
    /// Backward-compatible verification flag.
    ///
    /// New clients should prefer `profile_signature_verified` and
    /// `identifier_verified`. For signed-profile quotes this mirrors profile
    /// signature verification. For direct BIP-353 previews, legacy behavior may
    /// mirror DNSSEC identifier verification instead.
    pub verified: bool,
    pub profile_signature_verified: bool,
    pub identifier_verified: bool,
    pub identifier_verification: String,
    pub fingerprint: Option<String>,
}

/// The single response the UX renders by matching on `status`.
///
/// Serializes with an internal `status` tag in `snake_case`
/// (`ok` / `not_registered` / `no_route` / `invalid_signature`).
///
/// The `Ok` variant is intentionally larger than the others: the response shape
/// is the public UX/JSON contract, which embeds `PaymentMethod` unchanged. We do
/// not box it (that would alter the Rust API for consumers); the wire shape is
/// identical either way.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum QuoteResponse {
    Ok {
        recipient: QuoteRecipient,
        /// The selected payment method, embedded unchanged.
        selected_method: PaymentMethod,
        fee_sats: Option<u64>,
        eta: Option<String>,
        reason: String,
        qr: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        execution: Option<satspath_core::ExecutionMode>,
        #[serde(skip_serializing_if = "Option::is_none")]
        wallet_hint: Option<String>,
    },
    NotRegistered {
        invite: Invite,
    },
    NoRoute {
        reason: String,
    },
    InvalidSignature {
        recipient: QuoteRecipient,
    },
}

impl QuoteResponse {
    /// The `status` string this response serializes to (handy for callers/tests).
    pub fn status(&self) -> &'static str {
        match self {
            QuoteResponse::Ok { .. } => "ok",
            QuoteResponse::NotRegistered { .. } => "not_registered",
            QuoteResponse::NoRoute { .. } => "no_route",
            QuoteResponse::InvalidSignature { .. } => "invalid_signature",
        }
    }
}

// ─── Public entry points ──────────────────────────────────────────────────────

/// Resolve, verify, route, and build a payment payload for `recipient`.
///
/// Builds the default resolver chain (local registry → BIP-353 → HTTP → Nostr)
/// and, for a Lightning rail, best-effort fetches a real BOLT11 invoice so the
/// `qr` field is directly payable. Falls back to a safe Lightning pointer if the
/// fetch is unavailable.
///
/// Returns a [`QuoteResponse`] for every protocol outcome (found / not
/// registered / no route / invalid signature) — the frontend never sees a Rust
/// error type.
pub async fn quote(recipient: &str, amount_sats: u64) -> QuoteResponse {
    let resolver = default_resolver();
    quote_inner(&resolver, recipient, amount_sats, None, true).await
}

/// Like [`quote`], but against a caller-supplied resolver (e.g. an API server
/// that manages its own resolver chain). Uses live mempool fees and returns a
/// safe Lightning pointer rather than fetching an invoice in this layer.
pub async fn quote_with_resolver<R>(
    resolver: &R,
    recipient: &str,
    amount_sats: u64,
) -> QuoteResponse
where
    R: ProfileResolver + Sync + ?Sized,
{
    quote_inner(resolver, recipient, amount_sats, None, false).await
}

/// Route a profile only after an external transparency verifier has accepted
/// it. The allow-list contains independently verified ownership descriptors.
pub async fn quote_verified_profile(
    mut signed: satspath_core::SignedPaymentProfile,
    recipient: &str,
    amount_sats: u64,
    allowed_method_descriptors: &[String],
) -> QuoteResponse {
    let verified = verify_signed_profile(&signed).unwrap_or(false);
    if !verified {
        return QuoteResponse::InvalidSignature {
            recipient: recipient_of(&signed.profile, false),
        };
    }
    signed.profile.methods.retain(|method| {
        allowed_method_descriptors
            .iter()
            .any(|descriptor| descriptor == &method.ownership_descriptor())
    });
    if signed.profile.methods.is_empty() {
        return QuoteResponse::NoRoute {
            reason: "transparency verified, but no payment method has a valid ownership proof"
                .into(),
        };
    }
    route_verified_signed(signed, recipient, amount_sats, None, false).await
}

// ─── QR / payment payload ──────────────────────────────────────────────────────

/// Build a public payment payload for a method.
///
/// - **Lightning** — returns the best available pointer (LNURL, then Lightning
///   Address, then BOLT12). Fetching a concrete BOLT11 invoice happens in the
///   async [`quote`] flow (or the CLI/API layer), not here.
/// - **On-chain** — a BIP-21 URI: `bitcoin:<address>?amount=<btc>`.
/// - **Ark** — an Ark pointer: `ark:<pubkey>?server=…&amount=…`
///   (preview only; execution is gated elsewhere behind explicit testnet flags).
pub fn build_qr_payload(method: &PaymentMethod, amount_sats: u64) -> satspath_core::Result<String> {
    let payload = match method {
        PaymentMethod::Lightning {
            lightning_address,
            lnurl,
            bolt12,
            ..
        } => lnurl
            .clone()
            .or_else(|| lightning_address.clone())
            .or_else(|| bolt12.clone())
            .ok_or_else(|| {
                SatsPathError::InvalidPaymentPointer(
                    "Lightning method has no address, LNURL, or BOLT12 pointer".into(),
                )
            })?,
        PaymentMethod::Onchain {
            address,
            silent_payment_pubkey,
            ..
        } => {
            let target_address = silent_payment_pubkey
                .clone()
                .unwrap_or_else(|| address.clone().unwrap_or_default());
            format!(
                "bitcoin:{}?amount={}",
                target_address,
                sats_to_btc(amount_sats)
            )
        }
        PaymentMethod::Ark { server, pubkey, .. } => format!(
            "ark:{}?server={}&amount={}",
            urlencoding::encode(pubkey),
            urlencoding::encode(server),
            amount_sats
        ),
        PaymentMethod::Bolt12(offer_data) => offer_data.offer.clone(),
    };

    // Defence in depth: a payment payload must never carry private material.
    assert_no_private_material(&payload)?;
    Ok(payload)
}

/// Format sats as a fixed 8-decimal BTC string, e.g. `21000 -> 0.00021000`.
fn sats_to_btc(amount_sats: u64) -> String {
    format!(
        "{}.{:08}",
        amount_sats / 100_000_000,
        amount_sats % 100_000_000
    )
}

// ─── Core orchestration ─────────────────────────────────────────────────────────

/// The shared quote pipeline.
///
/// `fees`: `Some` uses deterministic routing (no network — used by tests);
/// `None` fetches live mempool fees.
/// `fetch_ln_invoice`: when `true`, a Lightning rail is upgraded to a real
/// BOLT11 invoice (best effort).
/// `NoRoute` reason for a recipient whose profile was revoked by its owner.
pub const PROFILE_REVOKED_REASON: &str = "Profile revoked by its owner.";

/// Quote a payment: resolve, verify, and pick a route; only an unregistered recipient gets an invite.
async fn quote_inner<R>(
    resolver: &R,
    recipient: &str,
    amount_sats: u64,
    fees: Option<FeeEstimate>,
    fetch_ln_invoice: bool,
) -> QuoteResponse
where
    R: ProfileResolver + Sync + ?Sized,
{
    // 1. Resolve. Anything unresolvable becomes an invite — never a hard error —
    // except a revoked profile: its owner withdrew it, so inviting them to
    // register again would route the sender around the revocation.
    let signed = match resolver.resolve_alias(recipient).await {
        Ok(signed) => signed,
        Err(SatsPathError::ProfileRevoked(_)) => {
            return QuoteResponse::NoRoute {
                reason: PROFILE_REVOKED_REASON.into(),
            };
        }
        Err(_) => {
            return QuoteResponse::NotRegistered {
                // No sender key in preview mode; invite is unsigned (no sender identity binding)
                // TTL: 24 hours
                invite: create_invite(recipient, amount_sats, None, 24 * 3600),
            };
        }
    };

    // 2. Verify signature.
    let verified = verify_signed_profile(&signed).unwrap_or(false);
    let recipient_info = recipient_of(&signed.profile, verified);
    if !verified {
        return QuoteResponse::InvalidSignature {
            recipient: recipient_info,
        };
    }

    route_verified_signed(signed, recipient, amount_sats, fees, fetch_ln_invoice).await
}

/// Pick a route for a recipient whose signed profile has been verified.
async fn route_verified_signed(
    signed: satspath_core::SignedPaymentProfile,
    recipient: &str,
    amount_sats: u64,
    fees: Option<FeeEstimate>,
    fetch_ln_invoice: bool,
) -> QuoteResponse {
    let recipient_info = recipient_of(&signed.profile, true);

    // 3. Expiry (mapped to no_route to keep the frontend contract to four states).
    if check_profile_expiry(&signed.profile).is_err() {
        return QuoteResponse::NoRoute {
            reason: "Profile expired.".into(),
        };
    }
    if signed.profile.revoked {
        return QuoteResponse::NoRoute {
            reason: PROFILE_REVOKED_REASON.into(),
        };
    }

    // 4. Route.
    let req = RouteRequest {
        alias: recipient.to_string(),
        amount_sats,
        signed_profile: signed.clone(),
        urgency: crate::urgency::PaymentUrgency::Normal,
        max_fee_sats: None,
        max_fee_percent: None,
    };
    let route = match fees {
        Some(fee_est) => select_route_with_fees(&req, &fee_est),
        None => select_route(&req).await,
    };
    let route = match route {
        Ok(route) => route,
        Err(SatsPathError::NoRouteFound(reason)) => return QuoteResponse::NoRoute { reason },
        Err(e) => {
            return QuoteResponse::NoRoute {
                reason: e.to_string(),
            }
        }
    };

    // 5. Build the payment payload.
    let mut qr = match build_qr_payload(&route.selected_method, amount_sats) {
        Ok(payload) => payload,
        Err(e) => {
            return QuoteResponse::NoRoute {
                reason: format!("could not build payment payload: {e}"),
            }
        }
    };

    // 6. Best-effort upgrade Lightning / BOLT12 to a concrete invoice.
    if fetch_ln_invoice {
        match &route.selected_method {
            PaymentMethod::Lightning {
                lightning_address: Some(addr),
                ..
            } => {
                if let Ok(invoice) = fetch_real_invoice(addr, amount_sats).await {
                    qr = invoice;
                }
            }
            PaymentMethod::Lightning {
                bolt12: Some(offer_str),
                lightning_address: None,
                ..
            } => {
                if let Ok(offer) = crate::bolt12::parse_bolt12_offer(offer_str) {
                    if let Ok(invoice) = crate::bolt12::fetch_bolt12_invoice(
                        &offer,
                        amount_sats * 1_000,
                        None,
                        None,
                        None,
                    )
                    .await
                    {
                        qr = invoice.invoice;
                    }
                }
            }
            PaymentMethod::Bolt12(offer_data) => {
                if let Ok(offer) = crate::bolt12::parse_bolt12_offer(&offer_data.offer) {
                    if let Ok(invoice) = crate::bolt12::fetch_bolt12_invoice(
                        &offer,
                        amount_sats * 1_000,
                        None,
                        None,
                        None,
                    )
                    .await
                    {
                        qr = invoice.invoice;
                    }
                }
            }
            _ => {}
        }
    }

    QuoteResponse::Ok {
        recipient: recipient_info,
        selected_method: route.selected_method,
        fee_sats: route.estimated_fee_sats,
        eta: route.estimated_confirmation,
        reason: route.reason,
        qr,
        execution: route.execution,
        wallet_hint: route.wallet_hint,
    }
}

fn recipient_of(profile: &PaymentProfile, verified: bool) -> QuoteRecipient {
    QuoteRecipient {
        alias: profile.alias.clone(),
        verified,
        profile_signature_verified: verified,
        identifier_verified: false,
        identifier_verification:
            "identifier-only; no inbox/domain ownership proof in this response".into(),
        fingerprint: fingerprint_pubkey(&profile.identity_pubkey).ok(),
    }
}

/// Two-step LNURL-pay: resolve metadata, then fetch a BOLT11 invoice.
async fn fetch_real_invoice(lightning_address: &str, amount_sats: u64) -> anyhow::Result<String> {
    let meta = fetch_lnurl_metadata(lightning_address).await?;
    fetch_invoice(&meta, amount_sats, None).await
}

/// The default resolver chain, mirroring the CLI: local registry, then public
/// resolvers. Registry lives in the always-gitignored `.satspath/`.
fn default_resolver() -> ChainResolver {
    let mut chain = ChainResolver::new();
    if let Ok(registry) = Registry::open(std::path::Path::new(".satspath")) {
        chain = chain.push(registry);
    }
    chain = chain.push(Bip353Resolver::new());
    chain = chain.push(HttpResolver::new());
    chain.push(NostrResolver::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use satspath_core::crypto::{generate_identity_keypair, sign_profile};
    use satspath_core::{BitcoinNetwork, PaymentProfile, SignedPaymentProfile};

    // Deterministic fees: cheap next block (on-chain viable when a method exists).
    /// A low fee estimate that keeps on-chain routes viable.
    fn cheap_fees() -> FeeEstimate {
        FeeEstimate {
            fastest_fee: 5,
            half_hour_fee: 4,
            hour_fee: 3,
            economy_fee: 2,
            minimum_fee: 1,
        }
    }

    // Expensive next block (> 20 sat/vB): on-chain not acceptable.
    /// A fee estimate high enough to rule out on-chain routes.
    fn expensive_fees() -> FeeEstimate {
        FeeEstimate {
            fastest_fee: 35,
            half_hour_fee: 30,
            hour_fee: 25,
            economy_fee: 20,
            minimum_fee: 10,
        }
    }

    struct MockResolver {
        signed: Option<SignedPaymentProfile>,
    }

    #[async_trait]
    impl ProfileResolver for MockResolver {
        /// Fail every lookup with the configured error.
        async fn resolve_alias(&self, alias: &str) -> satspath_core::Result<SignedPaymentProfile> {
            self.signed
                .clone()
                .ok_or_else(|| SatsPathError::AliasNotFound(alias.to_string()))
        }
    }

    /// Resolver whose backend reports the profile as revoked.
    struct RevokedResolver;

    #[async_trait]
    impl ProfileResolver for RevokedResolver {
        /// Report every alias as revoked by its owner.
        async fn resolve_alias(&self, alias: &str) -> satspath_core::Result<SignedPaymentProfile> {
            Err(SatsPathError::ProfileRevoked(alias.to_string()))
        }
    }

    /// A resolver-reported revocation must be a no-route, never a fresh invite.
    #[tokio::test]
    async fn resolver_revocation_returns_no_route_not_invite() {
        let resp = quote_inner(
            &RevokedResolver,
            "gone@satspath.dev",
            1_000,
            Some(cheap_fees()),
            false,
        )
        .await;
        match resp {
            QuoteResponse::NoRoute { reason } => assert_eq!(reason, PROFILE_REVOKED_REASON),
            other => panic!(
                "expected no_route for a revoked profile, got {}",
                other.status()
            ),
        }
    }

    /// A verified profile carrying `revoked: true` hits the router-side guard.
    #[tokio::test]
    async fn revoked_flag_on_verified_profile_returns_no_route() {
        let (mut profile, secret) = base_profile(
            "gone@satspath.dev",
            vec![lightning_method("gone@getalby.com")],
        );
        profile.revoked = true;
        let resolver = MockResolver {
            signed: Some(sign(profile, &secret)),
        };
        let resp = quote_inner(
            &resolver,
            "gone@satspath.dev",
            1_000,
            Some(cheap_fees()),
            false,
        )
        .await;
        match resp {
            QuoteResponse::NoRoute { reason } => assert_eq!(reason, PROFILE_REVOKED_REASON),
            other => panic!(
                "expected no_route for a revoked profile, got {}",
                other.status()
            ),
        }
    }

    fn sign(profile: PaymentProfile, secret: &secp256k1::SecretKey) -> SignedPaymentProfile {
        sign_profile(profile, secret).unwrap()
    }

    fn base_profile(
        alias: &str,
        methods: Vec<PaymentMethod>,
    ) -> (PaymentProfile, secp256k1::SecretKey) {
        let kp = generate_identity_keypair();
        let profile = PaymentProfile {
            alias: alias.to_string(),
            identity_pubkey: hex::encode(kp.public_key.serialize()),
            methods,
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
        (profile, kp.secret_key)
    }

    fn lightning_method(addr: &str) -> PaymentMethod {
        PaymentMethod::Lightning {
            label: "Lightning Address".into(),
            lightning_address: Some(addr.into()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        }
    }

    fn onchain_method(addr: &str) -> PaymentMethod {
        PaymentMethod::Onchain {
            label: "Bitcoin".into(),
            network: BitcoinNetwork::Mainnet,
            address: Some(addr.into()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        }
    }

    fn ark_method(server: &str, pubkey: &str) -> PaymentMethod {
        PaymentMethod::Ark {
            label: "Ark".into(),
            server: server.into(),
            pubkey: pubkey.into(),
            opaque_uri: None,
            vtxo_pointer: None,
            proof: None,
            expires_at: None,
        }
    }

    fn lightning_resolver(alias: &str, addr: &str) -> MockResolver {
        let (profile, secret) = base_profile(alias, vec![lightning_method(addr)]);
        MockResolver {
            signed: Some(sign(profile, &secret)),
        }
    }

    // 1–7: registered Lightning user → status ok with full payload.
    #[tokio::test]
    async fn registered_lightning_user_returns_ok_with_full_payload() {
        let resolver = lightning_resolver("rodrigo@satspath.dev", "rodrigo@getalby.com");
        let resp = quote_inner(
            &resolver,
            "rodrigo@satspath.dev",
            1000,
            Some(cheap_fees()),
            false,
        )
        .await;

        match resp {
            QuoteResponse::Ok {
                recipient,
                selected_method,
                fee_sats,
                eta,
                reason,
                qr,
                execution: _,
                wallet_hint: _,
            } => {
                // (2) alias, (3) verified true, (4) fingerprint
                assert_eq!(recipient.alias, "rodrigo@satspath.dev");
                assert!(recipient.verified);
                assert!(recipient.profile_signature_verified);
                assert!(!recipient.identifier_verified);
                assert!(recipient
                    .identifier_verification
                    .contains("identifier-only"));
                assert!(recipient.fingerprint.is_some());
                assert_eq!(recipient.fingerprint.as_ref().unwrap().len(), 8);
                // (5) PaymentMethod embedded unchanged
                assert!(matches!(selected_method, PaymentMethod::Lightning { .. }));
                // (6) fee_sats, eta, reason
                assert!(fee_sats.is_some());
                assert!(eta.is_some());
                assert!(!reason.is_empty());
                // (7) QR / payment payload present
                assert!(!qr.is_empty());
                assert_eq!(qr, "rodrigo@getalby.com"); // pointer (no fetch in this path)
            }
            other => panic!("expected Ok, got {}", other.status()),
        }
    }

    // 8–9: unknown user → not_registered with invite fields.
    #[tokio::test]
    async fn unknown_user_returns_not_registered_with_invite() {
        let resolver = MockResolver { signed: None };
        let resp = quote_inner(
            &resolver,
            "ghost@nowhere.dev",
            21_000,
            Some(cheap_fees()),
            false,
        )
        .await;
        match resp {
            QuoteResponse::NotRegistered { invite } => {
                assert!(!invite.alias_hash.is_empty());
                assert_eq!(invite.amount_sats, 21_000);
                assert!(invite.claim_url.contains("alias_hash="));
                assert!(invite.claim_url.contains("amount=21000"));
            }
            other => panic!("expected NotRegistered, got {}", other.status()),
        }
    }

    // 10: no usable route → no_route.
    #[tokio::test]
    async fn no_usable_route_returns_no_route() {
        // On-chain only, fees too high (35 > 20), no Lightning/Ark fallback.
        let (profile, secret) = base_profile("carol@satspath.dev", vec![]);
        let resolver = MockResolver {
            signed: Some(sign(profile, &secret)),
        };
        let resp = quote_inner(
            &resolver,
            "carol@satspath.dev",
            500_000,
            Some(expensive_fees()),
            false,
        )
        .await;
        assert_eq!(resp.status(), "no_route");
        assert!(matches!(resp, QuoteResponse::NoRoute { .. }));
    }

    // 11 & 12: invalid signature → invalid_signature, and never ok.
    #[tokio::test]
    async fn tampered_profile_returns_invalid_signature_never_ok() {
        let (profile, secret) = base_profile(
            "rodrigo@satspath.dev",
            vec![lightning_method("r@getalby.com")],
        );
        let mut signed = sign(profile, &secret);
        // Tamper after signing — signature no longer matches.
        signed.profile.alias = "evil@hacker.com".into();
        let resolver = MockResolver {
            signed: Some(signed),
        };
        let resp = quote_inner(
            &resolver,
            "evil@hacker.com",
            1000,
            Some(cheap_fees()),
            false,
        )
        .await;

        assert_ne!(
            resp.status(),
            "ok",
            "a tampered profile must never return ok"
        );
        match resp {
            QuoteResponse::InvalidSignature { recipient } => {
                assert!(!recipient.verified);
                assert!(!recipient.profile_signature_verified);
                assert!(!recipient.identifier_verified);
                assert!(recipient.fingerprint.is_some());
            }
            other => panic!("expected InvalidSignature, got {}", other.status()),
        }
    }

    // 13: on-chain QR is a BIP-21 URI.
    #[test]
    fn qr_payload_onchain_is_bip21() {
        let method = onchain_method("bc1qexampleaddr00000000000000000000000000");
        let qr = build_qr_payload(&method, 21_000).unwrap();
        assert_eq!(
            qr,
            "bitcoin:bc1qexampleaddr00000000000000000000000000?amount=0.00021000"
        );
    }

    // 14: Ark QR is an ark: URI.
    #[test]
    fn qr_payload_ark_is_ark_uri() {
        let method = ark_method(
            "https://ark.example.com",
            "02c0ded4d352532ee6d5d3fb69c7f08988c0a2b9f68a10fa79b2e769c123456789",
        );
        let qr = build_qr_payload(&method, 42).unwrap();
        assert!(qr.starts_with("ark:02c0ded4"));
        assert!(qr.contains("server=https%3A%2F%2Fark.example.com"));
        assert!(qr.contains("amount=42"));
    }

    // 15: JSON serialization uses snake_case status values.
    #[tokio::test]
    async fn json_uses_snake_case_status_values() {
        let resolver = lightning_resolver("rodrigo@satspath.dev", "rodrigo@getalby.com");
        let ok = quote_inner(
            &resolver,
            "rodrigo@satspath.dev",
            1000,
            Some(cheap_fees()),
            false,
        )
        .await;
        let json = serde_json::to_string(&ok).unwrap();
        assert!(json.contains("\"status\":\"ok\""), "json: {json}");

        let nr = quote_inner(
            &MockResolver { signed: None },
            "x@y.z",
            1,
            Some(cheap_fees()),
            false,
        )
        .await;
        assert!(serde_json::to_string(&nr)
            .unwrap()
            .contains("\"status\":\"not_registered\""));

        let (p, s) = base_profile("c@d.e", vec![]);
        let route_resolver = MockResolver {
            signed: Some(sign(p, &s)),
        };
        let nroute = quote_inner(
            &route_resolver,
            "c@d.e",
            500_000,
            Some(expensive_fees()),
            false,
        )
        .await;
        assert!(serde_json::to_string(&nroute)
            .unwrap()
            .contains("\"status\":\"no_route\""));

        let (p2, s2) = base_profile("r@s.t", vec![lightning_method("r@getalby.com")]);
        let mut tampered = sign(p2, &s2);
        tampered.profile.alias = "evil@x.y".into();
        let inv_resolver = MockResolver {
            signed: Some(tampered),
        };
        let inv = quote_inner(&inv_resolver, "evil@x.y", 1000, Some(cheap_fees()), false).await;
        assert!(serde_json::to_string(&inv)
            .unwrap()
            .contains("\"status\":\"invalid_signature\""));
    }

    // Success JSON embeds PaymentMethod with its `type` tag, unchanged.
    #[tokio::test]
    async fn ok_json_embeds_selected_method_with_type_tag() {
        let resolver = lightning_resolver("rodrigo@satspath.dev", "rodrigo@getalby.com");
        let ok = quote_inner(
            &resolver,
            "rodrigo@satspath.dev",
            1000,
            Some(cheap_fees()),
            false,
        )
        .await;
        let v: serde_json::Value = serde_json::to_value(&ok).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["selected_method"]["type"], "Lightning");
        assert_eq!(
            v["selected_method"]["lightning_address"],
            "rodrigo@getalby.com"
        );
        assert_eq!(v["recipient"]["verified"], true);
        assert_eq!(v["recipient"]["profile_signature_verified"], true);
        assert_eq!(v["recipient"]["identifier_verified"], false);
    }
}
