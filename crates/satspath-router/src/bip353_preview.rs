//! Map a resolved BIP-353 record into a Mainnet-Preview [`QuoteResponse`].
//!
//! BIP-353 resolution yields a public `bitcoin:` URI (and a DNSSEC verdict) but
//! no signed SatsPath profile, so the resulting recipient has `fingerprint: None`.
//! `identifier_verified` reflects DNSSEC validation. This is **preview only** —
//! the `qr` field is the authoritative payable URI; nothing is paid, signed, or
//! broadcast.

use satspath_core::{
    bip321::{parse_bip321, Bip321Instruction},
    Bip353Resolution, BitcoinNetwork, PaymentMethod,
};

use crate::quote_response::{QuoteRecipient, QuoteResponse};

/// Convert a BIP-353 resolution into a preview `QuoteResponse`.
///
/// Picks a representative payment method (on-chain → Lightning BOLT12 → Lightning
/// BOLT11) and returns the full `bitcoin:` URI as the scannable `qr`. Returns
/// `NoRoute` when the URI carries no actionable instruction.
pub fn quote_from_bip353_resolution(
    resolution: &Bip353Resolution,
    amount_sats: u64,
) -> QuoteResponse {
    let parsed = match parse_bip321(&resolution.bitcoin_uri) {
        Ok(p) => p,
        Err(e) => {
            return QuoteResponse::NoRoute {
                reason: format!("BIP-353 record is not a valid bitcoin: URI: {e}"),
            }
        }
    };
    // Fail closed on malformed, cross-network or amount-mismatched payloads.
    if let Err(e) = satspath_core::bip321_handoff::validate_payment_handoff(
        &parsed,
        BitcoinNetwork::Mainnet,
        Some(amount_sats),
    ) {
        return QuoteResponse::NoRoute {
            reason: format!("BIP-353 payment instruction rejected: {e}"),
        };
    }

    let recipient = QuoteRecipient {
        alias: resolution.name.display.clone(),
        // Backward compatibility: for direct BIP-353 previews, `verified`
        // historically meant DNSSEC validation rather than profile signature.
        verified: resolution.dnssec_validated,
        profile_signature_verified: false,
        identifier_verified: resolution.dnssec_validated,
        identifier_verification: if resolution.dnssec_validated {
            "dnssec-bip353"
        } else {
            "dnssec-not-validated"
        }
        .into(),
        fingerprint: None,
    };

    // Choose a representative rail: on-chain, then BOLT12 offer, then BOLT11.
    let (selected_method, rail) = if let Some(addr) = &parsed.address {
        (
            PaymentMethod::Onchain {
                label: "BIP-353 on-chain".into(),
                network: BitcoinNetwork::Mainnet,
                address: Some(addr.clone()),
                silent_payment_pubkey: None,
                pubkey_hint: None,
                descriptor_hint: None,
                address_list: vec![],
            },
            "on-chain",
        )
    } else if let Some(offer) = parsed.instructions.iter().find_map(|i| match i {
        Bip321Instruction::Bolt12Offer { offer } => Some(offer.clone()),
        _ => None,
    }) {
        (
            PaymentMethod::Lightning {
                label: "BIP-353 BOLT12 offer".into(),
                lightning_address: None,
                lnurl: None,
                bolt12: Some(offer),
                receiver_pubkey: None,
            },
            "lightning (BOLT12)",
        )
    } else if parsed
        .instructions
        .iter()
        .any(|i| matches!(i, Bip321Instruction::LightningBolt11 { .. }))
    {
        (
            PaymentMethod::Lightning {
                label: "BIP-353 BOLT11 invoice".into(),
                lightning_address: None,
                lnurl: None,
                bolt12: None,
                receiver_pubkey: None,
            },
            "lightning (BOLT11)",
        )
    } else {
        return QuoteResponse::NoRoute {
            reason: "BIP-353 record carries no on-chain, BOLT12, or BOLT11 instruction".into(),
        };
    };

    let dnssec_note = if resolution.dnssec_validated {
        "DNSSEC validated"
    } else {
        "DNSSEC NOT validated (preview)"
    };

    QuoteResponse::Ok {
        recipient,
        selected_method,
        fee_sats: None,
        eta: None,
        reason: format!(
            "Resolved via BIP-353 ({dnssec_note}); {rail} preview for {amount_sats} sats. \
             Mainnet preview only — no funds moved."
        ),
        // The authoritative payable is the BIP-353 bitcoin: URI itself.
        qr: resolution.bitcoin_uri.clone(),
        execution: None,
        wallet_hint: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use satspath_core::bip353::{
        resolve_bip353_with, Bip353Name, DnsTxtRecord, DnssecPolicy, MockDnsTxtResolver,
    };

    /// BIP-353 URI carrying the BOLT12 specification's test-vector offer.
    const BIP353_OFFER_URI: &str = "bitcoin:?lno=lno1pgx9getnwss8vetrw3hhyuckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg";

    /// A BIP-353 resolution of `uri` through a mock DNS backend.
    fn resolution(uri: &str, dnssec: bool) -> Bip353Resolution {
        let mut resolver = MockDnsTxtResolver::new();
        let name = Bip353Name {
            user: "rodrigo".into(),
            domain: "satspath.dev".into(),
            display: "₿rodrigo@satspath.dev".into(),
            dns_name: "rodrigo.user._bitcoin-payment.satspath.dev".into(),
        };
        resolver.insert(
            &name.dns_name,
            DnsTxtRecord {
                strings: vec![uri.to_string()],
                dnssec_validated: dnssec,
                ttl_seconds: Some(1800),
            },
        );
        let policy = if dnssec {
            DnssecPolicy::Strict
        } else {
            DnssecPolicy::DevInsecure
        };
        // Block on the async resolver in a small runtime.
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(resolve_bip353_with(
                &resolver,
                "rodrigo@satspath.dev",
                policy,
                1_700_000_000,
            ))
            .unwrap()
    }

    #[test]
    fn bip353_bolt12_maps_to_ok_quote() {
        let res = resolution(BIP353_OFFER_URI, true);
        let quote = quote_from_bip353_resolution(&res, 1000);
        match quote {
            QuoteResponse::Ok {
                recipient,
                selected_method,
                qr,
                ..
            } => {
                assert_eq!(recipient.alias, "₿rodrigo@satspath.dev");
                assert!(recipient.verified); // DNSSEC validated
                assert!(recipient.fingerprint.is_none());
                assert!(matches!(
                    selected_method,
                    PaymentMethod::Lightning {
                        bolt12: Some(_),
                        ..
                    }
                ));
                assert_eq!(qr, BIP353_OFFER_URI);
            }
            other => panic!("expected Ok, got {}", other.status()),
        }
    }

    #[test]
    fn bip353_onchain_maps_to_onchain_method() {
        let res = resolution(
            "bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq?amount=0.00001000",
            true,
        );
        let quote = quote_from_bip353_resolution(&res, 1000);
        match quote {
            QuoteResponse::Ok {
                selected_method,
                qr,
                ..
            } => {
                assert!(matches!(selected_method, PaymentMethod::Onchain { .. }));
                assert_eq!(
                    qr,
                    "bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq?amount=0.00001000"
                );
            }
            other => panic!("expected Ok, got {}", other.status()),
        }
    }

    #[test]
    fn bip353_unvalidated_dnssec_marks_recipient_unverified() {
        let res = resolution(BIP353_OFFER_URI, false);
        let quote = quote_from_bip353_resolution(&res, 1000);
        if let QuoteResponse::Ok { recipient, .. } = quote {
            assert!(!recipient.verified);
        } else {
            panic!("expected Ok");
        }
    }
}
