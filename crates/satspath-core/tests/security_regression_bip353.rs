//! Security regression — Finding #1: the BIP-353 resolver must not fabricate a
//! self-signature, and its authenticity must rest on a DNSSEC result that is
//! actually checked.
//!
//! Driven deterministically through an in-memory DNS backend (no live DNS):
//! * a TXT record that was not DNSSEC-validated must fail closed;
//! * a BIP-353 result must never be surfaced as a verified cryptographic
//!   identity signature.

use std::sync::Arc;

use satspath_core::bip353::{DnsTxtRecord, MockDnsTxtResolver};
use satspath_core::resolver::{ChainResolver, ProfileResolver};
use satspath_core::resolvers::bip353::Bip353Resolver;
use satspath_core::SatsPathError;

const NAME: &str = "₿alice@victim-domain.example";
const FQDN: &str = "alice.user._bitcoin-payment.victim-domain.example";
const ATTACKER_URI: &str = "bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

/// A BIP-353 resolver whose DNS backend serves `record` for the test name.
fn resolver_with(record: DnsTxtRecord) -> Bip353Resolver {
    let mut dns = MockDnsTxtResolver::new();
    dns.insert(FQDN, record);
    Bip353Resolver::with_dns_resolver(Arc::new(dns))
}

/// A single-string TXT record with the given DNSSEC status.
fn txt(uri: &str, dnssec_validated: bool) -> DnsTxtRecord {
    DnsTxtRecord {
        strings: vec![uri.to_string()],
        dnssec_validated,
        ttl_seconds: Some(300),
    }
}

/// A TXT record without DNSSEC validation must be rejected.
#[tokio::test]
async fn bip353_unauthenticated_record_must_fail_closed() {
    // Spoofed / cache-poisoned answer: no DNSSEC validation.
    let resolver = resolver_with(txt(ATTACKER_URI, false));

    assert!(
        matches!(
            resolver.resolve_instruction(NAME).await,
            Err(SatsPathError::DnssecUnavailable)
        ),
        "an unauthenticated TXT record must be rejected"
    );
    assert!(
        resolver.resolve_alias(NAME).await.is_err(),
        "an unauthenticated TXT record must not produce a profile"
    );
}

/// A BIP-353 name never yields a signed SatsPath profile, directly or via the chain.
#[tokio::test]
async fn bip353_profile_must_not_claim_signed_identity() {
    // Even a properly DNSSEC-validated record carries no SatsPath identity
    // key, so asking for a signed profile must be refused outright, never
    // answered with a profile (verified or not).
    let resolver = resolver_with(txt(ATTACKER_URI, true));
    let direct = resolver.resolve_alias(NAME).await;
    assert!(
        matches!(direct, Err(SatsPathError::Bip353(_))),
        "BIP-353 resolve_alias must refuse with Bip353, got {:?}",
        direct.map(|p| p.profile.identity_pubkey)
    );

    // Same through the chain the CLI uses.
    let chain = ChainResolver::new().push(resolver_with(txt(ATTACKER_URI, true)));
    let chained = chain.resolve_alias(NAME).await;
    assert!(
        matches!(chained, Err(SatsPathError::Bip353(_))),
        "ChainResolver must surface the Bip353 refusal, got {:?}",
        chained.map(|p| p.profile.identity_pubkey)
    );

    // The honest result is the DNSSEC-validated instruction itself.
    let instruction = resolver.resolve_instruction(NAME).await.unwrap();
    assert!(instruction.dnssec_validated);
    assert_eq!(instruction.bitcoin_uri, ATTACKER_URI);
}

/// More than one payment record for a name is ambiguous and rejected.
#[tokio::test]
async fn bip353_ambiguous_records_are_rejected() {
    let mut dns = MockDnsTxtResolver::new();
    dns.insert(FQDN, txt(ATTACKER_URI, true));
    dns.insert(
        FQDN,
        txt("bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", true),
    );
    let resolver = Bip353Resolver::with_dns_resolver(Arc::new(dns));
    assert!(resolver.resolve_instruction(NAME).await.is_err());
}

/// A TXT record split across strings is joined back into one URI.
#[tokio::test]
async fn bip353_multi_string_record_is_reconstructed() {
    // TXT RDATA longer than 255 bytes arrives split into character-strings.
    let (head, tail) = ATTACKER_URI.split_at(20);
    let record = DnsTxtRecord {
        strings: vec![head.into(), tail.into()],
        dnssec_validated: true,
        ttl_seconds: None,
    };
    let instruction = resolver_with(record)
        .resolve_instruction(NAME)
        .await
        .unwrap();
    assert_eq!(instruction.bitcoin_uri, ATTACKER_URI);
}
