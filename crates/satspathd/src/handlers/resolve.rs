//! Resolve and DNS handlers.

use anyhow::Result;
use satspath_core::{
    bip321::parse_bip321,
    bip321_handoff::validate_payment_handoff,
    bip353::{resolve_bip353_with, DnsTxtResolver, DnssecPolicy, DohTxtResolver},
    crypto::verify_signed_profile,
    resolver::ChainResolver,
    resolvers::bip353::HickoryDnssecTxtResolver,
    resolvers::{bip353::Bip353Resolver, http::HttpResolver, nostr::NostrResolver},
    BitcoinNetwork, CheckpointStore, ResolvedTransparentProfile, ResolverSource, SatsPathError,
    TransactionalTransparencyStore, VerificationStates,
};

use crate::config::AppState;
use crate::handlers::transparency::transparency_log;
use crate::types::{now, DnsResolveRequest, DnsResolveResponse};

pub(crate) fn resolver_chain(home: &std::path::Path) -> ChainResolver {
    use satspath_core::registry::Registry;
    let mut chain = ChainResolver::new();
    if let Ok(registry) = Registry::open(home) {
        chain = chain.push(registry);
    }
    chain
        .push(Bip353Resolver::new())
        .push(HttpResolver::new())
        .push(NostrResolver::new())
}

pub(crate) fn resolve_profile(state: &AppState, alias: &str) -> Result<ResolvedTransparentProfile> {
    let store = TransactionalTransparencyStore::open(&state.home)?;
    let signed = store
        .profile(alias)?
        .ok_or_else(|| SatsPathError::AliasNotFound(alias.into()))?;
    let profile_signature_verified = verify_signed_profile(&signed)?;
    if !profile_signature_verified {
        anyhow::bail!("stored profile signature is invalid");
    }
    let log = transparency_log(state)?;
    let identifier_hash = satspath_core::privacy::identifier_hash(alias);
    let history: Vec<_> = log.history(&identifier_hash).into_iter().cloned().collect();
    satspath_core::transparency::verify_identifier_history(&history)?;
    let latest_event = history
        .last()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("profile has no transparency history"))?;
    if !satspath_core::transparency::verify_event_profile(&latest_event, &signed)? {
        anyhow::bail!("profile does not match its latest transparency event");
    }
    let event_hash = latest_event.event_hash()?;
    let inclusion_proof = log.inclusion(&event_hash, None)?;
    let checkpoint = log
        .checkpoints()
        .last()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("transparency checkpoint unavailable"))?;
    satspath_core::transparency::verify_checkpoint_inclusion(
        &event_hash,
        &inclusion_proof,
        &checkpoint,
    )?;
    let transparency_inclusion_verified = true;
    let pins = CheckpointStore::new(&state.home).load()?;
    let pinned = pins.iter().find(|p| p.log_id == checkpoint.log_id);
    let consistency_proof = pinned
        .filter(|p| p.tree_size < checkpoint.log_size)
        .map(|p| log.consistency(p.tree_size, checkpoint.log_size))
        .transpose()?;
    if let Some(pin) = pinned {
        satspath_core::transparency::verify_checkpoint_transition(
            pin,
            &checkpoint,
            consistency_proof.as_ref(),
        )?;
    }
    CheckpointStore::new(&state.home).pin(&checkpoint)?;
    let payment_method_states = satspath_core::verify_payment_method_states(&signed.profile, now());
    let payment_methods_verified = !payment_method_states.is_empty()
        && payment_method_states.iter().all(|state| state.verified);
    let identifier_attestation = latest_event
        .identifier_attestation_hash
        .as_deref()
        .map(|hash| store.identifier_attestation(hash))
        .transpose()?
        .flatten();
    let trusted_verifiers: Vec<satspath_core::TrustedVerifier> =
        std::env::var("SATSPATH_TRUSTED_VERIFIERS_JSON")
            .ok()
            .map(|json| serde_json::from_str(&json))
            .transpose()
            .map_err(|e| anyhow::anyhow!("invalid SATSPATH_TRUSTED_VERIFIERS_JSON: {e}"))?
            .unwrap_or_default();
    let identifier_verified = identifier_attestation
        .as_ref()
        .map(|attestation| {
            satspath_core::transparency::verify_attestation_binding(
                attestation,
                &latest_event,
                &trusted_verifiers,
                now(),
            )
        })
        .transpose()?
        .unwrap_or(false);
    Ok(ResolvedTransparentProfile {
        signed_profile: signed,
        latest_event,
        inclusion_proof,
        checkpoint,
        consistency_proof,
        identifier_attestation,
        resolver_source: ResolverSource::LocalRegistry,
        verification: VerificationStates {
            profile_signature_verified,
            identifier_verified,
            key_continuity_verified: true,
            transparency_inclusion_verified,
            checkpoint_binding_verified: true,
            checkpoint_consistency_verified: true,
            operator_continuity_verified: true,
            payment_methods_verified,
            payment_method_states,
        },
    })
}

pub(crate) fn resolve_v2_envelope(
    state: &AppState,
    alias: &str,
) -> Result<satspath_core::transparency::ResolutionEnvelope> {
    use crate::handlers::transparency::namespace_descriptor;
    let store = TransactionalTransparencyStore::open(&state.home)?;
    let signed = store
        .profile(alias)?
        .ok_or_else(|| SatsPathError::AliasNotFound(alias.into()))?;
    if !verify_signed_profile(&signed)? {
        anyhow::bail!("stored profile signature is invalid");
    }
    let log = transparency_log(state)?;
    let identifier_hash = satspath_core::privacy::identifier_hash(alias);
    let history: Vec<_> = log.history(&identifier_hash).into_iter().cloned().collect();
    satspath_core::transparency::verify_identifier_history(&history)?;
    let latest_event = history
        .last()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("profile has no transparency history"))?;
    if !satspath_core::transparency::verify_event_profile(&latest_event, &signed)? {
        anyhow::bail!("profile does not match its latest transparency event");
    }
    let event_hash = latest_event.event_hash()?;
    let inclusion_proof = log.inclusion(&event_hash, None)?;
    let checkpoint = log
        .checkpoints()
        .last()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("transparency checkpoint unavailable"))?;
    satspath_core::transparency::verify_checkpoint_inclusion(
        &event_hash,
        &inclusion_proof,
        &checkpoint,
    )?;

    let current_state_proof = log.prove_state(&identifier_hash).ok();
    if let Some(state_proof) = &current_state_proof {
        if checkpoint.map_root.is_some() {
            satspath_core::transparency::verify_checkpoint_state_binding(state_proof, &checkpoint)?;
        }
    }

    let descriptor = namespace_descriptor(state)?;
    let served_at = chrono::Utc::now().timestamp();

    Ok(satspath_core::transparency::ResolutionEnvelope {
        version: 2,
        identifier: alias.to_string(),
        namespace_descriptor: descriptor,
        signed_profile: signed,
        name_events: history,
        inclusion_proof,
        checkpoint,
        consistency_proof: None,
        current_state_proof,
        witness_cosignatures: vec![],
        served_at,
    })
}

/// /v1/dns/resolve: resolve a BIP-353 name and validate its payment instruction.
pub(crate) async fn dns_resolve_response(body: DnsResolveRequest) -> DnsResolveResponse {
    let policy = if body.allow_insecure_dns_for_dev {
        DnssecPolicy::DevInsecure
    } else {
        DnssecPolicy::Strict
    };
    // Strict mode needs local DNSSEC validation; the DoH backend cannot
    // validate and is only used in the insecure dev mode.
    let resolver: Box<dyn DnsTxtResolver + Send + Sync> = if body.allow_insecure_dns_for_dev {
        Box::new(DohTxtResolver::new())
    } else {
        Box::new(HickoryDnssecTxtResolver::new())
    };
    match resolve_bip353_with(resolver.as_ref(), &body.name, policy, now()).await {
        Ok(resolution) => match parse_bip321(&resolution.bitcoin_uri).and_then(|parsed| {
            validate_payment_handoff(&parsed, BitcoinNetwork::Mainnet, None).map(|_| parsed)
        }) {
            Ok(parsed) => DnsResolveResponse::Ok { resolution, parsed },
            Err(e) => DnsResolveResponse::Error {
                name: body.name,
                error: e.to_string(),
                strict_mode: policy == DnssecPolicy::Strict,
            },
        },
        Err(e) => DnsResolveResponse::Error {
            name: body.name,
            error: e.to_string(),
            strict_mode: policy == DnssecPolicy::Strict,
        },
    }
}
