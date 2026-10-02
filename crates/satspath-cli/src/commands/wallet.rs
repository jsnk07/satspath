//! `satspath wallet` — a safe **receiver-profile** wallet.
//!
//! This wallet manages a SatsPath identity and **public receive pointers**
//! (Lightning Address, on-chain address, Ark server/pubkey), signs a payment
//! profile, and produces preview output. It is NOT a spending wallet:
//!
//! - It never moves funds, signs Bitcoin transactions, or broadcasts.
//! - It never asks for, derives, or stores seeds, xprv/tprv, descriptors with
//!   private data, macaroons, certs, API keys, passwords, or spending keys.
//!
//! The only secret it touches is the SatsPath **identity signing key** (used to
//! sign public profiles), which lives in the existing gitignored, owner-only
//! keystore — never in `wallet.json`.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use satspath_core::ark::validate_ark_server_url;
use satspath_core::crypto::{
    fingerprint_pubkey, generate_identity_keypair, generate_nonce, sign_profile,
    verify_signed_profile,
};
use satspath_core::privacy::{mask_address, mask_identifier, mask_pubkey};
use satspath_core::registry::Registry;
use satspath_core::validation::{
    assert_no_private_material, validate_bitcoin_address, validate_compressed_pubkey,
    validate_lightning_address,
};
use satspath_core::{BitcoinNetwork, PaymentMethod, PaymentProfile};

use super::{keystore, satspath_dir};

/// The improved guidance shown when a local profile fails signature verification.
const SIGNATURE_INVALID_HELP: &str =
    "Signature invalid. The profile may be tampered or stale from an older schema. \
     Re-run `satspath wallet add-methods` or recreate the local profile.";

const WALLET_FILE: &str = "wallet.json";

/// Local wallet state — **public data + the identity public key only**.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct WalletState {
    #[serde(skip_serializing_if = "Option::is_none")]
    alias: Option<String>,
    /// Identity *public* key (hex). The signing key stays in the keystore.
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lightning_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bolt12_offer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    onchain_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ark_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ark_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<i64>,
}

// ─── storage helpers ─────────────────────────────────────────────────────────

fn wallet_path() -> std::path::PathBuf {
    satspath_dir().join(WALLET_FILE)
}

fn ensure_dir() -> Result<()> {
    std::fs::create_dir_all(satspath_dir())?;
    Ok(())
}

fn open_registry() -> Result<Registry> {
    ensure_dir()?;
    Ok(Registry::open(&satspath_dir())?)
}

fn load_wallet() -> Result<WalletState> {
    let path = wallet_path();
    if !path.exists() {
        return Ok(WalletState::default());
    }
    let raw = std::fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&raw)?)
}

fn save_wallet(state: &WalletState) -> Result<()> {
    ensure_dir()?;
    let json = serde_json::to_string_pretty(state)?;
    // Defence in depth: never let private material reach wallet.json.
    assert_no_private_material(&json).map_err(|e| anyhow::anyhow!("{e}"))?;
    std::fs::write(wallet_path(), json)?;
    Ok(())
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

// ─── profile building / signing ──────────────────────────────────────────────

fn build_methods(state: &WalletState) -> Vec<PaymentMethod> {
    let mut methods = Vec::new();
    if let Some(addr) = &state.lightning_address {
        methods.push(PaymentMethod::Lightning {
            label: "Lightning Address".into(),
            lightning_address: Some(addr.clone()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        });
    }
    if let Some(offer) = &state.bolt12_offer {
        methods.push(PaymentMethod::Bolt12(satspath_core::profile::Bolt12Offer {
            label: "BOLT12 Offer".into(),
            offer: offer.clone(),
            network: BitcoinNetwork::Mainnet,
            minimum_amount_sats: None,
            expires_at: None,
            issuer_pubkey: state.identity_pubkey.clone().unwrap_or_default(),
        }));
    }
    if let Some(addr) = &state.onchain_address {
        methods.push(PaymentMethod::Onchain {
            label: "Bitcoin (mainnet)".into(),
            network: BitcoinNetwork::Mainnet,
            address: Some(addr.clone()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        });
    }
    if let (Some(server), Some(pubkey)) = (&state.ark_server, &state.ark_pubkey) {
        methods.push(PaymentMethod::Ark {
            label: "Ark".into(),
            server: server.clone(),
            pubkey: pubkey.clone(),
            vtxo_pointer: None,
            opaque_uri: None,
            proof: None,
            expires_at: None,
        });
    }
    methods
}

/// A privacy-preserving receive descriptor for the local UI: a **masked** alias,
/// the chosen rail, and a public receive payload. No raw identifier or identity
/// pubkey is exposed; nothing is fetched from the network.
#[derive(Debug, Clone, Serialize)]
pub struct ReceiveQr {
    /// Masked alias, e.g. `r***@gmail.com`.
    pub alias: String,
    /// The selected rail name (Lightning / Onchain / Ark).
    pub rail: String,
    /// The public receive payload to encode in the QR.
    pub payload: String,
}

/// Compute the wallet owner's preferred receive payload, entirely locally.
///
/// Route selection prefers Lightning (instant) → on-chain → Ark. With no amount
/// it returns a reusable receive pointer. No mempool/LNURL/DNS calls are made, so
/// the operation stays fully private.
pub fn local_receive_qr(amount_sats: Option<u64>) -> Result<ReceiveQr> {
    let state = load_wallet()?;
    let alias = state.alias.clone().ok_or_else(|| {
        anyhow::anyhow!("no wallet profile yet — run `satspath wallet add-methods`")
    })?;
    let methods = build_methods(&state);
    let method = methods
        .iter()
        .find(|m| matches!(m, PaymentMethod::Lightning { .. }))
        .or_else(|| {
            methods
                .iter()
                .find(|m| matches!(m, PaymentMethod::Onchain { .. }))
        })
        .or_else(|| {
            methods
                .iter()
                .find(|m| matches!(m, PaymentMethod::Ark { .. }))
        })
        .ok_or_else(|| anyhow::anyhow!("no receive methods — run `satspath wallet add-methods`"))?;

    Ok(ReceiveQr {
        alias: mask_identifier(&alias),
        rail: method.method_name().to_string(),
        payload: receive_payload_for(method, amount_sats)?,
    })
}

fn receive_payload_for(method: &PaymentMethod, amount_sats: Option<u64>) -> Result<String> {
    let payload = match method {
        PaymentMethod::Lightning {
            lightning_address: Some(addr),
            ..
        } => addr.clone(),
        PaymentMethod::Lightning {
            lnurl: Some(url), ..
        } => url.clone(),
        PaymentMethod::Bolt12(offer_data) => {
            // Provide BIP-321 bitcoin:?lno=... handoff or raw offer based on what makes sense
            // For now just raw offer since most wallets parse raw bolt12 directly.
            offer_data.offer.clone()
        }
        PaymentMethod::Onchain {
            address,
            silent_payment_pubkey,
            ..
        } => {
            let target = silent_payment_pubkey
                .clone()
                .unwrap_or_else(|| address.clone().unwrap_or_default());
            match amount_sats {
                Some(sats) => format!("bitcoin:{target}?amount={}", sats_to_btc(sats)),
                None => format!("bitcoin:{target}"),
            }
        }
        PaymentMethod::Ark { server, pubkey, .. } => match amount_sats {
            Some(sats) => format!(
                "satspath:ark?server={}&pubkey={}&amount={}",
                urlencoding::encode(server),
                urlencoding::encode(pubkey),
                sats
            ),
            None => format!(
                "satspath:ark?server={}&pubkey={}",
                urlencoding::encode(server),
                urlencoding::encode(pubkey)
            ),
        },
        _ => anyhow::bail!("selected method has no receive pointer"),
    };
    assert_no_private_material(&payload).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(payload)
}

fn sats_to_btc(sats: u64) -> String {
    format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000)
}

/// Build, sign, and persist the wallet's payment profile to the local registry.
fn sign_and_store(state: &WalletState) -> Result<String> {
    let alias = state.alias.as_ref().ok_or_else(|| {
        anyhow::anyhow!("wallet has no alias yet — run `satspath wallet add-methods <alias> ...`")
    })?;
    let pubkey = state.identity_pubkey.as_ref().ok_or_else(|| {
        anyhow::anyhow!("wallet not initialized — run `satspath wallet init` first")
    })?;

    let methods = build_methods(state);
    if methods.is_empty() {
        anyhow::bail!("no receive methods set — add at least a Lightning, on-chain, or Ark method");
    }

    let mut registry = open_registry()?;
    let current_sequence = registry
        .resolve_alias(alias)
        .map(|signed| signed.profile.sequence.unwrap_or(0))
        .unwrap_or(0);

    let secret = keystore::load_identity_key(&satspath_dir(), pubkey)?;
    let t = now();
    let profile = PaymentProfile {
        sequence: Some(current_sequence + 1),
        alias: alias.clone(),
        identity_pubkey: pubkey.clone(),
        methods,
        updated_at: t,
        expires_at: Some(t + 30 * 24 * 3600), // default 30-day expiry per spec §28
        preferences: vec!["lightning".into(), "ark".into(), "onchain".into()],
        nonce: Some(generate_nonce()),
        rotation: None,
        method_verifications: Vec::new(),
        hybrid_pubkey: None,
        pqc_required: false,
        revoked: false,
    };
    let signed = sign_profile(profile, &secret)?;
    let fp = fingerprint_pubkey(pubkey)?;
    registry
        .update_profile(signed)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(fp)
}

// ─── commands ────────────────────────────────────────────────────────────────

/// `satspath wallet init` — create/load the identity key.
pub fn cmd_wallet_init() -> Result<()> {
    ensure_dir()?;
    let mut state = load_wallet()?;

    if let Some(pubkey) = &state.identity_pubkey {
        keystore::load_identity_key(&satspath_dir(), pubkey)?;
        println!("Wallet already initialized.");
        println!("Identity fingerprint: {}", fingerprint_pubkey(pubkey)?);
        print_receiver_warning();
        return Ok(());
    }

    let kp = generate_identity_keypair();
    let pubkey = hex::encode(kp.public_key.serialize());
    keystore::save_identity_key(&satspath_dir(), &kp.secret_key)?;

    state.identity_pubkey = Some(pubkey.clone());
    state.created_at.get_or_insert(now());
    state.updated_at = Some(now());
    save_wallet(&state)?;

    println!("Initialized SatsPath receiver wallet.");
    println!("Identity fingerprint: {}", fingerprint_pubkey(&pubkey)?);
    println!(
        "Identity key stored in {} (gitignored, owner-only).",
        satspath_dir().join("identity").display()
    );
    print_receiver_warning();
    Ok(())
}

fn print_receiver_warning() {
    println!();
    println!("This is a receiver-profile wallet. It does not control or move funds.");
}

/// `satspath wallet rotate` — generate a new identity key and attach a KeyRotation proof.
pub fn cmd_wallet_rotate() -> Result<()> {
    let mut state = load_wallet()?;
    let old_pubkey_hex = state.identity_pubkey.clone().ok_or_else(|| {
        anyhow::anyhow!("wallet not initialized — run `satspath wallet init` first")
    })?;

    let old_secret = keystore::load_identity_key(&satspath_dir(), &old_pubkey_hex)?;

    let new_kp = generate_identity_keypair();
    let new_pubkey_hex = hex::encode(new_kp.public_key.serialize());
    keystore::save_identity_key(&satspath_dir(), &new_kp.secret_key)?;

    state.identity_pubkey = Some(new_pubkey_hex.clone());
    state.updated_at = Some(now());

    let alias = state
        .alias
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no alias"))?;
    let methods = build_methods(&state);
    if methods.is_empty() {
        anyhow::bail!("no receive methods set");
    }

    let mut registry = open_registry()?;
    let current_sequence = registry
        .resolve_alias(alias)
        .map(|signed| signed.profile.sequence.unwrap_or(0))
        .unwrap_or(0);

    let t = now();
    let rotation = satspath_core::rotation::KeyRotation::create(
        satspath_core::privacy::identifier_hash(alias),
        old_pubkey_hex.clone(),
        &old_secret,
        new_pubkey_hex.clone(),
        &new_kp.secret_key,
        format!("legacy-profile-sequence-{current_sequence}"),
        current_sequence + 1,
    )?;

    let profile = PaymentProfile {
        sequence: Some(current_sequence + 1),
        alias: alias.clone(),
        identity_pubkey: new_pubkey_hex.clone(),
        methods,
        updated_at: t,
        expires_at: Some(t + 30 * 24 * 3600),
        preferences: vec!["lightning".into(), "ark".into(), "onchain".into()],
        nonce: Some(generate_nonce()),
        rotation: Some(rotation),
        method_verifications: Vec::new(),
        hybrid_pubkey: None,
        pqc_required: false,
        revoked: false,
    };

    let signed = sign_profile(profile, &new_kp.secret_key)?;
    registry.update_profile(signed)?;
    save_wallet(&state)?;

    println!("Identity key rotated successfully.");
    println!(
        "New identity fingerprint: {}",
        fingerprint_pubkey(&new_pubkey_hex)?
    );

    Ok(())
}

/// `satspath wallet add-methods <alias> [--lightning-address] [--onchain-address] [--ark-server --ark-pubkey]`
pub fn cmd_wallet_add_methods(
    alias: &str,
    lightning_address: Option<&str>,
    onchain_address: Option<&str>,
    ark_server: Option<&str>,
    ark_pubkey: Option<&str>,
) -> Result<()> {
    let mut state = load_wallet()?;
    if state.identity_pubkey.is_none() {
        anyhow::bail!("wallet not initialized — run `satspath wallet init` first");
    }

    if lightning_address.is_none()
        && onchain_address.is_none()
        && (ark_server.is_none() || ark_pubkey.is_none())
    {
        anyhow::bail!(
            "provide at least one receive method (--lightning-address / --onchain-address / --ark-server + --ark-pubkey)"
        );
    }

    state.alias = Some(alias.to_string());
    if let Some(la) = lightning_address {
        validate_lightning_address(la)
            .map_err(|e| anyhow::anyhow!("invalid Lightning Address: {e}"))?;
        state.lightning_address = Some(la.to_string());
    }
    if let Some(addr) = onchain_address {
        validate_bitcoin_address(addr, BitcoinNetwork::Mainnet)
            .map_err(|e| anyhow::anyhow!("invalid Bitcoin address: {e}"))?;
        state.onchain_address = Some(addr.to_string());
    }
    match (ark_server, ark_pubkey) {
        (Some(server), Some(pubkey)) => {
            validate_ark_server_url(server)
                .map_err(|e| anyhow::anyhow!("invalid Ark server: {e}"))?;
            validate_compressed_pubkey(pubkey)
                .map_err(|e| anyhow::anyhow!("invalid Ark pubkey: {e}"))?;
            state.ark_server = Some(server.to_string());
            state.ark_pubkey = Some(pubkey.to_string());
        }
        (None, None) => {}
        _ => anyhow::bail!("--ark-server and --ark-pubkey must be provided together"),
    }
    state.updated_at = Some(now());

    let fp = sign_and_store(&state)?;
    save_wallet(&state)?;

    println!("Signed and saved profile for {}.", mask_identifier(alias));
    println!("Identity fingerprint: {fp}");
    println!("Receive methods:");
    for m in build_methods(&state) {
        println!("  - {}", m.method_name());
    }
    Ok(())
}

/// `satspath wallet add-lightning <addr>` — incremental update.
pub fn cmd_wallet_add_lightning(addr: &str) -> Result<()> {
    update_one(|state| {
        validate_lightning_address(addr)
            .map_err(|e| anyhow::anyhow!("invalid Lightning Address: {e}"))?;
        state.lightning_address = Some(addr.to_string());
        Ok(())
    })
}

/// `satspath wallet add-bolt12 <offer>` — incremental update.
pub fn cmd_wallet_add_bolt12(offer: &str) -> Result<()> {
    update_one(|state| {
        satspath_core::validation::validate_bolt12_offer(offer)
            .map_err(|e| anyhow::anyhow!("invalid BOLT12 offer: {e}"))?;
        state.bolt12_offer = Some(offer.to_string());
        Ok(())
    })
}

/// `satspath wallet add-onchain <addr>` — incremental update.
pub fn cmd_wallet_add_onchain(addr: &str) -> Result<()> {
    update_one(|state| {
        validate_bitcoin_address(addr, BitcoinNetwork::Mainnet)
            .map_err(|e| anyhow::anyhow!("invalid Bitcoin address: {e}"))?;
        state.onchain_address = Some(addr.to_string());
        Ok(())
    })
}

/// `satspath wallet add-ark --server <url> --pubkey <hex>` — incremental update.
pub fn cmd_wallet_add_ark(server: &str, pubkey: &str) -> Result<()> {
    update_one(|state| {
        validate_ark_server_url(server).map_err(|e| anyhow::anyhow!("invalid Ark server: {e}"))?;
        validate_compressed_pubkey(pubkey)
            .map_err(|e| anyhow::anyhow!("invalid Ark pubkey: {e}"))?;
        state.ark_server = Some(server.to_string());
        state.ark_pubkey = Some(pubkey.to_string());
        Ok(())
    })
}

fn update_one<F: FnOnce(&mut WalletState) -> Result<()>>(f: F) -> Result<()> {
    let mut state = load_wallet()?;
    if state.identity_pubkey.is_none() {
        anyhow::bail!("wallet not initialized — run `satspath wallet init` first");
    }
    if state.alias.is_none() {
        anyhow::bail!("set your alias first: `satspath wallet add-methods <alias> ...`");
    }
    f(&mut state)?;
    state.updated_at = Some(now());
    let fp = sign_and_store(&state)?;
    save_wallet(&state)?;
    println!("Updated and re-signed profile (fingerprint {fp}).");
    Ok(())
}

/// `satspath wallet show [--debug]`
pub fn cmd_wallet_show(debug: bool) -> Result<()> {
    let state = load_wallet()?;
    let Some(pubkey) = &state.identity_pubkey else {
        anyhow::bail!("wallet not initialized — run `satspath wallet init` first");
    };

    let mask_id = |s: &str| {
        if debug {
            s.to_string()
        } else {
            mask_identifier(s)
        }
    };
    let mask_addr = |s: &str| {
        if debug {
            s.to_string()
        } else {
            mask_address(s)
        }
    };
    let mask_pk = |s: &str| if debug { s.to_string() } else { mask_pubkey(s) };

    println!(
        "Alias: {}",
        state
            .alias
            .as_deref()
            .map(mask_id)
            .unwrap_or_else(|| "(not set)".into())
    );
    println!("Identity fingerprint: {}", fingerprint_pubkey(pubkey)?);
    if let Some(la) = &state.lightning_address {
        println!("Lightning: {}", mask_id(la));
    }
    if let Some(addr) = &state.onchain_address {
        println!("On-chain: {}", mask_addr(addr));
    }
    if let Some(server) = &state.ark_server {
        println!("Ark server: {}", mask_addr(server));
    }
    if let Some(pk) = &state.ark_pubkey {
        println!("Ark pubkey: {}", mask_pk(pk));
    }

    // Verify the stored signed profile.
    if let Some(alias) = &state.alias {
        match open_registry()?.resolve_alias(alias) {
            Ok(signed) => {
                if verify_signed_profile(signed)? {
                    println!("Profile signature: valid");
                } else {
                    println!("Profile signature: INVALID");
                    println!("{SIGNATURE_INVALID_HELP}");
                }
            }
            Err(_) => println!("Profile signature: (no signed profile saved yet)"),
        }
    }
    Ok(())
}

/// `satspath wallet publish [alias]` — export the signed profile for P2P sharing.
pub fn cmd_wallet_publish(alias: Option<&str>) -> Result<()> {
    let state = load_wallet()?;
    let alias = alias
        .map(str::to_string)
        .or_else(|| state.alias.clone())
        .ok_or_else(|| {
            anyhow::anyhow!("no alias — pass one or run `satspath wallet add-methods` first")
        })?;

    let registry = open_registry()?;
    let signed = registry
        .resolve_alias(&alias)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if !verify_signed_profile(signed)? {
        anyhow::bail!("{SIGNATURE_INVALID_HELP}");
    }

    let out_path = satspath_dir().join(format!("{}-profile.json", sanitize(&alias)));
    std::fs::write(&out_path, serde_json::to_string_pretty(signed)?)?;

    println!("Exported signed profile to {}", out_path.display());
    println!();
    println!("Publish it peer-to-peer with the Holepunch SDK:");
    println!("  cd sdk/satspath-p2p && npm install");
    println!("  node examples/publish.mjs {alias} {}", out_path.display());
    println!();
    println!("Another device can then resolve it:");
    println!("  node examples/resolve.mjs {alias}");
    Ok(())
}

fn sanitize(alias: &str) -> String {
    alias
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// `satspath wallet receive <alias> <amount_sats> --json` — preview-only output.
pub async fn cmd_wallet_receive(alias: &str, amount_sats: u64, json: bool) -> Result<()> {
    let preview = build_receive_preview(alias, amount_sats).await;
    if json {
        println!("{}", serde_json::to_string_pretty(&preview)?);
    } else {
        println!("Status:  {}", preview.status);
        println!("Mode:    {}", preview.mode);
        println!("Alias:   {}", mask_identifier(&preview.alias));
        if let Some(rail) = &preview.selected_rail {
            println!("Rail:    {rail}");
        }
        if let Some(reason) = &preview.reason {
            println!("Reason:  {reason}");
        }
        for w in &preview.warnings {
            println!("  ⚠  {w}");
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct WalletReceivePreview {
    status: String,
    mode: String,
    alias: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_rail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    qr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    warnings: Vec<String>,
}

async fn build_receive_preview(alias: &str, amount_sats: u64) -> WalletReceivePreview {
    use satspath_router::QuoteResponse;

    let warnings = vec![
        "No funds moved by SatsPath".to_string(),
        "Payment execution happens in external wallet".to_string(),
    ];
    let base = |status: &str| WalletReceivePreview {
        status: status.to_string(),
        mode: "preview_only".to_string(),
        alias: alias.to_string(),
        fingerprint: None,
        selected_rail: None,
        qr: None,
        reason: None,
        warnings: warnings.clone(),
    };

    match satspath_router::quote(alias, amount_sats).await {
        QuoteResponse::Ok {
            recipient,
            selected_method,
            qr,
            reason,
            ..
        } => WalletReceivePreview {
            fingerprint: recipient.fingerprint,
            selected_rail: Some(selected_method.method_name().to_string()),
            qr: Some(qr),
            reason: Some(reason),
            ..base("ok")
        },
        QuoteResponse::NoRoute { reason } => WalletReceivePreview {
            reason: Some(reason),
            ..base("no_route")
        },
        QuoteResponse::InvalidSignature { recipient } => WalletReceivePreview {
            fingerprint: recipient.fingerprint,
            reason: Some(SIGNATURE_INVALID_HELP.to_string()),
            ..base("invalid_signature")
        },
        QuoteResponse::NotRegistered { .. } => WalletReceivePreview {
            reason: Some("alias is not registered in the local wallet/registry".to_string()),
            ..base("not_registered")
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_state_serializes_without_private_fields() {
        let state = WalletState {
            alias: Some("rodrigo@satspath.dev".into()),
            identity_pubkey: Some("02abc".into()),
            lightning_address: Some("rodrigo@getalby.com".into()),
            onchain_address: Some("bc1qexample".into()),
            ark_server: Some("https://ark.example.com".into()),
            ark_pubkey: Some("02def".into()),
            bolt12_offer: Some("lno1qexampleoffer".into()),
            created_at: Some(1),
            updated_at: Some(2),
        };
        let json = serde_json::to_string(&state).unwrap();
        // Public-only: assert_no_private_material accepts it.
        assert!(assert_no_private_material(&json).is_ok());
        for term in ["xprv", "tprv", "seed", "mnemonic", "macaroon", "secret_key"] {
            assert!(!json.contains(term));
        }
    }

    #[test]
    fn build_methods_preserves_public_receive_pointers() {
        let state = WalletState {
            lightning_address: Some("a@b.com".into()),
            onchain_address: Some("bc1qx".into()),
            ark_server: Some("https://ark.x".into()),
            ark_pubkey: Some("02ab".into()),
            ..Default::default()
        };
        let methods = build_methods(&state);
        assert_eq!(methods.len(), 3);
        assert!(methods
            .iter()
            .any(|m| matches!(m, PaymentMethod::Lightning { .. })));
        assert!(methods
            .iter()
            .any(|m| matches!(m, PaymentMethod::Onchain { .. })));
        assert!(methods
            .iter()
            .any(|m| matches!(m, PaymentMethod::Ark { .. })));
    }

    #[test]
    fn ark_requires_both_server_and_pubkey() {
        let state = WalletState {
            ark_server: Some("https://ark.x".into()),
            ark_pubkey: None,
            ..Default::default()
        };
        // Only one of the pair → no Ark method built.
        assert!(!build_methods(&state)
            .iter()
            .any(|m| matches!(m, PaymentMethod::Ark { .. })));
    }
}
