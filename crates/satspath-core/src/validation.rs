use bech32::FromBase32;
use bitcoin::{Address, Network};
use secp256k1::PublicKey;
use std::str::FromStr;

use crate::ark::{validate_ark_receive_pointer, verify_ark_ownership_proof, ArkReceivePointer};
use crate::errors::{Result, SatsPathError};
use crate::pointer::BitcoinNetwork;
use crate::profile::{ClaimPolicy, PaymentMethod, PaymentProfile};

pub const LARGE_PREVIEW_AMOUNT_SATS: u64 = 100_000_000;
pub const MAX_PREVIEW_AMOUNT_SATS: u64 = 21_000_000 * 100_000_000;

pub fn validate_amount_sats(amount_sats: u64) -> Result<()> {
    if amount_sats == 0 {
        return Err(SatsPathError::InvalidPaymentPointer(
            "amount must be positive".into(),
        ));
    }
    if amount_sats > MAX_PREVIEW_AMOUNT_SATS {
        return Err(SatsPathError::InvalidPaymentPointer(
            "amount exceeds Bitcoin supply".into(),
        ));
    }
    Ok(())
}

pub fn validate_compressed_pubkey(pubkey_hex: &str) -> Result<()> {
    let bytes =
        hex::decode(pubkey_hex).map_err(|e| SatsPathError::InvalidPublicKey(e.to_string()))?;
    if bytes.len() != 33 || !matches!(bytes.first(), Some(0x02 | 0x03)) {
        return Err(SatsPathError::InvalidPublicKey(
            "expected 33-byte compressed secp256k1 pubkey".into(),
        ));
    }
    PublicKey::from_slice(&bytes).map_err(|e| SatsPathError::InvalidPublicKey(e.to_string()))?;
    Ok(())
}

pub fn validate_lightning_address(address: &str) -> Result<()> {
    let trimmed = address.trim();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return Err(SatsPathError::InvalidPaymentPointer(
            "Lightning Address must be user@domain".into(),
        ));
    };
    let valid_local = !local.is_empty()
        && local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'));
    let valid_domain = domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
    if valid_local && valid_domain {
        Ok(())
    } else {
        Err(SatsPathError::InvalidPaymentPointer(
            "invalid Lightning Address format".into(),
        ))
    }
}

/// Validate a BOLT12 offer string.
///
/// BOLT12 offers use the bech32 character set with the `lno` prefix but,
/// unlike BIP-173, carry **no checksum**, and may be split with `+` (optionally
/// followed by whitespace). A checksum-verifying bech32 decoder therefore
/// rejects every real offer; this decodes them as the BOLT12 spec defines.
pub fn validate_bolt12_offer(offer: &str) -> Result<()> {
    let invalid = |msg: &str| SatsPathError::InvalidPaymentPointer(format!("BOLT12 offer {msg}"));
    let trimmed = offer.trim();
    if trimmed.is_empty() {
        return Err(invalid("cannot be empty"));
    }
    let bytes = decode_bolt12_bech32(trimmed, "lno").map_err(|e| invalid(&e))?;
    // A real offer always carries substantial TLV data (at least a node id or
    // blinded path): reject payloads that are truncated, synthetic or a prefix.
    if bytes.len() < 25 {
        return Err(invalid("data too short -- likely truncated or invalid"));
    }
    assert_no_private_material(trimmed)?;
    Ok(())
}

/// Decode a checksum-less BOLT12 bech32 string with human-readable part `hrp`.
fn decode_bolt12_bech32(s: &str, hrp: &str) -> std::result::Result<Vec<u8>, String> {
    const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    // `+` joins parts; whitespace is only allowed directly after a `+`.
    let mut joined = String::with_capacity(s.len());
    let mut after_plus = false;
    for c in s.chars() {
        match c {
            '+' => after_plus = true,
            c if c.is_whitespace() && after_plus => {}
            c if c.is_whitespace() => return Err("contains whitespace".into()),
            c => {
                after_plus = false;
                joined.push(c);
            }
        }
    }
    if joined.chars().any(|c| c.is_ascii_uppercase())
        && joined.chars().any(|c| c.is_ascii_lowercase())
    {
        return Err("mixes upper and lower case".into());
    }
    let joined = joined.to_ascii_lowercase();
    let (prefix, data) = joined
        .rsplit_once('1')
        .ok_or_else(|| "has no bech32 separator".to_string())?;
    if prefix != hrp {
        return Err(format!("must start with '{hrp}1'"));
    }
    let mut out = Vec::with_capacity(data.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in data.bytes() {
        let value = CHARSET
            .iter()
            .position(|&x| x == c)
            .ok_or_else(|| format!("contains invalid character '{}'", c as char))?;
        acc = (acc << 5) | value as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if bits >= 5 || acc != 0 {
        return Err("has invalid padding".into());
    }
    Ok(out)
}

pub fn validate_bitcoin_address(address: &str, network: BitcoinNetwork) -> Result<()> {
    let parsed = Address::from_str(address.trim())
        .map_err(|e| SatsPathError::InvalidPaymentPointer(e.to_string()))?;
    let expected = match network {
        BitcoinNetwork::Mainnet => Network::Bitcoin,
        BitcoinNetwork::Testnet => Network::Testnet,
        BitcoinNetwork::Regtest => Network::Regtest,
    };
    parsed
        .require_network(expected)
        .map_err(|e| SatsPathError::InvalidPaymentPointer(e.to_string()))?;
    Ok(())
}

pub fn validate_silent_payment_address(address: &str, network: BitcoinNetwork) -> Result<()> {
    let trimmed = address.trim();
    if trimmed.is_empty() {
        return Err(SatsPathError::InvalidPaymentPointer(
            "silent payment address cannot be empty".into(),
        ));
    }

    assert_no_private_material(trimmed)?;

    let lower = trimmed.to_ascii_lowercase();

    // BIP-352: mainnet uses 'sp', testnet/regtest use 'tsp'
    let expected_hrp = match network {
        BitcoinNetwork::Mainnet => "sp",
        BitcoinNetwork::Testnet | BitcoinNetwork::Regtest => "tsp",
    };

    if !lower.starts_with(expected_hrp) {
        return Err(SatsPathError::InvalidPaymentPointer(format!(
            "silent payment address must start with '{expected_hrp}' for {network:?}"
        )));
    }

    let (hrp, data, variant) = bech32::decode(&lower).map_err(|e| {
        SatsPathError::InvalidPaymentPointer(format!("silent payment bech32 decode failed: {e}"))
    })?;

    if hrp != expected_hrp {
        return Err(SatsPathError::InvalidPaymentPointer(format!(
            "silent payment address HRP '{hrp}' does not match expected '{expected_hrp}'"
        )));
    }

    if variant != bech32::Variant::Bech32m {
        return Err(SatsPathError::InvalidPaymentPointer(
            "silent payment address must use Bech32m encoding".into(),
        ));
    }

    let bytes = Vec::<u8>::from_base32(&data).map_err(|e| {
        SatsPathError::InvalidPaymentPointer(format!(
            "silent payment base32 conversion failed: {e}"
        ))
    })?;

    // BIP-352 payload: 1 byte version (0x00) + 33 bytes scan pubkey + 33 bytes spend pubkey = 67 bytes
    if bytes.len() != 67 {
        return Err(SatsPathError::InvalidPaymentPointer(format!(
            "silent payment address payload must be 67 bytes, got {}",
            bytes.len()
        )));
    }

    if bytes[0] != 0 {
        return Err(SatsPathError::InvalidPaymentPointer(format!(
            "unsupported silent payment address version: {}",
            bytes[0]
        )));
    }

    // Validate both compressed public keys (must start with 0x02 or 0x03)
    let scan_header = bytes[1];
    let spend_header = bytes[34];
    if (scan_header != 0x02 && scan_header != 0x03)
        || (spend_header != 0x02 && spend_header != 0x03)
    {
        return Err(SatsPathError::InvalidPaymentPointer(
            "silent payment public keys must be 33-byte compressed secp256k1 keys".into(),
        ));
    }

    secp256k1::PublicKey::from_slice(&bytes[1..34]).map_err(|e| {
        SatsPathError::InvalidPaymentPointer(format!("invalid scan public key: {e}"))
    })?;
    secp256k1::PublicKey::from_slice(&bytes[34..67]).map_err(|e| {
        SatsPathError::InvalidPaymentPointer(format!("invalid spend public key: {e}"))
    })?;

    Ok(())
}

pub fn assert_no_private_material(payload: &str) -> Result<()> {
    let lower = payload.to_ascii_lowercase();
    let blocked = [
        "xprv",
        "tprv",
        "seed phrase",
        "mnemonic",
        "private_key",
        "private key",
        "secret_key",
        "macaroon",
        "cert",
        "api_key",
        "apikey",
        "secret_key",
        "secret_hex",
        "password",
    ];
    if let Some(term) = blocked.iter().find(|term| lower.contains(**term)) {
        return Err(SatsPathError::PrivateMaterialRejected((*term).into()));
    }

    let word_count = payload
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|word| word.len() >= 3)
        .count();
    if word_count >= 12 && lower.contains("seed") {
        return Err(SatsPathError::PrivateMaterialRejected(
            "seed phrase-like payload".into(),
        ));
    }
    Ok(())
}

pub fn assert_mainnet_preview_safe(payload: &str) -> Result<()> {
    assert_no_private_material(payload)?;

    let lower = payload.to_ascii_lowercase();
    let blocked = [
        "seed",
        "mnemonic",
        "xprv",
        "tprv",
        "private key",
        "privkey",
        "macaroon",
        "cert",
        "api_key",
        "secret_key",
        "secret_hex",
        "password",
        "refund_key",
        "claim_key",
        "preimage",
    ];
    if let Some(term) = blocked.iter().find(|term| lower.contains(**term)) {
        return Err(SatsPathError::PrivateMaterialRejected((*term).into()));
    }

    let secret_field_names = [
        "seed",
        "mnemonic",
        "xprv",
        "tprv",
        "private_key",
        "privkey",
        "macaroon",
        "cert",
        "api_key",
        "secret_key",
        "secret_hex",
        "password",
        "refund_key",
        "claim_key",
        "preimage",
    ];
    for field in secret_field_names {
        if lower.contains(&format!("\"{field}\"")) || lower.contains(&format!("'{field}'")) {
            return Err(SatsPathError::PrivateMaterialRejected(format!(
                "secret-bearing field `{field}`"
            )));
        }
    }

    Ok(())
}

pub fn validate_claim_policy(policy: &ClaimPolicy) -> Result<()> {
    match policy {
        ClaimPolicy::SingleSig { receiver_pubkey } => validate_compressed_pubkey(receiver_pubkey),
        ClaimPolicy::Multisig {
            threshold,
            pubkeys,
            descriptor,
        } => {
            if *threshold == 0 || usize::from(*threshold) > pubkeys.len() {
                return Err(SatsPathError::InvalidPaymentPointer(
                    "invalid multisig threshold".into(),
                ));
            }
            for pubkey in pubkeys {
                validate_compressed_pubkey(pubkey)?;
            }
            if let Some(descriptor) = descriptor {
                assert_no_private_material(descriptor)?;
            }
            Ok(())
        }
        ClaimPolicy::FutureTaproot {
            internal_key,
            script_policy_hint,
        } => {
            validate_compressed_pubkey(internal_key)?;
            if let Some(hint) = script_policy_hint {
                assert_no_private_material(hint)?;
            }
            Ok(())
        }
    }
}

pub fn validate_public_profile(profile: &PaymentProfile) -> Result<()> {
    assert_no_private_material(&profile.alias)?;
    validate_compressed_pubkey(&profile.identity_pubkey)?;
    if let Some(expires_at) = profile.expires_at {
        if expires_at <= profile.updated_at {
            return Err(SatsPathError::InvalidPaymentPointer(
                "profile expires before it is updated".into(),
            ));
        }
    }

    for method in &profile.methods {
        match method {
            PaymentMethod::Lightning {
                lightning_address,
                lnurl,
                bolt12,
                receiver_pubkey,
                ..
            } => {
                if let Some(address) = lightning_address {
                    validate_lightning_address(address)?;
                }
                if let Some(url) = lnurl {
                    let parsed = url::Url::parse(url)
                        .map_err(|e| SatsPathError::InvalidPaymentPointer(e.to_string()))?;
                    if !matches!(parsed.scheme(), "https" | "http") {
                        return Err(SatsPathError::InvalidPaymentPointer(
                            "LNURL must be http(s)".into(),
                        ));
                    }
                }
                if let Some(invoice) = bolt12 {
                    validate_bolt12_offer(invoice)?;
                }
                if let Some(pubkey) = receiver_pubkey {
                    validate_compressed_pubkey(pubkey)?;
                }
            }
            PaymentMethod::Onchain {
                network,
                address,
                silent_payment_pubkey,
                pubkey_hint,
                descriptor_hint,
                ..
            } => {
                if let Some(addr) = address {
                    validate_bitcoin_address(addr, *network)?;
                }
                if let Some(sp) = silent_payment_pubkey {
                    validate_silent_payment_address(sp, *network)?;
                }
                if let Some(pubkey) = pubkey_hint {
                    validate_compressed_pubkey(pubkey)?;
                }
                if let Some(descriptor) = descriptor_hint {
                    assert_no_private_material(descriptor)?;
                }
            }
            PaymentMethod::Bolt12(offer) => {
                validate_bolt12_offer(&offer.offer)?;
            }
            PaymentMethod::Ark {
                server,
                pubkey,
                vtxo_pointer,
                proof,
                expires_at,
                opaque_uri,
                ..
            } => {
                if let Some(uri) = opaque_uri {
                    // Arkade opaque URI path -- server + pubkey are empty sentinels.
                    // Validate only the public URI; ownership proof is not possible.
                    crate::ark::validate_arkade_opaque_uri(uri)?;
                } else {
                    // Full server + pubkey path -- existing validation.
                    let pointer = ArkReceivePointer {
                        server: server.clone(),
                        receiver_pubkey: pubkey.clone(),
                        vtxo_pointer: vtxo_pointer.clone(),
                        proof: proof.clone(),
                        expires_at: *expires_at,
                    };
                    let now = chrono::Utc::now().timestamp();
                    validate_ark_receive_pointer(&pointer, now)?;
                    if proof.is_some()
                        && !verify_ark_ownership_proof(
                            &profile.alias,
                            &profile.identity_pubkey,
                            &pointer,
                            now,
                        )?
                    {
                        return Err(SatsPathError::InvalidSignature);
                    }
                }
            }
        }
    }

    // Ownership attestations are structurally validated here (no private
    // material, well-formed proofs, sane expiry). Cryptographic re-verification
    // is performed separately at resolve time by
    // `ownership::verify_method_verification`.
    for verification in &profile.method_verifications {
        crate::ownership::validate_method_verification(verification)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    #[test]
    fn mainnet_address_accepted_in_mainnet_preview() {
        assert!(validate_bitcoin_address(
            "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            BitcoinNetwork::Mainnet
        )
        .is_ok());
    }

    #[test]
    fn testnet_address_rejected_in_mainnet_preview() {
        assert!(validate_bitcoin_address(
            "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
            BitcoinNetwork::Mainnet
        )
        .is_err());
    }

    #[test]
    fn compressed_secp256k1_pubkey_accepted() {
        assert!(validate_compressed_pubkey(VALID_PUBKEY).is_ok());
    }

    #[test]
    fn invalid_pubkey_rejected() {
        assert!(validate_compressed_pubkey("04abcdef").is_err());
    }

    #[test]
    fn lightning_address_parsed() {
        assert!(validate_lightning_address("rodrigo@example.com").is_ok());
        assert!(validate_lightning_address("not-an-address").is_err());
    }

    #[test]
    fn profile_rejects_private_material() {
        let profile = PaymentProfile {
            alias: "alice@example.com".into(),
            identity_pubkey: VALID_PUBKEY.into(),
            methods: vec![PaymentMethod::Lightning {
                label: "LN".into(),
                lightning_address: Some("alice@example.com".into()),
                lnurl: None,
                bolt12: Some("secret xprv payload".into()),
                receiver_pubkey: None,
            }],
            updated_at: 1,
            expires_at: Some(2),
            sequence: None,
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: Vec::new(),
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
        };
        assert!(validate_public_profile(&profile).is_err());
    }

    #[test]
    fn mainnet_preview_safe_rejects_secret_terms() {
        assert!(assert_mainnet_preview_safe("bitcoin:bc1qexample?amount=0.1").is_ok());
        assert!(assert_mainnet_preview_safe("{\"claim_key\":\"abc\"}").is_err());
        assert!(assert_mainnet_preview_safe("lnbc1_refund_key_payload").is_err());
    }

    #[test]
    fn multisig_claim_policy_validates_pubkeys() {
        let policy = ClaimPolicy::Multisig {
            threshold: 2,
            pubkeys: vec![VALID_PUBKEY.into(), VALID_PUBKEY.into()],
            descriptor: Some("wsh(sortedmulti(2,...))".into()),
        };
        assert!(validate_claim_policy(&policy).is_ok());
    }

    #[test]
    fn silent_payment_address_validation() {
        use bech32::ToBase32;

        let secp = secp256k1::Secp256k1::new();
        let sk1 = secp256k1::SecretKey::new(&mut rand::thread_rng());
        let pk1 = secp256k1::PublicKey::from_secret_key(&secp, &sk1);
        let sk2 = secp256k1::SecretKey::new(&mut rand::thread_rng());
        let pk2 = secp256k1::PublicKey::from_secret_key(&secp, &sk2);

        let mut payload = Vec::with_capacity(67);
        payload.push(0x00);
        payload.extend_from_slice(&pk1.serialize());
        payload.extend_from_slice(&pk2.serialize());

        let mainnet_sp =
            bech32::encode("sp", payload.to_base32(), bech32::Variant::Bech32m).unwrap();
        let testnet_sp =
            bech32::encode("tsp", payload.to_base32(), bech32::Variant::Bech32m).unwrap();

        // Valid addresses
        assert!(validate_silent_payment_address(&mainnet_sp, BitcoinNetwork::Mainnet).is_ok());
        assert!(validate_silent_payment_address(&testnet_sp, BitcoinNetwork::Testnet).is_ok());

        // Network mismatch
        assert!(validate_silent_payment_address(&mainnet_sp, BitcoinNetwork::Testnet).is_err());
        assert!(validate_silent_payment_address(&testnet_sp, BitcoinNetwork::Mainnet).is_err());

        // Empty address
        assert!(validate_silent_payment_address("", BitcoinNetwork::Mainnet).is_err());

        // Private material rejected
        assert!(
            validate_silent_payment_address("sp1q_xprv_secret", BitcoinNetwork::Mainnet).is_err()
        );

        // Truncated payload
        let truncated = bech32::encode(
            "sp",
            payload[..30].to_vec().to_base32(),
            bech32::Variant::Bech32m,
        )
        .unwrap();
        assert!(validate_silent_payment_address(&truncated, BitcoinNetwork::Mainnet).is_err());

        // Invalid version byte
        let mut bad_version_payload = payload.clone();
        bad_version_payload[0] = 0x01;
        let bad_version = bech32::encode(
            "sp",
            bad_version_payload.to_base32(),
            bech32::Variant::Bech32m,
        )
        .unwrap();
        assert!(validate_silent_payment_address(&bad_version, BitcoinNetwork::Mainnet).is_err());
    }
}
