//! Silent Payments (BIP-352) — EXPERIMENTAL.
//!
//! Experimental Silent Payments primitives and address/output construction are implemented.
//! BIP-352 conformance and interoperability remain unverified until the official send/receive
//! test vectors pass.

use anyhow::{anyhow, Result};
use bech32::{FromBase32, ToBase32, Variant};
use bitcoin::secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::Network;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// BIP-352 tagged hash domain tags.
pub const BIP0352_TAG_INPUTS: &str = "BIP0352/Inputs";
pub const BIP0352_TAG_SHARED_SECRET: &str = "BIP0352/SharedSecret";

/// BIP-340 / BIP-352 tagged hash implementation:
/// SHA256(SHA256(tag) || SHA256(tag) || data)
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    hasher.finalize().into()
}

/// Parse an outpoint string in "txid:vout" format into standard 36-byte Bitcoin wire format:
/// 32 bytes txid (internal byte order / reversed hex) followed by 4 bytes vout (little-endian).
pub fn parse_outpoint_to_bytes(outpoint_str: &str) -> Result<[u8; 36]> {
    let parts: Vec<&str> = outpoint_str.split(':').collect();
    if parts.len() != 2 {
        return Err(anyhow!(
            "Invalid outpoint format, expected txid:vout, got '{outpoint_str}'"
        ));
    }
    let txid_hex = parts[0].trim();
    let vout_str = parts[1].trim();
    if txid_hex.len() != 64 {
        return Err(anyhow!("Invalid txid length in outpoint: {txid_hex}"));
    }
    let mut txid_bytes =
        hex::decode(txid_hex).map_err(|e| anyhow!("Invalid txid hex in outpoint: {e}"))?;
    // Bitcoin wire format stores txid in little-endian order (reversed from display hex)
    txid_bytes.reverse();
    let vout: u32 = vout_str
        .parse()
        .map_err(|e| anyhow!("Invalid vout in outpoint: {e}"))?;

    let mut out = [0u8; 36];
    out[..32].copy_from_slice(&txid_bytes);
    out[32..].copy_from_slice(&vout.to_le_bytes());
    Ok(out)
}

/// Find the lexicographically smallest 36-byte outpoint among inputs as required by BIP-352.
pub fn find_smallest_outpoint(outpoints: &[[u8; 36]]) -> Option<[u8; 36]> {
    outpoints.iter().copied().min()
}

/// Compute BIP-352 input hash: TaggedHash("BIP0352/Inputs", outpoint_L || A)
pub fn compute_input_hash(
    smallest_outpoint: &[u8; 36],
    aggregate_input_pubkey: &PublicKey,
) -> [u8; 32] {
    let mut data = Vec::with_capacity(36 + 33);
    data.extend_from_slice(smallest_outpoint);
    data.extend_from_slice(&aggregate_input_pubkey.serialize());
    tagged_hash(BIP0352_TAG_INPUTS, &data)
}

/// Silent Payment (BIP-352) Scan Public Key
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SilentPaymentScanKey {
    /// The scan public key (33 bytes compressed hex)
    pub scan_pubkey: String,
    /// The spend public key (33 bytes compressed hex)
    pub spend_pubkey: Option<String>,
}

/// Silent Payment Address derived from scan and spend keys
/// BIP-352: bech32m(hrp, version || scan_pubkey || spend_pubkey)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    /// The silent payment bech32m address (starts with sp1q... or tsp1q...)
    pub address: String,
    /// The scan public key (hex)
    pub scan_pubkey: String,
    /// The spend public key (hex)
    pub spend_pubkey: String,
    /// Optional label
    pub label: Option<String>,
}

impl SilentPaymentAddress {
    /// Construct a SilentPaymentAddress from public keys and network.
    pub fn new(
        scan_pubkey: &PublicKey,
        spend_pubkey: &PublicKey,
        network: Network,
        label: Option<String>,
    ) -> Result<Self> {
        let address =
            create_silent_payment_address_for_network(scan_pubkey, spend_pubkey, network)?;
        Ok(Self {
            address,
            scan_pubkey: hex::encode(scan_pubkey.serialize()),
            spend_pubkey: hex::encode(spend_pubkey.serialize()),
            label,
        })
    }

    /// Parse a silent payment address string.
    pub fn parse(address_str: &str) -> Result<Self> {
        let (scan_pk, spend_pk, _network) = parse_silent_payment_address(address_str)?;
        Ok(Self {
            address: address_str.trim().to_ascii_lowercase(),
            scan_pubkey: hex::encode(scan_pk.serialize()),
            spend_pubkey: hex::encode(spend_pk.serialize()),
            label: None,
        })
    }
}

/// Silent Payment Output - an output that can be detected by the recipient
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SilentPaymentOutput {
    /// The output script (P2TR, format: "5120" + 32-byte x-only pubkey hex)
    pub script_pubkey: String,
    /// The amount in satoshis
    pub amount_sats: u64,
    /// The tweaked public key used for this output (hex)
    pub tweaked_pubkey: String,
    /// The shared secret used to derive the tweak (hex)
    pub shared_secret: Option<String>,
}

/// Silent Payment Input - used when creating a silent payment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SilentPaymentInput {
    /// The outpoint being spent ("txid:vout")
    pub outpoint: String,
    /// The taproot or standard public key of the input
    pub input_pubkey: String,
    /// The private key corresponding to the input (for signer)
    #[serde(skip_serializing)]
    pub input_privkey: Option<String>,
}

/// Silent Payment - a payment session using BIP-352 Silent Payments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SilentPayment {
    /// The scan public key of the recipient (hex)
    pub scan_pubkey: String,
    /// The spend public key of the recipient (hex)
    pub spend_pubkey: String,
    /// The amount in satoshis
    pub amount_sats: u64,
    /// The inputs being spent
    pub inputs: Vec<SilentPaymentInput>,
    /// The change output (optional)
    pub change_output: Option<SilentPaymentOutput>,
    /// The target network
    pub network: Network,
}

impl SilentPayment {
    /// Create a new silent payment instance
    pub fn new(
        scan_pubkey: String,
        spend_pubkey: String,
        amount_sats: u64,
        inputs: Vec<SilentPaymentInput>,
        change_output: Option<SilentPaymentOutput>,
        network: Network,
    ) -> Self {
        Self {
            scan_pubkey,
            spend_pubkey,
            amount_sats,
            inputs,
            change_output,
            network,
        }
    }

    /// Create the silent payment address for the recipient (defaults to mainnet)
    pub fn recipient_address(
        scan_pubkey: &str,
        spend_pubkey: &str,
    ) -> Result<String, anyhow::Error> {
        let scan_bytes = hex::decode(scan_pubkey.trim())?;
        let spend_bytes = hex::decode(spend_pubkey.trim())?;
        let scan = PublicKey::from_slice(&scan_bytes)?;
        let spend = PublicKey::from_slice(&spend_bytes)?;
        create_silent_payment_address(&scan, &spend)
    }

    /// Create the silent payment address for the recipient on a specific network
    pub fn recipient_address_for_network(
        scan_pubkey: &str,
        spend_pubkey: &str,
        network: Network,
    ) -> Result<String, anyhow::Error> {
        let scan_bytes = hex::decode(scan_pubkey.trim())?;
        let spend_bytes = hex::decode(spend_pubkey.trim())?;
        let scan = PublicKey::from_slice(&scan_bytes)?;
        let spend = PublicKey::from_slice(&spend_bytes)?;
        create_silent_payment_address_for_network(&scan, &spend, network)
    }

    /// Derive the tweaked public key for a silent payment output (index k = 0)
    pub fn derive_tweaked_pubkey(
        sender_privkey: &SecretKey,
        recipient_scan_pubkey: &PublicKey,
        recipient_spend_pubkey: &PublicKey,
    ) -> Result<PublicKey, anyhow::Error> {
        Self::derive_tweaked_pubkey_with_index(
            sender_privkey,
            recipient_scan_pubkey,
            recipient_spend_pubkey,
            0,
        )
    }

    /// Derive the tweaked public key for a silent payment output with specific index k
    pub fn derive_tweaked_pubkey_with_index(
        sender_privkey: &SecretKey,
        recipient_scan_pubkey: &PublicKey,
        recipient_spend_pubkey: &PublicKey,
        k: u32,
    ) -> Result<PublicKey, anyhow::Error> {
        let secp = Secp256k1::new();
        let sender_scalar = Scalar::from_be_bytes(sender_privkey.secret_bytes())
            .map_err(|e| anyhow!("Invalid scalar: {e}"))?;
        let shared_secret = recipient_scan_pubkey
            .mul_tweak(&secp, &sender_scalar)
            .map_err(|e| anyhow!("Failed to compute shared secret: {e}"))?;

        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&shared_secret.serialize());
        data.extend_from_slice(&k.to_be_bytes());

        let tweak_bytes = tagged_hash(BIP0352_TAG_SHARED_SECRET, &data);
        let tweak_scalar =
            Scalar::from_be_bytes(tweak_bytes).map_err(|e| anyhow!("Invalid tweak scalar: {e}"))?;

        let tweaked = recipient_spend_pubkey
            .add_exp_tweak(&secp, &tweak_scalar)
            .map_err(|e| anyhow!("Failed to tweak public key: {e}"))?;

        Ok(tweaked)
    }

    /// Create a silent payment output (k = 0)
    pub fn create_output(
        &self,
        recipient_scan_pubkey: &PublicKey,
        recipient_spend_pubkey: &PublicKey,
    ) -> Result<SilentPaymentOutput, anyhow::Error> {
        self.create_output_with_index(recipient_scan_pubkey, recipient_spend_pubkey, 0)
    }

    /// Create a silent payment output for a specific recipient output index k
    pub fn create_output_with_index(
        &self,
        recipient_scan_pubkey: &PublicKey,
        recipient_spend_pubkey: &PublicKey,
        k: u32,
    ) -> Result<SilentPaymentOutput, anyhow::Error> {
        let secp = Secp256k1::new();

        // Collect private keys and outpoints from inputs
        let mut privkeys: Vec<SecretKey> = Vec::new();
        let mut outpoints: Vec<[u8; 36]> = Vec::new();

        for input in &self.inputs {
            if let Some(priv_hex) = &input.input_privkey {
                let bytes = hex::decode(priv_hex.trim())
                    .map_err(|e| anyhow!("Invalid input private key hex: {e}"))?;
                let sk = SecretKey::from_slice(&bytes)
                    .map_err(|e| anyhow!("Invalid input secret key: {e}"))?;
                privkeys.push(sk);
            }
            if let Ok(op) = parse_outpoint_to_bytes(&input.outpoint) {
                outpoints.push(op);
            }
        }

        // Determine aggregate sender private key
        let sender_privkey = if privkeys.is_empty() {
            SecretKey::new(&mut OsRng)
        } else if privkeys.len() == 1 {
            privkeys[0]
        } else {
            let mut sum_key = privkeys[0];
            for sk in &privkeys[1..] {
                let sc = Scalar::from_be_bytes(sk.secret_bytes())
                    .map_err(|e| anyhow!("Invalid scalar: {e}"))?;
                sum_key = sum_key
                    .add_tweak(&sc)
                    .map_err(|e| anyhow!("Failed to sum input private keys: {e}"))?;
            }
            sum_key
        };

        let sender_pubkey = PublicKey::from_secret_key(&secp, &sender_privkey);
        let sender_scalar = Scalar::from_be_bytes(sender_privkey.secret_bytes())
            .map_err(|e| anyhow!("Invalid sender scalar: {e}"))?;

        // If outpoint exists, compute input_hash and fold into shared secret
        let shared_secret = if let Some(smallest_op) = find_smallest_outpoint(&outpoints) {
            let input_hash = compute_input_hash(&smallest_op, &sender_pubkey);
            let hash_scalar = Scalar::from_be_bytes(input_hash)
                .map_err(|e| anyhow!("Invalid input hash scalar: {e}"))?;
            recipient_scan_pubkey
                .mul_tweak(&secp, &sender_scalar)
                .map_err(|e| anyhow!("Failed to compute ECDH intermediate point: {e}"))?
                .mul_tweak(&secp, &hash_scalar)
                .map_err(|e| anyhow!("Failed to apply input hash tweak: {e}"))?
        } else {
            recipient_scan_pubkey
                .mul_tweak(&secp, &sender_scalar)
                .map_err(|e| anyhow!("Failed to compute shared secret: {e}"))?
        };

        // Compute tweak t_k = TaggedHash("BIP0352/SharedSecret", S || k)
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&shared_secret.serialize());
        data.extend_from_slice(&k.to_be_bytes());

        let tweak_bytes = tagged_hash(BIP0352_TAG_SHARED_SECRET, &data);
        let tweak_scalar =
            Scalar::from_be_bytes(tweak_bytes).map_err(|e| anyhow!("Invalid tweak scalar: {e}"))?;

        let tweaked_pubkey = recipient_spend_pubkey
            .add_exp_tweak(&secp, &tweak_scalar)
            .map_err(|e| anyhow!("Failed to tweak public key: {e}"))?;

        // Standard P2TR scriptPubkey: OP_1 (0x51) OP_PUSHBYTES_32 (0x20) <32-byte x-only pubkey>
        let (x_only, _) = tweaked_pubkey.x_only_public_key();
        let script_pubkey = format!("5120{}", hex::encode(x_only.serialize()));

        Ok(SilentPaymentOutput {
            script_pubkey,
            amount_sats: self.amount_sats,
            tweaked_pubkey: hex::encode(tweaked_pubkey.serialize()),
            shared_secret: Some(hex::encode(shared_secret.serialize())),
        })
    }

    /// Detect silent payments addressed to the recipient across transaction outputs
    pub fn detect_outputs(
        scan_privkey: &SecretKey,
        spend_pubkey: &PublicKey,
        input_pubkeys: &[PublicKey],
        tx_outputs: &[(String, u64)], // (script_pubkey, amount_sats)
    ) -> Result<Vec<SilentPaymentOutput>, anyhow::Error> {
        detect_silent_payment_outputs(scan_privkey, spend_pubkey, input_pubkeys, tx_outputs)
    }

    /// Detect silent payments when input hash is explicitly bound (with outpoint_L)
    pub fn detect_outputs_with_input_hash(
        scan_privkey: &SecretKey,
        spend_pubkey: &PublicKey,
        aggregate_input_pubkey: &PublicKey,
        input_hash: &[u8; 32],
        tx_outputs: &[(String, u64)],
    ) -> Result<Vec<SilentPaymentOutput>, anyhow::Error> {
        let secp = Secp256k1::new();
        let scan_scalar = Scalar::from_be_bytes(scan_privkey.secret_bytes())
            .map_err(|e| anyhow!("Invalid scan scalar: {e}"))?;
        let hash_scalar = Scalar::from_be_bytes(*input_hash)
            .map_err(|e| anyhow!("Invalid input hash scalar: {e}"))?;

        let shared_secret = aggregate_input_pubkey
            .mul_tweak(&secp, &scan_scalar)
            .map_err(|e| anyhow!("Failed to compute ECDH intermediate point: {e}"))?
            .mul_tweak(&secp, &hash_scalar)
            .map_err(|e| anyhow!("Failed to apply input hash tweak: {e}"))?;

        scan_outputs_for_shared_secret(&secp, spend_pubkey, &shared_secret, tx_outputs)
    }
}

/// Helper function to scan candidate transaction outputs for a given shared secret point S
fn scan_outputs_for_shared_secret(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    spend_pubkey: &PublicKey,
    shared_secret: &PublicKey,
    tx_outputs: &[(String, u64)],
) -> Result<Vec<SilentPaymentOutput>> {
    let mut detected = Vec::new();

    // Check outputs starting from index k = 0 upwards
    for k in 0..10u32 {
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&shared_secret.serialize());
        data.extend_from_slice(&k.to_be_bytes());

        let tweak_bytes = tagged_hash(BIP0352_TAG_SHARED_SECRET, &data);
        let tweak_scalar =
            Scalar::from_be_bytes(tweak_bytes).map_err(|e| anyhow!("Invalid tweak scalar: {e}"))?;

        let tweaked_pubkey = spend_pubkey
            .add_exp_tweak(secp, &tweak_scalar)
            .map_err(|e| anyhow!("Failed to tweak candidate pubkey: {e}"))?;

        let (x_only, _) = tweaked_pubkey.x_only_public_key();
        let expected_script = format!("5120{}", hex::encode(x_only.serialize()));

        let mut matched = false;
        for (script_pubkey, amount_sats) in tx_outputs {
            if script_pubkey.eq_ignore_ascii_case(&expected_script) {
                detected.push(SilentPaymentOutput {
                    script_pubkey: script_pubkey.clone(),
                    amount_sats: *amount_sats,
                    tweaked_pubkey: hex::encode(tweaked_pubkey.serialize()),
                    shared_secret: Some(hex::encode(shared_secret.serialize())),
                });
                matched = true;
            }
        }

        // If no match was found for k > 0, stop scanning higher indices
        if !matched && k > 0 {
            break;
        }
    }

    Ok(detected)
}

/// Free function to detect silent payment outputs given sender input pubkeys and tx outputs
pub fn detect_silent_payment_outputs(
    scan_privkey: &SecretKey,
    spend_pubkey: &PublicKey,
    input_pubkeys: &[PublicKey],
    tx_outputs: &[(String, u64)],
) -> Result<Vec<SilentPaymentOutput>> {
    if input_pubkeys.is_empty() || tx_outputs.is_empty() {
        return Ok(Vec::new());
    }

    let secp = Secp256k1::new();
    let aggregate_a = if input_pubkeys.len() == 1 {
        input_pubkeys[0]
    } else {
        let refs: Vec<&PublicKey> = input_pubkeys.iter().collect();
        PublicKey::combine_keys(&refs)
            .map_err(|e| anyhow!("Failed to combine input pubkeys: {e}"))?
    };

    let scan_scalar = Scalar::from_be_bytes(scan_privkey.secret_bytes())
        .map_err(|e| anyhow!("Invalid scan scalar: {e}"))?;

    let shared_secret = aggregate_a
        .mul_tweak(&secp, &scan_scalar)
        .map_err(|e| anyhow!("Failed to compute ECDH shared secret: {e}"))?;

    scan_outputs_for_shared_secret(&secp, spend_pubkey, &shared_secret, tx_outputs)
}

/// Derive the spending private key for a detected silent payment output:
/// p_k = b_spend + t_k (with taproot parity adjustment if required)
pub fn derive_spending_privkey(
    spend_privkey: &SecretKey,
    shared_secret: &PublicKey,
    k: u32,
) -> Result<SecretKey> {
    let secp = Secp256k1::new();
    let mut data = Vec::with_capacity(37);
    data.extend_from_slice(&shared_secret.serialize());
    data.extend_from_slice(&k.to_be_bytes());

    let tweak_bytes = tagged_hash(BIP0352_TAG_SHARED_SECRET, &data);
    let tweak_scalar =
        Scalar::from_be_bytes(tweak_bytes).map_err(|e| anyhow!("Invalid tweak scalar: {e}"))?;

    let tweaked_sk = spend_privkey
        .add_tweak(&tweak_scalar)
        .map_err(|e| anyhow!("Failed to tweak spend private key: {e}"))?;

    // Check parity of the resulting public key: BIP-340 Schnorr / Taproot requires even parity
    let derived_pk = PublicKey::from_secret_key(&secp, &tweaked_sk);
    let (_, parity) = derived_pk.x_only_public_key();

    let final_sk = if parity == Parity::Odd {
        tweaked_sk.negate()
    } else {
        tweaked_sk
    };

    Ok(final_sk)
}

/// Derive spending private key directly from scan private key and sender public key
pub fn derive_spending_privkey_from_scan(
    spend_privkey: &SecretKey,
    scan_privkey: &SecretKey,
    sender_pubkey: &PublicKey,
    k: u32,
) -> Result<SecretKey> {
    let secp = Secp256k1::new();
    let scan_scalar = Scalar::from_be_bytes(scan_privkey.secret_bytes())
        .map_err(|e| anyhow!("Invalid scan scalar: {e}"))?;
    let shared_secret = sender_pubkey
        .mul_tweak(&secp, &scan_scalar)
        .map_err(|e| anyhow!("Failed to compute shared secret: {e}"))?;

    derive_spending_privkey(spend_privkey, &shared_secret, k)
}

/// Generate a new silent payment key pair (scan + spend)
pub fn generate_silent_payment_keys() -> Result<(String, String, String, String), anyhow::Error> {
    let secp = Secp256k1::new();

    let scan_privkey = SecretKey::new(&mut OsRng);
    let scan_pubkey = PublicKey::from_secret_key(&secp, &scan_privkey);

    let spend_privkey = SecretKey::new(&mut OsRng);
    let spend_pubkey = PublicKey::from_secret_key(&secp, &spend_privkey);

    Ok((
        hex::encode(scan_privkey.secret_bytes()),
        hex::encode(scan_pubkey.serialize()),
        hex::encode(spend_privkey.secret_bytes()),
        hex::encode(spend_pubkey.serialize()),
    ))
}

/// Parse a silent payment scan public key
pub fn parse_silent_payment_scan_key(scan_key: &str) -> Result<PublicKey, anyhow::Error> {
    let trimmed = scan_key.trim();
    if !trimmed.starts_with("sp1q") && !trimmed.starts_with("tsp1q") {
        return Err(anyhow!(
            "Invalid silent payment scan key: must start with 'sp1q' or 'tsp1q'"
        ));
    }

    // Try full bech32m address decode first
    if let Ok((scan_pub, _, _)) = parse_silent_payment_address(trimmed) {
        return Ok(scan_pub);
    }

    // Fallback: legacy hex format after prefix (used in mock unit tests)
    let hex_part = if let Some(stripped) = trimmed.strip_prefix("tsp1q") {
        stripped
    } else if let Some(stripped) = trimmed.strip_prefix("sp1q") {
        stripped
    } else {
        trimmed
    };
    if let Ok(bytes) = hex::decode(hex_part) {
        if bytes.len() == 33 {
            return PublicKey::from_slice(&bytes)
                .map_err(|e| anyhow!("Invalid public key bytes: {e}"));
        }
    }

    Err(anyhow!("Unable to parse silent payment scan key"))
}

/// Create a silent payment address from scan and spend public keys (defaults to Mainnet)
pub fn create_silent_payment_address(
    scan_pubkey: &PublicKey,
    spend_pubkey: &PublicKey,
) -> Result<String, anyhow::Error> {
    create_silent_payment_address_for_network(scan_pubkey, spend_pubkey, Network::Bitcoin)
}

/// Create a silent payment address for a specific network:
/// Mainnet uses HRP "sp", Testnet/Signet/Regtest use HRP "tsp".
/// Payload: 1 byte version (0x00) || 33 bytes scan pubkey || 33 bytes spend pubkey (67 bytes total)
pub fn create_silent_payment_address_for_network(
    scan_pubkey: &PublicKey,
    spend_pubkey: &PublicKey,
    network: Network,
) -> Result<String, anyhow::Error> {
    let hrp = match network {
        Network::Bitcoin => "sp",
        Network::Testnet | Network::Signet | Network::Regtest => "tsp",
        _ => "tsp",
    };

    let mut payload = Vec::with_capacity(67);
    payload.push(0x00); // BIP-352 version 0
    payload.extend_from_slice(&scan_pubkey.serialize());
    payload.extend_from_slice(&spend_pubkey.serialize());

    let encoded = bech32::encode(hrp, payload.to_base32(), Variant::Bech32m)
        .map_err(|e| anyhow!("Failed to encode silent payment address: {e}"))?;

    Ok(encoded)
}

/// Parse and validate a BIP-352 silent payment address string into scan pubkey, spend pubkey, and Network
pub fn parse_silent_payment_address(
    address: &str,
) -> Result<(PublicKey, PublicKey, Network), anyhow::Error> {
    let trimmed = address.trim();
    let lower = trimmed.to_ascii_lowercase();

    let is_mainnet = lower.starts_with("sp1q");
    let is_testnet = lower.starts_with("tsp1q");
    if !is_mainnet && !is_testnet {
        return Err(anyhow!(
            "Invalid silent payment address prefix: expected 'sp1q' or 'tsp1q'"
        ));
    }

    let (hrp, data, variant) =
        bech32::decode(&lower).map_err(|e| anyhow!("Failed to decode bech32 address: {e}"))?;

    if variant != Variant::Bech32m {
        return Err(anyhow!(
            "Invalid silent payment address encoding: expected Bech32m"
        ));
    }

    let network = match hrp.as_str() {
        "sp" => Network::Bitcoin,
        "tsp" => Network::Testnet,
        other => return Err(anyhow!("Unknown silent payment HRP: {other}")),
    };

    let bytes =
        Vec::<u8>::from_base32(&data).map_err(|e| anyhow!("Failed to convert base32 data: {e}"))?;

    if bytes.len() != 67 {
        return Err(anyhow!(
            "Invalid silent payment address payload length: expected 67 bytes, got {}",
            bytes.len()
        ));
    }

    if bytes[0] != 0 {
        return Err(anyhow!(
            "Unsupported silent payment address version: {}",
            bytes[0]
        ));
    }

    let scan_pubkey = PublicKey::from_slice(&bytes[1..34])
        .map_err(|e| anyhow!("Invalid scan public key in address: {e}"))?;
    let spend_pubkey = PublicKey::from_slice(&bytes[34..67])
        .map_err(|e| anyhow!("Invalid spend public key in address: {e}"))?;

    Ok((scan_pubkey, spend_pubkey, network))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_silent_payment_keys() {
        let (scan_priv, scan_pub, spend_priv, spend_pub) = generate_silent_payment_keys().unwrap();
        assert_eq!(scan_priv.len(), 64);
        assert_eq!(scan_pub.len(), 66);
        assert_eq!(spend_priv.len(), 64);
        assert_eq!(spend_pub.len(), 66);
    }

    #[test]
    fn test_parse_silent_payment_scan_key_legacy() {
        let (_, scan_pub, _, _) = generate_silent_payment_keys().unwrap();
        let sp1q = format!("sp1q{}", scan_pub.to_lowercase());
        let result = parse_silent_payment_scan_key(&sp1q);
        assert!(result.is_ok());
    }

    #[test]
    fn test_bip352_address_encode_decode_roundtrip() {
        let secp = Secp256k1::new();
        let scan_sk = SecretKey::new(&mut OsRng);
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_sk = SecretKey::new(&mut OsRng);
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);

        // Mainnet
        let mainnet_addr = create_silent_payment_address(&scan_pk, &spend_pk).unwrap();
        assert!(mainnet_addr.starts_with("sp1q"));
        let (parsed_scan, parsed_spend, net) = parse_silent_payment_address(&mainnet_addr).unwrap();
        assert_eq!(parsed_scan, scan_pk);
        assert_eq!(parsed_spend, spend_pk);
        assert_eq!(net, Network::Bitcoin);

        // Testnet
        let testnet_addr =
            create_silent_payment_address_for_network(&scan_pk, &spend_pk, Network::Testnet)
                .unwrap();
        assert!(testnet_addr.starts_with("tsp1q"));
        let (parsed_scan_t, parsed_spend_t, net_t) =
            parse_silent_payment_address(&testnet_addr).unwrap();
        assert_eq!(parsed_scan_t, scan_pk);
        assert_eq!(parsed_spend_t, spend_pk);
        assert_eq!(net_t, Network::Testnet);
    }

    #[test]
    fn test_silent_payment_output_creation_and_detection() {
        let secp = Secp256k1::new();

        // Recipient keys
        let scan_sk = SecretKey::new(&mut OsRng);
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_sk = SecretKey::new(&mut OsRng);
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);

        // Sender input
        let sender_sk = SecretKey::new(&mut OsRng);
        let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);

        let input = SilentPaymentInput {
            outpoint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:0"
                .to_string(),
            input_pubkey: hex::encode(sender_pk.serialize()),
            input_privkey: Some(hex::encode(sender_sk.secret_bytes())),
        };

        let payment = SilentPayment::new(
            hex::encode(scan_pk.serialize()),
            hex::encode(spend_pk.serialize()),
            50_000,
            vec![input],
            None,
            Network::Bitcoin,
        );

        let output_0 = payment
            .create_output_with_index(&scan_pk, &spend_pk, 0)
            .unwrap();
        assert!(output_0.script_pubkey.starts_with("5120"));
        assert_eq!(output_0.script_pubkey.len(), 68);

        // Recipient detects output
        let tx_outputs = vec![
            (
                "5120deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
                10_000,
            ),
            (output_0.script_pubkey.clone(), 50_000),
        ];

        let outpoint_bytes = parse_outpoint_to_bytes(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:0",
        )
        .unwrap();
        let input_hash = compute_input_hash(&outpoint_bytes, &sender_pk);

        let detected = SilentPayment::detect_outputs_with_input_hash(
            &scan_sk,
            &spend_pk,
            &sender_pk,
            &input_hash,
            &tx_outputs,
        )
        .unwrap();

        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0].script_pubkey, output_0.script_pubkey);
        assert_eq!(detected[0].amount_sats, 50_000);

        // Derive spending private key and verify it matches the tweaked output key
        let shared_secret =
            PublicKey::from_slice(&hex::decode(output_0.shared_secret.unwrap()).unwrap()).unwrap();
        let derived_spending_sk = derive_spending_privkey(&spend_sk, &shared_secret, 0).unwrap();
        let derived_pk = PublicKey::from_secret_key(&secp, &derived_spending_sk);
        let (derived_x_only, _) = derived_pk.x_only_public_key();

        let expected_x_only_hex = &output_0.script_pubkey[4..];
        assert_eq!(hex::encode(derived_x_only.serialize()), expected_x_only_hex);
    }
}
