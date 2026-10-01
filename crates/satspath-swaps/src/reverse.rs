use rand::RngCore;
use secp256k1::{Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::boltz_client::{BoltzClient, ReverseSwapRequest};
use crate::errors::{Result, SwapError};
use crate::swap_store::SwapStore;
use crate::types::{SwapKind, SwapRecord, SwapResult, SwapStatus};

/// Parameters for creating a reverse swap.
///
/// Reverse = Lightning payment -> on-chain BTC delivery.
/// The sender pays a Boltz hold invoice; Boltz locks BTC on-chain;
/// the client claims by revealing the preimage.
pub struct ReverseParams {
    /// Amount in satoshis the sender wants to receive on-chain.
    pub receive_amount_sats: u64,
    /// Bitcoin address where the claimed BTC should land.
    pub destination_address: String,
}

/// Output of a created reverse swap (what the user needs to act on).
pub struct ReverseSwapCreated {
    /// Boltz swap ID.
    pub swap_id: String,
    /// Hold invoice to pay via Lightning.
    pub invoice: String,
    /// Address where Boltz will lock BTC on-chain.
    pub lockup_address: String,
    /// Block height timeout (after which the invoice expires).
    pub timeout_block_height: u32,
}

// --- Create ------------------------------------------------------------------

/// Create a reverse swap and persist the swap record locally.
///
/// After calling this:
/// 1. Display `invoice` to the user (or pay it programmatically from an LN wallet).
/// 2. Call `wait_reverse` which will auto-claim the on-chain BTC once
///    Boltz's lockup transaction is confirmed.
///
/// # Security
/// The 32-byte preimage is generated locally and NEVER transmitted to Boltz.
/// Only its SHA-256 hash is shared. The preimage is the only key to claim
/// the on-chain funds -- it is persisted in the encrypted SwapStore.
pub async fn create_reverse(
    client: &BoltzClient,
    store: &SwapStore,
    params: ReverseParams,
) -> Result<ReverseSwapCreated> {
    // Validate limits
    let limits = client.get_limits().await?;
    if params.receive_amount_sats < limits.minimal {
        return Err(SwapError::BelowMinimum {
            amount_sats: params.receive_amount_sats,
            min_sats: limits.minimal,
        });
    }
    if params.receive_amount_sats > limits.maximal {
        return Err(SwapError::ExceedsMaximum {
            amount_sats: params.receive_amount_sats,
            max_sats: limits.maximal,
        });
    }

    // Generate preimage (client secret -- this is the HTLC secret)
    let mut preimage = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut preimage);
    let preimage_hash: [u8; 32] = Sha256::digest(preimage).into();

    // Generate ephemeral claim keypair
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let claim_secret = SecretKey::new(&mut rng);
    let claim_pubkey = claim_secret.public_key(&secp);
    let claim_pubkey_hex = hex::encode(claim_pubkey.serialize());
    let claim_key_hex = hex::encode(claim_secret.secret_bytes());

    // Call Boltz API
    let req = ReverseSwapRequest {
        from: "BTC".into(),
        to: "BTC".into(),
        invoice_amount: params.receive_amount_sats,
        preimage_hash: hex::encode(preimage_hash),
        claim_public_key: claim_pubkey_hex,
    };
    let resp = client.create_reverse(&req).await?;

    let now = chrono::Utc::now().timestamp();

    // Persist swap record -- preimage is stored encrypted
    let record = SwapRecord {
        id: resp.id.clone(),
        kind: SwapKind::Reverse,
        status: SwapStatus::Created,
        amount_sats: params.receive_amount_sats,
        preimage_hex: Some(hex::encode(preimage)),
        preimage_hash_hex: Some(hex::encode(preimage_hash)),
        refund_key_hex: None,
        claim_key_hex: Some(claim_key_hex),
        invoice: Some(resp.invoice.clone()),
        lockup_address: Some(resp.lockup_address.clone()),
        expected_amount_sats: Some(params.receive_amount_sats),
        timeout_block_height: Some(resp.timeout_block_height),
        boltz_claim_pubkey: None,
        redeem_script: resp.redeem_script,
        lockup_txid: None,
        settlement_txid: None,
        destination_address: Some(params.destination_address),
        created_at: now,
        updated_at: now,
    };
    store.upsert(&record)?;

    Ok(ReverseSwapCreated {
        swap_id: resp.id,
        invoice: resp.invoice,
        lockup_address: resp.lockup_address,
        timeout_block_height: resp.timeout_block_height,
    })
}

// --- Wait & Claim -------------------------------------------------------------

/// Wait for the Boltz lockup transaction to be confirmed, then claim on-chain.
///
/// **Success path:**
/// 1. Boltz locks BTC on-chain -> `transaction.confirmed`
/// 2. Client builds + broadcasts claim tx revealing preimage
/// 3. Boltz captures preimage -> settles hold invoice -> `invoice.settled`
///
/// The claim transaction reveals the preimage publicly on-chain, which allows
/// Boltz to finalize the Lightning payment. This is the atomic "swap" moment.
pub async fn wait_and_claim_reverse(
    client: &BoltzClient,
    store: &SwapStore,
    swap_id: &str,
    max_wait: Duration,
) -> Result<SwapResult> {
    // Wait for lockup confirmation
    let update = client
        .wait_for_status(
            swap_id,
            Some(&[
                SwapStatus::TransactionConfirmed,
                SwapStatus::TransactionLockupFailed,
            ]),
            max_wait,
        )
        .await?;

    match update.status {
        SwapStatus::TransactionLockupFailed => {
            store.update_status(swap_id, SwapStatus::TransactionLockupFailed, None)?;
            Err(SwapError::LockupAmountMismatch {
                id: swap_id.to_string(),
                got: 0,
                expected: 0,
            })
        }
        SwapStatus::TransactionConfirmed => {
            // Retrieve persisted record to get preimage and claim key
            let record = store
                .get(swap_id)?
                .ok_or_else(|| SwapError::NotFound(swap_id.to_string()))?;

            let claim_txid = build_and_broadcast_claim(&record)?;
            store.update_status(
                swap_id,
                SwapStatus::TransactionClaimed,
                Some(claim_txid.clone()),
            )?;

            Ok(SwapResult {
                swap_id: swap_id.to_string(),
                kind: SwapKind::Reverse,
                status: SwapStatus::TransactionClaimed,
                settlement_txid: Some(claim_txid),
                preimage_hex: record.preimage_hex,
            })
        }
        other => Err(SwapError::Timeout {
            id: swap_id.to_string(),
            last_status: other.label().to_string(),
        }),
    }
}

// --- Claim Transaction Builder ------------------------------------------------

/// Build and broadcast the claim transaction for a confirmed Reverse swap.
///
/// This reveals the preimage on-chain, completing the atomic swap.
///
/// # Current Status
/// The claim transaction for Taproot (Boltz v2 default) requires:
///   1. Cooperative key-path spend (get partial sig from Boltz + combine with claim_key)
///   2. OR script-path spend using the HTLC leaf
///
/// The cooperative path produces a standard Schnorr signature, minimizing
/// on-chain footprint and improving privacy.
///
/// Not implemented: there is no Taproot claim builder and no broadcast path, so this
/// fails closed rather than recording a claim that never reached the chain. The swap
/// stays `TransactionConfirmed` with its preimage and claim key persisted for recovery.
fn build_and_broadcast_claim(record: &SwapRecord) -> Result<String> {
    record
        .lockup_txid
        .as_deref()
        .ok_or_else(|| SwapError::Key("Lockup txid missing from swap record".into()))?;

    Err(SwapError::Key(
        "Taproot claim broadcast not yet implemented — secrets preserved for recovery".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preimage_and_hash_are_consistent() {
        let mut preimage = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut preimage);
        let hash: [u8; 32] = Sha256::digest(preimage).into();

        // Verify deterministic
        let hash2: [u8; 32] = Sha256::digest(preimage).into();
        assert_eq!(hash, hash2);

        // Preimage hash is what we share with Boltz
        assert_ne!(preimage, hash);
        println!("Preimage: {}", hex::encode(preimage));
        println!("Hash:     {}", hex::encode(hash));
    }
}
