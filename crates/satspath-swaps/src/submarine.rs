use std::time::Duration;

use crate::boltz_client::{BoltzClient, SubmarineSwapRequest};
use crate::errors::{Result, SwapError};
use crate::swap_store::SwapStore;
use crate::types::{parse_swap_pubkey, SwapKind, SwapRecord, SwapResult, SwapStatus};

/// Parameters for creating a submarine swap.
///
/// Submarine = On-chain BTC (or Ark VTXO) -> Lightning invoice payment.
/// The sender deposits BTC at `lockup_address`; Boltz pays the LN invoice.
pub struct SubmarineParams {
    /// The Lightning invoice to pay (lnbc...).
    pub invoice: String,
    /// Amount in satoshis to send. Used to verify against Boltz limits.
    pub amount_sats: u64,
    /// Host-wallet public key (compressed, hex) that can refund the lockup.
    /// SatsPath never sees the matching secret key.
    pub refund_pubkey_hex: String,
}

/// Output of a created submarine swap (what the user needs to act on).
pub struct SubmarineSwapCreated {
    /// Boltz swap ID.
    pub swap_id: String,
    /// Address to deposit BTC to.
    pub lockup_address: String,
    /// Exact amount to deposit (may differ from invoice amount due to fees).
    pub expected_amount_sats: u64,
    /// CLTV expiry block. After this, refund is possible.
    pub timeout_block_height: u32,
}

// --- Create ------------------------------------------------------------------

/// Create a submarine swap and persist the swap record locally.
///
/// After calling this, the user must:
/// 1. Send exactly `expected_amount_sats` to `lockup_address`.
/// 2. Call `wait_submarine` to track and auto-handle the outcome.
pub async fn create_submarine(
    client: &BoltzClient,
    store: &SwapStore,
    params: SubmarineParams,
) -> Result<SubmarineSwapCreated> {
    // Fail closed before contacting Boltz: without a working claim/refund path a
    // created swap could strand the funds sent to it.
    crate::execution_gate::ensure_claim_refund_builders_available(SwapKind::Submarine)?;

    // Validate against Boltz limits
    let limits = client.get_limits().await?;
    if params.amount_sats < limits.minimal {
        return Err(SwapError::BelowMinimum {
            amount_sats: params.amount_sats,
            min_sats: limits.minimal,
        });
    }
    if params.amount_sats > limits.maximal {
        return Err(SwapError::ExceedsMaximum {
            amount_sats: params.amount_sats,
            max_sats: limits.maximal,
        });
    }

    // The refund key belongs to the host wallet; SatsPath only relays its pubkey.
    let refund_pubkey_hex = parse_swap_pubkey(&params.refund_pubkey_hex, "refund")?;

    // Call Boltz API
    let req = SubmarineSwapRequest {
        invoice: params.invoice.clone(),
        from: "BTC".into(),
        to: "BTC".into(),
        refund_public_key: refund_pubkey_hex.clone(),
    };
    let resp = client.create_submarine(&req).await?;

    let now = chrono::Utc::now().timestamp();

    // Persist swap record
    let record = SwapRecord {
        id: resp.id.clone(),
        kind: SwapKind::Submarine,
        status: SwapStatus::Created,
        amount_sats: params.amount_sats,
        preimage_hex: None,
        preimage_hash_hex: None,
        refund_pubkey_hex: Some(refund_pubkey_hex),
        claim_pubkey_hex: None,
        legacy_refund_key_hex: None,
        legacy_claim_key_hex: None,
        invoice: Some(params.invoice),
        lockup_address: Some(resp.address.clone()),
        expected_amount_sats: Some(resp.expected_amount),
        timeout_block_height: Some(resp.timeout_block_height),
        boltz_claim_pubkey: Some(resp.claim_public_key),
        redeem_script: resp.redeem_script,
        lockup_txid: None,
        settlement_txid: None,
        destination_address: None,
        created_at: now,
        updated_at: now,
    };
    store.upsert(&record)?;

    Ok(SubmarineSwapCreated {
        swap_id: resp.id,
        lockup_address: resp.address,
        expected_amount_sats: resp.expected_amount,
        timeout_block_height: resp.timeout_block_height,
    })
}

// --- Wait & Handle -----------------------------------------------------------

/// Wait for a submarine swap to reach a terminal state.
///
/// **Success path:** Boltz routes the payment -> `invoice.paid` -> returns Ok.
///
/// **Failure path:** Boltz can't route -> `invoice.failedToPay` -> triggers
/// refund transaction construction -> returns `Err(InvoiceFailedToPay)`.
///
/// # Timeout
/// Waits up to `max_wait` before returning `SwapError::Timeout`.
pub async fn wait_submarine(
    client: &BoltzClient,
    store: &SwapStore,
    swap_id: &str,
    max_wait: Duration,
) -> Result<SwapResult> {
    let update = client
        .wait_for_status(
            swap_id,
            Some(&[SwapStatus::InvoicePaid, SwapStatus::InvoiceFailedToPay]),
            max_wait,
        )
        .await?;

    match update.status {
        SwapStatus::InvoicePaid => {
            store.update_status(swap_id, SwapStatus::InvoicePaid, None)?;
            Ok(SwapResult {
                swap_id: swap_id.to_string(),
                kind: SwapKind::Submarine,
                status: SwapStatus::InvoicePaid,
                settlement_txid: None,
                preimage_hex: None,
            })
        }
        SwapStatus::InvoiceFailedToPay => {
            // Attempt automatic refund
            // Only record a refund that actually happened; otherwise keep the failure
            // status so the swap remains visibly recoverable.
            match attempt_submarine_refund(client, store, swap_id).await {
                Ok(txid) => {
                    store.update_status(swap_id, SwapStatus::TransactionRefunded, Some(txid))?
                }
                Err(_) => store.update_status(swap_id, SwapStatus::InvoiceFailedToPay, None)?,
            }
            Err(SwapError::InvoiceFailedToPay {
                id: swap_id.to_string(),
            })
        }
        other => {
            let label = other.label().to_string();
            Err(SwapError::Timeout {
                id: swap_id.to_string(),
                last_status: label,
            })
        }
    }
}

// --- Refund ------------------------------------------------------------------

/// Attempt to broadcast a refund transaction for a failed submarine swap.
///
/// Returns the refund TXID on success. Not implemented yet: `tx_builder` only builds
/// P2WSH HTLC refunds, which cannot spend Boltz v2 Taproot lockups, and nothing
/// broadcasts, so this fails closed instead of reporting a refund that never reached
/// the chain. The refund key stays with the host wallet.
async fn attempt_submarine_refund(
    _client: &BoltzClient,
    store: &SwapStore,
    swap_id: &str,
) -> Result<String> {
    store
        .get(swap_id)?
        .ok_or_else(|| SwapError::NotFound(swap_id.to_string()))?;

    Err(SwapError::Key(
        "Taproot refund broadcast not yet implemented — swap record preserved for recovery".into(),
    ))
}

#[cfg(test)]
mod tests {
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    #[test]
    fn preimage_hash_is_sha256() {
        // Verify the preimage -> hash relationship we'll use for Reverse swaps
        let mut preimage = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut preimage);
        let hash: [u8; 32] = Sha256::digest(preimage).into();
        // Hash must be different from preimage
        assert_ne!(preimage, hash);
        // Re-hashing the hash should be different again
        let double_hash: [u8; 32] = Sha256::digest(hash).into();
        assert_ne!(hash, double_hash);
    }
}
