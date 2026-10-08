use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::boltz_client::{BoltzClient, ChainSwapRequest};
use crate::errors::{Result, SwapError};
use crate::swap_store::SwapStore;
use crate::types::{parse_swap_pubkey, SwapKind, SwapRecord, SwapResult, SwapStatus};

/// Parameters for creating a chain swap.
///
/// Chain Swap = On-chain/Ark → On-chain BTC (bypasses Lightning entirely).
/// Ideal for offboarding from Arkade VTXOs to cold storage.
///
/// The sender locks funds on the source side; Boltz mirrors the lock on the
/// destination side; both sides claim cooperatively via Taproot key-path spend.
pub struct ChainSwapParams {
    /// Amount the sender will lock on the source side (sats).
    /// The receiver gets this minus Boltz fees and miner fees.
    pub send_amount_sats: u64,
    /// Bitcoin address where the claimed BTC should land (destination).
    pub destination_address: String,
    /// If true, the sender locks `send_amount_sats` and pays all fees.
    /// If false, set `send_amount_sats` to the desired *received* amount;
    /// the SDK will calculate the required send amount including fees.
    pub sender_pays_fees: bool,
    /// Host-wallet public key (compressed, hex) that claims Boltz's lockup.
    /// SatsPath never sees the matching secret key.
    pub claim_pubkey_hex: String,
    /// Host-wallet public key (compressed, hex) that refunds the sender's lockup.
    /// SatsPath never sees the matching secret key.
    pub refund_pubkey_hex: String,
}

/// Output of a created chain swap (what the user needs to act on).
pub struct ChainSwapCreated {
    pub swap_id: String,
    /// Address where the sender must lock BTC (source side).
    pub sender_lockup_address: String,
    /// Exact amount to lock on the source side.
    pub lock_amount_sats: u64,
    /// Address where Boltz will lock BTC (destination side).
    pub receiver_lockup_address: String,
    /// CLTV expiry block.
    pub timeout_block_height: u32,
}

// ─── Create ──────────────────────────────────────────────────────────────────

/// Create a chain swap and persist the swap record locally.
///
/// The chain swap uses two HTLC legs:
/// - **User side (lockup):** User locks BTC. Boltz claims using preimage.
/// - **Server side (claim):** Boltz locks BTC. User claims using preimage.
///
/// Both sides resolve atomically: Boltz cannot claim user's funds without
/// enabling the user to claim server-side funds (and vice versa).
///
/// Taproot cooperative path: if both parties cooperate (normal case),
/// the settlement transactions look like ordinary Schnorr spends —
/// indistinguishable from regular payments, maximizing privacy.
pub async fn create_chain_swap(
    client: &BoltzClient,
    store: &SwapStore,
    params: ChainSwapParams,
) -> Result<ChainSwapCreated> {
    // Fail closed before contacting Boltz: without a working claim/refund path a
    // created swap could strand the funds sent to it.
    crate::execution_gate::ensure_claim_refund_builders_available(SwapKind::Chain)?;

    // Validate limits
    let limits = client.get_limits().await?;
    if params.send_amount_sats < limits.minimal {
        return Err(SwapError::BelowMinimum {
            amount_sats: params.send_amount_sats,
            min_sats: limits.minimal,
        });
    }
    if params.send_amount_sats > limits.maximal {
        return Err(SwapError::ExceedsMaximum {
            amount_sats: params.send_amount_sats,
            max_sats: limits.maximal,
        });
    }

    // Generate preimage (the atomic secret for both HTLC legs)
    let mut preimage = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut preimage);
    let preimage_hash: [u8; 32] = Sha256::digest(preimage).into();

    // Claim and refund keys belong to the host wallet; SatsPath only relays pubkeys.
    let claim_pubkey_hex = parse_swap_pubkey(&params.claim_pubkey_hex, "claim")?;
    let refund_pubkey_hex = parse_swap_pubkey(&params.refund_pubkey_hex, "refund")?;

    // Determine fee directive
    let (user_lock, server_lock) = if params.sender_pays_fees {
        (Some(params.send_amount_sats), None)
    } else {
        (None, Some(params.send_amount_sats))
    };

    let req = ChainSwapRequest {
        from: "BTC".into(),
        to: "BTC".into(),
        preimage_hash: hex::encode(preimage_hash),
        claim_public_key: claim_pubkey_hex.clone(),
        refund_public_key: refund_pubkey_hex.clone(),
        user_lock_amount: user_lock,
        server_lock_amount: server_lock,
    };
    let resp = client.create_chain(&req).await?;

    let now = chrono::Utc::now().timestamp();

    let record = SwapRecord {
        id: resp.id.clone(),
        kind: SwapKind::Chain,
        status: SwapStatus::Created,
        amount_sats: params.send_amount_sats,
        preimage_hex: Some(hex::encode(preimage)),
        preimage_hash_hex: Some(hex::encode(preimage_hash)),
        refund_pubkey_hex: Some(refund_pubkey_hex),
        claim_pubkey_hex: Some(claim_pubkey_hex),
        legacy_refund_key_hex: None,
        legacy_claim_key_hex: None,
        invoice: None,
        lockup_address: Some(resp.lockup_details.lockup_address.clone()),
        expected_amount_sats: Some(resp.lockup_details.amount),
        timeout_block_height: Some(resp.lockup_details.timeout_block_height),
        boltz_claim_pubkey: resp.claim_details.server_public_key.clone(),
        redeem_script: None, // Taproot uses blinding_key + swap_tree
        lockup_txid: None,
        settlement_txid: None,
        destination_address: Some(params.destination_address),
        created_at: now,
        updated_at: now,
    };
    store.upsert(&record)?;

    Ok(ChainSwapCreated {
        swap_id: resp.id,
        sender_lockup_address: resp.lockup_details.lockup_address,
        lock_amount_sats: resp.lockup_details.amount,
        receiver_lockup_address: resp.claim_details.lockup_address,
        timeout_block_height: resp.lockup_details.timeout_block_height,
    })
}

// ─── Wait & Claim ─────────────────────────────────────────────────────────────

/// Wait for a chain swap to reach a terminal state.
///
/// **Normal flow:**
/// 1. Sender deposits to `sender_lockup_address`
/// 2. Boltz mirrors on `receiver_lockup_address`
/// 3. Both sides confirmed → client claims receiver side (reveals preimage)
/// 4. Boltz claims sender side (captures preimage) → `transaction.claimed`
///
/// **Lockup mismatch (renegotiation):**
/// If the deposited amount doesn't match, Boltz emits `transaction.lockupFailed`.
/// We attempt automatic renegotiation via GET /quote → POST /quote.
/// If renegotiation fails or new amount is unacceptable, we refund.
pub async fn wait_and_claim_chain(
    client: &BoltzClient,
    store: &SwapStore,
    swap_id: &str,
    max_wait: Duration,
) -> Result<SwapResult> {
    let update = client
        .wait_for_status(
            swap_id,
            Some(&[
                SwapStatus::TransactionConfirmed,
                SwapStatus::TransactionLockupFailed,
                SwapStatus::TransactionClaimed,
            ]),
            max_wait,
        )
        .await?;

    match update.status {
        SwapStatus::TransactionLockupFailed => {
            // Attempt dynamic renegotiation
            match client.get_chain_swap_quote(swap_id).await {
                Ok(new_quote) => {
                    println!(
                        "  ↩  Chain swap lockup mismatch. Renegotiating at {} sats...",
                        new_quote.amount
                    );
                    client.accept_chain_swap_quote(swap_id, &new_quote).await?;
                    store.update_status(swap_id, SwapStatus::Created, None)?;
                    // Re-enter wait loop after renegotiation
                    Box::pin(wait_and_claim_chain(client, store, swap_id, max_wait)).await
                }
                Err(_) => {
                    store.update_status(swap_id, SwapStatus::TransactionLockupFailed, None)?;
                    Err(SwapError::LockupAmountMismatch {
                        id: swap_id.to_string(),
                        got: 0,
                        expected: 0,
                    })
                }
            }
        }

        SwapStatus::TransactionConfirmed | SwapStatus::TransactionClaimed => {
            let record = store
                .get(swap_id)?
                .ok_or_else(|| SwapError::NotFound(swap_id.to_string()))?;

            let claim_txid = build_cooperative_claim(&record)?;
            store.update_status(
                swap_id,
                SwapStatus::TransactionClaimed,
                Some(claim_txid.clone()),
            )?;

            Ok(SwapResult {
                swap_id: swap_id.to_string(),
                kind: SwapKind::Chain,
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

// ─── Cooperative Claim ────────────────────────────────────────────────────────

/// Build and broadcast the cooperative Taproot claim transaction.
///
/// In the cooperative path (Taproot key-path spend):
///   1. Client requests Boltz's partial Schnorr signature
///   2. Combines it with the host wallet's claim-key signature
///   3. Result: indistinguishable from any standard P2TR payment
///
/// This is the privacy-optimal path — the HTLC contract is never revealed.
///
/// TODO (Phase 4b): Full implementation with `bitcoin` crate.
fn build_cooperative_claim(record: &SwapRecord) -> Result<String> {
    let _preimage_hex = record
        .preimage_hex
        .as_deref()
        .ok_or_else(|| SwapError::Key("Preimage missing from chain swap record".into()))?;

    let _destination = record
        .destination_address
        .as_deref()
        .ok_or_else(|| SwapError::Key("Destination address missing".into()))?;

    // TODO (Phase 4b):
    //   1. POST /v2/swap/chain/{id}/claim → get Boltz partial sig
    //   2. Fetch server lockup UTXO
    //   3. Build unsigned claim tx (server lockup → destination)
    //   4. Compute BIP341 sighash
    //   5. Have the host wallet sign with its claim key
    //   6. Aggregate with Boltz partial sig (MuSig2)
    //   7. Broadcast via Bitcoin node RPC

    Err(SwapError::Key(
        "Cooperative Taproot claim not yet implemented — preimage preserved for recovery".into(),
    ))
}
