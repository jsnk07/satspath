//! Unsigned claim/refund transactions for P2WSH HTLC swaps.
//!
//! SatsPath never holds swap spending keys. The builders here return a PSBT
//! for the host wallet to sign (see `WalletExecutor::sign_and_broadcast_psbt`),
//! and the `finalize_*` helpers assemble the HTLC witness from the signature
//! the wallet returns.
//!
//! Only P2WSH HTLCs are supported. Boltz v2 Taproot swaps need a MuSig2
//! key-path or BIP-341 script-path spend, which these builders do not produce.
//!
//! Before anything is built, the witness script is parsed against Boltz's two
//! P2WSH HTLC templates and its terms (payment hash, claim key, refund key,
//! timeout) are compared with what the swap expects. A script that merely
//! hashes to the lockup address is not enough: a counterparty could lock funds
//! to a script with different keys or timelock.

use std::str::FromStr;

use base64::Engine;
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::opcodes::all as op;
use bitcoin::hashes::{hash160, ripemd160, sha256, Hash};
use bitcoin::psbt::{Psbt, PsbtSighashType};
use bitcoin::script::{Instruction, Script};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    Address, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

use crate::errors::{Result, SwapError};
use crate::types::SwapRecord;

/// Parameters to build an unsigned claim transaction for a Reverse swap.
#[derive(Debug, Clone)]
pub struct ReverseClaimTxParams {
    /// Swap identifier.
    pub swap_id: String,
    /// Transaction ID of the Boltz lockup funding transaction.
    pub lockup_txid: String,
    /// Output index (vout) of the lockup UTXO.
    pub lockup_vout: u32,
    /// Value of the lockup UTXO as observed on-chain, in satoshis. This is the
    /// amount the BIP-143 sighash commits to, so it must be the real output
    /// value, not the invoice amount.
    pub lockup_amount_sats: u64,
    /// P2WSH address of the lockup output; must commit to the witness script.
    pub lockup_address: String,
    /// 32-byte secret preimage in hex (revealed on-chain to claim funds).
    pub preimage_hex: String,
    /// Host-wallet public key (compressed hex) that the HTLC must name as the
    /// claim key.
    pub claim_pubkey_hex: String,
    /// Expected HTLC timeout height, if known; checked against the script.
    pub timeout_block_height: Option<u32>,
    /// Destination address where claimed funds will land.
    pub destination_address: String,
    /// P2WSH HTLC witness script hex. Required: the claim cannot be spent without it.
    pub redeem_script_hex: Option<String>,
    /// Miner fee to deduct from the lockup amount (in sats, default 1,000).
    pub miner_fee_sats: u64,
}

/// Parameters to build an unsigned refund transaction for a Submarine swap.
#[derive(Debug, Clone)]
pub struct SubmarineRefundTxParams {
    /// Swap identifier.
    pub swap_id: String,
    /// Transaction ID of the client's lockup funding transaction.
    pub lockup_txid: String,
    /// Output index (vout) of the lockup UTXO.
    pub lockup_vout: u32,
    /// Value of the lockup UTXO as observed on-chain, in satoshis (the amount
    /// the BIP-143 sighash commits to).
    pub lockup_amount_sats: u64,
    /// P2WSH address of the lockup output; must commit to the witness script.
    pub lockup_address: String,
    /// CLTV timeout block height after which refund is valid. Must equal the
    /// timeout in the HTLC script.
    pub timeout_block_height: u32,
    /// Host-wallet public key (compressed hex) that the HTLC must name as the
    /// refund key.
    pub refund_pubkey_hex: String,
    /// SHA-256 payment hash (hex) the HTLC must commit to, if known.
    pub preimage_hash_hex: Option<String>,
    /// Destination address where refunded funds will land.
    pub destination_address: String,
    /// P2WSH HTLC witness script hex. Required: the refund cannot be spent without it.
    pub redeem_script_hex: Option<String>,
    /// Miner fee to deduct from the lockup amount (in sats, default 1,000).
    pub miner_fee_sats: u64,
}

/// An unsigned swap transaction ready for the host wallet to sign.
#[derive(Debug, Clone)]
pub struct UnsignedSwapTx {
    /// PSBT carrying the witness UTXO, witness script and sighash type
    /// (and, for claims, the preimage) the wallet needs to sign input 0.
    pub psbt: Psbt,
    /// `psbt` serialized as base64, for `WalletExecutor::sign_and_broadcast_psbt`.
    pub psbt_base64: String,
    /// Transaction ID. Segwit txids do not depend on the witness, so this is final.
    pub txid: String,
    /// BIP-143 SIGHASH_ALL digest of input 0, hex-encoded.
    pub sighash_hex: String,
    /// HTLC witness script, hex-encoded.
    pub witness_script_hex: String,
    /// Value of the single output in satoshis.
    pub output_amount_sats: u64,
    /// Miner fee in satoshis.
    pub fee_sats: u64,
}

/// Build an unsigned claim transaction for a confirmed Reverse swap.
///
/// The returned PSBT spends the P2WSH HTLC lockup to `destination_address`
/// and carries the preimage in `sha256_preimages`. After the host wallet signs
/// input 0, pass its signature to [`finalize_reverse_claim`].
pub fn build_reverse_claim_tx(params: ReverseClaimTxParams) -> Result<UnsignedSwapTx> {
    let preimage = decode_preimage(&params.preimage_hex)?;
    let input = HtlcInput::new(
        &params.lockup_txid,
        params.lockup_vout,
        params.lockup_amount_sats,
        &params.lockup_address,
        params.redeem_script_hex.as_deref(),
    )?;
    let terms = parse_htlc_script(&input.witness_script)?;
    if terms.payment_hash160 != hash160::Hash::hash(&preimage).to_byte_array() {
        return Err(htlc_mismatch("payment hash does not match the preimage"));
    }
    if terms.claim_pubkey != decode_pubkey(&params.claim_pubkey_hex, "claim")? {
        return Err(htlc_mismatch(
            "claim key is not the host wallet's claim key",
        ));
    }
    if let Some(timeout) = params.timeout_block_height {
        if terms.timeout_block_height != timeout {
            return Err(htlc_mismatch("timeout does not match the swap"));
        }
    }

    let mut built = input.build_unsigned(
        &params.destination_address,
        params.miner_fee_sats,
        LockTime::ZERO,
        Sequence::ENABLE_RBF_NO_LOCKTIME,
    )?;
    built
        .psbt
        .inputs
        .get_mut(0)
        .expect("PSBT has one input")
        .sha256_preimages
        .insert(sha256::Hash::hash(&preimage), preimage.to_vec());
    built.psbt_base64 = encode_psbt(&built.psbt);
    Ok(built)
}

/// Build an unsigned refund transaction for an expired Submarine swap.
///
/// The returned PSBT spends the P2WSH HTLC lockup after `timeout_block_height`.
/// After the host wallet signs input 0, pass its signature to
/// [`finalize_submarine_refund`].
pub fn build_submarine_refund_tx(params: SubmarineRefundTxParams) -> Result<UnsignedSwapTx> {
    let lock_time = LockTime::from_height(params.timeout_block_height)
        .map_err(|e| SwapError::Key(format!("Invalid timeout block height: {e}")))?;
    let input = HtlcInput::new(
        &params.lockup_txid,
        params.lockup_vout,
        params.lockup_amount_sats,
        &params.lockup_address,
        params.redeem_script_hex.as_deref(),
    )?;
    let terms = parse_htlc_script(&input.witness_script)?;
    if terms.refund_pubkey != decode_pubkey(&params.refund_pubkey_hex, "refund")? {
        return Err(htlc_mismatch(
            "refund key is not the host wallet's refund key",
        ));
    }
    // nLockTime comes from the swap; the script's CLTV must be the same height,
    // or the refund is either premature or permanently invalid.
    if terms.timeout_block_height != params.timeout_block_height {
        return Err(htlc_mismatch(
            "timeout does not match the refund's lock time",
        ));
    }
    if let Some(hash_hex) = &params.preimage_hash_hex {
        let payment_hash: [u8; 32] = hex::decode(hash_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| SwapError::Key("Invalid preimage hash hex".into()))?;
        if terms.payment_hash160 != ripemd160::Hash::hash(&payment_hash).to_byte_array() {
            return Err(htlc_mismatch("payment hash does not match the swap"));
        }
    }

    // Any non-final sequence enables nLockTime, which the CLTV branch requires.
    input.build_unsigned(
        &params.destination_address,
        params.miner_fee_sats,
        lock_time,
        Sequence::ENABLE_LOCKTIME_NO_RBF,
    )
}

/// Assemble the claim witness `[signature, preimage, witness_script]` from the
/// host wallet's signature over [`UnsignedSwapTx::sighash_hex`].
///
/// `signature` is a DER-encoded ECDSA signature followed by the SIGHASH_ALL byte.
pub fn finalize_reverse_claim(
    unsigned: &UnsignedSwapTx,
    signature: &[u8],
    preimage_hex: &str,
) -> Result<Transaction> {
    let preimage = decode_preimage(preimage_hex)?;
    finalize(unsigned, signature, preimage.to_vec())
}

/// Assemble the refund witness `[signature, <empty>, witness_script]` from the
/// host wallet's signature. The empty element selects the HTLC's timeout branch.
pub fn finalize_submarine_refund(
    unsigned: &UnsignedSwapTx,
    signature: &[u8],
) -> Result<Transaction> {
    finalize(unsigned, signature, Vec::new())
}

/// Helper to build claim parameters directly from a persisted SwapRecord.
///
/// `lockup_amount_sats` is the value of the lockup UTXO as observed on-chain.
/// For a reverse swap it is below the invoice amount (Boltz deducts its fees),
/// and the sighash must commit to the real value.
pub fn claim_params_from_record(
    record: &SwapRecord,
    lockup_txid: &str,
    lockup_vout: u32,
    lockup_amount_sats: u64,
    destination_address: &str,
) -> Result<ReverseClaimTxParams> {
    let preimage_hex = record
        .preimage_hex
        .clone()
        .ok_or_else(|| SwapError::Key("Record missing preimage".into()))?;
    let claim_pubkey_hex = record
        .claim_pubkey_hex
        .clone()
        .ok_or_else(|| SwapError::Key("Record missing host-wallet claim public key".into()))?;

    Ok(ReverseClaimTxParams {
        swap_id: record.id.clone(),
        lockup_txid: lockup_txid.to_string(),
        lockup_vout,
        lockup_amount_sats,
        lockup_address: record_lockup_address(record)?,
        preimage_hex,
        claim_pubkey_hex,
        timeout_block_height: record.timeout_block_height,
        destination_address: destination_address.to_string(),
        redeem_script_hex: record.redeem_script.clone(),
        miner_fee_sats: 1000,
    })
}

/// Helper to build refund parameters directly from a persisted SwapRecord.
///
/// `lockup_amount_sats` is the value of the lockup UTXO as observed on-chain.
pub fn refund_params_from_record(
    record: &SwapRecord,
    lockup_txid: &str,
    lockup_vout: u32,
    lockup_amount_sats: u64,
    destination_address: &str,
) -> Result<SubmarineRefundTxParams> {
    let timeout_block_height = record
        .timeout_block_height
        .ok_or_else(|| SwapError::Key("Record missing timeout block height".into()))?;
    let refund_pubkey_hex = record
        .refund_pubkey_hex
        .clone()
        .ok_or_else(|| SwapError::Key("Record missing host-wallet refund public key".into()))?;

    Ok(SubmarineRefundTxParams {
        swap_id: record.id.clone(),
        lockup_txid: lockup_txid.to_string(),
        lockup_vout,
        lockup_amount_sats,
        lockup_address: record_lockup_address(record)?,
        timeout_block_height,
        refund_pubkey_hex,
        preimage_hash_hex: record.preimage_hash_hex.clone(),
        destination_address: destination_address.to_string(),
        redeem_script_hex: record.redeem_script.clone(),
        miner_fee_sats: 1000,
    })
}

/// The lockup UTXO being spent, with its witness script checked against the
/// lockup address.
struct HtlcInput {
    outpoint: OutPoint,
    amount_sats: u64,
    script_pubkey: ScriptBuf,
    witness_script: ScriptBuf,
}

impl HtlcInput {
    /// Decode the lockup input and check the script commits to the lockup address.
    fn new(
        lockup_txid: &str,
        lockup_vout: u32,
        amount_sats: u64,
        lockup_address: &str,
        redeem_script_hex: Option<&str>,
    ) -> Result<Self> {
        let txid = Txid::from_str(lockup_txid)
            .map_err(|e| SwapError::Key(format!("Invalid lockup txid: {e}")))?;
        let witness_script = decode_witness_script(redeem_script_hex)?;

        // A script that does not hash to the lockup output yields a transaction
        // that can never spend it, so reject the mismatch before anything is signed.
        let script_pubkey = parse_address(lockup_address, "lockup")?.script_pubkey();
        if script_pubkey != ScriptBuf::new_p2wsh(&witness_script.wscript_hash()) {
            return Err(SwapError::Key(
                "Redeem script does not match the lockup address (P2WSH commitment mismatch)"
                    .into(),
            ));
        }

        Ok(Self {
            outpoint: OutPoint {
                txid,
                vout: lockup_vout,
            },
            amount_sats,
            script_pubkey,
            witness_script,
        })
    }

    /// Build the one-input, one-output transaction, its sighash and PSBT.
    fn build_unsigned(
        &self,
        destination_address: &str,
        miner_fee_sats: u64,
        lock_time: LockTime,
        sequence: Sequence,
    ) -> Result<UnsignedSwapTx> {
        if self.amount_sats <= miner_fee_sats {
            return Err(SwapError::Key(format!(
                "Lockup amount {} sats is too low to cover miner fee {} sats",
                self.amount_sats, miner_fee_sats
            )));
        }
        let output_amount_sats = self.amount_sats - miner_fee_sats;

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time,
            input: vec![TxIn {
                previous_output: self.outpoint,
                script_sig: ScriptBuf::new(),
                sequence,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(output_amount_sats),
                script_pubkey: parse_address(destination_address, "destination")?.script_pubkey(),
            }],
        };

        let sighash = SighashCache::new(&tx)
            .p2wsh_signature_hash(
                0,
                &self.witness_script,
                Amount::from_sat(self.amount_sats),
                EcdsaSighashType::All,
            )
            .map_err(|e| SwapError::Key(format!("Sighash computation failed: {e}")))?;

        let mut psbt = Psbt::from_unsigned_tx(tx.clone())
            .map_err(|e| SwapError::Key(format!("PSBT construction failed: {e}")))?;
        let input = &mut psbt.inputs[0];
        input.witness_utxo = Some(TxOut {
            value: Amount::from_sat(self.amount_sats),
            script_pubkey: self.script_pubkey.clone(),
        });
        input.witness_script = Some(self.witness_script.clone());
        input.sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::All));

        Ok(UnsignedSwapTx {
            psbt_base64: encode_psbt(&psbt),
            psbt,
            txid: tx.compute_txid().to_string(),
            sighash_hex: hex::encode(sighash.to_byte_array()),
            witness_script_hex: hex::encode(self.witness_script.as_bytes()),
            output_amount_sats,
            fee_sats: miner_fee_sats,
        })
    }
}

/// Place `[signature, branch_selector, witness_script]` on input 0.
fn finalize(
    unsigned: &UnsignedSwapTx,
    signature: &[u8],
    branch_selector: Vec<u8>,
) -> Result<Transaction> {
    let (sighash_byte, der) = signature
        .split_last()
        .ok_or_else(|| SwapError::Key("Empty signature".into()))?;
    if u32::from(*sighash_byte) != EcdsaSighashType::All.to_u32() {
        return Err(SwapError::Key("Signature must use SIGHASH_ALL".into()));
    }
    bitcoin::secp256k1::ecdsa::Signature::from_der(der)
        .map_err(|e| SwapError::Key(format!("Invalid DER signature: {e}")))?;

    let witness_script = unsigned.psbt.inputs[0]
        .witness_script
        .clone()
        .ok_or_else(|| SwapError::Key("PSBT is missing the witness script".into()))?;

    let mut tx = unsigned.psbt.unsigned_tx.clone();
    let mut witness = Witness::new();
    witness.push(signature);
    witness.push(branch_selector);
    witness.push(witness_script.as_bytes());
    tx.input[0].witness = witness;
    Ok(tx)
}

/// The terms of a Boltz P2WSH HTLC, read from its witness script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HtlcTerms {
    /// HASH160 (RIPEMD160 of SHA-256) of the preimage the claim path requires.
    pub payment_hash160: [u8; 20],
    /// Compressed public key that can claim with the preimage.
    pub claim_pubkey: [u8; 33],
    /// Compressed public key that can refund after the timeout.
    pub refund_pubkey: [u8; 33],
    /// Absolute block height of the refund timelock (OP_CHECKLOCKTIMEVERIFY).
    pub timeout_block_height: u32,
}

/// Parse a Boltz P2WSH HTLC witness script. Accepts exactly the two templates
/// Boltz uses and rejects anything else:
///
/// * reverse swap: `OP_SIZE 32 OP_EQUAL OP_IF OP_HASH160 <h160> OP_EQUALVERIFY
///   <claim> OP_ELSE OP_DROP <cltv> OP_CLTV OP_DROP <refund> OP_ENDIF OP_CHECKSIG`
/// * submarine swap: `OP_HASH160 <h160> OP_EQUAL OP_IF <claim> OP_ELSE <cltv>
///   OP_CLTV OP_DROP <refund> OP_ENDIF OP_CHECKSIG`
pub fn parse_htlc_script(script: &Script) -> Result<HtlcTerms> {
    let unrecognized = || htlc_mismatch("script is not a recognized Boltz P2WSH HTLC");
    let tokens = script
        .instructions_minimal()
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| unrecognized())?;
    let opcode = |i: usize, expected: bitcoin::Opcode| matches!(tokens.get(i), Some(Instruction::Op(o)) if *o == expected);
    let push = |i: usize, len: usize| match tokens.get(i) {
        Some(Instruction::PushBytes(b)) if b.len() == len => Some(b.as_bytes().to_vec()),
        _ => None,
    };
    let cltv = |i: usize| match tokens.get(i) {
        Some(Instruction::PushBytes(b)) if !b.is_empty() && b.len() <= 5 => {
            bitcoin::script::read_scriptint(b.as_bytes())
                .ok()
                .and_then(|n| u32::try_from(n).ok())
        }
        _ => None,
    };

    // Reverse-swap template.
    let reverse = tokens.len() == 16
        && opcode(0, op::OP_SIZE)
        && push(1, 1).as_deref() == Some(&[32u8][..])
        && opcode(2, op::OP_EQUAL)
        && opcode(3, op::OP_IF)
        && opcode(4, op::OP_HASH160)
        && opcode(6, op::OP_EQUALVERIFY)
        && opcode(8, op::OP_ELSE)
        && opcode(9, op::OP_DROP)
        && opcode(11, op::OP_CLTV)
        && opcode(12, op::OP_DROP)
        && opcode(14, op::OP_ENDIF)
        && opcode(15, op::OP_CHECKSIG);
    // Submarine-swap template.
    let submarine = tokens.len() == 12
        && opcode(0, op::OP_HASH160)
        && opcode(2, op::OP_EQUAL)
        && opcode(3, op::OP_IF)
        && opcode(5, op::OP_ELSE)
        && opcode(7, op::OP_CLTV)
        && opcode(8, op::OP_DROP)
        && opcode(10, op::OP_ENDIF)
        && opcode(11, op::OP_CHECKSIG);

    let (hash_at, claim_at, cltv_at, refund_at) = if reverse {
        (5, 7, 10, 13)
    } else if submarine {
        (1, 4, 6, 9)
    } else {
        return Err(unrecognized());
    };
    let payment_hash160 = push(hash_at, 20).ok_or_else(unrecognized)?;
    let claim_pubkey = push(claim_at, 33).ok_or_else(unrecognized)?;
    let refund_pubkey = push(refund_at, 33).ok_or_else(unrecognized)?;
    let timeout_block_height = cltv(cltv_at).ok_or_else(unrecognized)?;
    for key in [&claim_pubkey, &refund_pubkey] {
        bitcoin::secp256k1::PublicKey::from_slice(key).map_err(|_| unrecognized())?;
    }
    Ok(HtlcTerms {
        payment_hash160: payment_hash160.try_into().map_err(|_| unrecognized())?,
        claim_pubkey: claim_pubkey.try_into().map_err(|_| unrecognized())?,
        refund_pubkey: refund_pubkey.try_into().map_err(|_| unrecognized())?,
        timeout_block_height,
    })
}

/// Build the Boltz reverse-swap P2WSH HTLC script for `terms`.
pub fn reverse_htlc_script(terms: &HtlcTerms) -> ScriptBuf {
    bitcoin::script::Builder::new()
        .push_opcode(op::OP_SIZE)
        .push_int(32)
        .push_opcode(op::OP_EQUAL)
        .push_opcode(op::OP_IF)
        .push_opcode(op::OP_HASH160)
        .push_slice(terms.payment_hash160)
        .push_opcode(op::OP_EQUALVERIFY)
        .push_slice(terms.claim_pubkey)
        .push_opcode(op::OP_ELSE)
        .push_opcode(op::OP_DROP)
        .push_int(i64::from(terms.timeout_block_height))
        .push_opcode(op::OP_CLTV)
        .push_opcode(op::OP_DROP)
        .push_slice(terms.refund_pubkey)
        .push_opcode(op::OP_ENDIF)
        .push_opcode(op::OP_CHECKSIG)
        .into_script()
}

/// Build the Boltz submarine-swap P2WSH HTLC script for `terms`.
pub fn submarine_htlc_script(terms: &HtlcTerms) -> ScriptBuf {
    bitcoin::script::Builder::new()
        .push_opcode(op::OP_HASH160)
        .push_slice(terms.payment_hash160)
        .push_opcode(op::OP_EQUAL)
        .push_opcode(op::OP_IF)
        .push_slice(terms.claim_pubkey)
        .push_opcode(op::OP_ELSE)
        .push_int(i64::from(terms.timeout_block_height))
        .push_opcode(op::OP_CLTV)
        .push_opcode(op::OP_DROP)
        .push_slice(terms.refund_pubkey)
        .push_opcode(op::OP_ENDIF)
        .push_opcode(op::OP_CHECKSIG)
        .into_script()
}

/// An HTLC term that does not match what the swap expects.
fn htlc_mismatch(what: &str) -> SwapError {
    SwapError::Key(format!("HTLC script rejected: {what}"))
}

/// Decode a compressed public key from hex.
fn decode_pubkey(hex_key: &str, label: &str) -> Result<[u8; 33]> {
    let bytes = hex::decode(hex_key)
        .map_err(|e| SwapError::Key(format!("Invalid {label} public key hex: {e}")))?;
    bitcoin::secp256k1::PublicKey::from_slice(&bytes)
        .map_err(|e| SwapError::Key(format!("Invalid {label} public key: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| SwapError::Key(format!("{label} public key must be compressed")))
}

fn decode_preimage(preimage_hex: &str) -> Result<[u8; 32]> {
    hex::decode(preimage_hex)
        .map_err(|e| SwapError::Key(format!("Invalid preimage hex: {e}")))?
        .try_into()
        .map_err(|_| SwapError::Key("Preimage must be 32 bytes".into()))
}

/// Decode the HTLC witness script. A missing script is an error: spending
/// against a synthesized script would produce a transaction that can never be
/// valid on-chain.
fn decode_witness_script(redeem_script_hex: Option<&str>) -> Result<ScriptBuf> {
    let rs_hex = redeem_script_hex
        .ok_or_else(|| SwapError::Key("Redeem script missing: cannot spend HTLC".into()))?;
    let bytes = hex::decode(rs_hex)
        .map_err(|e| SwapError::Key(format!("Invalid redeem script hex: {e}")))?;
    if bytes.is_empty() {
        return Err(SwapError::Key("Redeem script is empty".into()));
    }
    Ok(ScriptBuf::from_bytes(bytes))
}

fn parse_address(address: &str, label: &str) -> Result<Address> {
    Ok(Address::from_str(address)
        .map_err(|e| SwapError::Key(format!("Invalid {label} address: {e}")))?
        .assume_checked())
}

fn record_lockup_address(record: &SwapRecord) -> Result<String> {
    record
        .lockup_address
        .clone()
        .ok_or_else(|| SwapError::Key("Record missing lockup address".into()))
}

fn encode_psbt(psbt: &Psbt) -> String {
    base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::Network;

    const DEST: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    const PREIMAGE: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const TIMEOUT: u32 = 850_000;

    /// The host wallet's key (claims reverse swaps, refunds submarine swaps).
    fn wallet_secret() -> SecretKey {
        SecretKey::from_slice(&[3u8; 32]).unwrap()
    }

    /// Compressed public key for `secret`.
    fn pubkey(secret: &SecretKey) -> [u8; 33] {
        secret.public_key(&Secp256k1::new()).serialize()
    }

    /// Boltz's key in these tests.
    fn boltz_pubkey() -> [u8; 33] {
        pubkey(&SecretKey::from_slice(&[2u8; 32]).unwrap())
    }

    /// Terms of a reverse swap the host wallet can claim with `PREIMAGE`.
    fn reverse_terms() -> HtlcTerms {
        HtlcTerms {
            payment_hash160: hash160::Hash::hash(&hex::decode(PREIMAGE).unwrap()).to_byte_array(),
            claim_pubkey: pubkey(&wallet_secret()),
            refund_pubkey: boltz_pubkey(),
            timeout_block_height: TIMEOUT,
        }
    }

    /// Terms of a submarine swap the host wallet can refund after `TIMEOUT`.
    fn submarine_terms() -> HtlcTerms {
        HtlcTerms {
            claim_pubkey: boltz_pubkey(),
            refund_pubkey: pubkey(&wallet_secret()),
            ..reverse_terms()
        }
    }

    /// Hex of the reverse-swap HTLC script.
    fn reverse_script_hex() -> String {
        hex::encode(reverse_htlc_script(&reverse_terms()).as_bytes())
    }

    /// Testnet P2WSH address committing to `script_hex`.
    fn lockup_address(script_hex: &str) -> String {
        let script = ScriptBuf::from_bytes(hex::decode(script_hex).unwrap());
        Address::p2wsh(&script, Network::Testnet).to_string()
    }

    /// Claim parameters for the reverse swap, with the given witness script.
    fn claim_params(redeem_script_hex: Option<String>) -> ReverseClaimTxParams {
        ReverseClaimTxParams {
            swap_id: "swap_rev".into(),
            lockup_txid: "0000000000000000000000000000000000000000000000000000000000000003".into(),
            lockup_vout: 0,
            lockup_amount_sats: 60_000,
            lockup_address: lockup_address(&reverse_script_hex()),
            preimage_hex: PREIMAGE.into(),
            claim_pubkey_hex: hex::encode(pubkey(&wallet_secret())),
            timeout_block_height: Some(TIMEOUT),
            destination_address: DEST.into(),
            redeem_script_hex,
            miner_fee_sats: 1_000,
        }
    }

    /// Refund parameters for the submarine swap.
    fn refund_params() -> SubmarineRefundTxParams {
        let script_hex = hex::encode(submarine_htlc_script(&submarine_terms()).as_bytes());
        let payment_hash = sha256::Hash::hash(&hex::decode(PREIMAGE).unwrap());
        SubmarineRefundTxParams {
            swap_id: "swap_sub".into(),
            lockup_txid: "0000000000000000000000000000000000000000000000000000000000000002".into(),
            lockup_vout: 1,
            lockup_amount_sats: 100_000,
            lockup_address: lockup_address(&script_hex),
            timeout_block_height: TIMEOUT,
            refund_pubkey_hex: hex::encode(pubkey(&wallet_secret())),
            preimage_hash_hex: Some(hex::encode(payment_hash.to_byte_array())),
            destination_address: DEST.into(),
            redeem_script_hex: Some(script_hex),
            miner_fee_sats: 1_500,
        }
    }

    /// Stands in for the host wallet: SatsPath itself never signs.
    fn wallet_sign(sighash_hex: &str, secret: &SecretKey) -> Vec<u8> {
        let digest: [u8; 32] = hex::decode(sighash_hex).unwrap().try_into().unwrap();
        let sig = Secp256k1::new().sign_ecdsa(&Message::from_digest(digest), secret);
        let mut out = sig.serialize_der().to_vec();
        out.push(EcdsaSighashType::All.to_u32() as u8);
        out
    }

    /// Both Boltz templates parse back to the terms they were built from;
    /// anything else is rejected.
    #[test]
    fn htlc_templates_round_trip_and_others_are_rejected() {
        let rev = reverse_terms();
        assert_eq!(parse_htlc_script(&reverse_htlc_script(&rev)).unwrap(), rev);
        let sub = submarine_terms();
        assert_eq!(
            parse_htlc_script(&submarine_htlc_script(&sub)).unwrap(),
            sub
        );
        for junk in ["6352670068", "51", ""] {
            let script = ScriptBuf::from_bytes(hex::decode(junk).unwrap());
            assert!(parse_htlc_script(&script).is_err(), "{junk}");
        }
    }

    /// The PSBT carries the witness UTXO, witness script and preimage.
    #[test]
    fn reverse_claim_psbt_carries_what_the_wallet_needs() {
        let built = build_reverse_claim_tx(claim_params(Some(reverse_script_hex()))).unwrap();
        assert_eq!(built.output_amount_sats, 59_000);
        assert_eq!(built.fee_sats, 1_000);

        let input = &built.psbt.inputs[0];
        let script = reverse_htlc_script(&reverse_terms());
        assert_eq!(input.witness_script.as_ref(), Some(&script));
        let utxo = input.witness_utxo.as_ref().unwrap();
        assert_eq!(utxo.value.to_sat(), 60_000);
        assert_eq!(
            utxo.script_pubkey,
            ScriptBuf::new_p2wsh(&script.wscript_hash())
        );
        let preimage = hex::decode(PREIMAGE).unwrap();
        assert_eq!(
            input.sha256_preimages.get(&sha256::Hash::hash(&preimage)),
            Some(&preimage)
        );
        assert!(built.psbt.unsigned_tx.input[0].witness.is_empty());

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&built.psbt_base64)
            .unwrap();
        assert_eq!(Psbt::deserialize(&decoded).unwrap(), built.psbt);
    }

    /// The reported sighash is the BIP-143 digest over the lockup value.
    #[test]
    fn sighash_is_the_bip143_digest() {
        let built = build_reverse_claim_tx(claim_params(Some(reverse_script_hex()))).unwrap();
        let script = reverse_htlc_script(&reverse_terms());
        let expected = SighashCache::new(&built.psbt.unsigned_tx)
            .p2wsh_signature_hash(0, &script, Amount::from_sat(60_000), EcdsaSighashType::All)
            .unwrap();
        assert_eq!(built.sighash_hex, hex::encode(expected.to_byte_array()));
    }

    /// The finalized claim has the HTLC witness and a signature that verifies
    /// under the claim key named in the script.
    #[test]
    fn finalized_claim_has_htlc_witness_and_verifiable_signature() {
        let built = build_reverse_claim_tx(claim_params(Some(reverse_script_hex()))).unwrap();
        let secret = wallet_secret();
        let sig = wallet_sign(&built.sighash_hex, &secret);

        let tx = finalize_reverse_claim(&built, &sig, PREIMAGE).unwrap();
        let witness = &tx.input[0].witness;
        assert_eq!(witness.len(), 3);
        assert_eq!(witness.nth(0).unwrap(), &sig[..]);
        assert_eq!(witness.nth(1).unwrap(), &hex::decode(PREIMAGE).unwrap()[..]);
        assert_eq!(
            witness.nth(2).unwrap(),
            &hex::decode(reverse_script_hex()).unwrap()[..]
        );
        assert_eq!(tx.compute_txid().to_string(), built.txid);

        let digest: [u8; 32] = hex::decode(&built.sighash_hex).unwrap().try_into().unwrap();
        let der = bitcoin::secp256k1::ecdsa::Signature::from_der(&sig[..sig.len() - 1]).unwrap();
        Secp256k1::new()
            .verify_ecdsa(
                &Message::from_digest(digest),
                &der,
                &secret.public_key(&Secp256k1::new()),
            )
            .expect("signature over the PSBT sighash must verify");
    }

    /// A script that does not hash to the lockup address is rejected.
    #[test]
    fn mismatched_redeem_script_is_rejected() {
        let mut params = claim_params(Some(reverse_script_hex()));
        params.lockup_address = lockup_address("6352670168");
        let err = build_reverse_claim_tx(params).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not match the lockup address"));
    }

    /// A claim cannot be built without the witness script.
    #[test]
    fn claim_without_redeem_script_is_rejected() {
        let err = build_reverse_claim_tx(claim_params(None)).unwrap_err();
        assert!(err.to_string().contains("Redeem script missing"));
    }

    /// An HTLC naming someone else's claim key, a different payment hash or a
    /// different timeout is refused even though it matches the lockup address.
    #[test]
    fn claim_rejects_htlc_with_unexpected_terms() {
        let other_key = pubkey(&SecretKey::from_slice(&[9u8; 32]).unwrap());
        let variants = [
            HtlcTerms {
                claim_pubkey: other_key,
                ..reverse_terms()
            },
            HtlcTerms {
                payment_hash160: [7u8; 20],
                ..reverse_terms()
            },
            HtlcTerms {
                timeout_block_height: TIMEOUT + 1,
                ..reverse_terms()
            },
        ];
        for terms in variants {
            let script_hex = hex::encode(reverse_htlc_script(&terms).as_bytes());
            let mut params = claim_params(Some(script_hex.clone()));
            params.lockup_address = lockup_address(&script_hex);
            let err = build_reverse_claim_tx(params).unwrap_err();
            assert!(err.to_string().contains("HTLC script rejected"), "{err}");
        }
    }

    /// A non-SIGHASH_ALL signature is refused.
    #[test]
    fn finalize_rejects_non_sighash_all_signature() {
        let built = build_reverse_claim_tx(claim_params(Some(reverse_script_hex()))).unwrap();
        let mut sig = wallet_sign(&built.sighash_hex, &wallet_secret());
        *sig.last_mut().unwrap() = EcdsaSighashType::None.to_u32() as u8;
        assert!(finalize_reverse_claim(&built, &sig, PREIMAGE).is_err());
    }

    /// The refund is timelocked to the script's CLTV and uses the timeout branch.
    #[test]
    fn submarine_refund_is_timelocked_and_finalizes_on_timeout_branch() {
        let built = build_submarine_refund_tx(refund_params()).unwrap();
        assert_eq!(built.output_amount_sats, 98_500);
        let unsigned = &built.psbt.unsigned_tx;
        assert_eq!(unsigned.lock_time.to_consensus_u32(), TIMEOUT);
        assert!(unsigned.input[0].sequence.enables_absolute_lock_time());

        let sig = wallet_sign(&built.sighash_hex, &wallet_secret());
        let tx = finalize_submarine_refund(&built, &sig).unwrap();
        assert_eq!(tx.input[0].witness.len(), 3);
        assert!(tx.input[0].witness.nth(1).unwrap().is_empty());
    }

    /// A refund whose lock time differs from the script's CLTV, or whose HTLC
    /// names another refund key, is refused.
    #[test]
    fn refund_rejects_mismatched_timeout_or_key() {
        let mut early = refund_params();
        early.timeout_block_height = TIMEOUT - 1;
        assert!(build_submarine_refund_tx(early).is_err());

        let mut foreign = refund_params();
        foreign.refund_pubkey_hex = hex::encode(boltz_pubkey());
        assert!(build_submarine_refund_tx(foreign).is_err());
    }
}
