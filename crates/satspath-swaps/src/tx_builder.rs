//! Unsigned claim/refund transactions for P2WSH HTLC swaps.
//!
//! SatsPath never holds swap spending keys. The builders here return a PSBT
//! for the host wallet to sign (see `WalletExecutor::sign_and_broadcast_psbt`),
//! and the `finalize_*` helpers assemble the HTLC witness from the signature
//! the wallet returns.
//!
//! Only P2WSH HTLCs are supported. Boltz v2 Taproot swaps need a MuSig2
//! key-path or BIP-341 script-path spend, which these builders do not produce.

use std::str::FromStr;

use base64::Engine;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::{Psbt, PsbtSighashType};
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
    /// Amount locked by Boltz in satoshis.
    pub lockup_amount_sats: u64,
    /// P2WSH address of the lockup output; must commit to the witness script.
    pub lockup_address: String,
    /// 32-byte secret preimage in hex (revealed on-chain to claim funds).
    pub preimage_hex: String,
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
    /// Amount locked by client in satoshis.
    pub lockup_amount_sats: u64,
    /// P2WSH address of the lockup output; must commit to the witness script.
    pub lockup_address: String,
    /// CLTV timeout block height after which refund is valid.
    pub timeout_block_height: u32,
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
pub fn claim_params_from_record(
    record: &SwapRecord,
    lockup_txid: &str,
    lockup_vout: u32,
    destination_address: &str,
) -> Result<ReverseClaimTxParams> {
    let preimage_hex = record
        .preimage_hex
        .clone()
        .ok_or_else(|| SwapError::Key("Record missing preimage".into()))?;

    Ok(ReverseClaimTxParams {
        swap_id: record.id.clone(),
        lockup_txid: lockup_txid.to_string(),
        lockup_vout,
        lockup_amount_sats: record.expected_amount_sats.unwrap_or(record.amount_sats),
        lockup_address: record_lockup_address(record)?,
        preimage_hex,
        destination_address: destination_address.to_string(),
        redeem_script_hex: record.redeem_script.clone(),
        miner_fee_sats: 1000,
    })
}

/// Helper to build refund parameters directly from a persisted SwapRecord.
pub fn refund_params_from_record(
    record: &SwapRecord,
    lockup_txid: &str,
    lockup_vout: u32,
    destination_address: &str,
) -> Result<SubmarineRefundTxParams> {
    let timeout_block_height = record
        .timeout_block_height
        .ok_or_else(|| SwapError::Key("Record missing timeout block height".into()))?;

    Ok(SubmarineRefundTxParams {
        swap_id: record.id.clone(),
        lockup_txid: lockup_txid.to_string(),
        lockup_vout,
        lockup_amount_sats: record.expected_amount_sats.unwrap_or(record.amount_sats),
        lockup_address: record_lockup_address(record)?,
        timeout_block_height,
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
    const SCRIPT: &str = "6352670068";

    fn lockup_address(script_hex: &str) -> String {
        let script = ScriptBuf::from_bytes(hex::decode(script_hex).unwrap());
        Address::p2wsh(&script, Network::Testnet).to_string()
    }

    fn claim_params(redeem_script_hex: Option<String>) -> ReverseClaimTxParams {
        ReverseClaimTxParams {
            swap_id: "swap_rev".into(),
            lockup_txid: "0000000000000000000000000000000000000000000000000000000000000003".into(),
            lockup_vout: 0,
            lockup_amount_sats: 60_000,
            lockup_address: lockup_address(SCRIPT),
            preimage_hex: PREIMAGE.into(),
            destination_address: DEST.into(),
            redeem_script_hex,
            miner_fee_sats: 1_000,
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

    #[test]
    fn reverse_claim_psbt_carries_what_the_wallet_needs() {
        let built = build_reverse_claim_tx(claim_params(Some(SCRIPT.into()))).unwrap();
        assert_eq!(built.output_amount_sats, 59_000);
        assert_eq!(built.fee_sats, 1_000);

        let input = &built.psbt.inputs[0];
        let script = ScriptBuf::from_bytes(hex::decode(SCRIPT).unwrap());
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

    #[test]
    fn sighash_is_the_bip143_digest() {
        let built = build_reverse_claim_tx(claim_params(Some(SCRIPT.into()))).unwrap();
        let script = ScriptBuf::from_bytes(hex::decode(SCRIPT).unwrap());
        let expected = SighashCache::new(&built.psbt.unsigned_tx)
            .p2wsh_signature_hash(0, &script, Amount::from_sat(60_000), EcdsaSighashType::All)
            .unwrap();
        assert_eq!(built.sighash_hex, hex::encode(expected.to_byte_array()));
    }

    #[test]
    fn finalized_claim_has_htlc_witness_and_verifiable_signature() {
        let built = build_reverse_claim_tx(claim_params(Some(SCRIPT.into()))).unwrap();
        let secret = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let sig = wallet_sign(&built.sighash_hex, &secret);

        let tx = finalize_reverse_claim(&built, &sig, PREIMAGE).unwrap();
        let witness = &tx.input[0].witness;
        assert_eq!(witness.len(), 3);
        assert_eq!(witness.nth(0).unwrap(), &sig[..]);
        assert_eq!(witness.nth(1).unwrap(), &hex::decode(PREIMAGE).unwrap()[..]);
        assert_eq!(witness.nth(2).unwrap(), &hex::decode(SCRIPT).unwrap()[..]);
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

    #[test]
    fn mismatched_redeem_script_is_rejected() {
        let mut params = claim_params(Some(SCRIPT.into()));
        params.lockup_address = lockup_address("6352670168");
        let err = build_reverse_claim_tx(params).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not match the lockup address"));
    }

    #[test]
    fn claim_without_redeem_script_is_rejected() {
        let err = build_reverse_claim_tx(claim_params(None)).unwrap_err();
        assert!(err.to_string().contains("Redeem script missing"));
    }

    #[test]
    fn finalize_rejects_non_sighash_all_signature() {
        let built = build_reverse_claim_tx(claim_params(Some(SCRIPT.into()))).unwrap();
        let mut sig = wallet_sign(
            &built.sighash_hex,
            &SecretKey::from_slice(&[3u8; 32]).unwrap(),
        );
        *sig.last_mut().unwrap() = EcdsaSighashType::None.to_u32() as u8;
        assert!(finalize_reverse_claim(&built, &sig, PREIMAGE).is_err());
    }

    #[test]
    fn submarine_refund_is_timelocked_and_finalizes_on_timeout_branch() {
        let built = build_submarine_refund_tx(SubmarineRefundTxParams {
            swap_id: "swap_sub".into(),
            lockup_txid: "0000000000000000000000000000000000000000000000000000000000000002".into(),
            lockup_vout: 1,
            lockup_amount_sats: 100_000,
            lockup_address: lockup_address("6352670168"),
            timeout_block_height: 850_000,
            destination_address: DEST.into(),
            redeem_script_hex: Some("6352670168".into()),
            miner_fee_sats: 1_500,
        })
        .unwrap();
        assert_eq!(built.output_amount_sats, 98_500);
        let unsigned = &built.psbt.unsigned_tx;
        assert_eq!(unsigned.lock_time.to_consensus_u32(), 850_000);
        assert!(unsigned.input[0].sequence.enables_absolute_lock_time());

        let sig = wallet_sign(
            &built.sighash_hex,
            &SecretKey::from_slice(&[2u8; 32]).unwrap(),
        );
        let tx = finalize_submarine_refund(&built, &sig).unwrap();
        assert_eq!(tx.input[0].witness.len(), 3);
        assert!(tx.input[0].witness.nth(1).unwrap().is_empty());
    }
}
