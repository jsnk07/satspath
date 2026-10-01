use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};

use crate::errors::{Result, SwapError};
use crate::types::SwapRecord;

/// Parameters to build an on-chain Claim transaction for a Reverse Swap or Chain Swap.
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
    /// 32-byte secret preimage in hex (revealed on-chain to claim funds).
    pub preimage_hex: String,
    /// Ephemeral private key hex for the claim output.
    pub claim_key_hex: String,
    /// Destination address where claimed funds will land.
    pub destination_address: String,
    /// P2WSH HTLC witness script hex. Required: the claim cannot be signed without it.
    pub redeem_script_hex: Option<String>,
    /// Miner fee to deduct from the lockup amount (in sats, default 1,000).
    pub miner_fee_sats: u64,
}

/// Parameters to build an on-chain Refund transaction for a Submarine Swap or Chain Swap.
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
    /// Ephemeral private key hex for the refund output.
    pub refund_key_hex: String,
    /// CLTV timeout block height after which refund is valid.
    pub timeout_block_height: u32,
    /// Destination address where refunded funds will land.
    pub destination_address: String,
    /// P2WSH HTLC witness script hex. Required: the refund cannot be signed without it.
    pub redeem_script_hex: Option<String>,
    /// Miner fee to deduct from the lockup amount (in sats, default 1,000).
    pub miner_fee_sats: u64,
}

/// Built transaction ready for broadcasting, along with its calculated txid and fee.
#[derive(Debug, Clone)]
pub struct BuiltSwapTx {
    pub transaction: Transaction,
    pub txid: String,
    pub raw_hex: String,
    pub output_amount_sats: u64,
    pub fee_sats: u64,
}

/// Build an on-chain Claim transaction for a confirmed Reverse swap.
///
/// Spends a P2WSH HTLC lockup UTXO by fulfilling the hash-lock (revealing the 32-byte
/// preimage) and signing the BIP-143 sighash with the claim private key.
///
/// Only P2WSH HTLCs are supported. Boltz v2 Taproot swaps need a MuSig2 key-path or
/// BIP-341 script-path spend, which this builder does not produce.
pub fn build_reverse_claim_tx(params: ReverseClaimTxParams) -> Result<BuiltSwapTx> {
    if params.lockup_amount_sats <= params.miner_fee_sats {
        return Err(SwapError::Key(format!(
            "Lockup amount {} sats is too low to cover miner fee {} sats",
            params.lockup_amount_sats, params.miner_fee_sats
        )));
    }

    let net_output_sats = params.lockup_amount_sats - params.miner_fee_sats;

    let txid = Txid::from_str(&params.lockup_txid)
        .map_err(|e| SwapError::Key(format!("Invalid lockup txid: {e}")))?;

    let outpoint = OutPoint {
        txid,
        vout: params.lockup_vout,
    };

    let dest_address = Address::from_str(&params.destination_address)
        .map_err(|e| SwapError::Key(format!("Invalid destination address: {e}")))?
        .assume_checked();

    let tx_in = TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };

    let tx_out = TxOut {
        value: Amount::from_sat(net_output_sats),
        script_pubkey: dest_address.script_pubkey(),
    };

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![tx_in],
        output: vec![tx_out],
    };

    // Decode preimage and claim key
    let preimage_bytes = hex::decode(&params.preimage_hex)
        .map_err(|e| SwapError::Key(format!("Invalid preimage hex: {e}")))?;
    if preimage_bytes.len() != 32 {
        return Err(SwapError::Key("Preimage must be 32 bytes".into()));
    }

    let claim_key_bytes = hex::decode(&params.claim_key_hex)
        .map_err(|e| SwapError::Key(format!("Invalid claim key hex: {e}")))?;
    let secp = Secp256k1::new();
    let claim_secret = SecretKey::from_slice(&claim_key_bytes)
        .map_err(|e| SwapError::Key(format!("Invalid claim secret key: {e}")))?;

    let redeem_script = decode_witness_script(params.redeem_script_hex.as_deref())?;
    let sig_der = sign_p2wsh_input(
        &tx,
        &redeem_script,
        params.lockup_amount_sats,
        &claim_secret,
        &secp,
    )?;

    // Witness stack for P2WSH HTLC claim spend: [signature, preimage, witness_script]
    let mut witness = Witness::new();
    witness.push(sig_der);
    witness.push(preimage_bytes);
    witness.push(redeem_script.as_bytes());

    tx.input[0].witness = witness;

    let computed_txid = tx.compute_txid().to_string();
    let raw_hex = hex::encode(bitcoin::consensus::serialize(&tx));

    Ok(BuiltSwapTx {
        transaction: tx,
        txid: computed_txid,
        raw_hex,
        output_amount_sats: net_output_sats,
        fee_sats: params.miner_fee_sats,
    })
}

/// Build an on-chain Refund transaction for an expired Submarine swap.
///
/// Spends a P2WSH HTLC lockup UTXO after `timeout_block_height`, signing the BIP-143
/// sighash with the client's refund private key. Taproot lockups are not supported.
pub fn build_submarine_refund_tx(params: SubmarineRefundTxParams) -> Result<BuiltSwapTx> {
    if params.lockup_amount_sats <= params.miner_fee_sats {
        return Err(SwapError::Key(format!(
            "Lockup amount {} sats is too low to cover miner fee {} sats",
            params.lockup_amount_sats, params.miner_fee_sats
        )));
    }

    let net_output_sats = params.lockup_amount_sats - params.miner_fee_sats;

    let txid = Txid::from_str(&params.lockup_txid)
        .map_err(|e| SwapError::Key(format!("Invalid lockup txid: {e}")))?;

    let outpoint = OutPoint {
        txid,
        vout: params.lockup_vout,
    };

    let dest_address = Address::from_str(&params.destination_address)
        .map_err(|e| SwapError::Key(format!("Invalid destination address: {e}")))?
        .assume_checked();

    let lock_time = LockTime::from_height(params.timeout_block_height)
        .map_err(|e| SwapError::Key(format!("Invalid timeout block height: {e}")))?;

    let tx_in = TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::from_height(1),
        witness: Witness::new(),
    };

    let tx_out = TxOut {
        value: Amount::from_sat(net_output_sats),
        script_pubkey: dest_address.script_pubkey(),
    };

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time,
        input: vec![tx_in],
        output: vec![tx_out],
    };

    // Decode refund secret key
    let refund_key_bytes = hex::decode(&params.refund_key_hex)
        .map_err(|e| SwapError::Key(format!("Invalid refund key hex: {e}")))?;
    let secp = Secp256k1::new();
    let refund_secret = SecretKey::from_slice(&refund_key_bytes)
        .map_err(|e| SwapError::Key(format!("Invalid refund secret key: {e}")))?;

    let redeem_script = decode_witness_script(params.redeem_script_hex.as_deref())?;
    let sig_der = sign_p2wsh_input(
        &tx,
        &redeem_script,
        params.lockup_amount_sats,
        &refund_secret,
        &secp,
    )?;

    // Witness stack for refund:
    // [signature, 0, redeem_script] (CLTV branch)
    let mut witness = Witness::new();
    witness.push(sig_der);
    witness.push(vec![]); // 0 pushes false to select the timeout branch
    witness.push(redeem_script.as_bytes());

    tx.input[0].witness = witness;

    let computed_txid = tx.compute_txid().to_string();
    let raw_hex = hex::encode(bitcoin::consensus::serialize(&tx));

    Ok(BuiltSwapTx {
        transaction: tx,
        txid: computed_txid,
        raw_hex,
        output_amount_sats: net_output_sats,
        fee_sats: params.miner_fee_sats,
    })
}

/// Decode the HTLC witness script. A missing script is an error: signing against a
/// synthesized script would produce a spend that can never be valid on-chain.
fn decode_witness_script(redeem_script_hex: Option<&str>) -> Result<ScriptBuf> {
    let rs_hex = redeem_script_hex
        .ok_or_else(|| SwapError::Key("Redeem script missing: cannot sign HTLC spend".into()))?;
    let bytes = hex::decode(rs_hex)
        .map_err(|e| SwapError::Key(format!("Invalid redeem script hex: {e}")))?;
    if bytes.is_empty() {
        return Err(SwapError::Key("Redeem script is empty".into()));
    }
    Ok(ScriptBuf::from_bytes(bytes))
}

/// Sign input 0 of `tx` as a P2WSH spend using the BIP-143 segwit v0 sighash,
/// returning a DER signature with the SIGHASH_ALL byte appended.
fn sign_p2wsh_input(
    tx: &Transaction,
    witness_script: &ScriptBuf,
    prevout_amount_sats: u64,
    secret: &SecretKey,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> Result<Vec<u8>> {
    let sighash = SighashCache::new(tx)
        .p2wsh_signature_hash(
            0,
            witness_script,
            Amount::from_sat(prevout_amount_sats),
            EcdsaSighashType::All,
        )
        .map_err(|e| SwapError::Key(format!("Sighash computation failed: {e}")))?;
    let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, secret);
    let mut sig_der = sig.serialize_der().to_vec();
    sig_der.push(EcdsaSighashType::All.to_u32() as u8);
    Ok(sig_der)
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

    let claim_key_hex = record
        .claim_key_hex
        .clone()
        .ok_or_else(|| SwapError::Key("Record missing claim key".into()))?;

    let lockup_amount_sats = record.expected_amount_sats.unwrap_or(record.amount_sats);

    Ok(ReverseClaimTxParams {
        swap_id: record.id.clone(),
        lockup_txid: lockup_txid.to_string(),
        lockup_vout,
        lockup_amount_sats,
        preimage_hex,
        claim_key_hex,
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
    let refund_key_hex = record
        .refund_key_hex
        .clone()
        .ok_or_else(|| SwapError::Key("Record missing refund key".into()))?;

    let timeout_block_height = record
        .timeout_block_height
        .ok_or_else(|| SwapError::Key("Record missing timeout block height".into()))?;

    let lockup_amount_sats = record.expected_amount_sats.unwrap_or(record.amount_sats);

    Ok(SubmarineRefundTxParams {
        swap_id: record.id.clone(),
        lockup_txid: lockup_txid.to_string(),
        lockup_vout,
        lockup_amount_sats,
        refund_key_hex,
        timeout_block_height,
        destination_address: destination_address.to_string(),
        redeem_script_hex: record.redeem_script.clone(),
        miner_fee_sats: 1000,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_reverse_claim_tx_structure() {
        let params = ReverseClaimTxParams {
            swap_id: "swap_rev_test_1".into(),
            lockup_txid: "0000000000000000000000000000000000000000000000000000000000000001".into(),
            lockup_vout: 0,
            lockup_amount_sats: 50_000,
            preimage_hex: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".into(),
            claim_key_hex: "0101010101010101010101010101010101010101010101010101010101010101"
                .into(),
            destination_address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".into(),
            redeem_script_hex: Some("6352670068".into()),
            miner_fee_sats: 1_200,
        };

        let built = build_reverse_claim_tx(params).expect("build reverse claim tx");
        assert_eq!(built.output_amount_sats, 48_800);
        assert_eq!(built.fee_sats, 1_200);
        assert_eq!(built.transaction.output.len(), 1);
        assert_eq!(built.transaction.output[0].value.to_sat(), 48_800);
        assert_eq!(built.transaction.input.len(), 1);
        assert_eq!(built.transaction.input[0].witness.len(), 3);
        assert_eq!(built.txid.len(), 64);
        assert!(!built.raw_hex.is_empty());
    }

    #[test]
    fn test_build_submarine_refund_tx_structure() {
        let params = SubmarineRefundTxParams {
            swap_id: "swap_sub_test_1".into(),
            lockup_txid: "0000000000000000000000000000000000000000000000000000000000000002".into(),
            lockup_vout: 1,
            lockup_amount_sats: 100_000,
            refund_key_hex: "0202020202020202020202020202020202020202020202020202020202020202"
                .into(),
            timeout_block_height: 850_000,
            destination_address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".into(),
            redeem_script_hex: Some("6352670168".into()),
            miner_fee_sats: 1_500,
        };

        let built = build_submarine_refund_tx(params).expect("build submarine refund tx");
        assert_eq!(built.output_amount_sats, 98_500);
        assert_eq!(built.fee_sats, 1_500);
        assert_eq!(built.transaction.lock_time.to_consensus_u32(), 850_000);
        assert_eq!(built.transaction.output[0].value.to_sat(), 98_500);
        assert_eq!(built.transaction.input[0].witness.len(), 3);
        assert_eq!(built.txid.len(), 64);
    }

    fn claim_params(redeem_script_hex: Option<String>) -> ReverseClaimTxParams {
        ReverseClaimTxParams {
            swap_id: "swap_rev_sig".into(),
            lockup_txid: "0000000000000000000000000000000000000000000000000000000000000003".into(),
            lockup_vout: 0,
            lockup_amount_sats: 60_000,
            preimage_hex: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".into(),
            claim_key_hex: "0303030303030303030303030303030303030303030303030303030303030303"
                .into(),
            destination_address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".into(),
            redeem_script_hex,
            miner_fee_sats: 1_000,
        }
    }

    #[test]
    fn claim_signature_commits_to_bip143_sighash() {
        let script = ScriptBuf::from_bytes(hex::decode("6352670068").unwrap());
        let built =
            build_reverse_claim_tx(claim_params(Some("6352670068".into()))).expect("build claim");

        let mut unsigned = built.transaction.clone();
        unsigned.input[0].witness = Witness::new();
        let sighash = SighashCache::new(&unsigned)
            .p2wsh_signature_hash(0, &script, Amount::from_sat(60_000), EcdsaSighashType::All)
            .unwrap();
        let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());

        let sig_bytes = built.transaction.input[0].witness.nth(0).unwrap();
        let (sighash_byte, der) = sig_bytes.split_last().unwrap();
        assert_eq!(*sighash_byte, EcdsaSighashType::All.to_u32() as u8);
        let sig = bitcoin::secp256k1::ecdsa::Signature::from_der(der).unwrap();

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[3u8; 32]).unwrap();
        secp.verify_ecdsa(&msg, &sig, &sk.public_key(&secp))
            .expect("signature must verify against the segwit v0 sighash");
    }

    #[test]
    fn claim_without_redeem_script_is_rejected() {
        let err = build_reverse_claim_tx(claim_params(None)).unwrap_err();
        assert!(err.to_string().contains("Redeem script missing"));
    }
}
