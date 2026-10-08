use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::{Address, Network, ScriptBuf};
use chrono::Utc;

use satspath_core::execution::{ExecutionGatePolicy, MockWalletExecutor, WalletExecutor};
use satspath_core::BitcoinNetwork;
use satspath_swaps::execution_gate::{
    claim_refund_builders_available, ensure_claim_refund_builders_available,
};
use satspath_swaps::tx_builder::{
    build_reverse_claim_tx, build_submarine_refund_tx, claim_params_from_record,
    finalize_reverse_claim, finalize_submarine_refund, refund_params_from_record,
};
use satspath_swaps::types::{SwapKind, SwapRecord, SwapStatus};

fn p2wsh_address(script_bytes: &[u8]) -> String {
    Address::p2wsh(
        &ScriptBuf::from_bytes(script_bytes.to_vec()),
        Network::Testnet,
    )
    .to_string()
}

fn record(kind: SwapKind, status: SwapStatus) -> SwapRecord {
    SwapRecord {
        id: format!("test-{kind:?}"),
        kind,
        status,
        created_at: Utc::now().timestamp(),
        updated_at: Utc::now().timestamp(),
        amount_sats: 50_000,
        preimage_hex: None,
        preimage_hash_hex: None,
        lockup_address: None,
        refund_pubkey_hex: None,
        claim_pubkey_hex: None,
        legacy_refund_key_hex: None,
        legacy_claim_key_hex: None,
        invoice: None,
        expected_amount_sats: None,
        timeout_block_height: None,
        boltz_claim_pubkey: None,
        redeem_script: None,
        lockup_txid: None,
        settlement_txid: None,
        destination_address: None,
    }
}

/// Plays the host wallet: signs the PSBT sighash. SatsPath never holds this key.
fn host_wallet_sign(sighash_hex: &str, secret: &bitcoin::secp256k1::SecretKey) -> Vec<u8> {
    let digest: [u8; 32] = hex::decode(sighash_hex).unwrap().try_into().unwrap();
    let sig = Secp256k1::new().sign_ecdsa(&Message::from_digest(digest), secret);
    let mut out = sig.serialize_der().to_vec();
    out.push(0x01); // SIGHASH_ALL
    out
}

#[test]
fn test_reverse_swap_claim_tx_from_record() {
    let preimage = [42u8; 32];
    let script_bytes = vec![0x63, 0x52, 0x67, 0x00, 0x68];

    let mut rec = record(SwapKind::Reverse, SwapStatus::TransactionConfirmed);
    rec.preimage_hex = Some(hex::encode(preimage));
    rec.lockup_address = Some(p2wsh_address(&script_bytes));
    rec.expected_amount_sats = Some(50_000);
    rec.redeem_script = Some(hex::encode(&script_bytes));

    let dest_addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    let lockup_txid = "1111111111111111111111111111111111111111111111111111111111111111";
    let params =
        claim_params_from_record(&rec, lockup_txid, 0, dest_addr).expect("claim params extraction");
    assert_eq!(params.destination_address, dest_addr);
    assert_eq!(params.lockup_amount_sats, 50_000);
    assert_eq!(params.miner_fee_sats, 1000);

    let unsigned = build_reverse_claim_tx(params).expect("claim tx building");
    assert_eq!(unsigned.output_amount_sats, 49_000);
    assert!(!unsigned.psbt_base64.is_empty());
    assert!(unsigned.psbt.unsigned_tx.input[0].witness.is_empty());

    let (wallet_key, _) = Secp256k1::new().generate_keypair(&mut rand::thread_rng());
    let sig = host_wallet_sign(&unsigned.sighash_hex, &wallet_key);
    let tx = finalize_reverse_claim(&unsigned, &sig, &hex::encode(preimage)).expect("finalize");

    // Witness structure: [signature, preimage, redeem_script]
    let witness = &tx.input[0].witness;
    assert_eq!(witness.len(), 3);
    assert_eq!(witness.last().unwrap(), &script_bytes[..]);
    assert_eq!(witness.iter().nth(1).unwrap(), &preimage[..]);
}

#[test]
fn test_submarine_swap_refund_tx_from_record() {
    let script_bytes = vec![0x63, 0x52, 0x67, 0x01, 0x68];

    let mut rec = record(SwapKind::Submarine, SwapStatus::InvoiceFailedToPay);
    rec.amount_sats = 100_000;
    rec.lockup_address = Some(p2wsh_address(&script_bytes));
    rec.expected_amount_sats = Some(100_000);
    rec.timeout_block_height = Some(800_000);
    rec.redeem_script = Some(hex::encode(&script_bytes));

    let refund_addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    let lockup_txid = "2222222222222222222222222222222222222222222222222222222222222222";
    let params = refund_params_from_record(&rec, lockup_txid, 1, refund_addr)
        .expect("refund params extraction");
    assert_eq!(params.lockup_amount_sats, 100_000);
    assert_eq!(params.timeout_block_height, 800_000);

    let unsigned = build_submarine_refund_tx(params).expect("refund tx building");
    assert_eq!(unsigned.output_amount_sats, 99_000);
    assert_eq!(
        unsigned.psbt.unsigned_tx.lock_time.to_consensus_u32(),
        800_000
    );

    let (wallet_key, _) = Secp256k1::new().generate_keypair(&mut rand::thread_rng());
    let sig = host_wallet_sign(&unsigned.sighash_hex, &wallet_key);
    let tx = finalize_submarine_refund(&unsigned, &sig).expect("finalize");

    // Witness structure: [signature, 0, redeem_script]
    let witness = &tx.input[0].witness;
    assert_eq!(witness.len(), 3);
    assert_eq!(witness.last().unwrap(), &script_bytes[..]);
}

#[test]
fn record_without_lockup_address_cannot_build_claim() {
    let mut rec = record(SwapKind::Reverse, SwapStatus::TransactionConfirmed);
    rec.preimage_hex = Some(hex::encode([1u8; 32]));
    let err = claim_params_from_record(
        &rec,
        &"11".repeat(32),
        0,
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
    )
    .unwrap_err();
    assert!(err.to_string().contains("lockup address"));
}

#[tokio::test]
async fn test_wallet_executor_and_gate_policy_interaction() {
    let mock = MockWalletExecutor::new(BitcoinNetwork::Testnet);

    // 1. Test Lightning payment via MockWalletExecutor
    let bolt11 = "lnbcrt10u1p3mockinvoice";
    let pay_res = mock.pay_bolt11(bolt11, Some(1_000_000)).await;
    assert!(pay_res.is_ok());
    let receipt = pay_res.unwrap();
    assert_eq!(receipt.amount_msats, 1_000_000);
    assert!(receipt.preimage.is_some());

    // 2. Test On-chain payment via MockWalletExecutor
    let onchain_addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    let onchain_res = mock.send_onchain(onchain_addr, 5000, Some(1)).await;
    assert!(onchain_res.is_ok());
    let o_receipt = onchain_res.unwrap();
    assert_eq!(o_receipt.amount_sats, 5000);
    assert_eq!(o_receipt.destination, onchain_addr);

    // 3. Execution gate policy safety tests
    let mut policy = ExecutionGatePolicy::default();

    // Mainnet blocked by default
    assert!(policy
        .check_execution_safety(BitcoinNetwork::Mainnet, 500, true)
        .is_err());

    // Mainnet with opt-in but exceeding 1,000 sats limit
    policy.mainnet_enabled = true;
    let over_limit = policy.check_execution_safety(BitcoinNetwork::Mainnet, 1500, true);
    assert!(over_limit.is_err());
    assert!(over_limit.unwrap_err().to_string().contains("1000"));

    // Mainnet without confirmation
    let no_conf = policy.check_execution_safety(BitcoinNetwork::Mainnet, 500, false);
    assert!(no_conf.is_err());
    assert!(no_conf.unwrap_err().to_string().contains("confirmation"));

    // Mainnet valid execution under limits
    assert!(policy
        .check_execution_safety(BitcoinNetwork::Mainnet, 500, true)
        .is_ok());

    // Testnet execution allowed under limits
    assert!(policy
        .check_execution_safety(BitcoinNetwork::Testnet, 500, true)
        .is_ok());
}

#[test]
fn test_claim_refund_builders_blocked_until_taproot_support() {
    assert!(!claim_refund_builders_available(SwapKind::Submarine));
    assert!(!claim_refund_builders_available(SwapKind::Reverse));
    assert!(!claim_refund_builders_available(SwapKind::Chain));

    assert!(ensure_claim_refund_builders_available(SwapKind::Submarine).is_err());
    assert!(ensure_claim_refund_builders_available(SwapKind::Reverse).is_err());
    assert!(ensure_claim_refund_builders_available(SwapKind::Chain).is_err());
}

#[tokio::test]
async fn swap_creation_fails_closed_before_contacting_boltz() {
    use satspath_swaps::boltz_client::BoltzClient;
    use satspath_swaps::chain_swap::{create_chain_swap, ChainSwapParams};
    use satspath_swaps::reverse::{create_reverse, ReverseParams};
    use satspath_swaps::submarine::{create_submarine, SubmarineParams};
    use satspath_swaps::SwapStore;

    // Nothing listens here: reaching the network would surface a connection error
    // instead of the execution-gate error asserted below.
    let client = BoltzClient::new("http://127.0.0.1:9/v2", "ws://127.0.0.1:9/v2/ws");
    let dir = tempfile::tempdir().unwrap();
    let store = SwapStore::open_plaintext_for_tests(dir.path().join("swaps.json"));
    let pubkey = "02".to_string() + &"11".repeat(32);
    let dest = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string();

    let errs = [
        create_submarine(
            &client,
            &store,
            SubmarineParams {
                invoice: "lntb1mock".into(),
                amount_sats: 50_000,
                refund_pubkey_hex: pubkey.clone(),
            },
        )
        .await
        .err()
        .map(|e| e.to_string()),
        create_reverse(
            &client,
            &store,
            ReverseParams {
                receive_amount_sats: 50_000,
                destination_address: dest.clone(),
                claim_pubkey_hex: pubkey.clone(),
            },
        )
        .await
        .err()
        .map(|e| e.to_string()),
        create_chain_swap(
            &client,
            &store,
            ChainSwapParams {
                send_amount_sats: 50_000,
                destination_address: dest,
                sender_pays_fees: false,
                claim_pubkey_hex: pubkey.clone(),
                refund_pubkey_hex: pubkey.clone(),
            },
        )
        .await
        .err()
        .map(|e| e.to_string()),
    ];
    for err in errs {
        let err = err.expect("swap creation must be refused");
        assert!(err.contains("execution blocked"), "unexpected error: {err}");
    }
    assert!(store.list_all().unwrap().is_empty());
}

#[test]
fn confirmed_reverse_swap_is_recoverable() {
    let mut rec = record(SwapKind::Reverse, SwapStatus::TransactionConfirmed);
    assert!(rec.is_recoverable());

    // A confirmed submarine lockup is Boltz's to claim, not ours to recover.
    rec.kind = SwapKind::Submarine;
    assert!(!rec.is_recoverable());
}

#[test]
fn legacy_secret_keys_survive_a_store_rewrite() {
    // Records written before swap keys moved to the host wallet still carry the
    // secret keys; dropping them on rewrite would strand an in-flight swap.
    let json = r#"{"id":"old","kind":"reverse","status":"transaction.confirmed","amount_sats":1,
        "claim_key_hex":"aa","refund_key_hex":"bb","created_at":0,"updated_at":0}"#;
    let rec: SwapRecord = serde_json::from_str(json).expect("legacy record parses");
    assert_eq!(rec.legacy_claim_key_hex.as_deref(), Some("aa"));
    assert_eq!(rec.legacy_refund_key_hex.as_deref(), Some("bb"));
    let out = serde_json::to_string(&rec).unwrap();
    assert!(out.contains(r#""claim_key_hex":"aa""#) && out.contains(r#""refund_key_hex":"bb""#));
}

#[test]
fn swap_pubkeys_are_validated() {
    use satspath_swaps::types::parse_swap_pubkey;
    let valid = "02".to_string()
        + &"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"[..64];
    assert_eq!(parse_swap_pubkey(&valid, "claim").unwrap(), valid);
    assert!(parse_swap_pubkey("not-a-key", "claim").is_err());
    assert!(parse_swap_pubkey(&"00".repeat(33), "refund").is_err());
}
