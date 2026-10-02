use bitcoin::secp256k1::Secp256k1;
use chrono::Utc;

use satspath_core::execution::{ExecutionGatePolicy, MockWalletExecutor, WalletExecutor};
use satspath_core::BitcoinNetwork;
use satspath_swaps::execution_gate::{
    claim_refund_builders_available, ensure_claim_refund_builders_available,
};
use satspath_swaps::tx_builder::{
    build_reverse_claim_tx, build_submarine_refund_tx, claim_params_from_record,
    refund_params_from_record,
};
use satspath_swaps::types::{SwapKind, SwapRecord, SwapStatus};

#[test]
fn test_reverse_swap_claim_tx_from_record() {
    let secp = Secp256k1::new();
    let (claim_sk, _) = secp.generate_keypair(&mut rand::thread_rng());
    let claim_key_hex = hex::encode(claim_sk.secret_bytes());

    let preimage = [42u8; 32];
    let preimage_hex = hex::encode(preimage);

    let script_bytes = vec![0x63, 0x52, 0x67, 0x00, 0x68];
    let script_hex = hex::encode(&script_bytes);

    let record = SwapRecord {
        id: "test-reverse-swap-1".into(),
        kind: SwapKind::Reverse,
        status: SwapStatus::TransactionConfirmed,
        created_at: Utc::now().timestamp(),
        updated_at: Utc::now().timestamp(),
        amount_sats: 50_000,
        preimage_hex: Some(preimage_hex.clone()),
        preimage_hash_hex: Some(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into(),
        ),
        lockup_address: Some("tb1qmocklockupaddressforreverseswap".into()),
        claim_key_hex: Some(claim_key_hex),
        refund_key_hex: None,
        invoice: Some("lnbcrt500u1mock".into()),
        expected_amount_sats: Some(50_000),
        timeout_block_height: None,
        boltz_claim_pubkey: None,
        redeem_script: Some(script_hex),
        lockup_txid: Some(
            "1111111111111111111111111111111111111111111111111111111111111111".into(),
        ),
        settlement_txid: None,
        destination_address: None,
    };

    let dest_addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    let lockup_txid = "1111111111111111111111111111111111111111111111111111111111111111";
    let params = claim_params_from_record(&record, lockup_txid, 0, dest_addr)
        .expect("claim params extraction");

    assert_eq!(params.swap_id, "test-reverse-swap-1");
    assert_eq!(params.destination_address, dest_addr);
    assert_eq!(params.lockup_amount_sats, 50_000);
    assert_eq!(params.miner_fee_sats, 1000);

    let built = build_reverse_claim_tx(params).expect("claim tx building");

    assert_eq!(built.transaction.input.len(), 1);
    assert_eq!(built.transaction.output.len(), 1);
    assert_eq!(built.transaction.output[0].value.to_sat(), 49_000);
    assert_eq!(built.output_amount_sats, 49_000);
    assert_eq!(built.fee_sats, 1000);

    // Verify witness structure: [signature, preimage, redeem_script]
    let witness = &built.transaction.input[0].witness;
    assert_eq!(witness.len(), 3);
    assert_eq!(witness.last().unwrap(), &script_bytes[..]);
    assert_eq!(witness.iter().nth(1).unwrap(), &preimage[..]);
}

#[test]
fn test_submarine_swap_refund_tx_from_record() {
    let secp = Secp256k1::new();
    let (refund_sk, _) = secp.generate_keypair(&mut rand::thread_rng());
    let refund_key_hex = hex::encode(refund_sk.secret_bytes());

    let script_bytes = vec![0x63, 0x52, 0x67, 0x01, 0x68];
    let script_hex = hex::encode(&script_bytes);

    let record = SwapRecord {
        id: "test-submarine-swap-1".into(),
        kind: SwapKind::Submarine,
        status: SwapStatus::InvoiceFailedToPay,
        created_at: Utc::now().timestamp(),
        updated_at: Utc::now().timestamp(),
        amount_sats: 100_000,
        preimage_hex: None,
        preimage_hash_hex: Some(
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".into(),
        ),
        lockup_address: Some("tb1qmocklockupaddressforsubmarineswap".into()),
        claim_key_hex: None,
        refund_key_hex: Some(refund_key_hex),
        invoice: Some("lnbcrt1m1mock".into()),
        expected_amount_sats: Some(100_000),
        timeout_block_height: Some(800_000),
        boltz_claim_pubkey: None,
        redeem_script: Some(script_hex),
        lockup_txid: Some(
            "2222222222222222222222222222222222222222222222222222222222222222".into(),
        ),
        settlement_txid: None,
        destination_address: None,
    };

    let refund_addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    let lockup_txid = "2222222222222222222222222222222222222222222222222222222222222222";
    let params = refund_params_from_record(&record, lockup_txid, 1, refund_addr)
        .expect("refund params extraction");

    assert_eq!(params.swap_id, "test-submarine-swap-1");
    assert_eq!(params.destination_address, refund_addr);
    assert_eq!(params.lockup_amount_sats, 100_000);
    assert_eq!(params.timeout_block_height, 800_000);

    let built = build_submarine_refund_tx(params).expect("refund tx building");

    assert_eq!(built.transaction.input.len(), 1);
    assert_eq!(built.transaction.output.len(), 1);
    assert_eq!(built.transaction.output[0].value.to_sat(), 99_000);
    assert_eq!(built.transaction.lock_time.to_consensus_u32(), 800_000);

    // Verify witness structure: [signature, 0, redeem_script]
    let witness = &built.transaction.input[0].witness;
    assert_eq!(witness.len(), 3);
    assert_eq!(witness.last().unwrap(), &script_bytes[..]);
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
    let dir = std::env::temp_dir().join(format!("satspath-gate-{}", std::process::id()));
    let store = SwapStore::open_plaintext_for_tests(dir.join("swaps.json"));
    let dest = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string();

    let errs = [
        create_submarine(
            &client,
            &store,
            SubmarineParams {
                invoice: "lntb1mock".into(),
                amount_sats: 50_000,
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
    let mut record = SwapRecord {
        id: "rev-confirmed".into(),
        kind: SwapKind::Reverse,
        status: SwapStatus::TransactionConfirmed,
        created_at: Utc::now().timestamp(),
        updated_at: Utc::now().timestamp(),
        amount_sats: 50_000,
        preimage_hex: None,
        preimage_hash_hex: None,
        lockup_address: None,
        claim_key_hex: None,
        refund_key_hex: None,
        invoice: None,
        expected_amount_sats: None,
        timeout_block_height: None,
        boltz_claim_pubkey: None,
        redeem_script: None,
        lockup_txid: None,
        settlement_txid: None,
        destination_address: None,
    };
    assert!(record.is_recoverable());

    // A confirmed submarine lockup is Boltz's to claim, not ours to recover.
    record.kind = SwapKind::Submarine;
    assert!(!record.is_recoverable());
}
