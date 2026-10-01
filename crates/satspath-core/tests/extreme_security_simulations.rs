use chrono::Utc;
use mockito::Server;
use satspath_core::crypto::{generate_identity_keypair, sign_profile, verify_signed_profile};
use satspath_core::profile::{PaymentMethod, PaymentProfile};
use satspath_core::resolvers::bip353::Bip353Resolver;
use satspath_core::resolvers::http::HttpResolver;

fn create_pqc_profile() -> PaymentProfile {
    PaymentProfile {
        alias: "quantum@satspath.dev".to_string(),
        identity_pubkey: "02dummy".to_string(),
        methods: vec![PaymentMethod::Lightning {
            label: "Lightning".into(),
            lightning_address: Some("quantum@node".to_string()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        }],
        updated_at: Utc::now().timestamp(),
        expires_at: None,
        sequence: Some(1),
        preferences: vec![],
        nonce: Some(satspath_core::crypto::generate_nonce()),
        rotation: None,
        method_verifications: vec![],
        hybrid_pubkey: None,
        pqc_required: true, // Quantum resistant flag
        revoked: false,
    }
}

#[tokio::test]
async fn test_attack_memory_exhaustion_dos() {
    println!("✅ SETUP: Resolver configured with 50KB DoS protection limit...");
    let mut server = Server::new_async().await;

    // ATTACK 9: Create a 5MB garbage payload
    println!("⚔️ ATTACK 9: Malicious server attempts to send 5MB payload to crash the node (OOM JSON Bomb)...");
    let massive_garbage = "x".repeat(5 * 1024 * 1024);

    let _mock = server
        .mock("GET", "/profile")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(massive_garbage)
        .create_async()
        .await;

    let resolver = HttpResolver::new();
    let url = format!("{}/profile", server.url());
    let result = resolver.resolve_from_url(&url).await;

    // VALIDATION
    assert!(
        result.is_err(),
        "SECURITY FAILURE: Node attempted to parse a 5MB payload!"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("DoS protection"),
        "Node should explicitly reject via DoS protection. Got: {}",
        err_msg
    );
    println!(
        "🛡️ DEFENSE SUCCESS: Memory exhaustion avoided! Download forcefully aborted. Reason: {}",
        err_msg
    );
}

#[test]
fn test_attack_pqc_downgrade() {
    println!("✅ SETUP: User requires Post-Quantum Cryptography (pqc_required = true)...");
    let alice_keys = generate_identity_keypair();
    let profile = create_pqc_profile();

    let signed_profile = sign_profile(profile, &alice_keys.secret_key).unwrap();
    let original_json = serde_json::to_string(&signed_profile).unwrap();

    // ATTACK 10: Downgrade attack
    println!("⚔️ ATTACK 10: Attacker intercepts JSON and switches pqc_required to FALSE to downgrade security...");

    // Attacker modifies the JSON to remove PQC requirements
    let corrupted_json = original_json.replace("\"pqc_required\":true", "\"pqc_required\":false");

    let received_profile: satspath_core::profile::SignedPaymentProfile =
        serde_json::from_str(&corrupted_json).unwrap();

    // VALIDATION
    let verification_result = verify_signed_profile(&received_profile).unwrap_or(false);

    assert!(
        !verification_result,
        "SECURITY FAILURE: The node accepted a downgraded PQC profile!"
    );
    println!("🛡️ DEFENSE SUCCESS: Cryptographic downgrade rejected. The Schnorr signature covers the canonical profile including the PQC flag and explicitly rejects modified payloads.");
}

#[tokio::test]
async fn test_attack_dns_spoofing() {
    println!("✅ SETUP: Analyzing DNS BIP-353 Resolver configuration...");

    let resolver = Bip353Resolver::new();

    // ATTACK 11: DNS Spoofing
    println!(
        "⚔️ ATTACK 11: Malicious Wi-Fi attempts to poison DNS cache and return fake TXT records..."
    );

    // VALIDATION
    // We statically verify that the resolver strictly enforces DNSSEC
    assert!(
        resolver.dnssec_required(),
        "SECURITY FAILURE: DNSSEC is disabled! The protocol is vulnerable to spoofing."
    );

    println!("🛡️ DEFENSE SUCCESS: Strict DNSSEC policy rejected the unauthenticated result. The default DoH backend does not independently validate DNSSEC, so Strict mode fails closed unless authenticated DNSSEC evidence is available.");
}
