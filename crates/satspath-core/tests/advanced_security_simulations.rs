use chrono::Utc;
use satspath_core::crypto::check_profile_expiry;
use satspath_core::profile::{PaymentMethod, PaymentProfile};
use satspath_core::ssrf::validate_url;

fn create_test_profile(expires_at: Option<i64>) -> PaymentProfile {
    PaymentProfile {
        alias: "victim@satspath.dev".to_string(),
        identity_pubkey: "02dummy".to_string(),
        methods: vec![PaymentMethod::Lightning {
            label: "Lightning".into(),
            lightning_address: Some("victim@lightning.node".to_string()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        }],
        updated_at: Utc::now().timestamp(),
        expires_at,
        sequence: Some(1),
        preferences: vec![],
        nonce: Some(satspath_core::crypto::generate_nonce()),
        rotation: None,
        method_verifications: vec![],
        hybrid_pubkey: None,
        pqc_required: false,
        revoked: false,
    }
}

#[test]
fn test_attack_ssrf_cloud_metadata() {
    println!("✅ SETUP: Resolver preparing to fetch remote profiles...");

    // ATTACK 6: SSRF Attacks
    println!("⚔️ ATTACK 6: Malicious alias triggers fetches to internal cloud endpoints and loopback IPs...");

    // Attacker tries to hit AWS/GCP Metadata endpoint
    let aws_metadata_url = "https://169.254.169.254/latest/meta-data/";
    let aws_result = validate_url(aws_metadata_url, false);

    // Attacker tries to hit local SSH port on IPv6 loopback
    let local_ssh_url = "https://[::1]:22/malicious";
    let ssh_result = validate_url(local_ssh_url, false);

    // Attacker tries to hit internal corporate network
    let private_net_url = "https://10.0.0.5/api/keys";
    let private_result = validate_url(private_net_url, false);

    // VALIDATION
    assert!(
        aws_result.is_err(),
        "SECURITY FAILURE: SSRF validation allowed connection to AWS Metadata endpoint!"
    );
    assert!(
        ssh_result.is_err(),
        "SECURITY FAILURE: SSRF validation allowed connection to localhost/SSH!"
    );
    assert!(
        private_result.is_err(),
        "SECURITY FAILURE: SSRF validation allowed connection to private IP space!"
    );

    println!(
        "🛡️ DEFENSE SUCCESS: URL validation rejected all tested literal loopback/private/internal destinations."
    );
}

#[test]
fn test_attack_replay_expired_profile() {
    println!("✅ SETUP: Generating an old profile from 6 months ago...");

    // ATTACK 7: Replay an expired profile
    // 6 months ago
    let past_timestamp = Utc::now().timestamp() - (180 * 24 * 60 * 60);
    let expired_profile = create_test_profile(Some(past_timestamp));

    println!(
        "⚔️ ATTACK 7: Attacker intercepts and replays the 6-month-old zombie profile today..."
    );

    // VALIDATION: The router must reject the expired profile even if the math signature is valid.
    let expiry_check = check_profile_expiry(&expired_profile);

    assert!(
        expiry_check.is_err(),
        "SECURITY FAILURE: Replayed expired profile was accepted as valid!"
    );

    let err_msg = expiry_check.unwrap_err().to_string();
    println!(
        "🛡️ DEFENSE SUCCESS: Profile strictly rejected due to timestamp expiration. Reason: {}",
        err_msg
    );
}
