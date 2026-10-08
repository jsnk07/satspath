//! `satspathd` is a local receiver-profile daemon.
//!
//! It manages SatsPath profile identity and public receive pointers only. It
//! does not move funds, sign Bitcoin transactions, broadcast transactions, or
//! store Bitcoin wallet seeds/spending keys.

mod auth;
mod config;
mod handlers;
mod http;
mod rate_limit;
mod router;
mod server;
mod types;
mod ui;
mod v2_api;

use std::fs;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;

use config::{default_home, AppState, Cli, DEFAULT_BIND, DEFAULT_NETWORK};
use handlers::status::print_startup_status;
use http::write_owner_only_file;
use server::{audit_binding_security, serve};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let bind = cli
        .bind
        .or_else(|| std::env::var("SATSPATHD_BIND").ok())
        .unwrap_or_else(|| DEFAULT_BIND.to_string())
        .parse::<std::net::SocketAddr>()
        .context("invalid bind address")?;
    let network = cli
        .network
        .or_else(|| std::env::var("SATSPATH_NETWORK").ok())
        .unwrap_or_else(|| DEFAULT_NETWORK.to_string());
    let home = cli
        .home
        .or_else(|| std::env::var_os("SATSPATH_HOME").map(std::path::PathBuf::from))
        .unwrap_or_else(default_home);

    fs::create_dir_all(&home).context("creating SATSPATH_HOME")?;

    if let Some(ref sources) = cli.fee_sources {
        std::env::set_var("SATSPATH_FEE_SOURCES", sources);
    }
    if let Some(staleness) = cli.fee_max_staleness {
        std::env::set_var("SATSPATH_FEE_MAX_STALENESS_SECS", staleness.to_string());
    }

    // SEC-04: Daemon API Authorization
    let macaroon_path = home.join("admin.macaroon");
    let auth_token = if let Ok(token) = std::env::var("SATSPATHD_AUTH_TOKEN") {
        let t = token.trim().to_string();
        if t.len() != 64 || hex::decode(&t).is_err() {
            anyhow::bail!(
                "SATSPATHD_AUTH_TOKEN must be a valid 64-character hex string (32 bytes)"
            );
        }
        t
    } else if !macaroon_path.exists() {
        use secp256k1::rand::RngCore;
        let mut token = [0u8; 32];
        secp256k1::rand::thread_rng().fill_bytes(&mut token);
        let token_hex = hex::encode(token);
        write_owner_only_file(&macaroon_path, token_hex.as_bytes())
            .context("writing admin.macaroon")?;
        token_hex
    } else {
        let content = fs::read_to_string(&macaroon_path).context("reading admin.macaroon")?;
        let t = content.trim().to_string();
        if t.len() != 64 || hex::decode(&t).is_err() {
            anyhow::bail!("admin.macaroon must be a valid 64-character hex string (32 bytes)");
        }
        t
    };

    handlers::wallet::load_or_create_identity(&home)?;

    let behind_proxy = cli.behind_proxy
        || std::env::var("SATSPATHD_BEHIND_PROXY")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

    let tls_cert_path = cli.tls_cert.or_else(|| {
        std::env::var("SATSPATHD_TLS_CERT")
            .ok()
            .map(std::path::PathBuf::from)
    });
    let tls_key_path = cli.tls_key.or_else(|| {
        std::env::var("SATSPATHD_TLS_KEY")
            .ok()
            .map(std::path::PathBuf::from)
    });

    let require_tls_or_proxy = cli.require_tls_or_proxy
        || std::env::var("SATSPATHD_REQUIRE_TLS_OR_PROXY")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

    let is_tls = tls_cert_path.is_some() && tls_key_path.is_some();
    if (tls_cert_path.is_some() && tls_key_path.is_none())
        || (tls_cert_path.is_none() && tls_key_path.is_some())
    {
        anyhow::bail!(
            "Both --tls-cert and --tls-key must be provided together to enable native TLS"
        );
    }

    audit_binding_security(bind, is_tls, behind_proxy, require_tls_or_proxy)?;

    let burst_capacity = cli
        .rate_limit_burst
        .or_else(|| {
            std::env::var("SATSPATHD_RATE_LIMIT_BURST")
                .ok()
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(rate_limit::DEFAULT_BURST_CAPACITY);

    let refill_rate = cli
        .rate_limit_rate
        .or_else(|| {
            std::env::var("SATSPATHD_RATE_LIMIT_RATE")
                .ok()
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(rate_limit::DEFAULT_REFILL_RATE);

    let rate_limiter_config = rate_limit::RateLimiterConfig {
        burst_capacity,
        refill_rate_per_sec: refill_rate,
        max_body_bytes: rate_limit::DEFAULT_MAX_BODY_BYTES,
        trust_proxy_headers: behind_proxy,
        cleanup_interval_secs: rate_limit::DEFAULT_CLEANUP_INTERVAL_SECS,
    };
    let rate_limiter = Arc::new(rate_limit::RateLimiter::new(rate_limiter_config));

    let state = AppState {
        home,
        bind,
        network,
        open_ui: !cli.no_open,
        auth_token,
        mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
        rate_limiter,
        is_tls,
    };

    let tls_config = if let (Some(cert), Some(key)) = (tls_cert_path, tls_key_path) {
        Some((cert, key))
    } else {
        None
    };

    print_startup_status(&state)?;
    serve(state, tls_config).await
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::path::Path;
    use std::sync::Arc;

    use satspath_core::{
        crypto::{generate_identity_keypair, sign_profile, verify_signed_profile},
        PaymentMethod, PaymentProfile, TransactionalTransparencyStore,
    };
    use satspath_router::QuoteResponse;
    use tiny_http::Server;

    use crate::config::AppState;
    use crate::handlers::{
        profile::{rotate_profile_key, sign_and_store},
        quote::{pay_response, quote_response},
        resolve::resolve_v2_envelope,
        send::send_response,
        wallet::{load_or_create_identity, save_wallet},
    };
    use crate::rate_limit;
    use crate::server::{audit_binding_security, serve_server};
    use crate::types::{now, PayRequest, PayResponse, QuoteRequest, SendRequest, SendResponse};

    fn test_state(home: &Path) -> AppState {
        AppState {
            home: home.to_owned(),
            bind: "127.0.0.1:0".parse().unwrap(),
            network: "devnet".into(),
            open_ui: false,
            auth_token: "test_auth_token".into(),
            mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
            rate_limiter: Arc::new(rate_limit::RateLimiter::new(
                rate_limit::RateLimiterConfig::default(),
            )),
            is_tls: false,
        }
    }

    #[test]
    fn identity_creation_persists_public_wallet_state_only() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = load_or_create_identity(dir.path()).unwrap();
        assert!(wallet.identity_pubkey.is_some());
        let raw = std::fs::read_to_string(crate::config::wallet_path(dir.path())).unwrap();
        assert!(!raw.contains("xprv"));
        assert!(!raw.contains("mnemonic"));
        assert!(!raw.contains("secret_key"));
    }

    #[tokio::test]
    async fn quote_rejects_profile_without_transparency() {
        use satspath_core::registry::Registry;
        let dir = tempfile::tempdir().unwrap();
        let key = generate_identity_keypair();
        let profile = PaymentProfile {
            alias: "alice@example.com".into(),
            identity_pubkey: hex::encode(key.public_key.serialize()),
            methods: vec![PaymentMethod::Lightning {
                label: "LN".into(),
                lightning_address: Some("alice@example.com".into()),
                lnurl: None,
                bolt12: None,
                receiver_pubkey: None,
            }],
            updated_at: now(),
            expires_at: None,
            sequence: Some(0),
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: vec![],
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
        };
        Registry::open(dir.path())
            .unwrap()
            .register_profile(sign_profile(profile, &key.secret_key).unwrap())
            .unwrap();
        let response = quote_response(
            &test_state(dir.path()),
            QuoteRequest {
                recipient: "alice@example.com".into(),
                amount_sats: 1_000,
            },
        )
        .await;
        assert!(
            matches!(response, QuoteResponse::NoRoute { ref reason } if reason.contains("transparency verification failed"))
        );
    }

    #[tokio::test]
    async fn quote_pay_and_preview_use_transparent_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = load_or_create_identity(dir.path()).unwrap();
        wallet.alias = Some("alice@example.com".into());
        wallet.lightning_address = Some("alice@example.com".into());
        sign_and_store(dir.path(), &mut wallet, "devnet").unwrap();
        let state = test_state(dir.path());
        let quote = quote_response(
            &state,
            QuoteRequest {
                recipient: "alice@example.com".into(),
                amount_sats: 1_000,
            },
        )
        .await;
        assert!(
            matches!(quote, QuoteResponse::NoRoute { ref reason } if reason.contains("ownership proof"))
        );
        let preview = quote_response(
            &state,
            QuoteRequest {
                recipient: "alice@example.com".into(),
                amount_sats: 1_000,
            },
        )
        .await;
        assert!(matches!(preview, QuoteResponse::NoRoute { .. }));
        let pay = pay_response(
            &state,
            PayRequest {
                recipient: "alice@example.com".into(),
                amount_sats: 1_000,
                memo: None,
            },
        )
        .await;
        assert!(matches!(pay, PayResponse::NoRoute { .. }));
    }

    #[test]
    fn rotation_sequence_is_consistent_across_profile_event_and_registry() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = load_or_create_identity(dir.path()).unwrap();
        wallet.alias = Some("alice@example.com".into());
        wallet.lightning_address = Some("alice@example.com".into());
        sign_and_store(dir.path(), &mut wallet, "devnet").unwrap();
        save_wallet(dir.path(), &wallet).unwrap();
        let response = rotate_profile_key(&test_state(dir.path())).unwrap();
        let store = TransactionalTransparencyStore::open(dir.path()).unwrap();
        let profile = store.profile("alice@example.com").unwrap().unwrap();
        let log = store.load_log().unwrap();
        let latest = log.events().last().unwrap();
        assert_eq!(response.sequence, 1);
        assert_eq!(profile.profile.sequence, Some(latest.sequence));
        assert_eq!(latest.rotation.as_ref().unwrap().sequence, latest.sequence);
    }

    #[test]
    fn profile_signing_writes_resolvable_signed_profile() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = load_or_create_identity(dir.path()).unwrap();
        wallet.alias = Some("alice@example.com".into());
        wallet.lightning_address = Some("alice@example.com".into());
        sign_and_store(dir.path(), &mut wallet, "devnet").unwrap();

        let signed = TransactionalTransparencyStore::open(dir.path())
            .unwrap()
            .profile("alice@example.com")
            .unwrap()
            .unwrap();
        assert!(verify_signed_profile(&signed).unwrap());
        assert_eq!(signed.profile.methods.len(), 1);
    }

    #[test]
    fn onchain_pubkey_is_saved_as_pubkey_hint() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = load_or_create_identity(dir.path()).unwrap();
        wallet.alias = Some("alice@example.com".into());
        wallet.onchain_address = Some("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn".into());
        wallet.onchain_pubkey =
            Some("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into());
        sign_and_store(dir.path(), &mut wallet, "devnet").unwrap();

        let signed = TransactionalTransparencyStore::open(dir.path())
            .unwrap()
            .profile("alice@example.com")
            .unwrap()
            .unwrap();
        match &signed.profile.methods[0] {
            PaymentMethod::Onchain { pubkey_hint, .. } => {
                assert_eq!(pubkey_hint.as_deref(), wallet.onchain_pubkey.as_deref());
            }
            other => panic!("expected on-chain method, got {other:?}"),
        }
    }

    #[test]
    fn v2_resolve_envelope_success_and_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let mut wallet = load_or_create_identity(dir.path()).unwrap();
        wallet.alias = Some("alice@example.com".into());
        wallet.lightning_address = Some("alice@example.com".into());
        sign_and_store(dir.path(), &mut wallet, "devnet").unwrap();
        save_wallet(dir.path(), &wallet).unwrap();

        let env = resolve_v2_envelope(&state, "alice@example.com").unwrap();
        assert_eq!(env.version, 2);
        assert_eq!(env.identifier, "alice@example.com");
        assert_eq!(env.signed_profile.profile.alias, "alice@example.com");
        assert_eq!(env.namespace_descriptor.version, 2);
        assert!(!env.name_events.is_empty());

        let not_found = resolve_v2_envelope(&state, "bob@example.com");
        assert!(not_found.is_err());
    }

    async fn start_test_daemon(
        config: rate_limit::RateLimiterConfig,
    ) -> (String, Arc<Server>, tokio::task::JoinHandle<()>) {
        start_test_daemon_full(config, None).await
    }

    async fn start_test_daemon_full(
        config: rate_limit::RateLimiterConfig,
        ssl_config: Option<tiny_http::SslConfig>,
    ) -> (String, Arc<Server>, tokio::task::JoinHandle<()>) {
        let dir = tempfile::tempdir().unwrap();
        let home = Box::leak(Box::new(dir)).path().to_path_buf();
        start_test_daemon_at(home, config, ssl_config).await
    }

    /// Start a test daemon serving `home`, so a test can seed state there first.
    async fn start_test_daemon_at(
        home: std::path::PathBuf,
        config: rate_limit::RateLimiterConfig,
        ssl_config: Option<tiny_http::SslConfig>,
    ) -> (String, Arc<Server>, tokio::task::JoinHandle<()>) {
        let (server, scheme) = if let Some(ssl) = ssl_config {
            let srv = Server::https("127.0.0.1:0", ssl).unwrap();
            (Arc::new(srv), "https")
        } else {
            let srv = Server::http("127.0.0.1:0").unwrap();
            (Arc::new(srv), "http")
        };
        let addr = server.server_addr().to_ip().unwrap();
        let state = Arc::new(AppState {
            home,
            bind: addr,
            network: "devnet".into(),
            open_ui: false,
            auth_token: "test_token".into(),
            mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
            rate_limiter: Arc::new(rate_limit::RateLimiter::new(config)),
            is_tls: scheme == "https",
        });
        let srv_clone = Arc::clone(&server);
        let handle = tokio::spawn(async move {
            let _ = serve_server(state, srv_clone).await;
        });
        (format!("{scheme}://{addr}"), server, handle)
    }

    #[tokio::test]
    async fn test_http_rate_limit_and_burst_protection() {
        let config = rate_limit::RateLimiterConfig {
            burst_capacity: 3,
            refill_rate_per_sec: 0.1,
            max_body_bytes: 65_536,
            trust_proxy_headers: false,
            cleanup_interval_secs: 300,
        };
        let (base_url, server, _handle) = start_test_daemon(config).await;
        let client = reqwest::Client::new();

        // 3 requests should succeed within burst
        for i in 1..=3 {
            let res = client
                .get(format!("{base_url}/health"))
                .send()
                .await
                .expect("send request");
            assert_eq!(
                res.status(),
                reqwest::StatusCode::OK,
                "request {i} within burst limit should succeed"
            );
        }

        // 4th request must be rejected with 429 Too Many Requests
        let res4 = client
            .get(format!("{base_url}/health"))
            .send()
            .await
            .expect("send request");
        assert_eq!(
            res4.status(),
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            "4th request exceeding burst should return 429"
        );

        let retry_header = res4.headers().get("Retry-After");
        assert!(
            retry_header.is_some(),
            "429 response must contain Retry-After header"
        );
        let retry_secs: u64 = retry_header
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .expect("parse retry-after header value");
        assert!(retry_secs >= 1, "retry_after must be >= 1 second");

        let body: serde_json::Value = res4.json().await.expect("parse 429 json body");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("Too Many Requests"),
            "body must contain error description"
        );

        server.unblock();
    }

    #[tokio::test]
    async fn test_http_claim_and_invite_listing_require_auth() {
        let config = rate_limit::RateLimiterConfig {
            burst_capacity: 50,
            refill_rate_per_sec: 50.0,
            max_body_bytes: 65_536,
            trust_proxy_headers: false,
            cleanup_interval_secs: 300,
        };
        let (base_url, server, _handle) = start_test_daemon(config).await;
        let client = reqwest::Client::new();

        // Unauthenticated claim using the daemon identity must not reach the handler.
        let res = client
            .post(format!("{base_url}/v1/claim"))
            .json(&serde_json::json!({
                "invite_id": "any",
                "alias": "victim@example.com",
                "lightning_address": "attacker@evil.example"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);

        // With the owner token it reaches the handler (unknown invite -> 404).
        let res = client
            .post(format!("{base_url}/v1/claim"))
            .bearer_auth("test_token")
            .json(&serde_json::json!({
                "invite_id": "missing",
                "alias": "victim@example.com",
                "lightning_address": "owner@example.com"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::NOT_FOUND);

        for path in ["/v1/invites", "/v1/invites/notifications"] {
            let res = client
                .get(format!("{base_url}{path}"))
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED, "{path}");

            let res = client
                .get(format!("{base_url}{path}"))
                .bearer_auth("test_token")
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), reqwest::StatusCode::OK, "{path}");
        }

        server.unblock();
    }

    #[tokio::test]
    async fn test_http_public_claim_with_signed_profile_skips_admin_auth() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        load_or_create_identity(&home).unwrap();

        // Sender creates an invite for an unregistered alias.
        let claim_url = match send_response(
            &test_state(&home),
            SendRequest {
                recipient: "carol@example.com".into(),
                amount_sats: 25_000,
                routing_ok: Some(true),
            },
        )
        .await
        {
            SendResponse::Invite { claim_url, .. } => claim_url,
            other => panic!("expected SendResponse::Invite, got {other:?}"),
        };
        let invite_id = claim_url
            .split("invite_id=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
            .to_string();

        // Receiver signs their own profile with their own key.
        let key = generate_identity_keypair();
        let profile = PaymentProfile {
            alias: "carol@example.com".into(),
            identity_pubkey: hex::encode(key.public_key.serialize()),
            methods: vec![PaymentMethod::Lightning {
                label: "LN".into(),
                lightning_address: Some("carol@getalby.com".into()),
                lnurl: None,
                bolt12: None,
                receiver_pubkey: None,
            }],
            updated_at: chrono::Utc::now().timestamp(),
            expires_at: None,
            sequence: Some(0),
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: vec![],
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
        };
        let signed = sign_profile(profile, &key.secret_key).unwrap();

        let config = rate_limit::RateLimiterConfig {
            burst_capacity: 50,
            refill_rate_per_sec: 50.0,
            max_body_bytes: 65_536,
            trust_proxy_headers: false,
            cleanup_interval_secs: 300,
        };
        let (base_url, server, _handle) = start_test_daemon_at(home, config, None).await;

        // No Authorization header: a receiver-signed claim must pass the auth layer
        // and reach the claim handler. (The handler cannot yet commit such a claim:
        // the transparency event needs the receiver's signature over the event
        // itself, which this API does not collect. That is tracked separately.)
        let res = reqwest::Client::new()
            .post(format!("{base_url}/v1/claim"))
            .json(&serde_json::json!({
                "invite_id": invite_id,
                "alias": "carol@example.com",
                "signed_profile": signed,
            }))
            .send()
            .await
            .unwrap();
        let status = res.status();
        let body: serde_json::Value = res.json().await.unwrap();
        server.unblock();
        assert_ne!(status, reqwest::StatusCode::UNAUTHORIZED, "{body}");
        assert!(
            !body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("Unauthorized"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn test_http_payload_too_large_rejection_413() {
        let config = rate_limit::RateLimiterConfig {
            burst_capacity: 10,
            refill_rate_per_sec: 10.0,
            max_body_bytes: 1024, // 1 KB max for testing
            trust_proxy_headers: false,
            cleanup_interval_secs: 300,
        };
        let (base_url, server, _handle) = start_test_daemon(config).await;
        let client = reqwest::Client::new();

        // Send a request with a body of 2048 bytes (> 1024 bytes)
        let large_body = vec![b'a'; 2048];
        let res = client
            .post(format!("{base_url}/v1/receive"))
            .header("Content-Type", "application/json")
            .body(large_body)
            .send()
            .await
            .expect("send request");

        assert_eq!(
            res.status(),
            reqwest::StatusCode::PAYLOAD_TOO_LARGE,
            "oversized body should return HTTP 413"
        );

        let body: serde_json::Value = res.json().await.expect("parse 413 json body");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("Payload Too Large"),
            "body must state Payload Too Large"
        );

        server.unblock();
    }

    #[tokio::test]
    async fn test_http_rate_limit_trusted_proxy_headers() {
        let config = rate_limit::RateLimiterConfig {
            burst_capacity: 2,
            refill_rate_per_sec: 0.1,
            max_body_bytes: 65_536,
            trust_proxy_headers: true,
            cleanup_interval_secs: 300,
        };
        let (base_url, server, _handle) = start_test_daemon(config).await;
        let client = reqwest::Client::new();

        // Client 1 (203.0.113.1) uses its 2 burst tokens
        for _ in 0..2 {
            let res = client
                .get(format!("{base_url}/health"))
                .header("X-Forwarded-For", "203.0.113.1, 10.0.0.1")
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), reqwest::StatusCode::OK);
        }

        // Client 1's 3rd request is blocked (429)
        let res_c1_blocked = client
            .get(format!("{base_url}/health"))
            .header("X-Forwarded-For", "203.0.113.1, 10.0.0.1")
            .send()
            .await
            .unwrap();
        assert_eq!(
            res_c1_blocked.status(),
            reqwest::StatusCode::TOO_MANY_REQUESTS
        );

        // Client 2 (198.51.100.5) is independent and should be allowed
        let res_c2 = client
            .get(format!("{base_url}/health"))
            .header("X-Forwarded-For", "198.51.100.5")
            .send()
            .await
            .unwrap();
        assert_eq!(res_c2.status(), reqwest::StatusCode::OK);

        server.unblock();
    }

    #[tokio::test]
    async fn test_http_diagnostics_rate_limit() {
        let config = rate_limit::RateLimiterConfig {
            burst_capacity: 5,
            refill_rate_per_sec: 1.0,
            max_body_bytes: 65_536,
            trust_proxy_headers: false,
            cleanup_interval_secs: 300,
        };
        let (base_url, server, _handle) = start_test_daemon(config).await;
        let client = reqwest::Client::new();

        // 1 successful request
        let _ = client
            .get(format!("{base_url}/health"))
            .send()
            .await
            .unwrap();

        let diag_res = client
            .get(format!("{base_url}/v1/diagnostics/rate_limit"))
            .send()
            .await
            .unwrap();
        assert_eq!(diag_res.status(), reqwest::StatusCode::OK);

        let stats: rate_limit::RateLimiterStats = diag_res.json().await.unwrap();
        assert!(stats.total_allowed >= 1);
        assert_eq!(stats.burst_capacity, 5);
        assert_eq!(stats.max_body_bytes, 65_536);

        server.unblock();
    }

    #[test]
    fn test_cleartext_audit_allows_loopback() {
        let addr: SocketAddr = "127.0.0.1:9737".parse().unwrap();
        assert!(audit_binding_security(addr, false, false, false).is_ok());
        assert!(audit_binding_security(addr, false, false, true).is_ok());
    }

    #[test]
    fn test_cleartext_audit_rejects_non_loopback_when_enforced() {
        let addr: SocketAddr = "0.0.0.0:9737".parse().unwrap();
        let err = audit_binding_security(addr, false, false, true).unwrap_err();
        assert!(err.to_string().contains("Security violation"));
    }

    #[test]
    fn test_cleartext_audit_allows_non_loopback_with_proxy_or_tls() {
        let addr: SocketAddr = "0.0.0.0:9737".parse().unwrap();
        // Allowed when behind reverse proxy
        assert!(audit_binding_security(addr, false, true, true).is_ok());
        // Allowed when native TLS is active
        assert!(audit_binding_security(addr, true, false, true).is_ok());
    }

    #[tokio::test]
    async fn test_native_tls_server_https_get_and_post() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
            .unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let ssl_config = tiny_http::SslConfig {
            certificate: cert_pem.into_bytes(),
            private_key: key_pem.into_bytes(),
        };

        let config = rate_limit::RateLimiterConfig::default();
        let (base_url, server, _handle) = start_test_daemon_full(config, Some(ssl_config)).await;
        assert!(base_url.starts_with("https://"));

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        let res = client
            .get(format!("{base_url}/health"))
            .send()
            .await
            .expect("send HTTPS request");
        assert_eq!(res.status(), reqwest::StatusCode::OK);

        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(body["ok"], true);

        server.unblock();
    }

    #[tokio::test]
    async fn test_end_to_end_invite_claim_flow() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        load_or_create_identity(dir.path()).unwrap();

        // 1. Sender initiates send to unregistered alias
        let send_res = send_response(
            &state,
            SendRequest {
                recipient: "carol@example.com".into(),
                amount_sats: 25_000,
                routing_ok: Some(true),
            },
        )
        .await;

        let claim_url = match send_res {
            SendResponse::Invite { claim_url, .. } => claim_url,
            other => panic!("expected SendResponse::Invite, got {other:?}"),
        };

        // Extract invite_id from claim_url
        let invite_id = claim_url
            .split("invite_id=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();

        // 2. Receiver inspects invite
        let inspect = crate::handlers::claim::inspect_invite_handler(&state, invite_id).unwrap();
        assert_eq!(inspect.invite_id, invite_id);
        assert_eq!(inspect.amount_sats, 25_000);
        assert!(inspect.is_claimable);
        assert!(!inspect.is_expired);
        assert!(inspect.sender_verified);

        // 3. Receiver claims invite with lightning address
        let claim_res = crate::handlers::claim::claim_invite_handler(
            &state,
            crate::types::ClaimRequest {
                invite_id: invite_id.to_string(),
                alias: "carol@example.com".into(),
                signed_profile: None,
                lightning_address: Some("carol@getalby.com".into()),
                onchain_address: None,
                onchain_pubkey: None,
                ark_server: None,
                ark_pubkey: None,
            },
        )
        .unwrap();

        assert_eq!(claim_res.status, "claimed");
        assert_eq!(claim_res.alias, "carol@example.com");
        assert_eq!(claim_res.amount_sats, 25_000);
        assert!(!claim_res.profile_pubkey.is_empty());

        // 4. Verify invite is now ClaimedWithPublicProfile
        let re_inspect = crate::handlers::claim::inspect_invite_handler(&state, invite_id).unwrap();
        assert_eq!(
            re_inspect.status,
            satspath_core::InviteStatus::ClaimedWithPublicProfile
        );
        assert!(!re_inspect.is_claimable);

        // 5. Verify claim notification exists for sender
        let notifications = crate::handlers::claim::list_notifications_handler(&state).unwrap();
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].invite_id, invite_id);
        assert_eq!(notifications[0].amount_sats, 25_000);
        assert!(!notifications[0].read);

        // 6. Sender marks notification as read
        crate::handlers::claim::mark_notification_read_handler(
            &state,
            &notifications[0].notification_id,
        )
        .unwrap();
        let updated_notifications =
            crate::handlers::claim::list_notifications_handler(&state).unwrap();
        assert!(updated_notifications[0].read);

        // 7. Double claiming fails with error
        let double_claim = crate::handlers::claim::claim_invite_handler(
            &state,
            crate::types::ClaimRequest {
                invite_id: invite_id.to_string(),
                alias: "carol@example.com".into(),
                signed_profile: None,
                lightning_address: Some("carol@getalby.com".into()),
                onchain_address: None,
                onchain_pubkey: None,
                ark_server: None,
                ark_pubkey: None,
            },
        );
        assert!(double_claim.is_err());
        assert!(double_claim
            .unwrap_err()
            .to_string()
            .contains("already been claimed"));

        // 8. Sender can now re-resolve carol@example.com in the transparency log
        let store = satspath_core::TransactionalTransparencyStore::open(dir.path()).unwrap();
        let profile = store.profile("carol@example.com").unwrap();
        assert!(profile.is_some());
        assert_eq!(profile.unwrap().profile.alias, "carol@example.com");
    }

    #[tokio::test]
    async fn test_expired_and_mismatched_claims() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        load_or_create_identity(dir.path()).unwrap();

        let mut store = satspath_core::InviteStore::open(dir.path()).unwrap();
        let expired_invite = satspath_core::create_invite_record(
            "alice@example.com",
            10_000,
            None,
            "sender-fp".into(),
            -10, // already expired
        );
        let expired_id = expired_invite.invite_id.clone();
        store.insert(expired_invite).unwrap();

        // Expired claim fails
        let expired_err = crate::handlers::claim::claim_invite_handler(
            &state,
            crate::types::ClaimRequest {
                invite_id: expired_id.clone(),
                alias: "alice@example.com".into(),
                signed_profile: None,
                lightning_address: Some("alice@example.com".into()),
                onchain_address: None,
                onchain_pubkey: None,
                ark_server: None,
                ark_pubkey: None,
            },
        )
        .unwrap_err();
        assert!(expired_err.to_string().contains("expired"));

        // Mismatched alias claim fails
        let valid_invite = satspath_core::create_invite_record(
            "bob@example.com",
            50_000,
            None,
            "sender-fp".into(),
            3600,
        );
        let valid_id = valid_invite.invite_id.clone();
        store.insert(valid_invite).unwrap();

        let mismatch_err = crate::handlers::claim::claim_invite_handler(
            &state,
            crate::types::ClaimRequest {
                invite_id: valid_id,
                alias: "mallory@example.com".into(),
                signed_profile: None,
                lightning_address: Some("mallory@example.com".into()),
                onchain_address: None,
                onchain_pubkey: None,
                ark_server: None,
                ark_pubkey: None,
            },
        )
        .unwrap_err();
        assert!(mismatch_err.to_string().contains("does not match"));
    }
}
