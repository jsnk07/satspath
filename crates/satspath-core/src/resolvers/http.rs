use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;

use crate::crypto::{check_profile_expiry, verify_signed_profile};
use crate::resolver::ProfileResolver;
use crate::ssrf::{pinned_client, resolve_and_validate, validate_url};
use crate::{Result, SatsPathError, SignedPaymentProfile};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolves a profile by making an HTTP GET request to the domain of the alias.
///
/// If the alias is `rodrigo@satspath.dev`, it fetches:
/// `https://satspath.dev/.well-known/satspath/rodrigo`
///
/// After fetching, the resolver:
/// 1. **SSRF validation** — resolves the host, blocks private/loopback/metadata
///    addresses, and pins the connection to the validated addresses.
/// 2. Verifies the profile signature (ECDSA secp256k1 over canonical JSON).
/// 3. Checks the profile expiry (`expires_at` field).
///
/// Both checks must pass. Fail-closed: unsigned or expired profiles are
/// rejected with a hard error, never passed through.
pub struct HttpResolver {
    client: Client,
    /// Lets tests reach a local mock server. Only [`Self::for_local_testing`]
    /// sets it, so a resolver built with [`Self::new`] never skips SSRF checks,
    /// even in a build with the `test-utils` feature enabled.
    allow_loopback_for_tests: bool,
}

impl HttpResolver {
    /// A resolver that applies the full SSRF policy to every request.
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(REQUEST_TIMEOUT)
                // Disallow redirects to prevent open redirect → SSRF chains
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            allow_loopback_for_tests: false,
        }
    }

    /// A resolver that may also fetch from `localhost`/`127.0.0.1`, for tests
    /// against a local mock server. Not available in normal builds.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn for_local_testing() -> Self {
        Self {
            allow_loopback_for_tests: true,
            ..Self::new()
        }
    }

    /// Build with a custom base URL (for testing with a mock server).
    #[cfg(test)]
    pub fn new_with_base_url(_base_url: &str) -> Self {
        // The base_url override is handled by rewriting the resolution URL in tests.
        Self::new()
    }
}

impl Default for HttpResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProfileResolver for HttpResolver {
    async fn resolve_alias(&self, alias: &str) -> Result<SignedPaymentProfile> {
        let parts: Vec<&str> = alias.split('@').collect();
        if parts.len() != 2 {
            return Err(SatsPathError::AliasNotFound(alias.to_string()));
        }

        let username = parts[0];
        let domain = parts[1];

        // Always HTTPS in production.
        let url = format!("https://{}/.well-known/satspath/{}", domain, username);

        // SSRF-01: validate URL before fetching
        validate_url(&url, false)?;

        self.resolve_from_url(&url).await
    }
}

impl HttpResolver {
    /// Fetch, verify, and return a signed profile from an explicit URL.
    ///
    /// Extracted so tests can pass a mock server URL directly without
    /// needing a real DNS entry for the test domain.
    pub async fn resolve_from_url(&self, url: &str) -> Result<SignedPaymentProfile> {
        let parsed =
            url::Url::parse(url).map_err(|e| SatsPathError::InvalidPaymentUri(e.to_string()))?;
        let is_local = parsed.username().is_empty()
            && parsed.password().is_none()
            && matches!(parsed.host_str(), Some("localhost" | "127.0.0.1"));

        let client = if self.allow_loopback_for_tests && is_local {
            if let Some(port) = parsed.port() {
                if matches!(port, 22 | 3306 | 5432 | 6379 | 27017) {
                    return Err(SatsPathError::ValidationError(format!(
                        "Blocked port '{port}'"
                    )));
                }
            }
            self.client.clone()
        } else {
            // SSRF-02: resolve the host, reject internal addresses, and pin
            // the connection to the validated addresses (no DNS rebinding).
            let target = resolve_and_validate(url, false).await?;
            pinned_client(&target, REQUEST_TIMEOUT)?
        };

        let mut resp = client.get(url).send().await.map_err(|e| {
            SatsPathError::NetworkError(format!("Failed to connect to {}: {}", url, e))
        })?;

        if resp.status() == 404 {
            return Err(SatsPathError::AliasNotFound(url.to_string()));
        }

        if !resp.status().is_success() {
            return Err(SatsPathError::NetworkError(format!(
                "HTTP error {} fetching profile",
                resp.status()
            )));
        }

        let mut bytes = Vec::new();
        let max_size = 50 * 1024; // 50 KB Limit (DoS Protection)

        while let Some(chunk) = resp.chunk().await.map_err(|e| {
            SatsPathError::NetworkError(format!("Error reading response stream: {}", e))
        })? {
            if bytes.len() + chunk.len() > max_size {
                return Err(SatsPathError::NetworkError(
                    "Payload exceeded size limit of 50KB (DoS protection)".to_string(),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }

        let signed: SignedPaymentProfile = serde_json::from_slice(&bytes).map_err(|e| {
            SatsPathError::SerializationError(format!("Failed to parse profile JSON: {}", e))
        })?;

        // RESOLVE-02: verify signature — fail closed.
        let valid = verify_signed_profile(&signed)?;
        if !valid {
            return Err(SatsPathError::InvalidSignature);
        }

        // SEC-01: enforce expiry — fail closed.
        check_profile_expiry(&signed.profile)?;

        Ok(signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_identity_keypair, sign_profile};
    use crate::profile::{PaymentMethod, PaymentProfile};
    use mockito::Server;

    /// Build a valid signed profile.
    fn make_valid_signed(alias: &str, expires_at: Option<i64>) -> SignedPaymentProfile {
        let kp = generate_identity_keypair();
        let pubkey_hex = hex::encode(kp.public_key.serialize());
        let profile = PaymentProfile {
            alias: alias.to_string(),
            identity_pubkey: pubkey_hex,
            methods: vec![PaymentMethod::Lightning {
                label: "LN".into(),
                lnurl: None,
                lightning_address: Some(alias.to_string()),
                bolt12: None,
                receiver_pubkey: None,
            }],
            updated_at: 1_700_000_000,
            expires_at,
            sequence: None,
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: vec![],
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
        };
        sign_profile(profile, &kp.secret_key).unwrap()
    }

    // ── Test 1: Valid profile — success ───────────────────────────────────────

    /// A valid signed profile from the mock server resolves.
    #[tokio::test]
    async fn valid_profile_resolves_ok() {
        let mut server = Server::new_async().await;
        let signed = make_valid_signed("alice@test.com", None);
        let body = serde_json::to_string(&signed).unwrap();

        let _mock = server
            .mock("GET", "/profile")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&body)
            .create_async()
            .await;

        let resolver = HttpResolver::for_local_testing();
        let url = format!("{}/profile", server.url());
        let result = resolver.resolve_from_url(&url).await;

        assert!(
            result.is_ok(),
            "valid profile should resolve successfully: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().profile.alias, "alice@test.com");
    }

    // ── Test 2: Invalid signature — rejected ──────────────────────────────────

    /// A profile with a bad signature is rejected.
    #[tokio::test]
    async fn invalid_signature_rejected() {
        let mut server = Server::new_async().await;
        let mut signed = make_valid_signed("bob@test.com", None);
        // Tamper: flip last hex char of the signature
        let last = signed.signature.pop().unwrap();
        signed.signature.push(if last == '0' { '1' } else { '0' });
        let body = serde_json::to_string(&signed).unwrap();

        let _mock = server
            .mock("GET", "/profile")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&body)
            .create_async()
            .await;

        let resolver = HttpResolver::for_local_testing();
        let url = format!("{}/profile", server.url());
        let result = resolver.resolve_from_url(&url).await;

        assert!(result.is_err(), "tampered signature must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid signature") || err.contains("crypto") || err.contains("Invalid"),
            "error must mention signature: {err}"
        );
    }

    // ── Test 3: Expired profile — rejected ────────────────────────────────────

    /// An expired profile is rejected.
    #[tokio::test]
    async fn expired_profile_rejected() {
        let mut server = Server::new_async().await;
        // expires_at 1 hour in the past
        let past = chrono::Utc::now().timestamp() - 3_600;
        let signed = make_valid_signed("carol@test.com", Some(past));
        let body = serde_json::to_string(&signed).unwrap();

        let _mock = server
            .mock("GET", "/profile")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&body)
            .create_async()
            .await;

        let resolver = HttpResolver::for_local_testing();
        let url = format!("{}/profile", server.url());
        let result = resolver.resolve_from_url(&url).await;

        assert!(result.is_err(), "expired profile must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("expired"), "error must mention expiry: {err}");
    }

    // ── Test 4: 404 → AliasNotFound ───────────────────────────────────────────

    /// A 404 maps to AliasNotFound.
    #[tokio::test]
    async fn not_found_404() {
        let mut server = Server::new_async().await;

        let _mock = server
            .mock("GET", "/profile")
            .with_status(404)
            .create_async()
            .await;

        let resolver = HttpResolver::for_local_testing();
        let url = format!("{}/profile", server.url());
        let result = resolver.resolve_from_url(&url).await;

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), SatsPathError::AliasNotFound(_)),
            "404 must map to AliasNotFound"
        );
    }

    // ── Test 5: 5xx server error → NetworkError ───────────────────────────────

    /// A 5xx maps to a network error.
    #[tokio::test]
    async fn server_error_5xx() {
        let mut server = Server::new_async().await;

        let _mock = server
            .mock("GET", "/profile")
            .with_status(503)
            .create_async()
            .await;

        let resolver = HttpResolver::for_local_testing();
        let url = format!("{}/profile", server.url());
        let result = resolver.resolve_from_url(&url).await;

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), SatsPathError::NetworkError(_)),
            "5xx must map to NetworkError"
        );
    }

    // ── Test 6: Malformed JSON → SerializationError ───────────────────────────

    /// Malformed JSON is rejected.
    #[tokio::test]
    async fn malformed_json_rejected() {
        let mut server = Server::new_async().await;

        let _mock = server
            .mock("GET", "/profile")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"not": "a signed profile at all"}"#)
            .create_async()
            .await;

        let resolver = HttpResolver::for_local_testing();
        let url = format!("{}/profile", server.url());
        let result = resolver.resolve_from_url(&url).await;

        assert!(result.is_err(), "malformed JSON must be rejected");
        assert!(
            matches!(result.unwrap_err(), SatsPathError::SerializationError(_)),
            "malformed JSON must map to SerializationError"
        );
    }

    /// The default resolver never takes the loopback test path, even in a
    /// build with `test-utils` enabled.
    #[tokio::test]
    async fn default_resolver_refuses_loopback() {
        let result = HttpResolver::new()
            .resolve_from_url("https://127.0.0.1:8443/profile")
            .await;
        assert!(
            matches!(result, Err(SatsPathError::ValidationError(_))),
            "{result:?}"
        );
    }
}
