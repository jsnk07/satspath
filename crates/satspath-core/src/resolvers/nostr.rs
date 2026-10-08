use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{client_async_tls_with_config, connect_async, tungstenite::Message};

use crate::crypto::{check_profile_expiry, verify_signed_profile};
use crate::peer_registry::canonicalize_identifier;
use crate::resolver::ProfileResolver;
use crate::{Result, SatsPathError, SignedPaymentProfile};

const SATSPATH_PROFILE_KIND: u64 = 30_078;
const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
];
const NOSTR_TIMEOUT: Duration = Duration::from_secs(8);
const NIP05_TIMEOUT: Duration = Duration::from_secs(6);
/// Largest NIP-05 document accepted from an (untrusted) identifier's domain.
const NIP05_MAX_BYTES: usize = 64 * 1024;
/// Largest relay message accepted; a SatsPath profile event is a few KiB.
const RELAY_MAX_MESSAGE_BYTES: usize = 256 * 1024;

/// Resolver for SatsPath profiles announced over Nostr.
///
/// Discovery is transport-neutral:
/// 1. Resolve `user@domain` through NIP-05 (`/.well-known/nostr.json?name=user`).
/// 2. Use the returned pubkey and relay hints.
/// 3. Query relay events for kind 30078 and `d=satspath-profile:<canonical_id>`.
/// 4. Parse event content as `SignedPaymentProfile`.
/// 5. Verify the SatsPath profile signature and expiry before returning it.
///
/// Nostr event signatures identify the Nostr author. They do not replace the
/// SatsPath profile signature, which is still the protocol authority.
pub struct NostrResolver {
    fallback_relays: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Nip05Document {
    names: HashMap<String, String>,
    #[serde(default)]
    relays: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
struct Nip05Resolution {
    pubkey: String,
    relays: Vec<String>,
}

impl Default for NostrResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl NostrResolver {
    pub fn new() -> Self {
        Self {
            fallback_relays: env_relays().unwrap_or_else(|| {
                DEFAULT_RELAYS
                    .iter()
                    .map(|relay| relay.to_string())
                    .collect()
            }),
        }
    }

    pub fn with_relays(relays: Vec<String>) -> Self {
        Self {
            fallback_relays: relays,
        }
    }

    /// Look up the NIP-05 record for `alias` over a pinned, SSRF-checked connection.
    async fn resolve_nip05(&self, alias: &str) -> Result<Nip05Resolution> {
        let canonical = canonicalize_identifier(alias);
        let (name, domain) = canonical
            .split_once('@')
            .ok_or_else(|| SatsPathError::AliasNotFound(alias.to_string()))?;
        let mut url = url::Url::parse(&format!("https://{domain}/.well-known/nostr.json"))
            .map_err(|e| SatsPathError::ValidationError(format!("invalid NIP-05 domain: {e}")))?;
        url.query_pairs_mut().append_pair("name", name);
        let url = url.to_string();
        // SSRF-02: the domain comes from an untrusted identifier. Resolve it,
        // reject internal addresses, pin the connection, and refuse redirects.
        let target = crate::ssrf::resolve_and_validate(&url, false).await?;
        let client = crate::ssrf::pinned_client(&target, NIP05_TIMEOUT)?;
        let mut resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| SatsPathError::NetworkError(format!("NIP-05 fetch failed: {e}")))?
            .error_for_status()
            .map_err(|e| SatsPathError::NetworkError(format!("NIP-05 HTTP error: {e}")))?;
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| SatsPathError::NetworkError(format!("NIP-05 read failed: {e}")))?
        {
            if body.len() + chunk.len() > NIP05_MAX_BYTES {
                return Err(SatsPathError::NetworkError(format!(
                    "NIP-05 document exceeds {NIP05_MAX_BYTES} bytes"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        let document: Nip05Document = serde_json::from_slice(&body)
            .map_err(|e| SatsPathError::SerializationError(format!("NIP-05 JSON: {e}")))?;

        let pubkey = document
            .names
            .get(name)
            .or_else(|| document.names.get(&name.to_ascii_lowercase()))
            .cloned()
            .ok_or_else(|| SatsPathError::AliasNotFound(alias.to_string()))?;
        validate_nostr_pubkey(&pubkey)?;

        let mut relays = document.relays.get(&pubkey).cloned().unwrap_or_default();
        if relays.is_empty() {
            relays = self.fallback_relays.clone();
        }
        // Relay hints come from the untrusted NIP-05 document: keep only TLS
        // relays whose URL passes the SSRF policy (the address is re-checked
        // and pinned again at connect time in `query_relay`).
        relays.retain(|relay| {
            relay_http_url(relay)
                .and_then(|url| crate::ssrf::validate_url(&url, false))
                .is_ok()
        });
        relays.truncate(8);
        if relays.is_empty() {
            return Err(SatsPathError::NetworkError(
                "no usable Nostr relays for NIP-05 identity".into(),
            ));
        }

        Ok(Nip05Resolution { pubkey, relays })
    }

    /// Fetch the profile event from one relay after validating its address.
    async fn query_relay(
        &self,
        relay: &str,
        pubkey: &str,
        alias: &str,
    ) -> Result<SignedPaymentProfile> {
        let canonical = canonicalize_identifier(alias);
        let d_tag = format!("satspath-profile:{canonical}");
        let sub_id = format!("satspath-{}", chrono::Utc::now().timestamp_millis());
        let req = json!([
            "REQ",
            sub_id,
            {
                "authors": [pubkey],
                "kinds": [SATSPATH_PROFILE_KIND],
                "#d": [d_tag],
                "limit": 5
            }
        ]);

        let relay_result = timeout(NOSTR_TIMEOUT, async {
            // SSRF-02: relay hints come from the (untrusted) NIP-05 document.
            // Resolve and validate the relay host, then connect the socket to
            // a validated address so DNS cannot be re-pointed in between.
            let target = crate::ssrf::resolve_and_validate(&relay_http_url(relay)?, false).await?;
            let stream = tokio::net::TcpStream::connect(target.addrs.as_slice())
                .await
                .map_err(|e| SatsPathError::NetworkError(format!("Nostr relay connect: {e}")))?;
            let config = WebSocketConfig::default()
                .max_message_size(Some(RELAY_MAX_MESSAGE_BYTES))
                .max_frame_size(Some(RELAY_MAX_MESSAGE_BYTES));
            let (mut ws, _) = client_async_tls_with_config(relay, stream, Some(config), None)
                .await
                .map_err(|e| SatsPathError::NetworkError(format!("Nostr relay connect: {e}")))?;
            ws.send(Message::Text(req.to_string().into()))
                .await
                .map_err(|e| SatsPathError::NetworkError(format!("Nostr relay send: {e}")))?;

            while let Some(msg) = ws.next().await {
                let msg =
                    msg.map_err(|e| SatsPathError::NetworkError(format!("Nostr relay read: {e}")))?;
                let Message::Text(text) = msg else {
                    continue;
                };
                if let Some(signed) = signed_profile_from_event(&text, &sub_id, pubkey, alias)? {
                    return Ok(signed);
                }
            }

            Err(SatsPathError::AliasNotFound(alias.to_string()))
        })
        .await
        .map_err(|_| SatsPathError::NetworkError(format!("Nostr relay timeout: {relay}")))?;

        relay_result
    }
}

#[async_trait]
impl ProfileResolver for NostrResolver {
    async fn resolve_alias(&self, alias: &str) -> Result<SignedPaymentProfile> {
        let nip05 = self.resolve_nip05(alias).await?;

        let futures: Vec<_> = nip05
            .relays
            .iter()
            .map(|relay| self.query_relay(relay, &nip05.pubkey, alias))
            .collect();

        let results = futures_util::future::join_all(futures).await;

        let mut best_profile: Option<SignedPaymentProfile> = None;
        let mut last_error = None;

        for result in results {
            match result {
                Ok(signed) => {
                    let current_best_seq = best_profile
                        .as_ref()
                        .and_then(|p| p.profile.sequence)
                        .unwrap_or(0);
                    let new_seq = signed.profile.sequence.unwrap_or(0);

                    if best_profile.is_none() || new_seq > current_best_seq {
                        best_profile = Some(signed);
                    }
                }
                Err(e) => last_error = Some(e),
            }
        }

        match best_profile {
            Some(profile) => {
                if profile.profile.revoked {
                    Err(SatsPathError::RegistryError(format!(
                        "Alias {} has been revoked",
                        alias
                    )))
                } else {
                    Ok(profile)
                }
            }
            None => match last_error {
                Some(e) => Err(e),
                None => Err(SatsPathError::AliasNotFound(alias.to_string())),
            },
        }
    }
}

fn signed_profile_from_event(
    raw: &str,
    sub_id: &str,
    expected_pubkey: &str,
    alias: &str,
) -> Result<Option<SignedPaymentProfile>> {
    let value: Value = serde_json::from_str(raw)?;
    let Some(array) = value.as_array() else {
        return Ok(None);
    };
    if array.first().and_then(Value::as_str) != Some("EVENT") {
        return Ok(None);
    }
    if array.get(1).and_then(Value::as_str) != Some(sub_id) {
        return Ok(None);
    }
    let Some(event) = array.get(2) else {
        return Ok(None);
    };
    if event.get("kind").and_then(Value::as_u64) != Some(SATSPATH_PROFILE_KIND) {
        return Ok(None);
    }
    if event.get("pubkey").and_then(Value::as_str) != Some(expected_pubkey) {
        return Ok(None);
    }

    let wanted = canonicalize_identifier(alias);
    let d_tag = format!("satspath-profile:{wanted}");
    if !event_has_tag(event, "d", &d_tag) {
        return Ok(None);
    }

    let content = event
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| SatsPathError::SerializationError("Nostr event missing content".into()))?;
    let signed: SignedPaymentProfile = serde_json::from_str(content)?;
    let got = canonicalize_identifier(&signed.profile.alias);
    if got != wanted {
        return Err(SatsPathError::InvalidRoute(format!(
            "Nostr profile alias mismatch: expected {wanted}, got {got}"
        )));
    }
    let id_pk = &signed.profile.identity_pubkey;
    if id_pk != expected_pubkey
        && !id_pk.ends_with(expected_pubkey)
        && !expected_pubkey.ends_with(id_pk)
    {
        return Err(SatsPathError::InvalidSignature);
    }
    if !verify_signed_profile(&signed)? {
        return Err(SatsPathError::InvalidSignature);
    }
    check_profile_expiry(&signed.profile)?;
    Ok(Some(signed))
}

fn event_has_tag(event: &Value, tag_name: &str, tag_value: &str) -> bool {
    event
        .get("tags")
        .and_then(Value::as_array)
        .map(|tags| {
            tags.iter().any(|tag| {
                let Some(items) = tag.as_array() else {
                    return false;
                };
                items.first().and_then(Value::as_str) == Some(tag_name)
                    && items.get(1).and_then(Value::as_str) == Some(tag_value)
            })
        })
        .unwrap_or(false)
}

/// Map a `wss://` / `ws://` relay URL to the equivalent `https://` / `http://`
/// URL so it can go through the SSRF guard.
/// The `https://` form of a `wss://` relay URL, for SSRF validation.
/// Plaintext `ws://` relays are refused: relay hints come from untrusted
/// NIP-05 documents, and lookups must not leak over unencrypted connections.
fn relay_http_url(relay: &str) -> Result<String> {
    relay
        .strip_prefix("wss://")
        .map(|rest| format!("https://{rest}"))
        .ok_or_else(|| {
            SatsPathError::ValidationError(format!(
                "unsupported relay URL scheme (wss:// required): {relay}"
            ))
        })
}

fn validate_nostr_pubkey(pubkey: &str) -> Result<()> {
    if pubkey.len() == 64 && pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(SatsPathError::InvalidPublicKey(
            "NIP-05 pubkey must be 32-byte hex".into(),
        ))
    }
}

fn env_relays() -> Option<Vec<String>> {
    std::env::var("SATSPATH_NOSTR_RELAYS").ok().map(|value| {
        if value.trim() == "none" || value.trim().is_empty() {
            Vec::new()
        } else {
            value
                .split(',')
                .map(str::trim)
                .filter(|relay| !relay.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        }
    })
}

/// Publishes a SignedPaymentProfile to a set of Nostr relays as a NIP-01 kind 30078 event.
/// Returns the number of relays the event was successfully sent to.
pub async fn publish_profile(
    signed: &SignedPaymentProfile,
    secret_key: &secp256k1::SecretKey,
    relays: Option<&[String]>,
) -> Result<usize> {
    use secp256k1::{Keypair, Secp256k1};
    use sha2::{Digest, Sha256};

    let default_relays =
        env_relays().unwrap_or_else(|| DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect());
    let relays_to_use = relays.unwrap_or(&default_relays);
    if relays_to_use.is_empty() {
        return Err(SatsPathError::NetworkError(
            "No Nostr relays configured".into(),
        ));
    }

    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret_key);
    let pubkey_hex = hex::encode(keypair.x_only_public_key().0.serialize());
    let created_at = chrono::Utc::now().timestamp();
    let content_value = serde_json::to_value(signed)
        .map_err(|e| SatsPathError::SerializationError(e.to_string()))?;
    let content = canonical_json::to_string(&content_value)
        .map_err(|e| SatsPathError::SerializationError(e.to_string()))?;
    let canonical_alias = canonicalize_identifier(&signed.profile.alias);

    let tags = vec![vec![
        "d".to_string(),
        format!("satspath-profile:{}", canonical_alias),
    ]];

    // NIP-01 ID = SHA256 of [0, pubkey, created_at, kind, tags, content]
    let id_payload = json!([
        0,
        pubkey_hex,
        created_at,
        SATSPATH_PROFILE_KIND,
        tags,
        content
    ]);

    // Serialize with zero whitespace as required by NIP-01
    // serde_json::to_string produces compact JSON without spaces
    let id_json = id_payload.to_string();
    let digest = Sha256::digest(id_json.as_bytes());
    let id_hex = hex::encode(digest);

    let message = secp256k1::Message::from_digest(digest.into());
    let sig = secp.sign_schnorr(&message, &keypair);
    let sig_hex = hex::encode(sig.serialize());

    let event = json!({
        "id": id_hex,
        "pubkey": pubkey_hex,
        "created_at": created_at,
        "kind": SATSPATH_PROFILE_KIND,
        "tags": tags,
        "content": content,
        "sig": sig_hex
    });

    let msg = json!(["EVENT", event]).to_string();
    let mut success_count = 0;

    for relay in relays_to_use {
        let Ok(Ok((mut ws, _))) =
            tokio::time::timeout(std::time::Duration::from_secs(2), connect_async(relay)).await
        else {
            continue;
        };

        if ws.send(Message::Text(msg.clone().into())).await.is_ok() {
            // Wait for the OK response from the relay
            if let Ok(Some(Ok(Message::Text(resp)))) =
                tokio::time::timeout(std::time::Duration::from_secs(3), ws.next()).await
            {
                if let Ok(Value::Array(arr)) = serde_json::from_str(&resp) {
                    if let (Some(Value::String(msg_type)), Some(Value::Bool(accepted))) =
                        (arr.first(), arr.get(2))
                    {
                        if msg_type == "OK" && *accepted {
                            success_count += 1;
                        }
                    }
                }
            }
        }
        let _ = ws.close(None).await;
    }

    if success_count == 0 {
        return Err(SatsPathError::NetworkError(
            "Failed to publish profile to any Nostr relay".into(),
        ));
    }

    Ok(success_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_identity_keypair, sign_profile};
    use crate::{PaymentMethod, PaymentProfile};

    fn signed(alias: &str) -> SignedPaymentProfile {
        let kp = generate_identity_keypair();
        let profile = PaymentProfile {
            sequence: Some(1),
            alias: alias.to_string(),
            identity_pubkey: hex::encode(kp.public_key.serialize()),
            methods: vec![PaymentMethod::Lightning {
                label: "Lightning".into(),
                lightning_address: Some(alias.to_string()),
                lnurl: None,
                bolt12: None,
                receiver_pubkey: None,
            }],
            updated_at: 1_782_810_000,
            expires_at: None,
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: Vec::new(),
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
        };
        sign_profile(profile, &kp.secret_key).unwrap()
    }

    #[test]
    fn validates_nostr_pubkey_shape() {
        assert!(validate_nostr_pubkey(&"a".repeat(64)).is_ok());
        assert!(validate_nostr_pubkey("npub1abc").is_err());
    }

    #[test]
    fn parses_signed_profile_event_content() {
        let profile = signed("alice@example.com");
        let nostr_pk = if profile.profile.identity_pubkey.len() == 66 {
            &profile.profile.identity_pubkey[2..]
        } else {
            &profile.profile.identity_pubkey
        };
        let content = serde_json::to_string(&profile).unwrap();
        let raw = json!([
            "EVENT",
            "sub",
            {
                "kind": SATSPATH_PROFILE_KIND,
                "pubkey": nostr_pk,
                "content": content,
                "tags": [["d", "satspath-profile:alice@example.com"]]
            }
        ])
        .to_string();

        let parsed = signed_profile_from_event(&raw, "sub", nostr_pk, "alice@example.com")
            .unwrap()
            .unwrap();
        assert_eq!(parsed.profile.alias, "alice@example.com");
    }

    #[test]
    fn rejects_event_for_wrong_alias() {
        let profile = signed("bob@example.com");
        let nostr_pk = if profile.profile.identity_pubkey.len() == 66 {
            &profile.profile.identity_pubkey[2..]
        } else {
            &profile.profile.identity_pubkey
        };
        let content = serde_json::to_string(&profile).unwrap();
        let raw = json!([
            "EVENT",
            "sub",
            {
                "kind": SATSPATH_PROFILE_KIND,
                "pubkey": nostr_pk,
                "tags": [["d", "satspath-profile:alice@example.com"]],
                "content": content
            }
        ])
        .to_string();

        let parsed = signed_profile_from_event(&raw, "sub", nostr_pk, "alice@example.com");
        assert!(parsed.is_err());
    }

    /// Plaintext and internal relay hints are refused before any connection.
    #[test]
    fn relay_hints_require_wss_and_public_host() {
        assert!(relay_http_url("wss://relay.example.com").is_ok());
        assert!(relay_http_url("ws://relay.example.com").is_err());
        assert!(relay_http_url("https://relay.example.com").is_err());
        let internal = relay_http_url("wss://127.0.0.1:7777").unwrap();
        assert!(crate::ssrf::validate_url(&internal, false).is_err());
    }
}
