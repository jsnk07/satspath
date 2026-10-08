//! BIP-353 DNS Payment Instructions — resolver layer.
//!
//! Resolves a human-readable `₿user@domain` (or `user@domain`) to a DNSSEC-backed
//! `bitcoin:` URI published at `<user>.user._bitcoin-payment.<domain>`.
//!
//! This is a **resolver/preview** layer: it never pays, signs, or broadcasts.
//!
//! # DNSSEC is mandatory
//!
//! Per BIP-353 all payment instructions must be DNSSEC-signed. The default
//! [`resolve_bip353`] validates DNSSEC locally against the root trust anchor
//! (see [`crate::resolvers::bip353::HickoryDnssecTxtResolver`]) under
//! [`DnssecPolicy::Strict`] and **fails closed** ([`SatsPathError::DnssecUnavailable`]
//! or a lookup error) rather than trusting an upstream resolver's AD bit.
//! [`DohTxtResolver`] cannot validate and is only usable with [`DnssecPolicy::DevInsecure`],
//! which exists for local testing only, is never the default, and emits loud warnings.

use std::collections::HashMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::bip321::parse_bip321;
use crate::errors::{Result, SatsPathError};
use crate::validation::assert_no_private_material;

/// The fixed BIP-353 label under which payment instructions live.
pub const BIP353_LABEL: &str = "user._bitcoin-payment";

/// How strictly DNSSEC validation is enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum DnssecPolicy {
    /// Require real DNSSEC validation; fail closed otherwise. The only safe default.
    #[default]
    Strict,
    /// Local testing only — accept unvalidated records with loud warnings.
    /// Never the default; gated behind an explicit CLI flag.
    DevInsecure,
}

/// A parsed BIP-353 human-readable name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip353Name {
    pub user: String,
    pub domain: String,
    /// Display form, e.g. `₿rodrigo@satspath.dev`.
    pub display: String,
    /// DNS query name, e.g. `rodrigo.user._bitcoin-payment.satspath.dev`.
    pub dns_name: String,
}

/// The result of resolving a [`Bip353Name`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip353Resolution {
    pub name: Bip353Name,
    pub bitcoin_uri: String,
    pub dnssec_validated: bool,
    pub ttl_seconds: Option<u32>,
    pub resolved_at: i64,
    pub warnings: Vec<String>,
}

/// A single TXT resource record: its ordered RDATA character-strings plus the
/// DNSSEC validation outcome and TTL for that record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsTxtRecord {
    /// `<=255`-byte character-strings, in RDATA order. Reconstructed by
    /// concatenation **without** separators. Never concatenated across records.
    pub strings: Vec<String>,
    pub dnssec_validated: bool,
    pub ttl_seconds: Option<u32>,
}

impl DnsTxtRecord {
    /// Reconstruct the full TXT payload from its RDATA character-strings.
    pub fn reconstruct(&self) -> String {
        self.strings.concat()
    }
}

/// Abstraction over a TXT lookup. Implementations decide whether they can offer
/// real DNSSEC proof; the resolver enforces policy on the result.
#[async_trait]
pub trait DnsTxtResolver {
    /// Return every TXT resource record present at `fqdn`.
    async fn query_txt(&self, fqdn: &str) -> Result<Vec<DnsTxtRecord>>;
}

// ─── Name parsing ───────────────────────────────────────────────────────────────

/// Parse `₿user@domain` or `user@domain` into a [`Bip353Name`].
pub fn parse_bip353_name(input: &str) -> Result<Bip353Name> {
    let trimmed = input.trim();
    // The Bitcoin sign prefix is optional; strip it if present.
    let body = trimmed.strip_prefix('₿').unwrap_or(trimmed).trim();

    let (user, domain) = body
        .split_once('@')
        .ok_or_else(|| SatsPathError::Bip353("name must be user@domain".into()))?;
    let user = user.trim();
    let domain = domain.trim();

    if user.is_empty() {
        return Err(SatsPathError::Bip353("missing user part".into()));
    }
    if domain.is_empty() {
        return Err(SatsPathError::Bip353("missing domain part".into()));
    }
    validate_user_label(user)?;
    validate_domain(domain)?;

    Ok(Bip353Name {
        user: user.to_string(),
        domain: domain.to_string(),
        display: format!("₿{user}@{domain}"),
        dns_name: format!("{user}.{BIP353_LABEL}.{domain}"),
    })
}

fn validate_user_label(user: &str) -> Result<()> {
    if user.len() > 63 {
        return Err(SatsPathError::Bip353("user label too long (>63)".into()));
    }
    if !user.is_ascii() {
        return Err(SatsPathError::Bip353(
            "non-ASCII user label (punycode not supported)".into(),
        ));
    }
    let ok = user
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !ok || user.starts_with('-') || user.ends_with('-') {
        return Err(SatsPathError::Bip353("malformed user label".into()));
    }
    Ok(())
}

fn validate_domain(domain: &str) -> Result<()> {
    if !domain.is_ascii() {
        return Err(SatsPathError::Bip353(
            "non-ASCII domain (punycode not supported)".into(),
        ));
    }
    if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
        return Err(SatsPathError::Bip353("malformed domain".into()));
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(SatsPathError::Bip353("malformed DNS label".into()));
        }
        let ok = label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        if !ok || label.starts_with('-') || label.ends_with('-') {
            return Err(SatsPathError::Bip353("malformed DNS label".into()));
        }
    }
    Ok(())
}

// ─── Resolution ─────────────────────────────────────────────────────────────────

/// Resolve a BIP-353 name using `resolver` and enforce `policy`.
///
/// Reconstructs each TXT record's RDATA, keeps only those that begin with
/// `bitcoin:`, and:
/// - rejects when **none** match,
/// - rejects when **more than one** matches (ambiguous → invalid per BIP-353),
/// - validates the payload is a parseable BIP-321 URI carrying no private material,
/// - enforces DNSSEC: `Strict` fails closed on an unvalidated record, while
///   `DevInsecure` proceeds with a loud warning.
pub async fn resolve_bip353_with<R>(
    resolver: &R,
    input: &str,
    policy: DnssecPolicy,
    now: i64,
) -> Result<Bip353Resolution>
where
    R: DnsTxtResolver + ?Sized,
{
    let name = parse_bip353_name(input)?;
    let records = resolver.query_txt(&name.dns_name).await?;

    // Keep only TXT records that reconstruct to a `bitcoin:` URI. Each record is
    // reconstructed independently — never concatenate across records.
    let mut matching: Vec<&DnsTxtRecord> = Vec::new();
    for record in &records {
        if record.reconstruct().starts_with("bitcoin:") {
            matching.push(record);
        }
    }

    if matching.is_empty() {
        return Err(SatsPathError::Bip353(
            "no bitcoin: TXT record at this name".into(),
        ));
    }
    if matching.len() > 1 {
        return Err(SatsPathError::Bip353(
            "multiple bitcoin: TXT records present — invalid per BIP-353".into(),
        ));
    }

    let record = matching[0];
    let uri = record.reconstruct();

    // Safety: a public payment instruction must never carry private material...
    assert_no_private_material(&uri)?;
    // ...and must be a valid BIP-321 URI (this also rejects unknown req-* keys).
    parse_bip321(&uri)?;

    let mut warnings = Vec::new();
    match policy {
        DnssecPolicy::Strict => {
            if !record.dnssec_validated {
                return Err(SatsPathError::DnssecUnavailable);
            }
        }
        DnssecPolicy::DevInsecure => {
            if !record.dnssec_validated {
                warnings.push(
                    "⚠ DNSSEC NOT validated (DevInsecure mode). DO NOT trust on mainnet.".into(),
                );
            }
        }
    }

    Ok(Bip353Resolution {
        name,
        bitcoin_uri: uri,
        dnssec_validated: record.dnssec_validated,
        ttl_seconds: record.ttl_seconds,
        resolved_at: now,
        warnings,
    })
}

/// Resolve a BIP-353 name with local DNSSEC validation and **Strict** policy.
///
/// Uses [`crate::resolvers::bip353::HickoryDnssecTxtResolver`], which drops any
/// record that does not chain-validate to the root trust anchor, so unsigned
/// zones and broken chains fail closed.
pub async fn resolve_bip353(name: &str) -> Result<Bip353Resolution> {
    let resolver = crate::resolvers::bip353::HickoryDnssecTxtResolver::new();
    let now = chrono::Utc::now().timestamp();
    resolve_bip353_with(&resolver, name, DnssecPolicy::Strict, now).await
}

// ─── Ownership verification ─────────────────────────────────────────────────────

/// Verify that a resolved BIP-353 record genuinely belongs to a signed profile.
///
/// Checks (per the BIP-353 ownership model):
/// - the DNS name matches the profile alias's user/domain,
/// - the record was DNSSEC validated,
/// - the `bitcoin:` URI references at least one method present in the signed
///   profile, **or** carries a SatsPath `sp-profile` / `sp-profile-hash` pointer,
/// - the profile signature is valid.
pub fn verify_bip353_ownership(
    resolution: &Bip353Resolution,
    signed: &crate::profile::SignedPaymentProfile,
) -> Result<bool> {
    use crate::profile::PaymentMethod;

    if !resolution.dnssec_validated {
        return Ok(false);
    }
    if !crate::crypto::verify_signed_profile(signed)? {
        return Ok(false);
    }

    // The alias should resolve to the same BIP-353 name.
    let alias_name = parse_bip353_name(&signed.profile.alias)?;
    if alias_name.dns_name != resolution.name.dns_name {
        return Ok(false);
    }

    let parsed = parse_bip321(&resolution.bitcoin_uri)?;

    // A SatsPath profile pointer is sufficient linkage.
    if parsed.sp_profile.is_some() || parsed.sp_profile_hash.is_some() {
        return Ok(true);
    }

    // Otherwise require the URI to reference a method the profile actually owns.
    let matches_method = signed.profile.methods.iter().any(|m| match m {
        PaymentMethod::Onchain { address, .. } => parsed.address.as_deref() == address.as_deref(),
        PaymentMethod::Lightning {
            bolt12: Some(offer),
            ..
        } => resolution.bitcoin_uri.contains(offer.as_str()),
        _ => false,
    });
    Ok(matches_method)
}

// ─── Backends ───────────────────────────────────────────────────────────────────

/// In-memory resolver for tests. Maps an FQDN to its TXT records.
#[derive(Debug, Default, Clone)]
pub struct MockDnsTxtResolver {
    pub records: HashMap<String, Vec<DnsTxtRecord>>,
}

impl MockDnsTxtResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a single TXT record at `fqdn`.
    pub fn insert(&mut self, fqdn: &str, record: DnsTxtRecord) {
        self.records
            .entry(fqdn.to_string())
            .or_default()
            .push(record);
    }
}

#[async_trait]
impl DnsTxtResolver for MockDnsTxtResolver {
    async fn query_txt(&self, fqdn: &str) -> Result<Vec<DnsTxtRecord>> {
        Ok(self.records.get(fqdn).cloned().unwrap_or_default())
    }
}

/// DNS-over-HTTPS TXT resolver (Cloudflare JSON API).
///
/// This performs a real lookup but **cannot locally validate DNSSEC**, so every
/// record it returns is marked `dnssec_validated = false`. It is therefore only
/// usable under [`DnssecPolicy::DevInsecure`]; Strict mode fails closed.
pub struct DohTxtResolver {
    endpoint: String,
}

impl Default for DohTxtResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DohTxtResolver {
    pub fn new() -> Self {
        Self {
            endpoint: "https://cloudflare-dns.com/dns-query".to_string(),
        }
    }
}

#[async_trait]
impl DnsTxtResolver for DohTxtResolver {
    async fn query_txt(&self, fqdn: &str) -> Result<Vec<DnsTxtRecord>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| SatsPathError::NetworkError(e.to_string()))?;
        let resp = client
            .get(&self.endpoint)
            .query(&[("name", fqdn), ("type", "TXT")])
            .header("accept", "application/dns-json")
            .send()
            .await
            .map_err(|e| SatsPathError::NetworkError(e.to_string()))?;
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SatsPathError::NetworkError(e.to_string()))?;

        let mut out = Vec::new();
        if let Some(answers) = json.get("Answer").and_then(|a| a.as_array()) {
            for ans in answers {
                // TXT record type == 16
                if ans.get("type").and_then(|t| t.as_u64()) != Some(16) {
                    continue;
                }
                let ttl = ans.get("TTL").and_then(|t| t.as_u64()).map(|t| t as u32);
                let data = ans.get("data").and_then(|d| d.as_str()).unwrap_or("");
                let strings = extract_quoted_strings(data);
                if !strings.is_empty() {
                    out.push(DnsTxtRecord {
                        strings,
                        // We did not validate DNSSEC locally — never claim we did.
                        dnssec_validated: false,
                        ttl_seconds: ttl,
                    });
                }
            }
        }
        Ok(out)
    }
}

/// Extract the `"..."`-quoted character-strings from a DoH TXT `data` field.
fn extract_quoted_strings(data: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = data.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' {
            let mut s = String::new();
            while let Some(&n) = chars.peek() {
                chars.next();
                if n == '\\' {
                    if let Some(&e) = chars.peek() {
                        chars.next();
                        s.push(e);
                    }
                } else if n == '"' {
                    break;
                } else {
                    s.push(n);
                }
            }
            out.push(s);
        }
    }
    if out.is_empty() && !data.is_empty() {
        out.push(data.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000;

    fn txt(strings: &[&str], dnssec: bool) -> DnsTxtRecord {
        DnsTxtRecord {
            strings: strings.iter().map(|s| s.to_string()).collect(),
            dnssec_validated: dnssec,
            ttl_seconds: Some(1800),
        }
    }

    async fn resolve(
        records: Vec<DnsTxtRecord>,
        input: &str,
        policy: DnssecPolicy,
    ) -> Result<Bip353Resolution> {
        let name = parse_bip353_name(input).unwrap();
        let mut resolver = MockDnsTxtResolver::new();
        for r in records {
            resolver.insert(&name.dns_name, r);
        }
        resolve_bip353_with(&resolver, input, policy, NOW).await
    }

    #[test]
    fn parses_name_with_bitcoin_prefix() {
        let n = parse_bip353_name("₿rodrigo@satspath.dev").unwrap();
        assert_eq!(n.user, "rodrigo");
        assert_eq!(n.domain, "satspath.dev");
        assert_eq!(n.display, "₿rodrigo@satspath.dev");
        assert_eq!(n.dns_name, "rodrigo.user._bitcoin-payment.satspath.dev");
    }

    #[test]
    fn parses_name_without_prefix() {
        let n = parse_bip353_name("rodrigo@satspath.dev").unwrap();
        assert_eq!(n.dns_name, "rodrigo.user._bitcoin-payment.satspath.dev");
    }

    #[test]
    fn builds_correct_dns_name() {
        let n = parse_bip353_name("alice@example.com").unwrap();
        assert_eq!(n.dns_name, "alice.user._bitcoin-payment.example.com");
    }

    #[test]
    fn rejects_malformed_names() {
        assert!(parse_bip353_name("nobody").is_err()); // no @
        assert!(parse_bip353_name("@example.com").is_err()); // no user
        assert!(parse_bip353_name("alice@").is_err()); // no domain
        assert!(parse_bip353_name("alice@nodot").is_err()); // domain has no dot
        assert!(parse_bip353_name("a lice@example.com").is_err()); // bad label char
        assert!(parse_bip353_name("rodrigo@satspath.dev₿").is_err()); // non-ASCII domain
    }

    #[tokio::test]
    async fn reconstructs_chunked_txt_into_one_uri() {
        // One TXT RR split into multiple character-strings → concatenated.
        let r = txt(
            &["bitcoin:?lno=lno1qveryl", "ongofferstringcontinued"],
            true,
        );
        let res = resolve(vec![r], "rodrigo@satspath.dev", DnssecPolicy::Strict)
            .await
            .unwrap();
        assert_eq!(
            res.bitcoin_uri,
            "bitcoin:?lno=lno1qverylongofferstringcontinued"
        );
        assert!(res.dnssec_validated);
        assert_eq!(res.ttl_seconds, Some(1800));
    }

    #[tokio::test]
    async fn ignores_non_bitcoin_txt_records() {
        let records = vec![
            txt(&["v=spf1 include:_spf.example.com ~all"], true),
            txt(&["bitcoin:?lno=lno1qoffer"], true),
        ];
        let res = resolve(records, "rodrigo@satspath.dev", DnssecPolicy::Strict)
            .await
            .unwrap();
        assert_eq!(res.bitcoin_uri, "bitcoin:?lno=lno1qoffer");
    }

    #[tokio::test]
    async fn rejects_multiple_bitcoin_txt_records() {
        let records = vec![
            txt(&["bitcoin:?lno=lno1aaa"], true),
            txt(&["bitcoin:?lno=lno1bbb"], true),
        ];
        let err = resolve(records, "rodrigo@satspath.dev", DnssecPolicy::Strict)
            .await
            .unwrap_err();
        assert!(matches!(err, SatsPathError::Bip353(_)));
    }

    #[tokio::test]
    async fn strict_mode_fails_closed_without_dnssec() {
        let r = txt(&["bitcoin:?lno=lno1qoffer"], false); // not DNSSEC validated
        let err = resolve(vec![r], "rodrigo@satspath.dev", DnssecPolicy::Strict)
            .await
            .unwrap_err();
        assert!(matches!(err, SatsPathError::DnssecUnavailable));
    }

    #[tokio::test]
    async fn dev_insecure_allows_unvalidated_with_warning() {
        let r = txt(&["bitcoin:?lno=lno1qoffer"], false);
        let res = resolve(vec![r], "rodrigo@satspath.dev", DnssecPolicy::DevInsecure)
            .await
            .unwrap();
        assert!(!res.dnssec_validated);
        assert!(!res.warnings.is_empty());
        assert!(res.warnings[0].contains("DNSSEC NOT validated"));
    }

    #[tokio::test]
    async fn rejects_private_material_in_txt_payload() {
        let r = txt(&["bitcoin:?lno=lno1&note=my xprv9s1 secret"], true);
        let err = resolve(vec![r], "rodrigo@satspath.dev", DnssecPolicy::Strict)
            .await
            .unwrap_err();
        assert!(matches!(err, SatsPathError::PrivateMaterialRejected(_)));
    }

    #[tokio::test]
    async fn rejects_unknown_required_param_via_bip321() {
        let r = txt(&["bitcoin:?req-future=1"], true);
        let err = resolve(vec![r], "rodrigo@satspath.dev", DnssecPolicy::Strict)
            .await
            .unwrap_err();
        assert!(matches!(err, SatsPathError::InvalidPaymentUri(_)));
    }

    #[test]
    fn default_policy_is_strict() {
        assert_eq!(DnssecPolicy::default(), DnssecPolicy::Strict);
    }

    #[test]
    fn doh_extracts_quoted_strings() {
        assert_eq!(
            extract_quoted_strings("\"bitcoin:?lno=lno1\" \"continued\""),
            vec!["bitcoin:?lno=lno1".to_string(), "continued".to_string()]
        );
    }
}
