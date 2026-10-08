//! BIP-353 adapter for the resolver chain.
//!
//! A BIP-353 name (`₿alice@example.com`) resolves to a DNSSEC-signed
//! `bitcoin:` URI. That is a *payment instruction* authenticated by DNSSEC —
//! it is **not** a SatsPath profile signed by the recipient's identity key.
//!
//! An earlier version of this resolver parsed the TXT record, generated a
//! fresh random keypair, and self-signed a synthetic profile with it. The
//! `pay` command then verified that self-signature and printed
//! "Signature valid.", presenting an unauthenticated DNS answer as a verified
//! identity. The signature attested nothing about the recipient.
//!
//! This resolver therefore:
//! * delegates resolution to [`crate::bip353::resolve_bip353_with`] under
//!   [`DnssecPolicy::Strict`], which fails closed on any record that was not
//!   DNSSEC-validated, rejects multiple `bitcoin:` records, reconstructs
//!   multi-string TXT records correctly and validates the BIP-321 URI;
//! * exposes the result as a [`Bip353Resolution`] via
//!   [`Bip353Resolver::resolve_instruction`];
//! * never fabricates a key or signature. As a [`ProfileResolver`] it refuses
//!   `₿` names with an explicit error instead of returning a "signed" profile.

use std::sync::Arc;

use async_trait::async_trait;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
// Compile-time guard: this type only exists when hickory is built with DNSSEC
// support. Without it, `validate = true` silently degrades to unvalidated
// lookups, which would make every record below falsely "validated".
#[allow(unused_imports)]
use hickory_resolver::proto::xfer::DnssecDnsHandle as _;
use hickory_resolver::TokioAsyncResolver;

use crate::bip353::{
    resolve_bip353_with, Bip353Resolution, DnsTxtRecord, DnsTxtResolver, DnssecPolicy,
};
use crate::resolver::ProfileResolver;
use crate::{Result, SatsPathError, SignedPaymentProfile};

/// Resolves BIP-353 names to DNSSEC-authenticated payment instructions.
pub struct Bip353Resolver {
    dns: Arc<dyn DnsTxtResolver + Send + Sync>,
}

impl Default for Bip353Resolver {
    /// Same as [`Bip353Resolver::new`].
    fn default() -> Self {
        Self::new()
    }
}

impl Bip353Resolver {
    /// Resolver backed by a local, DNSSEC-validating DNS client.
    pub fn new() -> Self {
        Self::with_dns_resolver(Arc::new(HickoryDnssecTxtResolver::new()))
    }

    /// Resolver backed by a caller-supplied TXT backend (tests, custom DNS).
    pub fn with_dns_resolver(dns: Arc<dyn DnsTxtResolver + Send + Sync>) -> Self {
        Self { dns }
    }

    /// DNSSEC is always required; there is no insecure mode on this path.
    pub fn dnssec_required(&self) -> bool {
        true
    }

    /// Resolve `name` to its DNSSEC-validated `bitcoin:` payment instruction.
    ///
    /// Fails closed ([`SatsPathError::DnssecUnavailable`]) if the record was
    /// not DNSSEC-validated.
    pub async fn resolve_instruction(&self, name: &str) -> Result<Bip353Resolution> {
        let now = chrono::Utc::now().timestamp();
        resolve_bip353_with(self.dns.as_ref(), name, DnssecPolicy::Strict, now).await
    }
}

#[async_trait]
impl ProfileResolver for Bip353Resolver {
    /// Always refuses `₿` names: a BIP-353 record is a payment instruction,
    /// not a signed SatsPath profile. Use [`Bip353Resolver::resolve_instruction`].
    async fn resolve_alias(&self, alias: &str) -> Result<SignedPaymentProfile> {
        if !alias.trim_start().starts_with('₿') {
            return Err(SatsPathError::AliasNotFound(alias.to_string()));
        }
        // A BIP-353 record carries no SatsPath identity key, so there is no
        // honest way to return a *signed* profile for it. Refuse explicitly
        // rather than fabricate a signature.
        Err(SatsPathError::Bip353(
            "BIP-353 names resolve to DNSSEC-authenticated payment instructions, not to \
             signed SatsPath profiles; use Bip353Resolver::resolve_instruction \
             (`satspath dns resolve`)"
                .into(),
        ))
    }
}

/// TXT backend using hickory's DNSSEC-validating resolver.
///
/// With `validate = true`, hickory-resolver 0.24 wraps the connection in its
/// DNSSEC handle, which verifies every RRset against a chain of trust rooted
/// in the IANA trust anchor, **drops any RRset that does not validate**, and
/// returns an error when nothing validates (so unsigned zones fail too).
/// Records that reach this function have therefore been validated locally —
/// not merely flagged by an upstream resolver's AD bit.
///
/// The resolver honours the strict contract of [`DnsTxtResolver`]: it reports
/// `dnssec_validated = true` only when validation is enabled.
pub struct HickoryDnssecTxtResolver {
    resolver: TokioAsyncResolver,
    validating: bool,
}

impl Default for HickoryDnssecTxtResolver {
    /// Same as [`HickoryDnssecTxtResolver::new`].
    fn default() -> Self {
        Self::new()
    }
}

impl HickoryDnssecTxtResolver {
    /// A resolver that validates DNSSEC locally, querying Cloudflare's servers.
    pub fn new() -> Self {
        let mut opts = ResolverOpts::default();
        opts.validate = true;
        // Local hosts-file answers carry no DNSSEC proof; never consult them.
        opts.use_hosts_file = false;
        Self {
            resolver: TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts),
            validating: true,
        }
    }
}

#[async_trait]
impl DnsTxtResolver for HickoryDnssecTxtResolver {
    /// Query TXT records for `fqdn` through the DNSSEC-validating resolver.
    async fn query_txt(&self, fqdn: &str) -> Result<Vec<DnsTxtRecord>> {
        let lookup = self
            .resolver
            .lookup(fqdn, RecordType::TXT)
            .await
            .map_err(|e| SatsPathError::NetworkError(format!("BIP-353 DNS lookup failed: {e}")))?;

        let mut out = Vec::new();
        for record in lookup.record_iter() {
            let Some(txt) = record.data().and_then(|d| d.as_txt()) else {
                continue;
            };
            // Keep each record's character-strings separate and in order;
            // `DnsTxtRecord::reconstruct` concatenates them (never across
            // records), as BIP-353 requires.
            let strings = txt
                .iter()
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();
            out.push(DnsTxtRecord {
                strings,
                dnssec_validated: self.validating,
                ttl_seconds: Some(record.ttl()),
            });
        }
        Ok(out)
    }
}
