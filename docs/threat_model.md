# SatsPath Threat Model & Security Architecture

> **Security Notice:** SatsPath is experimental, non-custodial software designed for Bitcoin payment discovery, profile verification, and route selection. SatsPath does not hold user funds, does not manage private spending keys or seed phrases, and does not execute mainnet payments. All transaction signing and fund execution are delegated to host wallets. Independent external cryptographic and security audits remain a prerequisite before production deployment with real funds.

---

## 1. Scope & Core Architectural Invariants

This document establishes the threat model for the SatsPath protocol prototype, focusing on identifier resolution, profile signature verification, key transparency, and payment-route selection. It does not replace the underlying security models of the Bitcoin blockchain, the Lightning Network (BOLT11/12), or off-chain settlement protocols (Ark).

### Core Invariants

1. **Non-Custodial Separation:** SatsPath never generates, stores, or transmits Bitcoin spending keys, wallet seeds, BIP-39 mnemonics, or Lightning macaroons. Identity keypairs (`secp256k1`) sign public payment profiles and rotation records; they carry zero spending authority.
2. **Custody Risk vs. Payment Redirection Risk:** Compromising SatsPath does not directly expose wallet spending keys or authorize Bitcoin transactions. However, a compromised discovery or handoff component may attempt payment redirection, which is why authenticated profiles, key continuity, resolver verification, and wallet-side confirmation of amounts and destinations remain security-critical.
3. **Payment Execution Sovereignty:** SatsPath discovers and validates payment capabilities, then hands off public instructions (BOLT11/12 invoices, BIP-21 URIs, Ark pointers) to the user's host wallet. The host wallet signs and executes the transaction.
4. **No Unauthenticated State:** A resolver or network transport is untrusted. Unverified, malformed, expired, or conflicting profile data fails closed.
5. **Attributable Operator State:** Servers and log operators must commit to an append-only event history and sign public checkpoints. Signed equivocation can produce attributable cryptographic evidence. Rollback attempts are detected against pinned monotonic state and rejected.

---

## 2. Decomposition of Trust Properties

SatsPath avoids collapsing security guarantees into an ambiguous `verified: true` status. Trust is factored into distinct properties, each mapped to specific mechanisms and boundaries:

| Property | Definition | Component Guaranteeing It | Underlying Assumption | Failure Mode / Limitation |
| :--- | :--- | :--- | :--- | :--- |
| **Integrity** | Payload has not been modified in transit. | Profile Schnorr Signature (`BIP-340`) over canonical JSON | `secp256k1` signature unforgeability (ECDLP/ROM) | Fails closed on semantic modifications to signed profile fields that change their RFC 8785 canonical representation. |
| **Authenticity** | Profile is authorized by the current controller of the identity key. | Domain-separated signature (`SatsPathProfileV1`) | Private key generated securely on user device and never leaked | Does not prove initial domain/namespace ownership. |
| **Freshness** | Profile represents current, unexpired payment capabilities. | `expires_at` timestamps, monotonic sequence numbers | Synchronized client wall clock within acceptable drift | Stale profiles are rejected once expiration timestamp passes. |
| **Consistency** | All verifiers observe identical, append-only history without forks. | RFC 6962-style Merkle log, signed checkpoints, witness quorum ($K$-of-$N$) | At least $(N - K + 1)$ honest, non-colluding witnesses | Local pinning detects local forks; global split-views require gossip monitors. |
| **Namespace Authority** | The human-readable name is published by the legitimate controller. | DNSSEC delegation, HTTPS well-known, Nostr NIP-05 pubkey binding | Integrity of DNS root KSK/ZSK or WebPKI root store | Provider can censor or de-list, but cannot forge identity signatures. |
| **Payment Method Ownership** | Advertised addresses/nodes belong to the profile owner. | Method ownership proofs (e.g. signed address/pubkey attestations) | Verification of proof parameters against identity key | Unproved methods represent self-asserted receive pointers. |
| **Availability** | Verifiers can locate and download signed profiles on demand. | Redundant multi-transport resolvers (HTTPS, Nostr relays, local cache) | At least one configured transport endpoint remains reachable | Adversary can deny service or withhold responses; fails to `Unavailable`. |

---

## 3. Trust-On-First-Use (TOFU) & First-Contact Limitations

When a client queries an identifier for the very first time without prior out-of-band key verification, it operates under **Trust-On-First-Use (TOFU)** assumptions:

* **What TOFU Protects Against:** Once a client observes and pins an initial checkpoint (`log_id`, operator key, sequence, root hash), subsequent attacks attempting to roll back history, present a lower tree size, or substitute an unauthorized operator key are detected immediately and rejected.
* **What TOFU Does NOT Protect Against:** If an active man-in-the-middle attacker or rogue namespace operator controls resolution during the *initial first contact*, the client may pin the attacker's fraudulent state, provided the attacker can satisfy transport proofs.
* **Mitigation via Witness Quorum & Gossip:** S2S v2 requires checkpoints to be cosigned by an independent witness quorum ($K$-of-$N$). A single rogue operator cannot serve an un-witnessed root without failing quorum checks. Future cross-witness gossip can reduce first-contact consistency risk and improve split-view detection, but does not by itself authenticate the initial namespace-to-key binding without out-of-band verification.

---

## 4. Privacy Model & Hashed Identifier Limitations

SatsPath uses `SHA256(canonical_identifier)` for internal indexation and transport topics:

* **Direct Plaintext Protection:** Hashing prevents passive network eavesdroppers from immediately reading plaintext email addresses in wire metadata or DHT routing tables.
* **Dictionary Enumeration Vulnerability:** Because human-readable identifiers (e.g., `alice@example.com`, `satoshi@gmail.com`) possess low entropy, deterministic hashing does **not** protect against an adversary performing offline dictionary attacks or rainbow-table enumeration.
* **Cryptographic Reality:** Deterministic hashing of predictable names provides pseudonymity and transit obfuscation, **not absolute anonymity**. Integrations requiring high privacy must treat identifier lookup metadata as potentially correlatable by motivated network adversaries.

---

## 5. Comprehensive Threat & Adversary Matrix

| Adversary / Attack Vector | Attack Description | Expected Detection / Prevention | Cryptographic & System Assumptions | Remaining Limitations |
| :--- | :--- | :--- | :--- | :--- |
| **Malicious Resolver** | Resolver modifies payment addresses or swaps profiles in transit. | Client recomputes canonical SHA-256 digest and verifies Schnorr signature; fails verification. | Client executes verification in local memory; signature unforgeability. | Resolver can withhold data, causing denial of service (`Unavailable`). |
| **Compromised Server / Registry** | Registry replaces Alice's identity key with an attacker's key. | Client verifies sequential history chain; registration requires initial key; updates require dual-signed `KeyRotation`. | Client validates full historical chain or pins predecessor checkpoint. | First-contact without history pin relies on TOFU or independent attestations. |
| **Malicious Namespace Provider** | Provider revokes Alice's account or points `alice@domain.com` to Bob. | Client detects break in key continuity; UI flags conflicting provider identity; some forms of equivocation or history inconsistency can be cryptographically detected. | Client maintains pin of prior identity key for existing contacts. | Pure refusal to serve or publish data is an availability/censorship event and may not produce cryptographic proof. |
| **Malicious Witness / Collusion** | Rogue witness cosigns a fraudulent or split-view checkpoint. | Quorum policy requires $K$-of-$N$ distinct signatures ($K \ge 2$); single witness cannot satisfy threshold. | At most $(K - 1)$ witnesses are compromised or collude with rogue operator. | If $\ge K$ witnesses collude with the operator, split views are undetected until audited out-of-band. |
| **Compromised Transport (MITM)** | Network attacker intercepts HTTP or DNS traffic. | TLS certificate checks, strict DNSSEC fail-closed policy, and end-to-end Schnorr profile signatures. | CA root store or DNS root trust anchor remains uncompromised. | Passive metadata leakage (IP address, timing, identifier hash). |
| **Replay Attacker** | Attacker replays a valid 6-month-old profile pointing to decommissioned addresses. | Client strictly evaluates `expires_at` against current time and rejects expired profiles. | Client local clock is reasonably accurate ($\pm$ hours, not years). | Valid profiles remain replayable until their explicit `expires_at` deadline. |
| **Rollback Attacker** | Attacker serves a valid older checkpoint to un-publish a recent rotation. | Client pins highest observed log size and sequence; rejecting any `size < pinned_size`. | Client persists monotonic pin state locally across restarts. | Fresh client without local cache relies on witness quorum freshness timestamps. |
| **Split-View / Equivocation** | Operator serves Root A to Alice and Root B to Bob for the same log size. | Checkpoint consistency proofs (RFC 6962) and witness cosigning detect distinct roots at the same sequence. | Checkpoints must be presented to common witnesses or public monitors. | Without real-time witness gossip, split views are only detected post-facto. |
| **Malicious Replica** | Desynchronized or hostile replica serves stale/omitted records. | Clients evaluate self-contained cryptographic envelopes; Merkle inclusion must bind to signed checkpoint. | Envelope contains valid inclusion proof to a fresh, witnessed checkpoint. | Replica can delay synchronization, appearing temporarily unreachable. |
| **DNS Manipulation / Cache Poisoning** | Attacker injects fraudulent DNS records for BIP-353 names. | `DnssecPolicy::Strict` requires authentic DNSSEC results and fails closed otherwise. | Validating resolver has correct trust anchors (DNS root `.`). | Default DoH backend does not independently validate the DNSSEC chain; Strict mode therefore fails closed without authenticated DNSSEC results. |
| **Profile / Key Substitution** | Attacker self-signs a fresh profile with an attacker key for victim's alias. | Log inclusion check verifies that the identity key matches the canonical history in the append-only tree. | Attacker cannot forge the victim's private key signature authorizing rotation. | Relies on client verifying log inclusion rather than bare self-signature. |
| **Identifier Enumeration** | Attacker iterates rainbow tables against `SHA256(alias)` topics. | Obfuscation limits casual sniffing; rate-limiting on directory daemons. | None (SHA-256 is deterministic and public). | Low-entropy aliases (short names, popular domains) can be enumerated offline. |
| **Payment Method Substitution** | Attacker compromises a third-party LNURL endpoint listed in profile. | SatsPath verifies LNURL metadata and match bounds; method ownership proofs bind keys to profile. | Host wallet displays payment destination details before execution. | Compromise of third-party LNURL domain can redirect payments if not pinned. |
| **Server-Side Request Forgery (SSRF)** | Malicious alias causes resolver to query cloud metadata (`169.254.169.254`) or loopback. | `validate_url` blocks known unsafe schemes, ports, hosts, and literal private/reserved IP addresses. | URL parsing and literal IP check before network request. | DNS rebinding protection requires resolution-aware validation and connection pinning and should not be assumed unless explicitly enabled by the networking backend. |
| **Denial of Service (DoS / JSON Bomb)** | Attacker serves multi-gigabyte payload or nested JSON. | Resolvers enforce strict byte-size limits (50KB) and stream aborts prior to JSON parsing. | Client runtime terminates connections exceeding size thresholds. | Attacker can temporarily consume network sockets until threshold triggers. |
| **Unicode / Confusable Identifier Attacks** | Attacker registers `аlice@example.com` (Cyrillic 'а') to impersonate `alice@example.com`. | Canonical normalization: lowercase conversion, whitespace stripping, and punycode domain parsing. | Integrating wallets display punycode (`xn--`) or issue warnings on mixed scripts. | Homograph attacks require vigilance at the UI/wallet display layer. |

---

## 6. Silent Payments (BIP-352) Security Model

SatsPath implements experimental BIP-352 Silent Payments for private on-chain settlement, decoupling sender payments from public address reuse:

### Cryptographic Foundation
1. **Computational Diffie-Hellman (CDH) over secp256k1:** Shared secret $S = a \cdot B_{\text{scan}} = b_{\text{scan}} \cdot A$, where $A$ is the sum of eligible input public keys and $B_{\text{scan}}$ is the recipient's scan public key.
2. **Dual-Key Isolation:** Recipient advertises a scan key ($B_{\text{scan}}$) and spend key ($B_{\text{spend}}$). Online scanning nodes require only $b_{\text{scan}}$ to detect incoming funds, keeping $b_{\text{spend}}$ cold.
3. **Tagged Hashing Domain Separation:** Hashes conform to BIP-340/352 (`BIP0352/Inputs` and `BIP0352/SharedSecret`) ensuring scalar tweaks cannot collide with Taproot script trees.
4. **Input Outpoint Binding:** Lexicographically smallest outpoint ($outpoint_L$) is committed to prevent tweak malleability across multi-input transactions.
5. **Conformance Status:** Experimental BIP-352 primitives and address/output construction are implemented. Standards conformance and mainnet interoperability are not claimed until the official BIP-352 test vectors pass.

---

## 7. Multi-Source Fee Consensus Security

To defend against fee manipulation where compromised or malicious oracles report inflated or deflated rates:

1. **Multi-Source Median Consensus:** Queries independent sources concurrently (Bitcoin Core RPC via `estimatesmartfee`, Esplora API, and Mempool.space). Rates are aggregated using median filtering, ensuring resilience against single-oracle manipulation or outliers.
2. **Prioritized Configuration:** Operators configure explicit, trusted fee endpoints via `SATSPATH_FEE_SOURCES` and `SATSPATH_BITCOIN_RPC_URL`.
3. **Staleness Discard:** Estimates older than `SATSPATH_FEE_MAX_STALENESS_SECS` (default: 30 minutes) are discarded.
4. **Decaying Fallback:** Under full network partitions, the router uses the last valid consensus estimate and decays it gradually toward conservative baseline fallback rates rather than aborting abruptly.

---

## 8. Summary of Residual Limitations & Release Gates

Before SatsPath can be recommended for mainnet real-funds settlement:

1. **Independent Cryptographic Audit:** Formal third-party review of canonical serialization, Merkle proof verifiers, key rotation, and domain-separated signing schemes.
2. **Decentralized Witness Quorum Deployment:** Production deployment of heterogeneous, multi-operator witnesses with public alert mechanisms.
3. **Local DNSSEC Validation:** Native inclusion of an embedded validating DNSSEC resolver for BIP-353 without reliance on upstream flags.
4. **BOLT12 Conformance & Interoperability:** Implementation of standards-conformant checksumless BOLT12 string decoding, all-TLV Merkle tree root hashing, invoice-request construction, and interoperability testing against live Core Lightning and LDK nodes.
5. **Standardized Wallet Handoff:** Finalization of BIP-21/BOLT12 handoff specifications with major open-source Bitcoin wallets.
