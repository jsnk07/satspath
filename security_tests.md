# SatsPath Security Simulation Tests & Validation Log

This document records the execution logs, results, verified security properties, and explicit boundary limitations of automated attack simulations run against SatsPath components.

> **Evaluation Methodology:**
> These simulations validate that specific defensive code paths (signature verifiers, expiry guards, heuristic rail filters, size limiters, and policy flags) execute as intended under simulated adversarial conditions. They validate defense-in-depth mechanisms implemented in the current codebase; they do not mathematically prove absolute security or replace independent third-party security audits.

---

## 1. Core Cryptography & Profile Integrity Simulations

```text
running 2 tests
✅ SETUP: Alice's profile generated and signed successfully.
⚔️ ATTACK 1: Malicious server attempts to replace Lightning address...
🛡️ DEFENSE SUCCESS: The cryptographic signature rejected the tampered profile.
test test_attack_payload_tampering ... ok

✅ SETUP: Bob's profile generated and signed successfully.
⚔️ ATTACK 2: Attacker attempts an unauthorized key rotation...
🛡️ DEFENSE SUCCESS: The rotation was rejected because it was not signed by Bob's original key.
test test_attack_unauthorized_key_rotation ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

### Attack 1: Payload Tampering (In-Transit Modification)

* **TEST:** Modifying the receiving Lightning Address in Alice's serialized profile while preserving the original cryptographic signature.
* **EXPECTED:** Verification fails closed and the tampered profile is rejected.
* **RESULT:** `verify_signed_profile` recomputed the canonical JSON payload digest (RFC 8785) and verified the BIP-340 Schnorr signature against `identity_pubkey`. Signature validation failed; the tampered profile was rejected.
* **SECURITY PROPERTY VALIDATED:** In-transit modification of signed profile fields without access to the identity private key is detected by the cryptographic signature verifier.
* **LIMITATIONS:** Does not prevent a malicious transport from dropping or withholding the profile (denial of service), nor does it authenticate that `identity_pubkey` belongs to a specific real-world human on first contact (TOFU boundary).

### Attack 2: Unauthorized Key Rotation (Identity Hijacking Attempt)

* **TEST:** Injecting an unauthorized `KeyRotation` object signed only by a freshly generated attacker key, without authorization from the victim's existing key.
* **EXPECTED:** The key rotation validator rejects the transition and preserves the existing identity key.
* **RESULT:** `is_rotation_valid` rejected the transition. The protocol requires an `AuthorizationV1` statement signed by the active predecessor key (`K1`) alongside an `AcceptanceV1` statement signed by the successor key (`K2`).
* **SECURITY PROPERTY VALIDATED:** Successor keys cannot unilaterally replace an active identity key without cryptographic authorization signed by the predecessor key.
* **LIMITATIONS:** Does not protect against an attacker who has compromised the predecessor private key itself. Key recovery without the active private key is deliberately unsupported.

---

## 2. Router Defense & Fallback Simulations

```text
running 3 tests

✅ SETUP: Normal network conditions correctly prioritize On-chain.

⚔️ ATTACK 3: Malicious oracle reports catastrophically high fees (1000 sat/vB) to force excessive miner fees...
🛡️ DEFENSE SUCCESS: Router automatically abandoned On-chain due to high fees. Reason: On-chain skipped (fee 1000 sat/vB > 30); using Lightning.
test test_attack_fee_oracle_manipulation ... ok

⚔️ ATTACK 4: Malicious node fakes high fees AND censors Lightning routes...
🛡️ DEFENSE SUCCESS: Router safely fell back to Ark (L3). Reason: Lightning skipped (routing problem); falling back to Ark.
test test_attack_routing_blackhole ... ok

⚔️ ATTACK 5: Attacker attempts to route massive payment (10 BTC) via Lightning...
🛡️ DEFENSE SUCCESS: Router blocked massive L2 payment to protect liquidity. Reason: Lightning skipped (payment too large); falling back to Ark.
test test_attack_extreme_value_liquidity ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

### Attack 3: Fee Oracle Manipulation (Spurious Fee Spike)

* **TEST:** Supplying an extreme simulated on-chain fee rate (1000 sat/vB) to the routing decision engine for a standard-sized payment.
* **EXPECTED:** Router skips the on-chain rail and selects an advertised low-fee alternative (Lightning).
* **RESULT:** The fee exceeded `HIGH_FEE_SAT_VB` (30 sat/vB); on-chain routing was skipped and Lightning was selected for the quote.
* **SECURITY PROPERTY VALIDATED:** Local heuristic fee boundaries prevent generating high-fee on-chain handoff instructions when lower-fee advertised alternatives exist.
* **LIMITATIONS:** Validates router heuristics only. SatsPath does not execute payments. If all advertised rails report high fees or routing failures, payment handoff generation will fail (`NoRouteFound`).

### Attack 4: Routing Blackhole & L2 Censorship Fallback

* **TEST:** Simulating simultaneous high on-chain fees and Lightning route unavailability (`routing_ok = false`).
* **EXPECTED:** Router detects channel route failure and evaluates the next priority rail (Ark).
* **RESULT:** The router skipped both on-chain and Lightning rails, successfully selecting the advertised Ark (L3) payment pointer as fallback.
* **SECURITY PROPERTY VALIDATED:** Routing engine implements multi-rail fallback when primary rails report channel or fee constraints.
* **LIMITATIONS:** Relies on recipient advertising valid alternative payment rails in their profile. Client-side Ark DAG validation and settlement are delegated to the host wallet.

### Attack 5: Extreme Value Liquidity Route Protection

* **TEST:** Attempting to route a 10 BTC payment through the Lightning rail.
* **EXPECTED:** Router identifies transaction size exceeding L2 liquidity safety thresholds and chooses an alternative rail.
* **RESULT:** Transaction amount exceeded `LARGE_PAYMENT_SATS`; the router bypassed Lightning and generated instructions for an alternative rail.
* **SECURITY PROPERTY VALIDATED:** High-value payments are diverted from off-chain channel routing where liquidity lockups or HTLC routing failures are common.
* **LIMITATIONS:** Heuristic threshold check only. Does not inspect live Lightning gossip channel balances across public nodes.

---

## 3. Advanced Network & Replay Attack Simulations

```text
running 2 tests
✅ SETUP: Resolver preparing to fetch remote profiles...
⚔️ ATTACK 6: Malicious alias triggers fetches to internal cloud endpoints and loopback IPs...
🛡️ DEFENSE SUCCESS: URL validation rejected all tested literal loopback/private/internal destinations.
test test_attack_ssrf_cloud_metadata ... ok

✅ SETUP: Generating an old profile from 6 months ago...
⚔️ ATTACK 7: Attacker intercepts and replays the 6-month-old zombie profile today...
🛡️ DEFENSE SUCCESS: Profile strictly rejected due to timestamp expiration. Reason: registry error: profile for 'victim@satspath.dev' expired at unix timestamp 1769803296 (now: 1785355296)
test test_attack_replay_expired_profile ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

### Attack 6: SSRF Literal Private IP & Cloud Metadata Guard

* **TEST:** Passing URLs targeting loopback (`127.0.0.1`, `[::1]`), RFC1918 private ranges (`10.0.0.1`, `192.168.1.1`), and cloud metadata (`169.254.169.254`) to `validate_url`.
* **EXPECTED:** All literal internal, link-local, loopback, and metadata destinations are rejected.
* **RESULT:** `validate_url` identified the literal IP addresses and blocked hostnames, rejecting each input before any network socket was initialized.
* **SECURITY PROPERTY VALIDATED:** URL validation blocks literal private/loopback/cloud metadata IP addresses and prohibited host strings.
* **LIMITATIONS:** Validates literal IP strings and blocked hostnames only. It does not resolve DNS hostnames prior to connection, does not pin resolved IP addresses, does not protect against DNS rebinding (TOCTOU between resolution and TCP connect), and does not inspect HTTP redirect destinations.

### Attack 7: Replay of Expired Historical Profile

* **TEST:** Replaying a historically valid, correctly signed profile whose `expires_at` timestamp has elapsed.
* **EXPECTED:** Verification fails closed due to elapsed expiration time.
* **RESULT:** `check_profile_expiry` compared `expires_at` against the current wall-clock timestamp and returned an expiration error, aborting resolution.
* **SECURITY PROPERTY VALIDATED:** Correctly signed profiles cannot be indefinitely replayed once their validity window has expired.
* **LIMITATIONS:** Profiles remain replayable within their active validity window. If a user's keys or payment methods change before `expires_at`, clients without an updated sequence or revocation event may accept the unexpired prior profile until expiration.

---

## 4. P2P Transport & Network Transit Simulations

```text
running 2 tests
✅ SETUP: User generates Testnet profile from CLI/GUI...

⚔️ ATTACK 8 (Part 1): Sniffer listens to the Hyperswarm DHT announcements...
🔍 SNIFFER SEES: Announcing on DHT Topic: 18605124289845250c7d2c090b952b2341e96df723a93033e557020f5bd8b181
🛡️ DEFENSE SUCCESS: Privacy Rule P2P-03 enforced. Alias is hashed prior to network broadcast.
test test_attack_p2p_dht_scraping_privacy ... ok

✅ SETUP: Payload broadcasted to P2P network.
⚔️ ATTACK 8 (Part 2): Sniffer intercepts the P2P payload in-transit and modifies the Testnet address...
🛡️ DEFENSE SUCCESS: The receiving Rust Core detected the P2P MITM corruption and aborted wallet-handoff generation.
test test_attack_p2p_in_transit_corruption ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

### Attack 8 (Part 1): P2P DHT Identifier Hashing

* **TEST:** Inspecting the topic key announced to the P2P network during identifier publication.
* **EXPECTED:** Identifier is published under `SHA256(canonical_alias)` rather than cleartext email string.
* **RESULT:** The transport topic matched the 32-byte SHA-256 digest; cleartext alias was not broadcast as the discovery topic.
* **SECURITY PROPERTY VALIDATED:** Prevents passive wire-sniffing tools from directly collecting plaintext email addresses from transport routing headers.
* **LIMITATIONS:** SHA-256 is deterministic and public. Low-entropy identifiers (e.g. `alice@gmail.com`) remain vulnerable to offline dictionary enumeration and rainbow-table attacks. Hashing alone does not provide full anonymity.

### Attack 8 (Part 2): P2P In-Transit Payload Corruption

* **TEST:** Modifying an advertised testnet address inside a profile transported over an untrusted P2P transport.
* **EXPECTED:** The receiving node detects payload tampering via signature mismatch and aborts handoff generation.
* **RESULT:** `verify_signed_profile` rejected the corrupted payload; handoff generation was aborted.
* **SECURITY PROPERTY VALIDATED:** Untrusted or compromised network transports cannot alter profile receiving methods without triggering signature failure.
* **LIMITATIONS:** P2P peers can refuse to relay messages or partition the network (censorship/DoS). Validates payload integrity, not transport availability.

---

## 5. Protocol Boundaries, DoS & DNSSEC Simulations

```text
running 3 tests

✅ SETUP: Resolver configured with 50KB DoS protection limit...
⚔️ ATTACK 9: Malicious server attempts to send 5MB payload to crash the node (OOM JSON Bomb)...
🛡️ DEFENSE SUCCESS: Memory exhaustion avoided! Download forcefully aborted. Reason: network error: Payload exceeded size limit of 50KB (DoS protection)
test test_attack_memory_exhaustion_dos ... ok

✅ SETUP: User requires Post-Quantum Cryptography (pqc_required = true)...
⚔️ ATTACK 10: Attacker intercepts JSON and switches pqc_required to FALSE to downgrade security...
🛡️ DEFENSE SUCCESS: Cryptographic downgrade rejected. The Schnorr signature covers the canonical profile including the PQC flag and explicitly rejects modified payloads.
test test_attack_pqc_downgrade ... ok

✅ SETUP: Analyzing DNS BIP-353 Resolver configuration...
⚔️ ATTACK 11: Malicious Wi-Fi attempts to poison DNS cache and return fake TXT records...
🛡️ DEFENSE SUCCESS: Strict DNSSEC policy rejected the unauthenticated result. The default DoH backend does not independently validate DNSSEC, so Strict mode fails closed unless authenticated DNSSEC evidence is available.
test test_attack_dns_spoofing ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
```

### Attack 9: DoS Memory Exhaustion (OOM Payload Bomb)

* **TEST:** Serving a 5MB payload to an HTTP resolver configured with a 50KB maximum size ceiling.
* **EXPECTED:** Stream is terminated as soon as downloaded bytes exceed 50KB, without buffering into memory.
* **RESULT:** The resolver aborted the download stream upon crossing the 50KB threshold with a payload size limit error.
* **SECURITY PROPERTY VALIDATED:** Memory exhaustion from oversized or unbounded HTTP response payloads is prevented by stream-level size gating.
* **LIMITATIONS:** Protects local process memory against single large payloads. Does not protect against resource exhaustion caused by high concurrency or connection exhaustion.

### Attack 10: Post-Quantum Flag Downgrade Attempt

* **TEST:** Modifying the `pqc_required: true` field to `false` in a profile that includes post-quantum public keys.
* **EXPECTED:** Classical signature verification fails because the canonical JSON hash includes all profile flags.
* **RESULT:** The signature check over the altered payload failed immediately; downgrade attempt rejected.
* **SECURITY PROPERTY VALIDATED:** Profile security policy flags cannot be toggled in transit without invalidating the outer BIP-340 signature.
* **LIMITATIONS:** PQC signatures (`crates/satspath-pqc`) are an experimental research module (ML-DSA-65) and are not part of the production safety claim.

### Attack 11: DNS Cache Spoofing (BIP-353 Strict Policy)

* **TEST:** Presenting unauthenticated or unsigned DNS TXT records to the BIP-353 resolver under default `DnssecPolicy::Strict`.
* **EXPECTED:** Resolver refuses to return unauthenticated DNS payment instructions and fails closed.
* **RESULT:** Strict policy rejected records where `dnssec_validated == false`, returning `SatsPathError::DnssecUnavailable`.
* **SECURITY PROPERTY VALIDATED:** Strict mode fails closed on unauthenticated DNS records, refusing to process unauthenticated payment instructions.
* **LIMITATIONS:** The default DoH resolver backend does not locally validate the DNSSEC cryptographic chain; it queries upstream resolvers and sets `dnssec_validated = false`. Consequently, Strict mode fails closed unless an authenticated DNS environment or custom validating resolver is provided.
