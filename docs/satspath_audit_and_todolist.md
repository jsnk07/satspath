# 🔍 SatsPath Codebase Audit & Implementation Roadmap

**Date:** July / August 2026  
**Repository:** `Truja503/satspath`  
**Wallet Target:** Arkade Money / SatsPath Web PWA

---

## 1. Branch Strategy & Cleanup Plan

### Context
The repository consolidated its historical feature branches into the main workspace. All core Rust functionality, cryptographic primitives, S2S v2 daemon endpoints, and unit/integration tests are contained on `main`.

### Merged Branches (Cleaned)
The following feature branches have been merged directly into `main`:

| Branch | Description | Status |
| :--- | :--- | :--- |
| `origin/chore/remove-stray-scratch-files` | File cleanup | ✅ Merged |
| `origin/codex/p2p-daemon-resolver` | P2P wire daemon | ✅ Merged |
| `origin/codex/p2p-publish-repair` | P2P publish repairs | ✅ Merged |
| `origin/feat/bip353-dns-resolution` | BIP-353 DNSSEC resolution | ✅ Merged |
| `origin/feat/holepunch-p2p-sdk` | Holepunch P2P SDK | ✅ Merged |
| `origin/feat/peer-export-import` | Profile export/import | ✅ Merged |
| `origin/feat/quote-json-contract` | QuoteResponse JSON schema | ✅ Merged |
| `origin/feat/swap-engine-ark-bridge` | Swap engine Ark bridge | ✅ Merged |
| `origin/feat/wallet-profile-manager` | Wallet profile manager | ✅ Merged |
| `origin/feature/ark-send-receive-swaps` | Ark send/receive directives | ✅ Merged |
| `origin/feature/payment-method-ownership-proofs` | Cryptographic ownership proofs | ✅ Merged |
| `origin/feature/protocol-invite-routing-model` | Invites + routing model | ✅ Merged |
| `origin/fix/v0-priority-issues` | Priority routing fixes | ✅ Merged |
| `origin/feature/mainnet-preview-mode-v2` | Mainnet safety preview | ✅ Merged |

---

## 2. Implemented Capabilities (Verified in Code)

### ✅ Protocol Core — [`satspath-core`](../crates/satspath-core/src)

| Feature | File(s) | Status |
| :--- | :--- | :--- |
| `PaymentProfile` (Lightning, On-chain, Ark) | [`profile.rs`](../crates/satspath-core/src/profile.rs) | ✅ Complete |
| `SignedPaymentProfile` with Schnorr signatures | [`profile.rs`](../crates/satspath-core/src/profile.rs) | ✅ Complete |
| Deterministic secp256k1 key derivation (`m/9737'/0'`) | [`crypto.rs`](../crates/satspath-core/src/crypto.rs) | ✅ Complete |
| Domain separator signing (`SatsPathProfileV1`) | [`crypto.rs`](../crates/satspath-core/src/crypto.rs) | ✅ Complete |
| RFC 6962 Merkle tree transparency engine | [`transparency.rs`](../crates/satspath-core/src/transparency.rs) | ✅ Complete |
| Expiration and monotonic sequence checks | [`crypto.rs`](../crates/satspath-core/src/crypto.rs) | ✅ Complete |
| Replay protection nonces | [`crypto.rs`](../crates/satspath-core/src/crypto.rs) | ✅ Complete |
| RFC-8785 Canonical JSON serialization | [`crypto.rs`](../crates/satspath-core/src/crypto.rs) | ✅ Complete |
| Public profile validation | [`validation.rs`](../crates/satspath-core/src/validation.rs) | ✅ Complete |
| Private material rejection (`xprv`, seeds) | [`validation.rs`](../crates/satspath-core/src/validation.rs) | ✅ Complete |
| Bitcoin address network validation | [`validation.rs`](../crates/satspath-core/src/validation.rs) | ✅ Complete |
| Lightning address & BOLT12 validation | [`validation.rs`](../crates/satspath-core/src/validation.rs) | ✅ Complete |
| SSRF filtering: resolved-address checks, connection pinning (anti DNS-rebinding), port allowlist | [`ssrf.rs`](../crates/satspath-core/src/ssrf.rs) | ✅ Complete |
| Cryptographic method ownership proofs | [`ownership.rs`](../crates/satspath-core/src/ownership.rs) | ✅ Complete |
| Universal request codec & payment pointers | [`codec.rs`](../crates/satspath-core/src/codec.rs), [`pointer.rs`](../crates/satspath-core/src/pointer.rs) | ✅ Complete |

### ✅ Resolver Chain — [`satspath-core/resolvers`](../crates/satspath-core/src/resolvers)

| Resolver | File | Status |
| :--- | :--- | :--- |
| `ChainResolver` (compositor with anti-substitution) | [`resolver.rs`](../crates/satspath-core/src/resolver.rs) | ✅ Complete |
| `HttpResolver` (HTTPS `.well-known` + NIP-05) | [`http.rs`](../crates/satspath-core/src/resolvers/http.rs) | ✅ Complete (SSRF-hardened) |
| `Bip353Resolver` (DNS TXT via DoH) | [`bip353.rs`](../crates/satspath-core/src/resolvers/bip353.rs) | ✅ Complete |
| `NostrResolver` (NIP-05 author binding) | [`nostr.rs`](../crates/satspath-core/src/resolvers/nostr.rs) | ✅ Complete |
| `PearResolver` (Hyperswarm P2P sidecar) | [`pear.rs`](../crates/satspath-core/src/resolvers/pear.rs) | ✅ Functional |

### ✅ Router Engine — [`satspath-router`](../crates/satspath-router/src)

| Feature | File | Status |
| :--- | :--- | :--- |
| `select_route()` (Lightning → On-chain → Ark) | [`router.rs`](../crates/satspath-router/src/router.rs) | ✅ Complete |
| Live `mempool.space` fee estimation | [`fees.rs`](../crates/satspath-router/src/fees.rs) | ✅ Complete |
| Multi-factor scoring engine | [`scoring.rs`](../crates/satspath-router/src/scoring.rs) | ✅ Complete |
| LNURL-pay 2-step (metadata → BOLT11 fetch) | [`lightning.rs`](../crates/satspath-router/src/lightning.rs) | ✅ Complete |
| Stable `QuoteResponse` UX JSON contract | [`quote_response.rs`](../crates/satspath-router/src/quote_response.rs) | ✅ Complete |

### ✅ WebAssembly Bindings — [`satspath-wasm`](../crates/satspath-wasm/src)

| Feature | File | Status |
| :--- | :--- | :--- |
| `derive_identity_keypair_from_seed()` | [`crypto.rs`](../crates/satspath-wasm/src/crypto.rs) | ✅ Complete |
| `sign_profile()` / `verify_signed_profile()` | [`crypto.rs`](../crates/satspath-wasm/src/crypto.rs) | ✅ Complete |
| `quote()` (resolve + multi-rail route) | [`router.rs`](../crates/satspath-wasm/src/router.rs) | ✅ Complete |
| Resolver chain in WASM | [`resolver.rs`](../crates/satspath-wasm/src/resolver.rs) | ✅ Complete |

### ✅ Server Daemon — [`satspathd`](../crates/satspathd/src)

| Feature | File | Status |
| :--- | :--- | :--- |
| S2S v2 Authoritative API (`/v2/resolve`, `/.well-known/satspath-authority`) | [`main.rs`](../crates/satspathd/src/main.rs) | ✅ Complete |
| RFC 6962 append-only log + Bitcoin on-chain checkpoint anchoring | [`main.rs`](../crates/satspathd/src/main.rs) | ✅ Complete (Bitcoin Core regtest verified) |
| Healthcheck & status endpoints | [`main.rs`](../crates/satspathd/src/main.rs) | ✅ Complete |

---

## 3. Production Roadmap (v0.2 Tasks)

### Phase 1: Reference Wallet Integration (Arkade Money PWA)
- [ ] Connect `@satspath/wasm` to Arkade wallet onboarding modal.
- [ ] Auto-populate public receiving addresses (Lightning, Ark pubkey, On-chain) upon identity initialization.
- [ ] Intercept send input for `@` human-readable identifiers and call `quote()`.

### Phase 2: Post-Quantum & Advanced Cryptography
- [ ] **Hybrid Signature Scheme**: Combine classical `secp256k1` Schnorr with **ML-DSA (Dilithium)**.
- [ ] **Hybrid P2P Key Encapsulation**: Combine `X25519` with **ML-KEM (Kyber)** for peer-to-peer secrets.
- [ ] **Silent Payments (BIP-352)**: Full ephemeral address derivation in client SDK.

### Phase 3: Distributed Witness Consensus
- [ ] Multi-node $K$-of-$N$ cosigning protocol in `satspath-witness`.
- [ ] Split-view automated gossip and alert propagation.
