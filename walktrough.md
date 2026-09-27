# SatsPath Engine — Walkthrough

## What SatsPath Is

SatsPath is a backend engine, protocol daemon (`satspathd`), and CLI designed to act as a universal signed payment resolver and router.
It is intended to be embedded into existing wallets (via WASM or FFI) or run as a standalone service, acting as the discovery and verification layer for resolving identity profiles and optimizing payment routing.

It can:

- Resolve a local or remote signed profile via multiple resolution methods (Local Registry, BIP-353 DNS, HTTP Well-Known, Nostr).
- Select an optimal payment rail (Lightning, On-chain, Ark) based on live mempool fees and routing rules.
- Authenticate and verify hybrid Post-Quantum signatures (ML-DSA-65 + Schnorr).
- Fetch real LNURL invoices and inspect prototype BOLT12 offers.
- Evaluate experimental Silent Payments (BIP-352) and build BIP-21 on-chain URIs.
- Preview swap directives (testnet only).

It cannot (and intentionally does not):

- Move funds automatically.
- Sign Bitcoin transactions (no spending key access or PSBT signing).
- Broadcast transactions to the network.
- Store or generate seed phrases.
- Execute mainnet swaps.

## Architecture

The project has been pruned into a minimal, standalone backend ecosystem focused purely on Rust (`crates/`), Cloudflare workers (`proxy-workers/`), and integration SDKs.

- **`satspath-core`**: Core models, profile definition, identity keys (ECDSA/Schnorr/PQC), local registry, and resolvers (BIP-353, Nostr, HTTP).
- **`satspath-router`**: The routing engine that queries live fees (with redundant oracles like mempool.space and Esplora) and selects the best payment path.
- **`satspath-pqc`**: Hybrid cryptographic suite combining classical signatures with ML-DSA-65.
- **`satspathd`**: The standalone SatsPath daemon. It features zero-configuration authentication (auto-generating an `admin.macaroon` token) and a secure API middleware.
- **`satspath-witness`**: Standalone witness node for $K$-of-$N$ checkpoint cosigning and split-view detection.
- **`satspath-wasm`**: WASM bindings that allow embedding the SatsPath resolver and router into frontend applications.
- **`satspath-cli`**: Command-line interface for human-readable interactions (ASCII QR codes, profile management, JSON quoting).
- **`satspath-swaps`**: Experimental scaffold for Boltz Exchange v2 swap integration (testnet intent preview only).

## Security and Cryptography

SatsPath is built around a strict cryptographic separation of identity and transport:

- **Identity Cryptography:** Classical `secp256k1` Schnorr signatures (BIP-340) form the primary identity layer. A hybrid post-quantum module (`ML-DSA-65-Schnorr`) is provided in `crates/satspath-pqc` as an experimental research primitive.
- **SSRF Protection:** Resolvers strictly validate URLs and block loopback, private, and internal metadata IP ranges (e.g., `169.254.169.254`) on literal IP inputs and blocked hostnames. (DNS rebinding protection requires resolution-aware connection pinning and is not currently provided by the HTTP resolver).
- **Nostr Concurrency & Tombstoning:** Concurrent multi-relay resolution reduces stale-profile selection by choosing the highest valid sequence observed across queried relays. It does not by itself prevent downgrade through coordinated withholding, malicious relay collusion, or network partitioning. It strictly rejects revoked (tombstoned) profiles.
- **Safe Persistence:** Local state uses SHA-256 keyed indexing (preventing accidental plaintext disclosure, though low-entropy aliases remain susceptible to offline dictionary enumeration). Sensitive swap material is encrypted via AES-256-GCM.

## Supported Payment Rails

1. **Lightning Network:** Selected for smaller amounts (< 100k sats). It handles LNURL-pay two-step fetches and parses BOLT11 invoices to verify amounts.
2. **On-chain:** Selected for larger amounts when fees are acceptable. Includes support for Silent Payments (`sp1...` keys) which are seamlessly integrated into the generated `bitcoin:` URIs.
3. **Ark:** Fallback for when fees are high. Provides Ark payment pointers. (Client-side DAG validation is delegated to the integrating wallet).
4. **BOLT12 (Experimental / Partial):** Prototype TLV, offer-handling, and blinded-path primitives exist in `satspath-router`, but standards-conformant checksumless BOLT12 string decoding, invoice-request construction, Merkle signing, and interoperability with implementations such as Core Lightning and LDK remain incomplete. An optional HTTP proxy scaffold (`proxy-workers/bolt12`) is available for environments without direct node RPC.

## What is Implemented vs. What is Not

| Feature | Maturity Status | Architectural Boundary |
| :--- | :--- | :--- |
| Signed profile resolution (Nostr, HTTP, Local) | **IMPLEMENTED** | Validated via unit/integration tests |
| BIP-353 DNS resolution | **PREVIEW** | Strict mode fails closed without local DNSSEC validator |
| Hybrid Identity Signature Verification (PQC ML-DSA + Schnorr) | **RESEARCH** | Research primitive in `satspath-pqc` |
| SSRF-protected Resolvers | **IMPLEMENTED** | Blocks literal private/reserved IPs and metadata hosts |
| Live multi-source fee consensus | **IMPLEMENTED** | Core RPC, Esplora, Mempool median filtering |
| Lightning rail selection & LNURL invoice fetch | **IMPLEMENTED** | Generates handoff invoice payload |
| On-chain rail & BIP-21 URI formatting | **IMPLEMENTED** | Generates standard `bitcoin:` URI |
| BOLT12 prototype primitives & blinded paths | **EXPERIMENTAL (Partial)** | Standards-conformant string decoding and CLN/LDK interop incomplete |
| Experimental Silent Payments (BIP-352) | **EXPERIMENTAL** | Primitives implemented; standards conformance & mainnet interop not claimed until vectors pass |
| Ark fallback rail selection | **PREVIEW** | Pointers and routing exist; ASP rounds simulated |
| Terminal QR code (Dense1x2 unicode) | **IMPLEMENTED** | CLI preview display |
| LocalPeerRegistry (SHA-256 keyed, no raw email) | **IMPLEMENTED** | Local state storage |
| SwapStore AES-256-GCM encryption & guards | **IMPLEMENTED** | Encrypted local store |
| Boltz API client & Swap creation (testnet) | **EXPERIMENTAL** | Testnet/regtest scaffolding in `satspath-swaps` |
| Claim/Refund transaction construction | **EXPERIMENTAL** | Testnet/regtest scaffolding in `satspath-swaps` |
| PSBT transaction signing | **OUT OF SCOPE** | Delegated strictly to host wallet |
| Ark VTXO DAG validation | **OUT OF SCOPE** | Delegated strictly to host wallet |
| Mainnet swap execution | **OUT OF SCOPE** | Deliberately unsupported in SatsPath |
| Mainnet transaction broadcast | **OUT OF SCOPE** | Delegated strictly to host wallet |

## Getting Started (Dockerized Environment)

A `docker-compose.yml` file is provided to quickly launch and auto-configure the `satspathd` daemon via a lightweight Multi-Stage Build, making it trivial to deploy a trusted local registry node.

```bash
make build
make up
make logs
```
