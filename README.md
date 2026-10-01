# SatsPath

**Open-source Bitcoin payment discovery and routing protocol**

**One identity. Every path.**

SatsPath maps a human-readable recipient identifier such as `alice@example.com` to a cryptographically signed payment profile, verifies it, discovers the receiver's available Bitcoin payment methods, and returns a wallet handoff for a compatible route.

> **Experimental software**
>
> Mainnet payment execution is **not implemented**. SatsPath must not be used to move real funds. Internal v2 conformance work has been completed, but an independent external security / cryptographic review is still required before any production or real-funds claim.

Website: <https://satspath.com>

---

## What SatsPath does

A Bitcoin user should not need to know which payment rail another user supports before trying to pay them.

SatsPath separates **identity and payment discovery** from **payment execution**:

```text
Human-readable identity
        |
        v
Resolver chain
HTTPS / Nostr / BIP-353 / local
        |
        v
Cryptographic verification
signature / expiry / alias / trust state
        |
        v
Payment capability discovery
Lightning / on-chain / Ark / experimental methods
        |
        v
Reference routing policy
amount / fees / urgency / available methods
        |
        v
Wallet handoff
BOLT11 / Lightning pointer / BIP-21 / Ark pointer
        |
        v
Host wallet executes the payment
```

SatsPath does **not**:

- hold custody of funds;
- store wallet seeds or spending keys;
- operate a Lightning node or Ark server;
- sign mainnet transactions;
- broadcast mainnet transactions;
- execute mainnet swaps or Ark transfers.

The protocol works with public payment data and leaves spending authority with the user's wallet.

---

## Current capability status

This table is the source of truth for public claims about the current implementation.

| Capability | Current status | Notes |
| --- | --- | --- |
| Signed payment profiles | **Implemented** | secp256k1 Schnorr signatures, canonical serialization, expiry and safety validation |
| HTTPS resolver | **Active** | Resolves signed profiles over HTTPS with SSRF/network hardening |
| Nostr resolver | **Active** | NIP-05 + kind 30078 resolution support |
| BIP-353 / DNS | **Preview / experimental** | Strict mode uses local DNSSEC validation (fails closed); results are DNS payment instructions and are never presented as signed SatsPath identities |
| Lightning Address / LNURL | **Implemented for discovery and handoff** | Can resolve public metadata and produce a wallet-facing payment payload |
| BOLT11 | **Implemented for handoff paths** | Concrete invoices may be fetched through supported LNURL flows; SatsPath does not pay them |
| BOLT12 | **Implemented for discovery and handoff** | Bech32m/TLV offer parsing, blinded path privacy routing, signed invoice requests, invoice validation, and gateway handoff |
| Bitcoin on-chain / BIP-21 | **Implemented for handoff** | Address validation, fee-aware routing and BIP-21 payload generation |
| Silent Payments | **Experimental** | Public pointer / routing support exists; spending execution remains outside SatsPath |
| Ark | **Preview / testnet-oriented** | Receive pointers and routing exist; some execution paths are mocked or simulated; no mainnet Ark execution |
| S2S v2 transparency / witnesses | **Internal conformance completed** | v2 security architecture exists; external review is still pending |
| Mainnet payment execution | **Not implemented** | Deliberately outside the current safety boundary |

If documentation, the website, or a presentation disagrees with this table, the more conservative status should be used until the implementation is verified.

---

## Reference routing policy

The current router is a **reference policy**, not a claim that one globally optimal payment route exists.

The policy currently:

1. prefers Lightning for compatible smaller payments;
2. evaluates live on-chain fee conditions and requested urgency when Lightning is not selected;
3. uses on-chain when the configured fee threshold is acceptable;
4. can fall back to Ark when an Ark receive method is available;
5. returns no route when a safe compatible method cannot be produced.

Routing logic lives in:

```text
crates/satspath-router/src/router.rs
crates/satspath-router/src/scoring.rs
crates/satspath-router/src/fees.rs
crates/satspath-router/src/lightning.rs
crates/satspath-router/src/onchain.rs
crates/satspath-router/src/ark.rs
```

Future routing policies can consider additional dimensions such as privacy, reliability, liquidity, trust assumptions, and wallet preferences without changing the core identity-resolution model.

---

## Repository architecture

SatsPath is organized as a Rust workspace with TypeScript / WASM integration surfaces.

| Component | Purpose |
| --- | --- |
| **crates/satspath-core** | Protocol types, signatures, validation, resolver chain, identity and transparency primitives |
| **crates/satspath-router** | Payment-method discovery, fee evaluation, routing and wallet-handoff generation |
| **crates/satspath-cli** | Reference command-line client for development and protocol testing |
| **crates/satspathd** | Local / authoritative daemon and HTTP API |
| **crates/satspath-wasm** | WebAssembly bindings for web and wallet integrations |
| **crates/satspath-witness** | Independent checkpoint witness / split-view detection infrastructure |
| **crates/satspath-swaps** | Experimental, testnet-only execution scaffolding |
| **crates/satspath-pqc** | Experimental post-quantum research primitives; not part of the production safety claim |
| **sdk/** | TypeScript SDK packages and integration helpers |

---

## Quickstart

### Build the Rust workspace

```bash
git clone https://github.com/satspath/satspath.git
cd satspath

cargo build --workspace
cargo test --workspace --all-targets
```

For linting and formatting:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

### Wallet / SDK integration

Start with:

- [SDK Quickstart](docs/SDK_QUICKSTART.md)
- [Protocol specification](docs/protocol.md)
- [Implementation mapping](docs/implementations.md)
- [Resolver architecture](docs/resolvers.md)

The SDK and WASM packages are experimental. Check package/release status before depending on a registry publication in production.

---

## CLI

The CLI is a reference client. It is designed for development, testing, and safe payment-preview / wallet-handoff flows.

Common areas include:

```text
satspath register
satspath quote
satspath preview
satspath pay
satspath dns
satspath peer
```

Exact flags and supported modes evolve with the protocol. Use **--help** and the documentation for the current build.

Mainnet preview may inspect public payment data, but **mainnet execution does not exist**.

---

## Security model

SatsPath is designed around a strict separation between **payment identity** and **wallet spending authority**.

### Core guarantees

- Protocol identity keys are separate from Bitcoin wallet spending keys.
- Public payment profiles are signed before they are used for routing.
- Invalid, stale, ambiguous, or unsafe profile data should fail closed.
- Resolver transports do not automatically become trust anchors.
- Public resolver requests include SSRF and network-boundary protections.
- Mainnet payment execution is intentionally outside the current implementation.

### v2 security work

The v2 architecture adds work around:

- append-only transparency logs;
- signed checkpoints;
- witness quorum / split-view detection;
- namespace and domain authority;
- replay / rollback resistance;
- server-to-server proof-carrying resolution;
- stronger adversarial and conformance testing.

Internal v2 conformance work tracked in [Issue #60](https://github.com/satspath/satspath/issues/60) is complete.

That does **not** mean SatsPath is externally audited. An independent security / cryptographic review remains a release gate before production or real-funds claims.

See:

- [Mainnet safety](docs/mainnet_safety.md)
- [Key transparency](docs/key_transparency.md)
- [S2S trust model v2](docs/s2s/trust-model-v2.md)
- [S2S server protocol v2](docs/s2s/server-v2.md)

---

## Protocol scope

The currently documented stable protocol surface in [docs/protocol.md](docs/protocol.md) is still the v1 payment-discovery and wallet-handoff model.

The repository also contains v2 security and server-to-server work. Until v2 is formally released and externally reviewed, documentation should distinguish between:

- **implemented stable / reference behavior**;
- **preview or experimental behavior**;
- **v2 security architecture**;
- **future production claims**.

This distinction is intentional. SatsPath should be useful without pretending unfinished payment rails are finished.

---

## Project origin

SatsPath began during the **Plan ₿ Summer School 2026 in Lugano**, where the project placed **second in the hackathon**.

The project has since evolved from a hackathon prototype into an open-source effort focused on Bitcoin payment identity, capability discovery, verification, and routing.

The long-term goal is not to become another wallet or another payment rail. It is to provide infrastructure that wallets and applications can use to discover **how** a recipient can be paid while preserving wallet sovereignty.

---

## Documentation

Useful entry points:

- [Protocol specification](docs/protocol.md)
- [Architecture](docs/architecture.md)
- [Implementation mapping](docs/implementations.md)
- [Resolvers](docs/resolvers.md)
- [BIP-353 DNS resolution](docs/bip353_dns_resolution.md)
- [Mainnet safety](docs/mainnet_safety.md)
- [Key transparency](docs/key_transparency.md)
- [Docker deployment](docs/docker.md)
- [SDK Quickstart](docs/SDK_QUICKSTART.md)

---

## Contributing

SatsPath is open source. Contributions should keep implementation, tests, and public claims aligned.

Before opening a PR:

1. link the relevant issue;
2. explain security and documentation impact;
3. run formatting, linting, and tests;
4. avoid introducing mainnet execution claims without a separately reviewed safety design;
5. update capability status when implementation reality changes.

---

## License

The repository currently includes the **MIT License**. See [LICENSE](LICENSE).

> Note: workspace package metadata should remain consistent with the license files shipped in the repository.

