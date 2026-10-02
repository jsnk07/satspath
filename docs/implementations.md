# SatsPath Implementations

This document maps the SatsPath Protocol specification to the current repository implementation.

The implementation must be understood as a protocol stack, not as a single P2P system. P2P is one transport implementation among several.

## Repository Layout

```txt
crates/satspath-core      protocol data types, signatures, resolvers, validation, transparency log, state map
crates/satspath-router    quote response contract, fee consensus, BOLT12, Silent Payments, route selection
crates/satspath-cli       command-line reference client
crates/satspathd          local / authoritative daemon and HTTP API
crates/satspath-witness   independent witness node and K-of-N checkpoint cosigner
crates/satspath-wasm      WebAssembly bindings for browser / wallet integrations
crates/satspath-swaps     experimental testnet/regtest swap scaffolding (Boltz v2)
crates/satspath-pqc       experimental post-quantum hybrid signature research module (ML-DSA-65)
docs/                     protocol, security, and operational documentation
```

## Core Protocol Types

Implemented in:

```txt
crates/satspath-core/src/profile.rs
```

Spec mapping:

| Spec object               | Rust type                  |
| ------------------------- | -------------------------- |
| `PaymentProfile`          | `PaymentProfile`           |
| `SignedPaymentProfile`    | `SignedPaymentProfile`     |
| `PaymentMethod.Lightning` | `PaymentMethod::Lightning` |
| `PaymentMethod.Onchain`   | `PaymentMethod::Onchain`   |
| `PaymentMethod.Ark`       | `PaymentMethod::Ark`       |
| Invite                    | `Invite`, `InviteRecord`   |

## Signature and Safety Validation

Implemented in:

```txt
crates/satspath-core/src/crypto.rs
crates/satspath-core/src/validation.rs
```

Responsibilities:

- Generate protocol identity keypairs (`secp256k1`).
- Sign public profiles with BIP-340 Schnorr signatures.
- Verify signed profiles over canonical JSON (RFC 8785).
- Compute identity fingerprints.
- Reject malformed public keys.
- Reject private material in public protocol objects.
- Validate Lightning addresses, Bitcoin addresses, Ark URLs, and compressed pubkeys.

Protocol identity keys are not wallet spending keys.

## Resolver Implementations

Implemented in:

```txt
crates/satspath-core/src/resolver.rs
crates/satspath-core/src/resolvers/
crates/satspath-core/src/registry.rs
crates/satspath-core/src/peer_registry.rs
```

Current resolver surfaces:

| Resolver            | File                               | Status                                                                    |
| ------------------- | ---------------------------------- | ------------------------------------------------------------------------- |
| Local registry      | `registry.rs`                      | Active local storage                                                      |
| Local peer registry | `peer_registry.rs`                 | Active local peer storage                                                 |
| BIP-353             | `resolvers/bip353.rs`, `bip353.rs` | Resolver and DNS primitives; strict DNSSEC fails closed without validator |
| HTTPS               | `resolvers/http.rs`                | Active HTTPS `.well-known` resolver with URL validation                   |
| Nostr               | `resolvers/nostr.rs`               | Active NIP-05 + kind 30078 resolver                                       |
| Platform            | `resolvers/platform.rs`            | Scaffold                                                                  |

Resolver chain behavior is implemented by `ChainResolver`.

## Quote Response and Routing

Implemented in:

```txt
crates/satspath-router/src/quote_response.rs
crates/satspath-router/src/router.rs
crates/satspath-router/src/fees.rs
crates/satspath-router/src/lightning.rs
crates/satspath-router/src/bolt12.rs
crates/satspath-router/src/silent_payments.rs
```

Spec mapping:

| Spec behavior         | Implementation                           |
| --------------------- | ---------------------------------------- |
| Resolve identifier    | `quote_inner` + `ProfileResolver`        |
| Verify profile        | `verify_signed_profile`                  |
| Check expiry          | `check_profile_expiry`                   |
| Select route          | `select_route`, `select_route_with_fees` |
| Build payment payload | `build_qr_payload`                       |
| Standard response contract | `QuoteResponse`                          |

`QuoteResponse` status values:

```txt
ok
not_registered
no_route
invalid_signature
```

These values are the UI and API contract.

## Daemon Implementation

Implemented in:

```txt
crates/satspathd/src/main.rs
```

The daemon exposes the protocol over a local/reverse-proxied HTTP API:

| Endpoint                   | Purpose                                       |
| -------------------------- | --------------------------------------------- |
| `GET /health`              | Liveness                                      |
| `GET /v1/status`           | Local daemon/protocol status                  |
| `GET /v1/node`             | Aggregate status, profile, peers, connections |
| `GET /v1/profile`          | Local wallet profile state                    |
| `PUT/POST /v1/profile`     | Create or update local public profile         |
| `POST /v1/profile/methods` | Update receive methods                        |
| `POST /v1/resolve`         | Resolve a local profile                       |
| `POST /v1/quote`           | Protocol quote response                       |
| `POST /v1/pay`             | Wallet handoff using protocol quote response  |
| `POST /v1/dns/resolve`     | BIP-353/DNS resolution                        |

`/v1/pay` does not move funds. It returns a wallet handoff containing a public payment payload and QR SVG.

## CLI Implementation

Implemented in:

```txt
crates/satspath-cli/src/
```

Important commands:

| Command | Protocol role |
| :--- | :--- |
| `register <alias>` | Create signed public profile |
| `show <alias>` | Display profile and optionally verify domain proofs online (`--verify-online`) |
| `wallet <subcommand>` | Manage local identity key and receive profile (`init`, `rotate`, `add-methods`, `show`, `publish`) |
| `quote <alias> <amount>` | Produce quote response with multi-source fee evaluation |
| `preview <recipient> <amount>` | Build mainnet-compatible public payment preview (`--mainnet`, `--json`) |
| `pay <alias> <amount>` | Resolve, route, and build QR preview |
| `dns resolve <name>` | BIP-353 resolver tooling (`--allow-insecure-dns-for-dev`) |
| `export <alias>` | Export signed profile as JSON to stdout |
| `import [file] [--url <url>]` | Import and cryptographically verify signed profile from file, stdin, or URL |
| `prove` / `attach-proof` | Generate challenge and attach method ownership proofs |
| `encode` / `decode` | Universal SatsPath URI encoding and decoding |
| `invite` / `claim` | Invitation generation and claim flows |
| `server` | Sovereign server and DNS operator onboarding (`init`, `check`) |
| `web` | Minimal local receive web UI on localhost |
| `demo` | Run full local protocol demonstration flow |

The CLI is a reference client for local development and protocol testing.

## P2P Transport Implementation

Documented in:

```txt
docs/wire_p2p.md
```

This specification defines an optional transport. It publishes and resolves signed profiles over Pear/Holepunch. It must be treated as a resolver transport, not the whole protocol.

Conformance requirements:

- Return `SignedPaymentProfile` objects.
- Verify before import or route use.
- Never treat peer connectivity as profile ownership.
- Never carry wallet private material.

Wire behavior is documented in [wire_p2p.md](./wire_p2p.md).

## Current Gaps

Known v1/v2 implementation gaps:

- **DNSSEC Local Validation:** BIP-353 strict mode requires an embedded validating resolver to avoid relying on upstream resolver flags or failing closed.
- **BOLT12 Interoperability:** Prototype TLV, offer-handling, and blinded-path primitives exist, but standards-conformant checksumless BOLT12 string decoding, invoice-request construction, Merkle signing, and interoperability with implementations such as Core Lightning and LDK remain incomplete.
- **Silent Payments Interoperability:** Experimental Silent Payments primitives and address/output construction are implemented; BIP-352 conformance and interoperability remain unverified until the official send/receive test vectors pass.
- **External Security Audit:** Independent third-party cryptographic and security audit is required before recommending real-funds production usage.
- **Ark Settlement:** Ark remains preview / simulated (receive pointers and routing exist; live ASP round execution is mocked).
- **Mainnet Payment Execution:** Mainnet payment execution and transaction signing are deliberately unsupported (delegated to host wallets).
- **Cross-Witness Gossip:** Cross-witness public gossip protocol for real-time split-view alerting is designed but not yet deployed.
- **Method Ownership Proofs:** Method ownership proofs exist in core and are enforced for quotes, with wider resolver adoption ongoing.

## Conformance Checklist

An implementation in this repo should be considered conformant when it:

- Uses `SignedPaymentProfile` for receiver data.
- Verifies signatures before routing.
- Applies expiry checks.
- Rejects unsafe private material.
- Produces the four-status `QuoteResponse`.
- Keeps resolver transports separate from protocol verification.
- Treats Pear/Holepunch as optional transport.
- Returns wallet handoff data instead of executing mainnet payments.
