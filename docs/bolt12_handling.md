# BOLT12 Offer Handling and Blinded Paths in SatsPath

## Overview

BOLT12 (Lightning Offers) provides reusable, static payment codes that support:
- Amount negotiation and tip/quantity specifications.
- Onion message-based invoice request negotiation.
- Recipient and payer privacy via **blinded paths**.
- Native integration with BIP-353 (`user@domain` TXT record resolution to `lno1...`).

BOLT12 — EXPERIMENTAL / PARTIAL. Prototype TLV, offer-handling, and blinded-path primitives exist, but standards-conformant checksumless BOLT12 string decoding, invoice-request construction, Merkle signing, and interoperability with implementations such as Core Lightning and LDK remain incomplete.

---

## Protocol Lifecycle: Offer to Invoice

The payment flow proceeds through the following stages:

```text
Recipient Profile / BIP-353
         |
         v
    Bolt12Offer (lno1... / lnot1...)
         |
         v
    Validation & Blinded Path Extraction
         |
         v
    Bolt12InvoiceRequest (lnr1... / lnrt1...)
    (Payer signs request_id with ephemeral or identity key)
         |
         v
    Transport Gateway / Onion Message Proxy
    (HTTP Proxy via SATSPATH_BOLT12_PROXY or direct node RPC)
         |
         v
    Bolt12Invoice (lni1... / lnit1...)
    (Validated against offer parameters, amount, and expiry)
         |
         v
    Host Wallet Handoff / Execution
```

---

## Data Structures and TLV Encoding

BOLT12 encodes records using Type-Length-Value (TLV) streams inside bech32-style payloads (note: official BOLT12 uses its own bech32 format without the standard BIP-350 Bech32m checksum).

### 1. Bolt12Offer
- **HRP:** `lno` (Mainnet), `lnot` (Testnet), `lnob` (Regtest).
- **TLV Types:**
  - Type 2 (`offer_chains`): Genesis chain hashes.
  - Type 6 (`offer_currency`): Currency code (default: `btc`).
  - Type 8 (`offer_amount`): Truncated `u64` (tu64) amount in millisatoshis.
  - Type 10 (`offer_description`): UTF-8 description.
  - Type 14 (`offer_absolute_expiry`): Epoch timestamp.
  - Type 16 (`offer_paths`): Blinded routing paths.
  - Type 18 (`offer_issuer`): Domain or merchant identity string.
  - Type 20 (`offer_quantity_max`): Maximum item quantity.
  - Type 22 (`offer_node_id`): 33-byte compressed secp256k1 public key.
  - Type 240 (`signature`): 64-byte BIP-340 Schnorr signature.

### 2. Blinded Paths (Privacy-Preserving Routing)
A blinded path allows an offer creator to receive payments without revealing their real node public key or channel topology:
- **`introduction_node_id`**: Public entry node to the blinded route.
- **`blinding_point`**: 33-byte ephemeral public key used by hops to derive blinding factors.
- **`blinded_hops`**: Sequence of hops with encrypted onion payloads and blinded node IDs.

In SatsPath's routing engine, offers containing valid blinded paths receive an increased **privacy score** (9/10 vs 7/10 for standard Lightning), signaling enhanced sender/receiver unlinkability.

### 3. Bolt12InvoiceRequest
- **HRP:** `lnr` / `lnrt`.
- Created by the payer when initiating payment.
- Contains `offer_id` (currently computed via SHA-256 over concatenated TLVs; full all-TLV Merkle tree root alignment is scheduled for v0.2), `invreq_amount`, `payer_node_id`, optional `payer_note`, and a BIP-340 Schnorr signature.

### 4. Bolt12Invoice
- **HRP:** `lni` / `lnit`.
- Issued by the offer recipient's Lightning node.
- Validated before handoff:
  - Exact match of requested vs invoice millisatoshis.
  - Confirmation of non-expired validity window.
  - Verification of 32-byte cryptographic payment hash.

---

## Configuration and Gateway Transport

SatsPath delegates Lightning peer-to-peer onion message transmission to an external gateway or node RPC:
- **Environment Variable:** `SATSPATH_BOLT12_PROXY`
  - URL pointing to a BOLT12-capable proxy endpoint (e.g. `https://bolt12-proxy.satspath.dev`).
- **Test Mode:** `SATSPATH_MOCK_BOLT12=1`
  - Enables local simulated invoice generation for automated testing and offline development.

---

## Safety and Security Bounds

1. **No Spending Authority:** SatsPath never holds node credentials, channel funds, or private keys used for fund transfers.
2. **Strict Amount Bounds:** Invoices exceeding offer bounds (`min_amount_msats`, `max_amount_msats`, or fixed amounts) are rejected immediately.
3. **No Private Material:** Payment pointers and invoice requests are audited before return to guarantee zero leakage of secret keys or seed material.
