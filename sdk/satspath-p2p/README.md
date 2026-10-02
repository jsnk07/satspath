# Experimental SatsPath P2P transport

Minimal Node.js >= 20 ESM examples using Hyperswarm to exchange existing public
SignedPaymentProfile JSON. This completes the transport referenced by `wallet publish`.
No daemon, WASM build, or centralized profile server is required.

Publisher:
```text
satspath wallet publish/export
    ↓
SignedPaymentProfile
    ↓
Hyperswarm
```

Resolver:
```text
Hyperswarm
    ↓
SignedPaymentProfile
    ↓
satspath import
    ↓
SatsPath signature verification
```

## Usage

Export your public signed profile with `satspath wallet publish` (or wallet export).
Use the exported file's actual path, and its exact `profile.alias`:

```sh
cd sdk/satspath-p2p
npm ci
node examples/publish.mjs alice@example.com /path/to/alice-profile.json
```

Keep the publisher running. On another device/network:

```sh
cd sdk/satspath-p2p
npm ci
node examples/resolve.mjs alice@example.com received-profile.json
satspath import --file received-profile.json
satspath show alice@example.com
```

The default output is `profile.json`; existing output files are never overwritten.
Output is UTF-8 without BOM. Ctrl+C stops either example and destroys its swarm.
The resolver times out after 30 seconds; each peer exchange has a 10-second limit.
Invalid responses are discarded while discovery continues.

## Protocol and trust boundary

Discovery topic: `SHA256("satspath:v1:" + canonical_alias)` as 32 raw bytes.
Canonical aliases follow `satspath-core/src/privacy.rs`: trim surrounding
whitespace, lowercase ASCII, reject non-ASCII inputs. Discovery normalization
does not change profile data: the JSON alias must exactly equal the CLI argument.
Use the profile's exact alias on both devices.

The request is the ASCII bytes `GET_PROFILE\n`. The server accepts fragmented
requests, sends the JSON bytes, and ends its stream. EOF frames the response.
Files and accumulated responses are limited to 50 KB (51,200 bytes).
Transport checks JSON structure and alias binding only; it does **not** verify
signatures, expiry, ownership, key continuity, or freshness. P2P is **not a trust
layer**. SignedPaymentProfile verification remains in the Rust SatsPath
implementation through import/show. A discovered peer can serve forged or stale
data; never treat a successful download as cryptographic verification.

Only give the publisher an exported public SignedPaymentProfile. These scripts
do not load spending keys or identity private keys, sign Bitcoin transactions,
or move funds. They preserve the existing profile format and introduce no new
cryptography. Hyperswarm's ephemeral transport identity is separate from the
SatsPath identity. Status logs do not print profiles, aliases, keys, or peer addresses.

[Hyperswarm](https://github.com/holepunchto/hyperswarm) uses DHT bootstrap
infrastructure for discovery. Connectivity depends on network/firewall conditions;
cross-network connectivity is experimental and not guaranteed. Hashed aliases
are discoverable through dictionary guessing, and profiles are public to anyone
who knows the alias. This is not an anonymity mechanism.

## Tests

```sh
npm test
```

Tests cover deterministic discovery, core alias normalization, exact alias
binding, byte limits, malformed JSON/UTF-8, fragmented responses, and timeouts.
They run offline; real cross-network discovery requires two online devices.
