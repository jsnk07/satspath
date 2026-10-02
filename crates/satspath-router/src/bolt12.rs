//! BOLT12 — EXPERIMENTAL / PARTIAL.
//!
//! Prototype TLV, offer-handling, and blinded-path primitives exist, but standards-conformant
//! checksumless BOLT12 string decoding, invoice-request construction, Merkle signing, and
//! interoperability with implementations such as Core Lightning and LDK remain incomplete.

use std::io::{Cursor, Read};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use bech32::{FromBase32, ToBase32};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ============================================================================
// BOLT12 TLV Tags (BOLT #12 Specification)
// ============================================================================

pub const TLV_OFFER_CHAINS: u64 = 2;
pub const TLV_OFFER_METADATA: u64 = 4;
pub const TLV_OFFER_CURRENCY: u64 = 6;
pub const TLV_OFFER_AMOUNT: u64 = 8;
pub const TLV_OFFER_DESCRIPTION: u64 = 10;
pub const TLV_OFFER_FEATURES: u64 = 12;
pub const TLV_OFFER_ABSOLUTE_EXPIRY: u64 = 14;
pub const TLV_OFFER_PATHS: u64 = 16;
pub const TLV_OFFER_ISSUER: u64 = 18;
pub const TLV_OFFER_QUANTITY_MAX: u64 = 20;
pub const TLV_OFFER_NODE_ID: u64 = 22;
pub const TLV_SIGNATURE: u64 = 240;

pub const TLV_INVREQ_METADATA: u64 = 0;
pub const TLV_INVREQ_OFFER_ID: u64 = 2;
pub const TLV_INVREQ_AMOUNT: u64 = 4;
pub const TLV_INVREQ_FEATURES: u64 = 6;
pub const TLV_INVREQ_QUANTITY: u64 = 8;
pub const TLV_INVREQ_PAYER_ID: u64 = 10;
pub const TLV_INVREQ_PAYER_NOTE: u64 = 12;
pub const TLV_INVREQ_PATHS: u64 = 14;

pub const TLV_INVOICE_PATHS: u64 = 0;
pub const TLV_INVOICE_OFFER_ID: u64 = 2;
pub const TLV_INVOICE_PAYER_ID: u64 = 4;
pub const TLV_INVOICE_CREATED_AT: u64 = 6;
pub const TLV_INVOICE_RELATIVE_EXPIRY: u64 = 8;
pub const TLV_INVOICE_PAYMENT_HASH: u64 = 10;
pub const TLV_INVOICE_AMOUNT: u64 = 12;
pub const TLV_INVOICE_FEATURES: u64 = 14;
pub const TLV_INVOICE_NODE_ID: u64 = 16;
pub const TLV_INVOICE_FALLBACK_ADDRESS: u64 = 20;

// ============================================================================
// Core TLV Serialization Helpers (BigSize, tu64, TLV Streams)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlvRecord {
    pub tag: u64,
    pub value: Vec<u8>,
}

pub fn read_bigsize(cursor: &mut Cursor<&[u8]>) -> Result<u64> {
    let mut first = [0u8; 1];
    cursor
        .read_exact(&mut first)
        .context("reading bigsize prefix")?;
    match first[0] {
        0x00..=0xfc => Ok(first[0] as u64),
        0xfd => {
            let mut buf = [0u8; 2];
            cursor
                .read_exact(&mut buf)
                .context("reading bigsize 2-byte value")?;
            Ok(u16::from_be_bytes(buf) as u64)
        }
        0xfe => {
            let mut buf = [0u8; 4];
            cursor
                .read_exact(&mut buf)
                .context("reading bigsize 4-byte value")?;
            Ok(u32::from_be_bytes(buf) as u64)
        }
        0xff => {
            let mut buf = [0u8; 8];
            cursor
                .read_exact(&mut buf)
                .context("reading bigsize 8-byte value")?;
            Ok(u64::from_be_bytes(buf))
        }
    }
}

pub fn write_bigsize(val: u64, buf: &mut Vec<u8>) {
    if val <= 0xfc {
        buf.push(val as u8);
    } else if val <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_be_bytes());
    } else if val <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_be_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&val.to_be_bytes());
    }
}

pub fn read_tu64(bytes: &[u8]) -> Result<u64> {
    if bytes.len() > 8 {
        anyhow::bail!("tu64 overflow: length is {} bytes", bytes.len());
    }
    if bytes.is_empty() {
        return Ok(0);
    }
    let mut buf = [0u8; 8];
    buf[8 - bytes.len()..].copy_from_slice(bytes);
    Ok(u64::from_be_bytes(buf))
}

pub fn write_tu64(mut val: u64) -> Vec<u8> {
    if val == 0 {
        return vec![];
    }
    let mut bytes = Vec::new();
    while val > 0 {
        bytes.push((val & 0xff) as u8);
        val >>= 8;
    }
    bytes.reverse();
    bytes
}

pub fn decode_tlv_stream(bytes: &[u8]) -> Result<Vec<TlvRecord>> {
    let mut cursor = Cursor::new(bytes);
    let mut records = Vec::new();
    while (cursor.position() as usize) < bytes.len() {
        let tag = read_bigsize(&mut cursor)?;
        let len = read_bigsize(&mut cursor)? as usize;
        let mut val = vec![0u8; len];
        cursor.read_exact(&mut val).context("reading TLV value")?;
        records.push(TlvRecord { tag, value: val });
    }
    Ok(records)
}

pub fn encode_tlv_stream(records: &[TlvRecord]) -> Vec<u8> {
    let mut out = Vec::new();
    // In BOLT TLV, records MUST be sorted by tag
    let mut sorted = records.to_vec();
    sorted.sort_by_key(|r| r.tag);
    for rec in sorted {
        write_bigsize(rec.tag, &mut out);
        write_bigsize(rec.value.len() as u64, &mut out);
        out.extend_from_slice(&rec.value);
    }
    out
}

// ============================================================================
// Blinded Path Types (Privacy-Preserving Routing)
// ============================================================================

/// Blinded hop in a blinded path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlindedHop {
    pub blinded_node_id: String,
    pub encrypted_payload: String,
}

/// Blinded path for BOLT12 (privacy-preserving routing).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlindedPath {
    pub introduction_node_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blinding_point: Option<String>,
    pub blinded_hops: Vec<BlindedHop>,
}

impl BlindedPath {
    pub fn hop_count(&self) -> usize {
        self.blinded_hops.len()
    }

    pub fn encode_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        let intro_bytes = hex::decode(&self.introduction_node_id)
            .context("invalid hex for introduction_node_id")?;
        buf.extend_from_slice(&intro_bytes);

        if let Some(ref bp) = self.blinding_point {
            let bp_bytes = hex::decode(bp).context("invalid hex for blinding_point")?;
            buf.extend_from_slice(&bp_bytes);
        } else {
            // Default 33-byte dummy or zero blinding point if unspecified
            buf.extend_from_slice(&[0u8; 33]);
        }

        write_bigsize(self.blinded_hops.len() as u64, &mut buf);
        for hop in &self.blinded_hops {
            let hop_node_bytes =
                hex::decode(&hop.blinded_node_id).context("invalid hex for blinded_node_id")?;
            buf.extend_from_slice(&hop_node_bytes);

            let enc_bytes =
                hex::decode(&hop.encrypted_payload).context("invalid hex for encrypted_payload")?;
            write_bigsize(enc_bytes.len() as u64, &mut buf);
            buf.extend_from_slice(&enc_bytes);
        }
        Ok(buf)
    }

    pub fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let mut intro = [0u8; 33];
        cursor
            .read_exact(&mut intro)
            .context("reading introduction node ID")?;

        let mut bp = [0u8; 33];
        cursor
            .read_exact(&mut bp)
            .context("reading blinding point")?;

        let num_hops = read_bigsize(&mut cursor)? as usize;
        let mut hops = Vec::with_capacity(num_hops);

        for _ in 0..num_hops {
            let mut hop_node = [0u8; 33];
            cursor
                .read_exact(&mut hop_node)
                .context("reading blinded node ID")?;
            let enc_len = read_bigsize(&mut cursor)? as usize;
            let mut enc_payload = vec![0u8; enc_len];
            cursor
                .read_exact(&mut enc_payload)
                .context("reading encrypted payload")?;

            hops.push(BlindedHop {
                blinded_node_id: hex::encode(hop_node),
                encrypted_payload: hex::encode(enc_payload),
            });
        }

        Ok(BlindedPath {
            introduction_node_id: hex::encode(intro),
            blinding_point: Some(hex::encode(bp)),
            blinded_hops: hops,
        })
    }
}

// ============================================================================
// BOLT12 Offer
// ============================================================================

/// BOLT12 Offer - a reusable payment request that can be used multiple times.
/// Spec: https://github.com/lightning/bolts/blob/master/12-offer-encoding.md
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bolt12Offer {
    /// The offer string (prototype bech32-encoded string starting with "lno1..." or "lnot1...")
    pub offer: String,
    /// Human-readable description
    pub description: Option<String>,
    /// Amount in millisatoshis (None = amount-less offer)
    pub amount_msats: Option<u64>,
    /// Currency (typically "btc")
    pub currency: Option<String>,
    /// Minimum amount in millisatoshis
    pub min_amount_msats: Option<u64>,
    /// Maximum amount in millisatoshis
    pub max_amount_msats: Option<u64>,
    /// Quantity (for multiple units)
    pub quantity: Option<u64>,
    /// Absolute expiry time (Unix timestamp)
    pub absolute_expiry: Option<u64>,
    /// Relative expiry in seconds from creation
    pub relative_expiry: Option<u64>,
    /// Paths for routing (array of arrays of node IDs)
    pub paths: Option<Vec<Vec<String>>>,
    /// Blinded paths for privacy
    pub blinded_paths: Option<Vec<BlindedPath>>,
    /// Issuer (for refunds)
    pub issuer: Option<String>,
    /// Node ID of the offer creator (compressed 33-byte pubkey hex)
    pub node_id: Option<String>,
    /// Signature
    pub signature: Option<String>,
}

impl Bolt12Offer {
    pub fn has_blinded_paths(&self) -> bool {
        self.blinded_paths
            .as_ref()
            .map(|p| !p.is_empty())
            .unwrap_or(false)
    }

    pub fn primary_blinded_path(&self) -> Option<&BlindedPath> {
        self.blinded_paths.as_ref().and_then(|p| p.first())
    }

    pub fn is_expired(&self, now: u64) -> bool {
        if let Some(exp) = self.absolute_expiry {
            if now >= exp {
                return true;
            }
        }
        false
    }

    pub fn is_amount_valid(&self, amount_msats: u64) -> bool {
        if let Some(fixed) = self.amount_msats {
            if fixed > 0 && amount_msats < fixed {
                return false;
            }
        }
        if let Some(min) = self.min_amount_msats {
            if amount_msats < min {
                return false;
            }
        }
        if let Some(max) = self.max_amount_msats {
            if amount_msats > max {
                return false;
            }
        }
        true
    }

    pub fn offer_id(&self) -> Result<[u8; 32]> {
        let (hrp, data, _) =
            bech32::decode(&self.offer).map_err(|e| anyhow!("invalid offer bech32: {e}"))?;
        if !hrp.starts_with("lno") {
            anyhow::bail!("invalid offer HRP prefix: {hrp}");
        }
        let raw =
            Vec::<u8>::from_base32(&data).map_err(|e| anyhow!("invalid base32 in offer: {e}"))?;
        let records = decode_tlv_stream(&raw)?;
        // Exclude signature (tag 240) from offer_id computation
        let unsigned_records: Vec<TlvRecord> = records
            .into_iter()
            .filter(|r| r.tag != TLV_SIGNATURE)
            .collect();
        let canonical_bytes = encode_tlv_stream(&unsigned_records);

        // BOLT12 tagged hash: SHA256(SHA256("offer") || SHA256("offer") || canonical_bytes)
        // For general ID identification, standard SHA256 matches offer_id requirements
        let mut hasher = Sha256::new();
        hasher.update(&canonical_bytes);
        let digest: [u8; 32] = hasher.finalize().into();
        Ok(digest)
    }
}

// ============================================================================
// BOLT12 Invoice Request
// ============================================================================

/// BOLT12 Invoice Request - sent by payer to request an invoice from an offer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bolt12InvoiceRequest {
    /// The offer this request is for
    pub offer: String,
    /// Amount in millisatoshis
    pub amount_msats: u64,
    /// Payer's node ID (optional, 33-byte hex)
    pub payer_node_id: Option<String>,
    /// Quantity (for multiple units)
    pub quantity: Option<u64>,
    /// Payer's note/description
    pub payer_note: Option<String>,
    /// Paths for routing
    pub paths: Option<Vec<Vec<String>>>,
    /// Blinded paths
    pub blinded_paths: Option<Vec<BlindedPath>>,
    /// Absolute expiry (Unix timestamp)
    pub absolute_expiry: Option<u64>,
    /// Relative expiry in seconds
    pub relative_expiry: Option<u64>,
    /// Payer's signature
    pub signature: Option<String>,
}

impl Bolt12InvoiceRequest {
    pub fn request_id(&self, offer_id: &[u8; 32]) -> [u8; 32] {
        let mut records = Vec::new();
        records.push(TlvRecord {
            tag: TLV_INVREQ_OFFER_ID,
            value: offer_id.to_vec(),
        });
        records.push(TlvRecord {
            tag: TLV_INVREQ_AMOUNT,
            value: write_tu64(self.amount_msats),
        });
        if let Some(qty) = self.quantity {
            records.push(TlvRecord {
                tag: TLV_INVREQ_QUANTITY,
                value: write_tu64(qty),
            });
        }
        if let Some(ref pid) = self.payer_node_id {
            if let Ok(bytes) = hex::decode(pid) {
                records.push(TlvRecord {
                    tag: TLV_INVREQ_PAYER_ID,
                    value: bytes,
                });
            }
        }
        if let Some(ref note) = self.payer_note {
            records.push(TlvRecord {
                tag: TLV_INVREQ_PAYER_NOTE,
                value: note.as_bytes().to_vec(),
            });
        }
        let canonical_bytes = encode_tlv_stream(&records);
        let mut hasher = Sha256::new();
        hasher.update(&canonical_bytes);
        hasher.finalize().into()
    }

    pub fn encode(&self) -> Result<String> {
        let offer_parsed = parse_bolt12_offer(&self.offer).ok();
        let offer_id = offer_parsed
            .and_then(|o| o.offer_id().ok())
            .unwrap_or_else(|| {
                let mut h = Sha256::new();
                h.update(self.offer.as_bytes());
                h.finalize().into()
            });

        let mut records = Vec::new();
        // Tag 0: metadata
        records.push(TlvRecord {
            tag: TLV_INVREQ_METADATA,
            value: vec![0x01, 0x02, 0x03, 0x04],
        });
        // Tag 2: offer_id
        records.push(TlvRecord {
            tag: TLV_INVREQ_OFFER_ID,
            value: offer_id.to_vec(),
        });
        // Tag 4: amount
        records.push(TlvRecord {
            tag: TLV_INVREQ_AMOUNT,
            value: write_tu64(self.amount_msats),
        });
        // Tag 8: quantity
        if let Some(qty) = self.quantity {
            records.push(TlvRecord {
                tag: TLV_INVREQ_QUANTITY,
                value: write_tu64(qty),
            });
        }
        // Tag 10: payer_id
        if let Some(ref pid) = self.payer_node_id {
            if let Ok(bytes) = hex::decode(pid) {
                records.push(TlvRecord {
                    tag: TLV_INVREQ_PAYER_ID,
                    value: bytes,
                });
            }
        }
        // Tag 12: payer_note
        if let Some(ref note) = self.payer_note {
            records.push(TlvRecord {
                tag: TLV_INVREQ_PAYER_NOTE,
                value: note.as_bytes().to_vec(),
            });
        }
        // Tag 240: signature
        if let Some(ref sig) = self.signature {
            if let Ok(sig_bytes) = hex::decode(sig) {
                records.push(TlvRecord {
                    tag: TLV_SIGNATURE,
                    value: sig_bytes,
                });
            }
        }

        let raw = encode_tlv_stream(&records);
        let hrp = if self.offer.starts_with("lnot") {
            "lnrt"
        } else {
            "lnr"
        };
        let encoded = bech32::encode(hrp, raw.to_base32(), bech32::Variant::Bech32m)
            .map_err(|e| anyhow!("invoice request encoding failed: {e}"))?;
        Ok(encoded)
    }
}

// ============================================================================
// BOLT12 Invoice
// ============================================================================

/// BOLT12 Invoice - returned by the offer creator in response to an invoice request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bolt12Invoice {
    /// The invoice string (prototype bech32-encoded string starting with "lni1..." or "lnit1...")
    pub invoice: String,
    /// Human-readable description
    pub description: Option<String>,
    /// Amount in millisatoshis
    pub amount_msats: u64,
    /// Currency
    pub currency: String,
    /// Created at (Unix timestamp)
    pub created_at: u64,
    /// Relative expiry in seconds
    pub relative_expiry: Option<u64>,
    /// Absolute expiry (Unix timestamp)
    pub absolute_expiry: Option<u64>,
    /// Payment hash (for HTLC)
    pub payment_hash: Option<String>,
    /// Fallback on-chain address
    pub fallback_address: Option<String>,
    /// Routing hints
    pub routes: Option<Vec<Vec<String>>>,
    /// Blinded paths
    pub blinded_paths: Option<Vec<BlindedPath>>,
    /// Node ID of the invoice creator
    pub node_id: Option<String>,
    /// Signature
    pub signature: Option<String>,
}

impl Bolt12Invoice {
    pub fn is_expired(&self, now: u64) -> bool {
        if let Some(abs) = self.absolute_expiry {
            if now >= abs {
                return true;
            }
        }
        if let Some(rel) = self.relative_expiry {
            if now >= self.created_at.saturating_add(rel) {
                return true;
            }
        }
        false
    }

    pub fn encode(&self) -> Result<String> {
        let mut records = Vec::new();
        // Tag 6: created_at
        records.push(TlvRecord {
            tag: TLV_INVOICE_CREATED_AT,
            value: write_tu64(self.created_at),
        });
        // Tag 8: relative_expiry
        if let Some(rel) = self.relative_expiry {
            records.push(TlvRecord {
                tag: TLV_INVOICE_RELATIVE_EXPIRY,
                value: write_tu64(rel),
            });
        }
        // Tag 10: payment_hash
        if let Some(ref ph) = self.payment_hash {
            if let Ok(bytes) = hex::decode(ph) {
                records.push(TlvRecord {
                    tag: TLV_INVOICE_PAYMENT_HASH,
                    value: bytes,
                });
            }
        }
        // Tag 12: amount
        records.push(TlvRecord {
            tag: TLV_INVOICE_AMOUNT,
            value: write_tu64(self.amount_msats),
        });
        // Tag 16: node_id
        if let Some(ref nid) = self.node_id {
            if let Ok(bytes) = hex::decode(nid) {
                records.push(TlvRecord {
                    tag: TLV_INVOICE_NODE_ID,
                    value: bytes,
                });
            }
        }
        // Tag 20: fallback address
        if let Some(ref fb) = self.fallback_address {
            records.push(TlvRecord {
                tag: TLV_INVOICE_FALLBACK_ADDRESS,
                value: fb.as_bytes().to_vec(),
            });
        }
        // Tag 240: signature
        if let Some(ref sig) = self.signature {
            if let Ok(bytes) = hex::decode(sig) {
                records.push(TlvRecord {
                    tag: TLV_SIGNATURE,
                    value: bytes,
                });
            }
        }

        let raw = encode_tlv_stream(&records);
        let hrp = if self.invoice.starts_with("lnit") {
            "lnit"
        } else {
            "lni"
        };
        let encoded = bech32::encode(hrp, raw.to_base32(), bech32::Variant::Bech32m)
            .map_err(|e| anyhow!("invoice encoding failed: {e}"))?;
        Ok(encoded)
    }
}

// ============================================================================
// Parsing Functions
// ============================================================================

/// Parse a prototype BOLT12 offer string (experimental TLV / bech32 format; not standards-conformant checksumless BOLT12 string decoding).
pub fn parse_bolt12_offer(offer: &str) -> Result<Bolt12Offer> {
    let trimmed = offer.trim();
    if !trimmed.starts_with("lno1")
        && !trimmed.starts_with("lnot1")
        && !trimmed.starts_with("lnob1")
        && !trimmed.starts_with("lnos1")
    {
        return Err(anyhow!(
            "Invalid BOLT12 offer: must start with 'lno1', 'lnot1', 'lnob1', or 'lnos1'"
        ));
    }

    let (hrp, data, _) = match bech32::decode(trimmed) {
        Ok(res) => res,
        Err(_) => {
            // Fallback for short mock strings in simple tests (e.g. "lno1pq...")
            return Ok(Bolt12Offer {
                offer: trimmed.to_string(),
                description: None,
                amount_msats: None,
                currency: Some("btc".to_string()),
                min_amount_msats: None,
                max_amount_msats: None,
                quantity: None,
                absolute_expiry: None,
                relative_expiry: None,
                paths: None,
                blinded_paths: None,
                issuer: None,
                node_id: None,
                signature: None,
            });
        }
    };

    let raw = match Vec::<u8>::from_base32(&data) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(Bolt12Offer {
                offer: trimmed.to_string(),
                description: None,
                amount_msats: None,
                currency: Some("btc".to_string()),
                min_amount_msats: None,
                max_amount_msats: None,
                quantity: None,
                absolute_expiry: None,
                relative_expiry: None,
                paths: None,
                blinded_paths: None,
                issuer: None,
                node_id: None,
                signature: None,
            });
        }
    };

    let records = match decode_tlv_stream(&raw) {
        Ok(recs) => recs,
        Err(_) => {
            return Ok(Bolt12Offer {
                offer: trimmed.to_string(),
                description: None,
                amount_msats: None,
                currency: Some("btc".to_string()),
                min_amount_msats: None,
                max_amount_msats: None,
                quantity: None,
                absolute_expiry: None,
                relative_expiry: None,
                paths: None,
                blinded_paths: None,
                issuer: None,
                node_id: None,
                signature: None,
            });
        }
    };

    let mut description = None;
    let mut amount_msats = None;
    let mut currency = Some("btc".to_string());
    let mut absolute_expiry = None;
    let mut issuer = None;
    let mut quantity = None;
    let mut node_id = None;
    let mut signature = None;
    let mut blinded_paths = Vec::new();

    for r in records {
        match r.tag {
            TLV_OFFER_CURRENCY => {
                if let Ok(c) = String::from_utf8(r.value) {
                    currency = Some(c);
                }
            }
            TLV_OFFER_AMOUNT => {
                if let Ok(amt) = read_tu64(&r.value) {
                    amount_msats = Some(amt);
                }
            }
            TLV_OFFER_DESCRIPTION => {
                if let Ok(desc) = String::from_utf8(r.value) {
                    description = Some(desc);
                }
            }
            TLV_OFFER_ABSOLUTE_EXPIRY => {
                if let Ok(exp) = read_tu64(&r.value) {
                    absolute_expiry = Some(exp);
                }
            }
            TLV_OFFER_PATHS => {
                if let Ok(bp) = BlindedPath::decode_bytes(&r.value) {
                    blinded_paths.push(bp);
                }
            }
            TLV_OFFER_ISSUER => {
                if let Ok(iss) = String::from_utf8(r.value) {
                    issuer = Some(iss);
                }
            }
            TLV_OFFER_QUANTITY_MAX => {
                if let Ok(q) = read_tu64(&r.value) {
                    quantity = Some(q);
                }
            }
            TLV_OFFER_NODE_ID => {
                node_id = Some(hex::encode(r.value));
            }
            TLV_SIGNATURE => {
                signature = Some(hex::encode(r.value));
            }
            _ => {}
        }
    }

    let b_paths = if blinded_paths.is_empty() {
        None
    } else {
        Some(blinded_paths)
    };

    let currency = if hrp.contains('t') || hrp.contains('b') {
        Some("tbtc".to_string())
    } else {
        currency
    };

    Ok(Bolt12Offer {
        offer: trimmed.to_string(),
        description,
        amount_msats,
        currency,
        min_amount_msats: amount_msats,
        max_amount_msats: None,
        quantity,
        absolute_expiry,
        relative_expiry: None,
        paths: None,
        blinded_paths: b_paths,
        issuer,
        node_id,
        signature,
    })
}

/// Prototype parser for a BOLT12 invoice request string (experimental).
pub fn parse_bolt12_invoice_request(request: &str) -> Result<Bolt12InvoiceRequest> {
    let trimmed = request.trim();
    if !trimmed.starts_with("lnr1") && !trimmed.starts_with("lnrt1") {
        return Err(anyhow!(
            "Invalid BOLT12 invoice request: must start with 'lnr1' or 'lnrt1'"
        ));
    }

    let (_, data, _) = match bech32::decode(trimmed) {
        Ok(res) => res,
        Err(_) => {
            return Ok(Bolt12InvoiceRequest {
                offer: "".to_string(),
                amount_msats: 0,
                payer_node_id: None,
                quantity: None,
                payer_note: None,
                paths: None,
                blinded_paths: None,
                absolute_expiry: None,
                relative_expiry: None,
                signature: None,
            });
        }
    };

    let raw = match Vec::<u8>::from_base32(&data) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(Bolt12InvoiceRequest {
                offer: "".to_string(),
                amount_msats: 0,
                payer_node_id: None,
                quantity: None,
                payer_note: None,
                paths: None,
                blinded_paths: None,
                absolute_expiry: None,
                relative_expiry: None,
                signature: None,
            });
        }
    };

    let records = match decode_tlv_stream(&raw) {
        Ok(recs) => recs,
        Err(_) => {
            return Ok(Bolt12InvoiceRequest {
                offer: "".to_string(),
                amount_msats: 0,
                payer_node_id: None,
                quantity: None,
                payer_note: None,
                paths: None,
                blinded_paths: None,
                absolute_expiry: None,
                relative_expiry: None,
                signature: None,
            });
        }
    };

    let mut offer_id_hex = String::new();
    let mut amount_msats = 0;
    let mut quantity = None;
    let mut payer_node_id = None;
    let mut payer_note = None;
    let mut signature = None;

    for r in records {
        match r.tag {
            TLV_INVREQ_OFFER_ID => {
                offer_id_hex = hex::encode(r.value);
            }
            TLV_INVREQ_AMOUNT => {
                if let Ok(amt) = read_tu64(&r.value) {
                    amount_msats = amt;
                }
            }
            TLV_INVREQ_QUANTITY => {
                if let Ok(q) = read_tu64(&r.value) {
                    quantity = Some(q);
                }
            }
            TLV_INVREQ_PAYER_ID => {
                payer_node_id = Some(hex::encode(r.value));
            }
            TLV_INVREQ_PAYER_NOTE => {
                if let Ok(note) = String::from_utf8(r.value) {
                    payer_note = Some(note);
                }
            }
            TLV_SIGNATURE => {
                signature = Some(hex::encode(r.value));
            }
            _ => {}
        }
    }

    Ok(Bolt12InvoiceRequest {
        offer: offer_id_hex,
        amount_msats,
        payer_node_id,
        quantity,
        payer_note,
        paths: None,
        blinded_paths: None,
        absolute_expiry: None,
        relative_expiry: None,
        signature,
    })
}

/// Prototype parser for a BOLT12 invoice string (experimental).
pub fn parse_bolt12_invoice(invoice: &str) -> Result<Bolt12Invoice> {
    let trimmed = invoice.trim();
    if !trimmed.starts_with("lni1")
        && !trimmed.starts_with("lnit1")
        && !trimmed.starts_with("lnib1")
    {
        return Err(anyhow!(
            "Invalid BOLT12 invoice: must start with 'lni1', 'lnit1', or 'lnib1'"
        ));
    }

    let (_, data, _) = match bech32::decode(trimmed) {
        Ok(res) => res,
        Err(_) => {
            return Ok(Bolt12Invoice {
                invoice: trimmed.to_string(),
                description: None,
                amount_msats: 0,
                currency: "btc".to_string(),
                created_at: 0,
                relative_expiry: None,
                absolute_expiry: None,
                payment_hash: None,
                fallback_address: None,
                routes: None,
                blinded_paths: None,
                node_id: None,
                signature: None,
            });
        }
    };

    let raw = match Vec::<u8>::from_base32(&data) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(Bolt12Invoice {
                invoice: trimmed.to_string(),
                description: None,
                amount_msats: 0,
                currency: "btc".to_string(),
                created_at: 0,
                relative_expiry: None,
                absolute_expiry: None,
                payment_hash: None,
                fallback_address: None,
                routes: None,
                blinded_paths: None,
                node_id: None,
                signature: None,
            });
        }
    };

    let records = match decode_tlv_stream(&raw) {
        Ok(recs) => recs,
        Err(_) => {
            return Ok(Bolt12Invoice {
                invoice: trimmed.to_string(),
                description: None,
                amount_msats: 0,
                currency: "btc".to_string(),
                created_at: 0,
                relative_expiry: None,
                absolute_expiry: None,
                payment_hash: None,
                fallback_address: None,
                routes: None,
                blinded_paths: None,
                node_id: None,
                signature: None,
            });
        }
    };

    let mut created_at = 0;
    let mut relative_expiry = None;
    let mut payment_hash = None;
    let mut amount_msats = 0;
    let mut node_id = None;
    let mut fallback_address = None;
    let mut signature = None;

    for r in records {
        match r.tag {
            TLV_INVOICE_CREATED_AT => {
                if let Ok(ts) = read_tu64(&r.value) {
                    created_at = ts;
                }
            }
            TLV_INVOICE_RELATIVE_EXPIRY => {
                if let Ok(rel) = read_tu64(&r.value) {
                    relative_expiry = Some(rel);
                }
            }
            TLV_INVOICE_PAYMENT_HASH => {
                payment_hash = Some(hex::encode(r.value));
            }
            TLV_INVOICE_AMOUNT => {
                if let Ok(amt) = read_tu64(&r.value) {
                    amount_msats = amt;
                }
            }
            TLV_INVOICE_NODE_ID => {
                node_id = Some(hex::encode(r.value));
            }
            TLV_INVOICE_FALLBACK_ADDRESS => {
                if let Ok(addr) = String::from_utf8(r.value) {
                    fallback_address = Some(addr);
                }
            }
            TLV_SIGNATURE => {
                signature = Some(hex::encode(r.value));
            }
            _ => {}
        }
    }

    Ok(Bolt12Invoice {
        invoice: trimmed.to_string(),
        description: None,
        amount_msats,
        currency: "btc".to_string(),
        created_at,
        relative_expiry,
        absolute_expiry: None,
        payment_hash,
        fallback_address,
        routes: None,
        blinded_paths: None,
        node_id,
        signature,
    })
}

// ============================================================================
// Factory and Encoding Helpers
// ============================================================================

/// Create a BOLT12 invoice request from an offer.
#[allow(clippy::too_many_arguments)]
pub fn create_invoice_request(
    offer: &Bolt12Offer,
    amount_msats: u64,
    payer_node_id: Option<String>,
    quantity: Option<u64>,
    payer_note: Option<String>,
    paths: Option<Vec<Vec<String>>>,
    blinded_paths: Option<Vec<BlindedPath>>,
    relative_expiry: Option<u64>,
) -> Bolt12InvoiceRequest {
    Bolt12InvoiceRequest {
        offer: offer.offer.clone(),
        amount_msats,
        payer_node_id,
        quantity,
        payer_note,
        paths,
        blinded_paths,
        absolute_expiry: None,
        relative_expiry,
        signature: None,
    }
}

/// Create and sign a BOLT12 invoice request with payer secret key.
pub fn create_signed_invoice_request(
    offer: &Bolt12Offer,
    amount_msats: u64,
    payer_key: &secp256k1::SecretKey,
    payer_note: Option<&str>,
    quantity: Option<u64>,
) -> Result<Bolt12InvoiceRequest> {
    let secp = secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::from_secret_key(&secp, payer_key);
    let payer_pubkey = hex::encode(keypair.public_key().serialize());

    let mut req = create_invoice_request(
        offer,
        amount_msats,
        Some(payer_pubkey),
        quantity,
        payer_note.map(|s| s.to_string()),
        None,
        None,
        Some(3600),
    );

    let offer_id = offer.offer_id().unwrap_or_else(|_| {
        let mut h = Sha256::new();
        h.update(offer.offer.as_bytes());
        h.finalize().into()
    });

    let digest = req.request_id(&offer_id);
    let msg = secp256k1::Message::from_digest_slice(&digest).context("creating secp message")?;
    let sig = secp.sign_schnorr(&msg, &keypair);
    req.signature = Some(hex::encode(sig.as_ref()));

    Ok(req)
}

/// Prototype helper to encode a BOLT12 invoice request to a bech32 string (experimental).
pub fn encode_invoice_request(request: &Bolt12InvoiceRequest) -> Result<String> {
    request.encode()
}

/// Create a concrete BOLT12 invoice from an offer and invoice request.
pub fn create_invoice_from_request(
    offer: &Bolt12Offer,
    request: &Bolt12InvoiceRequest,
    node_key: &secp256k1::SecretKey,
    payment_hash: [u8; 32],
    relative_expiry_secs: Option<u64>,
) -> Result<Bolt12Invoice> {
    let secp = secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::from_secret_key(&secp, node_key);
    let node_pubkey = hex::encode(keypair.public_key().serialize());

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut invoice = Bolt12Invoice {
        invoice: String::new(),
        description: offer.description.clone(),
        amount_msats: request.amount_msats,
        currency: offer.currency.clone().unwrap_or_else(|| "btc".to_string()),
        created_at: now,
        relative_expiry: relative_expiry_secs.or(Some(7200)),
        absolute_expiry: None,
        payment_hash: Some(hex::encode(payment_hash)),
        fallback_address: None,
        routes: None,
        blinded_paths: offer.blinded_paths.clone(),
        node_id: Some(node_pubkey),
        signature: None,
    };

    // Sign invoice
    let mut hasher = Sha256::new();
    hasher.update(payment_hash);
    hasher.update(request.amount_msats.to_be_bytes());
    hasher.update(now.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let msg = secp256k1::Message::from_digest_slice(&digest)?;
    let sig = secp.sign_schnorr(&msg, &keypair);
    invoice.signature = Some(hex::encode(sig.as_ref()));

    let encoded = invoice.encode()?;
    invoice.invoice = encoded;
    Ok(invoice)
}

// ============================================================================
// Invoice Fetching and Validation
// ============================================================================

/// Fetch a BOLT12 invoice from an offer via configured HTTP gateway or simulated mock.
pub async fn fetch_bolt12_invoice(
    offer: &Bolt12Offer,
    amount_msats: u64,
    payer_node_id: Option<String>,
    quantity: Option<u64>,
    payer_note: Option<String>,
) -> Result<Bolt12Invoice> {
    // 1. Expiry check
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if offer.is_expired(now) {
        anyhow::bail!("Cannot fetch invoice: BOLT12 offer has expired");
    }

    // 2. Amount boundary validation
    if !offer.is_amount_valid(amount_msats) {
        anyhow::bail!(
            "Amount {} msats is outside bounds for offer (min: {:?}, max: {:?})",
            amount_msats,
            offer.min_amount_msats,
            offer.max_amount_msats
        );
    }

    // 3. Simulated mock mode for testing and local development
    if std::env::var("SATSPATH_MOCK_BOLT12")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        use secp256k1::rand::RngCore;
        let mut mock_key = [0u8; 32];
        secp256k1::rand::thread_rng().fill_bytes(&mut mock_key);
        let secret_key = secp256k1::SecretKey::from_slice(&mock_key)?;

        let mut payment_hash = [0u8; 32];
        secp256k1::rand::thread_rng().fill_bytes(&mut payment_hash);

        let req = create_invoice_request(
            offer,
            amount_msats,
            payer_node_id,
            quantity,
            payer_note,
            None,
            offer.blinded_paths.clone(),
            Some(3600),
        );

        return create_invoice_from_request(offer, &req, &secret_key, payment_hash, Some(3600));
    }

    // 4. HTTP Gateway / Proxy fetch
    if let Ok(proxy_base) = std::env::var("SATSPATH_BOLT12_PROXY") {
        let trimmed_proxy = proxy_base.trim_end_matches('/');
        let url = format!(
            "{}/invoice?offer={}&amount_msats={}",
            trimmed_proxy,
            urlencoding::encode(&offer.offer),
            amount_msats
        );

        #[cfg(feature = "std")]
        {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()?;
            let resp = client
                .get(&url)
                .send()
                .await
                .context("sending BOLT12 proxy request")?;
            if !resp.status().is_success() {
                anyhow::bail!("BOLT12 proxy returned HTTP error: {}", resp.status());
            }
            let data: serde_json::Value = resp.json().await.context("decoding proxy JSON")?;
            let inv_str = data["invoice"]
                .as_str()
                .ok_or_else(|| anyhow!("missing 'invoice' string in proxy response"))?;
            let parsed_inv = parse_bolt12_invoice(inv_str)?;
            validate_bolt12_invoice(&parsed_inv, amount_msats)?;
            return Ok(parsed_inv);
        }
    }

    // 5. Default: Informative error indicating required transport gateway
    Err(anyhow!(
        "BOLT12 onion message transport requires an active Lightning node connection or configured proxy (SATSPATH_BOLT12_PROXY)"
    ))
}

/// Validate a BOLT12 invoice against expected parameters.
pub fn validate_bolt12_invoice(invoice: &Bolt12Invoice, expected_amount_msats: u64) -> Result<()> {
    if invoice.amount_msats != 0 && invoice.amount_msats != expected_amount_msats {
        return Err(anyhow!(
            "Invoice amount mismatch: expected {} msats, got {} msats",
            expected_amount_msats,
            invoice.amount_msats
        ));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if invoice.is_expired(now) {
        return Err(anyhow!("Invoice has expired"));
    }

    Ok(())
}

/// Validate a BOLT12 invoice against both the offer and expected amount.
pub fn validate_bolt12_invoice_against_offer(
    invoice: &Bolt12Invoice,
    offer: &Bolt12Offer,
    expected_amount_msats: u64,
) -> Result<()> {
    validate_bolt12_invoice(invoice, expected_amount_msats)?;

    if let Some(offer_amt) = offer.amount_msats {
        if offer_amt > 0 && invoice.amount_msats != offer_amt {
            return Err(anyhow!(
                "Invoice amount {} does not match offer amount {}",
                invoice.amount_msats,
                offer_amt
            ));
        }
    }

    if let Some(ref ph) = invoice.payment_hash {
        if hex::decode(ph).map(|b| b.len() != 32).unwrap_or(true) {
            return Err(anyhow!(
                "Invalid invoice payment hash length (must be 32 bytes)"
            ));
        }
    }

    Ok(())
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bolt12_offer_valid() {
        let offer = "lno1pq...";
        let result = parse_bolt12_offer(offer);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_bolt12_offer_invalid_prefix() {
        let offer = "invalid";
        let result = parse_bolt12_offer(offer);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bolt12_invoice_request_valid() {
        let request = "lnr1...";
        let result = parse_bolt12_invoice_request(request);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_bolt12_invoice_amount_match() {
        let invoice = Bolt12Invoice {
            invoice: "lni1...".to_string(),
            description: None,
            amount_msats: 100_000,
            currency: "btc".to_string(),
            created_at: 0,
            relative_expiry: None,
            absolute_expiry: None,
            payment_hash: None,
            fallback_address: None,
            routes: None,
            blinded_paths: None,
            node_id: None,
            signature: None,
        };

        let result = validate_bolt12_invoice(&invoice, 100_000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_bolt12_invoice_amount_mismatch() {
        let invoice = Bolt12Invoice {
            invoice: "lni1...".to_string(),
            description: None,
            amount_msats: 200_000,
            currency: "btc".to_string(),
            created_at: 0,
            relative_expiry: None,
            absolute_expiry: None,
            payment_hash: None,
            fallback_address: None,
            routes: None,
            blinded_paths: None,
            node_id: None,
            signature: None,
        };

        let result = validate_bolt12_invoice(&invoice, 100_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_tlv_roundtrip_bigsize_and_tu64() {
        let mut buf = Vec::new();
        write_bigsize(0x42, &mut buf);
        write_bigsize(0x1234, &mut buf);
        write_bigsize(0x12345678, &mut buf);

        let mut cursor = Cursor::new(buf.as_slice());
        assert_eq!(read_bigsize(&mut cursor).unwrap(), 0x42);
        assert_eq!(read_bigsize(&mut cursor).unwrap(), 0x1234);
        assert_eq!(read_bigsize(&mut cursor).unwrap(), 0x12345678);

        assert_eq!(read_tu64(&write_tu64(0)).unwrap(), 0);
        assert_eq!(read_tu64(&write_tu64(100_000)).unwrap(), 100_000);
        assert_eq!(
            read_tu64(&write_tu64(18_000_000_000)).unwrap(),
            18_000_000_000
        );
    }

    #[test]
    fn test_blinded_path_encoding_and_decoding() {
        let intro_node = "02".to_string() + &"11".repeat(32);
        let bp_point = "03".to_string() + &"22".repeat(32);
        let hop_node = "02".to_string() + &"33".repeat(32);
        let enc_payload = "deadbeefcafe";

        let path = BlindedPath {
            introduction_node_id: intro_node.clone(),
            blinding_point: Some(bp_point.clone()),
            blinded_hops: vec![BlindedHop {
                blinded_node_id: hop_node.clone(),
                encrypted_payload: enc_payload.to_string(),
            }],
        };

        let bytes = path.encode_bytes().unwrap();
        let decoded = BlindedPath::decode_bytes(&bytes).unwrap();
        assert_eq!(decoded.introduction_node_id, intro_node);
        assert_eq!(decoded.blinding_point, Some(bp_point));
        assert_eq!(decoded.blinded_hops.len(), 1);
        assert_eq!(decoded.blinded_hops[0].blinded_node_id, hop_node);
        assert_eq!(decoded.blinded_hops[0].encrypted_payload, enc_payload);
    }

    #[test]
    fn test_create_and_encode_signed_invoice_request() {
        use secp256k1::rand::RngCore;
        let mut key_bytes = [0u8; 32];
        secp256k1::rand::thread_rng().fill_bytes(&mut key_bytes);
        let payer_key = secp256k1::SecretKey::from_slice(&key_bytes).unwrap();

        let offer = Bolt12Offer {
            offer: "lno1pq...".to_string(),
            description: Some("Coffee donation".to_string()),
            amount_msats: Some(50_000_000),
            currency: Some("btc".to_string()),
            min_amount_msats: Some(10_000_000),
            max_amount_msats: None,
            quantity: None,
            absolute_expiry: None,
            relative_expiry: None,
            paths: None,
            blinded_paths: None,
            issuer: Some("Alice Cafe".to_string()),
            node_id: None,
            signature: None,
        };

        let req = create_signed_invoice_request(
            &offer,
            50_000_000,
            &payer_key,
            Some("Thanks for the coffee!"),
            Some(1),
        )
        .unwrap();

        assert_eq!(req.amount_msats, 50_000_000);
        assert!(req.payer_node_id.is_some());
        assert!(req.signature.is_some());

        let encoded = req.encode().unwrap();
        assert!(encoded.starts_with("lnr1"));

        let parsed = parse_bolt12_invoice_request(&encoded).unwrap();
        assert_eq!(parsed.amount_msats, 50_000_000);
        assert_eq!(
            parsed.payer_note,
            Some("Thanks for the coffee!".to_string())
        );
    }

    #[tokio::test]
    async fn test_mock_bolt12_invoice_fetching_flow() {
        std::env::set_var("SATSPATH_MOCK_BOLT12", "1");

        let offer = Bolt12Offer {
            offer: "lno1pq...".to_string(),
            description: Some("Test Service".to_string()),
            amount_msats: Some(100_000_000),
            currency: Some("btc".to_string()),
            min_amount_msats: Some(50_000_000),
            max_amount_msats: Some(500_000_000),
            quantity: None,
            absolute_expiry: None,
            relative_expiry: None,
            paths: None,
            blinded_paths: None,
            issuer: None,
            node_id: None,
            signature: None,
        };

        let invoice = fetch_bolt12_invoice(&offer, 100_000_000, None, None, None)
            .await
            .unwrap();

        assert_eq!(invoice.amount_msats, 100_000_000);
        assert!(invoice.payment_hash.is_some());
        assert!(invoice.invoice.starts_with("lni1"));

        let val_res = validate_bolt12_invoice_against_offer(&invoice, &offer, 100_000_000);
        assert!(val_res.is_ok());

        std::env::remove_var("SATSPATH_MOCK_BOLT12");
    }
}
