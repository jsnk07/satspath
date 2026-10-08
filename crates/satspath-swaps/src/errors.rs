use thiserror::Error;

#[derive(Debug, Error)]
pub enum SwapError {
    // ── Network / API ────────────────────────────────────────────────────────
    #[error("Boltz API error ({status}): {message}")]
    BoltzApi { status: u16, message: String },

    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("WebSocket error: {0}")]
    WebSocket(String),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    // ── Swap lifecycle ───────────────────────────────────────────────────────
    #[error("Swap {id} failed: invoice could not be routed by Lightning")]
    InvoiceFailedToPay { id: String },

    #[error("Swap {id} failed: lockup amount mismatch — got {got} sats, expected {expected} sats")]
    LockupAmountMismatch { id: String, got: u64, expected: u64 },

    #[error("Swap {id} timed out waiting for status: {last_status}")]
    Timeout { id: String, last_status: String },

    #[error("Swap {id} was refunded — funds returned to sender")]
    Refunded { id: String },

    #[error("No recoverable swap found for id: {0}")]
    NotFound(String),

    #[error(
        "Swap store {0} holds swap spending keys written by an older SatsPath version. \
         SatsPath no longer holds spending keys and will not load them. The file was not \
         modified: back it up, finish or refund those swaps with the version that created \
         them (or import the keys into your wallet), then remove the file."
    )]
    LegacySpendingKeys(String),

    // ── Amount validation ────────────────────────────────────────────────────
    #[error(
        "Amount {amount_sats} sats is below dust threshold {dust_sats} sats at {fee_rate} sat/vB"
    )]
    BelowDustThreshold {
        amount_sats: u64,
        dust_sats: u64,
        fee_rate: u64,
    },

    #[error("Amount {amount_sats} sats exceeds Boltz maximum {max_sats} sats for this pair")]
    ExceedsMaximum { amount_sats: u64, max_sats: u64 },

    #[error("Amount {amount_sats} sats is below Boltz minimum {min_sats} sats for this pair")]
    BelowMinimum { amount_sats: u64, min_sats: u64 },

    // ── Crypto ──────────────────────────────────────────────────────────────
    #[error("Key error: {0}")]
    Key(String),

    #[error("Signature error: {0}")]
    Signature(String),

    // ── Storage ─────────────────────────────────────────────────────────────
    #[error("Storage IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Storage encryption/decryption failed: {0}")]
    Encryption(String),

    #[error("Storage corruption — swap record is malformed: {0}")]
    StorageCorruption(String),
}

pub type Result<T> = std::result::Result<T, SwapError>;
