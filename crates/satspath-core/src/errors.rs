use thiserror::Error;

#[derive(Debug, Error)]
pub enum SatsPathError {
    #[error("alias not found: {0}")]
    AliasNotFound(String),

    #[error("alias already registered: {0}")]
    AliasAlreadyRegistered(String),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("unauthorized identity key replacement")]
    UnauthorizedKeyReplacement,

    #[error("profile revoked by its owner: {0}")]
    ProfileRevoked(String),

    #[error("invalid key rotation: {0}")]
    InvalidRotation(String),

    #[error("transparency failure: {0}")]
    Transparency(#[from] crate::transparency::TransparencyError),

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("invalid payment URI: {0}")]
    InvalidPaymentUri(String),

    #[error("invalid payment pointer: {0}")]
    InvalidPaymentPointer(String),

    #[error("private material rejected: {0}")]
    PrivateMaterialRejected(String),

    #[error("BIP-353 resolution error: {0}")]
    Bip353(String),

    #[error("DNSSEC validation unavailable — failing closed (Strict mode)")]
    DnssecUnavailable,

    #[error("ownership proof invalid: {0}")]
    OwnershipProofInvalid(String),

    #[error("ownership proof expired")]
    OwnershipProofExpired,

    #[error("ownership proof unsupported: {0}")]
    OwnershipProofUnsupported(String),

    #[error("no payment methods available")]
    NoPaymentMethods,

    #[error("no suitable payment rail found: {0}")]
    NoRouteFound(String),

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("registry error: {0}")]
    RegistryError(String),

    #[error("crypto error: {0}")]
    CryptoError(String),

    #[error("network error: {0}")]
    NetworkError(String),

    #[error("invalid route: {0}")]
    InvalidRoute(String),

    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("validation error: {0}")]
    ValidationError(String),

    #[error("json error: {0}")]
    JsonError(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, SatsPathError>;
