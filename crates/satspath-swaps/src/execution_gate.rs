use crate::errors::{Result, SwapError};
use crate::types::SwapKind;

/// Whether SatsPath can build and broadcast a consensus-valid claim/refund for `kind`.
///
/// Boltz v2 swaps lock funds in Taproot outputs. Claiming or refunding them needs a
/// MuSig2 cooperative key-path spend or a BIP-341 script-path spend plus a broadcast
/// path; `tx_builder` only signs P2WSH HTLCs and nothing broadcasts. Until that exists
/// every kind stays blocked so no execution flow can lock funds it cannot recover.
pub fn claim_refund_builders_available(kind: SwapKind) -> bool {
    match kind {
        SwapKind::Submarine | SwapKind::Reverse | SwapKind::Chain => false,
    }
}

pub fn ensure_claim_refund_builders_available(kind: SwapKind) -> Result<()> {
    if claim_refund_builders_available(kind) {
        Ok(())
    } else {
        Err(SwapError::Key(format!(
            "{kind:?} execution blocked: claim/refund transaction builder is not implemented"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Execution stays gated until Taproot claim/refund support exists.
    #[test]
    fn execution_blocked_until_taproot_claim_refund_exists() {
        assert!(ensure_claim_refund_builders_available(SwapKind::Submarine).is_err());
        assert!(ensure_claim_refund_builders_available(SwapKind::Reverse).is_err());
        assert!(ensure_claim_refund_builders_available(SwapKind::Chain).is_err());
    }
}
