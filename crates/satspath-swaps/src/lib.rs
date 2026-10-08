#![allow(warnings)]
pub mod ark_bridge;
pub mod boltz_client;
pub mod chain_swap;
pub mod errors;
pub mod execution_gate;
pub mod reverse;
pub mod submarine;
pub mod swap_manager;
pub mod swap_store;
pub mod tx_builder;
pub mod types;

// Re-export common types
pub use boltz_client::BoltzClient;
pub use errors::{Result, SwapError};
pub use execution_gate::{claim_refund_builders_available, ensure_claim_refund_builders_available};
pub use swap_manager::SwapManager;
pub use swap_store::SwapStore;
pub use tx_builder::{
    build_reverse_claim_tx, build_submarine_refund_tx, claim_params_from_record,
    finalize_reverse_claim, finalize_submarine_refund, parse_htlc_script,
    refund_params_from_record, reverse_htlc_script, submarine_htlc_script, HtlcTerms,
    ReverseClaimTxParams, SubmarineRefundTxParams, UnsignedSwapTx,
};
pub use types::{PairFees, PairLimits, SwapKind, SwapResult, SwapStatus};
