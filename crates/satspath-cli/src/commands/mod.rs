mod ark;
mod claim;
mod demo;
mod dns;
mod encode;
mod init;
mod invite;
mod keystore;
mod pay;
mod peer;
mod preview;
mod proofs;
mod qr;
mod quote;
mod register;
mod server;
mod show;
mod wallet;
mod web;

pub use ark::{cmd_ark_receive, cmd_ark_send, cmd_ark_swap, ArkSwapSide};
pub use claim::cmd_claim;
pub use demo::cmd_demo;
pub use dns::cmd_dns_resolve;
pub use encode::{cmd_decode, cmd_encode};
pub use init::cmd_init;
pub use invite::cmd_invite;
pub use pay::cmd_pay;
pub use peer::{cmd_export, cmd_import};
pub use preview::cmd_preview;
pub use proofs::{cmd_attach_proof, cmd_prove};
pub use quote::{cmd_quote, cmd_quote_json};
pub use register::cmd_register;
pub use server::{cmd_server_check, cmd_server_init};
pub use show::cmd_show;
pub use wallet::{
    cmd_wallet_add_ark, cmd_wallet_add_bolt12, cmd_wallet_add_lightning, cmd_wallet_add_methods,
    cmd_wallet_add_onchain, cmd_wallet_init, cmd_wallet_publish, cmd_wallet_receive,
    cmd_wallet_rotate, cmd_wallet_show,
};
pub use web::cmd_web;

use anyhow::Result;
use satspath_core::registry::Registry;
use std::path::PathBuf;

/// The CLI's local state directory (`.satspath/`).
pub(crate) fn satspath_dir() -> PathBuf {
    PathBuf::from(".satspath")
}

/// Open the local profile registry inside [`satspath_dir`].
pub(crate) fn open_registry() -> Result<Registry> {
    let dir = satspath_dir();
    if !dir.exists() {
        anyhow::bail!(".satspath/ not found. Run `satspath init` first.");
    }
    Ok(Registry::open(&dir)?)
}

use satspath_core::key_pins::{FileKeyStore, MemoryKeyStore, PinnedResolver, TrustedKeyStore};
use satspath_core::resolver::ChainResolver;
use satspath_core::resolvers::bip353::Bip353Resolver;
use satspath_core::resolvers::http::HttpResolver;
use satspath_core::resolvers::nostr::NostrResolver;
use std::sync::Arc;

/// The resolver every command uses: the transport chain wrapped in key
/// continuity enforcement, so a resolved profile is bound to the identity key
/// already trusted for that alias (TOFU pin, or an authorized rotation).
pub(crate) fn get_resolver() -> Result<PinnedResolver<ChainResolver>> {
    let dir = satspath_dir();
    let store: Arc<dyn TrustedKeyStore> = if dir.exists() {
        Arc::new(FileKeyStore::open(&dir)?)
    } else {
        eprintln!(
            "Warning: .satspath/ not found — key pins will not persist across runs. \
             Run `satspath init` to enable key continuity checks."
        );
        Arc::new(MemoryKeyStore::new())
    };
    Ok(PinnedResolver::new(build_chain(), store))
}

/// The resolver chain used by CLI commands, before key pinning is applied.
fn build_chain() -> ChainResolver {
    let mut chain = ChainResolver::new();

    // Add local registry first
    if let Ok(reg) = open_registry() {
        chain = chain.push(reg);
    }

    chain = chain.push(Bip353Resolver::new());

    // Add public HTTP resolver fallback
    chain = chain.push(HttpResolver::new());
    chain = chain.push(NostrResolver::new());

    chain
}
