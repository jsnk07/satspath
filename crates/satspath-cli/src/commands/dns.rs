//! `satspath dns resolve` — BIP-353 DNS payment-instruction resolution.
//!
//! Mainnet **preview** only: resolves and displays public payment instructions.
//! It never pays, signs, or broadcasts. Strict DNSSEC is the default; the
//! `--allow-insecure-dns-for-dev` flag drops to an insecure dev mode with loud
//! warnings and must never be used on mainnet.

use anyhow::Result;

use satspath_core::bip321::{parse_bip321, Bip321Instruction};
use satspath_core::bip321_handoff::validate_payment_handoff;
use satspath_core::bip353::{resolve_bip353_with, DnsTxtResolver, DnssecPolicy, DohTxtResolver};
use satspath_core::resolvers::bip353::HickoryDnssecTxtResolver;
use satspath_core::BitcoinNetwork;

/// `satspath dns resolve`: print the DNSSEC-validated BIP-353 payment instruction for `name`.
pub async fn cmd_dns_resolve(name: &str, json: bool, allow_insecure: bool) -> Result<()> {
    let policy = if allow_insecure {
        DnssecPolicy::DevInsecure
    } else {
        DnssecPolicy::Strict
    };

    // Strict mode needs a backend that validates DNSSEC locally; the DoH JSON
    // backend cannot, so it is only used in the insecure dev mode.
    let resolver: Box<dyn DnsTxtResolver + Send + Sync> = if allow_insecure {
        Box::new(DohTxtResolver::new())
    } else {
        Box::new(HickoryDnssecTxtResolver::new())
    };
    let now = chrono::Utc::now().timestamp();
    // DNSSEC only proves who published the URI. Validate its contents (mainnet
    // addresses, invoices, offers, amount) before displaying anything.
    let result = resolve_bip353_with(resolver.as_ref(), name, policy, now)
        .await
        .and_then(|resolution| {
            let parsed = parse_bip321(&resolution.bitcoin_uri)?;
            validate_payment_handoff(&parsed, BitcoinNetwork::Mainnet, None)?;
            Ok(resolution)
        });

    if json {
        // JSON mode prints ONLY JSON — success or a structured error object.
        match result {
            Ok(resolution) => println!("{}", serde_json::to_string_pretty(&resolution)?),
            Err(e) => {
                let err = serde_json::json!({ "status": "error", "error": e.to_string() });
                println!("{}", serde_json::to_string_pretty(&err)?);
            }
        }
        return Ok(());
    }

    if allow_insecure {
        eprintln!("════════════════════════════════════════════════════════════");
        eprintln!("  ⚠  INSECURE DEV MODE: DNSSEC validation is DISABLED.");
        eprintln!("     Resolved instructions are NOT trustworthy. Never use on");
        eprintln!("     mainnet. This exists for local testing only.");
        eprintln!("════════════════════════════════════════════════════════════");
    }

    match result {
        Ok(resolution) => {
            println!("Name:   {}", resolution.name.display);
            println!("DNS:    {}", resolution.name.dns_name);
            println!(
                "DNSSEC: {}",
                if resolution.dnssec_validated {
                    "valid"
                } else {
                    "NOT validated (insecure dev mode)"
                }
            );
            println!("URI:    {}", resolution.bitcoin_uri);
            println!("Parsed:");
            if let Ok(parsed) = parse_bip321(&resolution.bitcoin_uri) {
                for instr in &parsed.instructions {
                    println!("  - {}", describe(instr));
                }
                if let Some(p) = &parsed.sp_profile {
                    println!("  - SatsPath profile pointer: {p}");
                }
            }
            match resolution.ttl_seconds {
                Some(ttl) => println!("TTL:    {ttl} seconds"),
                None => println!("TTL:    (unspecified)"),
            }
            for w in &resolution.warnings {
                println!("Warning: {w}");
            }
            println!();
            println!("MAINNET PREVIEW ONLY");
            println!("No funds moved.");
            println!("No transaction signed.");
            println!("No transaction broadcast.");
        }
        Err(e) => {
            println!("Resolution failed: {e}");
            if !allow_insecure {
                println!();
                println!("SatsPath fails closed in Strict mode: BIP-353 records must be");
                println!("DNSSEC-validated locally, and this lookup could not be validated");
                println!("(unsigned zone, broken chain of trust, or DNS unreachable). For");
                println!("local testing only, re-run with --allow-insecure-dns-for-dev.");
            }
        }
    }
    Ok(())
}

/// One-line human summary of a BIP-321 payment instruction.
fn describe(instr: &Bip321Instruction) -> String {
    match instr {
        Bip321Instruction::Onchain {
            address,
            amount_btc,
        } => match amount_btc {
            Some(a) => format!("on-chain address {address} (amount {a} BTC)"),
            None => format!("on-chain address {address}"),
        },
        Bip321Instruction::LightningBolt11 { .. } => "Lightning BOLT11 invoice".into(),
        Bip321Instruction::Bolt12Offer { .. } => "Lightning BOLT12 offer".into(),
        Bip321Instruction::SilentPayment { .. } => "Silent Payment address (preview)".into(),
        Bip321Instruction::Unknown { key, required, .. } => {
            format!("unknown parameter '{key}' (required={required})")
        }
    }
}
