//! Strict validation of a BIP-321 payment instruction before it is handed to
//! a wallet or shown to the user.
//!
//! A BIP-353 record proves only that the domain published the `bitcoin:` URI.
//! It says nothing about whether the address, invoice or offer inside it is
//! well formed, on the right network, or for the right amount. This module
//! checks all of that and fails closed on anything it cannot verify.
//!
//! Amount precedence: an `amount` in the URI is binding. A requested amount
//! must match it exactly, and a BOLT11 invoice that carries an amount must
//! match whichever amount applies. A mismatch is an error, never a choice.

use std::str::FromStr;

use lightning_invoice::{Bolt11Invoice, Currency};

use crate::bip321::{Bip321Instruction, ParsedBip321Uri};
use crate::errors::{Result, SatsPathError};
use crate::pointer::BitcoinNetwork;
use crate::validation::{
    validate_amount_sats, validate_bitcoin_address, validate_bolt12_offer,
    validate_silent_payment_address,
};

/// Total supply cap, in satoshis. No valid amount can exceed it.
const MAX_SATS: u64 = 21_000_000 * 100_000_000;

/// Validate every payment instruction in `parsed` for `network`.
///
/// `requested_sats` is the amount the user asked to send, if any. Returns the
/// amount that applies (URI amount, else requested amount, else `None`).
pub fn validate_payment_handoff(
    parsed: &ParsedBip321Uri,
    network: BitcoinNetwork,
    requested_sats: Option<u64>,
) -> Result<Option<u64>> {
    let uri_sats = parsed
        .amount_btc
        .as_deref()
        .map(parse_btc_amount)
        .transpose()?;
    if let Some(requested) = requested_sats {
        validate_amount_sats(requested)?;
    }
    if let (Some(uri), Some(requested)) = (uri_sats, requested_sats) {
        if uri != requested {
            return Err(handoff_error(format!(
                "amount mismatch: the payment instruction asks for {uri} sats but \
                 {requested} sats were requested"
            )));
        }
    }
    let amount = uri_sats.or(requested_sats);

    let mut usable = 0usize;
    if let Some(address) = &parsed.address {
        validate_bitcoin_address(address, network)?;
        usable += 1;
    }
    for instruction in &parsed.instructions {
        match instruction {
            Bip321Instruction::Onchain { address, .. } => {
                validate_bitcoin_address(address, network)?;
                usable += 1;
            }
            Bip321Instruction::LightningBolt11 { invoice } => {
                validate_bolt11_for_handoff(invoice, network, amount)?;
                usable += 1;
            }
            Bip321Instruction::Bolt12Offer { offer } => {
                validate_bolt12_offer(offer)?;
                usable += 1;
            }
            Bip321Instruction::SilentPayment { address } => {
                validate_silent_payment_address(address, network)?;
                usable += 1;
            }
            Bip321Instruction::Unknown { key, required, .. } => {
                if *required {
                    return Err(handoff_error(format!(
                        "unsupported required parameter `{key}`"
                    )));
                }
            }
        }
    }
    if usable == 0 {
        return Err(handoff_error(
            "payment instruction carries no usable address, invoice or offer".into(),
        ));
    }
    Ok(amount)
}

/// Decode a BOLT11 invoice and check its network, expiry and amount.
fn validate_bolt11_for_handoff(
    invoice: &str,
    network: BitcoinNetwork,
    expected_sats: Option<u64>,
) -> Result<()> {
    let decoded = Bolt11Invoice::from_str(invoice.trim())
        .map_err(|e| handoff_error(format!("invalid BOLT11 invoice: {e}")))?;
    let expected_currency = match network {
        BitcoinNetwork::Mainnet => Currency::Bitcoin,
        BitcoinNetwork::Testnet => Currency::BitcoinTestnet,
        BitcoinNetwork::Regtest => Currency::Regtest,
    };
    if decoded.currency() != expected_currency {
        return Err(handoff_error(format!(
            "BOLT11 invoice is for {:?}, not {network:?}",
            decoded.currency()
        )));
    }
    if decoded.is_expired() {
        return Err(handoff_error("BOLT11 invoice has expired".into()));
    }
    if let (Some(msats), Some(expected)) = (decoded.amount_milli_satoshis(), expected_sats) {
        if msats != expected.saturating_mul(1000) {
            return Err(handoff_error(format!(
                "BOLT11 invoice amount ({msats} msat) does not match {expected} sats"
            )));
        }
    }
    Ok(())
}

/// Parse a BIP-321 decimal BTC amount into satoshis, strictly.
///
/// Accepts digits with at most 8 decimal places; rejects signs, exponents,
/// zero, and anything above the 21M BTC supply.
pub fn parse_btc_amount(value: &str) -> Result<u64> {
    let invalid = || handoff_error(format!("invalid amount `{value}`"));
    let (whole, frac) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty() && frac.is_empty()
        || frac.len() > 8
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid());
    }
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().map_err(|_| invalid())?
    };
    let frac: u64 = format!("{frac:0<8}").parse().map_err(|_| invalid())?;
    let sats = whole
        .checked_mul(100_000_000)
        .and_then(|w| w.checked_add(frac))
        .ok_or_else(invalid)?;
    if sats == 0 || sats > MAX_SATS {
        return Err(invalid());
    }
    Ok(sats)
}

/// A handoff validation failure.
fn handoff_error(msg: String) -> SatsPathError {
    SatsPathError::InvalidPaymentUri(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip321::parse_bip321;

    const MAINNET_ADDR: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    const TESTNET_ADDR: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

    /// Parse `uri` and validate it for mainnet.
    fn check(uri: &str, requested: Option<u64>) -> Result<Option<u64>> {
        validate_payment_handoff(
            &parse_bip321(uri).unwrap(),
            BitcoinNetwork::Mainnet,
            requested,
        )
    }

    /// The BOLT12 specification's test-vector offer (no bech32 checksum) is
    /// accepted, also when split with `+`.
    #[test]
    fn real_bolt12_offer_passes() {
        let offer =
            "lno1pgx9getnwss8vetrw3hhyuckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg";
        assert!(check(&format!("bitcoin:?lno={offer}"), Some(1_000)).is_ok());
        let (a, b) = offer.split_at(30);
        assert!(crate::validation::validate_bolt12_offer(&format!("{a}+ {b}")).is_ok());
    }

    /// A well-formed mainnet address with a matching amount passes.
    #[test]
    fn valid_mainnet_onchain_passes() {
        let uri = format!("bitcoin:{MAINNET_ADDR}?amount=0.0005");
        assert_eq!(check(&uri, Some(50_000)).unwrap(), Some(50_000));
        assert_eq!(
            check(&format!("bitcoin:{MAINNET_ADDR}"), None).unwrap(),
            None
        );
    }

    /// A testnet address is refused on mainnet.
    #[test]
    fn cross_network_address_rejected() {
        assert!(check(&format!("bitcoin:{TESTNET_ADDR}"), None).is_err());
    }

    /// Malformed addresses and offers are refused.
    #[test]
    fn malformed_payloads_rejected() {
        assert!(check("bitcoin:not-an-address", None).is_err());
        assert!(check("bitcoin:?lno=garbage", None).is_err());
        assert!(check("bitcoin:?lightning=lnbc1garbage", None).is_err());
        assert!(check("bitcoin:", None).is_err(), "no usable instruction");
    }

    /// A URI amount different from the requested amount is refused.
    #[test]
    fn amount_mismatch_rejected() {
        let uri = format!("bitcoin:{MAINNET_ADDR}?amount=0.001");
        assert!(check(&uri, Some(50_000)).is_err());
        assert_eq!(check(&uri, None).unwrap(), Some(100_000));
    }

    /// Amount parsing is strict about format and range.
    #[test]
    fn btc_amount_parsing_is_strict() {
        assert_eq!(parse_btc_amount("1").unwrap(), 100_000_000);
        assert_eq!(parse_btc_amount("0.00000001").unwrap(), 1);
        assert_eq!(parse_btc_amount(".5").unwrap(), 50_000_000);
        for bad in [
            "0",
            "0.0",
            "-1",
            "1e3",
            "0.000000001",
            "21000001",
            "",
            ".",
            "1,5",
        ] {
            assert!(parse_btc_amount(bad).is_err(), "{bad} must be rejected");
        }
    }
}
