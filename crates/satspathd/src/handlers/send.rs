//! Send, receive, broadcast, and email invite handlers.

use anyhow::Result;
use satspath_core::{
    privacy::mask_identifier,
    validation::{assert_no_private_material, validate_amount_sats},
    PaymentMethod, ProfileResolver, SatsPathError,
};
use satspath_router::{fees::fetch_fee_estimate, select_priority_route};

use crate::config::AppState;
use crate::handlers::profile::ensure_signed_profile;
use crate::handlers::resolve::resolver_chain;
use crate::handlers::wallet::load_wallet;
use crate::types::{
    build_methods, fmt_btc, pct, safety_status, EmailInvite, ReceiveRequest, ReceiveView,
    SendRequest, SendResponse,
};
use crate::ui::qr_svg;

pub(crate) fn receive_view(state: &AppState, req: ReceiveRequest) -> Result<ReceiveView> {
    let wallet = load_wallet(&state.home)?;
    let alias = wallet
        .alias
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no profile yet -- set one via POST /v1/profile"))?;
    let methods = build_methods(&wallet, &state.network);

    let method = if let Some(req_rail) = req.rail {
        let req_rail = req_rail.to_lowercase();
        methods
            .into_iter()
            .find(|m| m.method_name().to_lowercase() == req_rail)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "requested rail '{}' is not configured in your profile",
                    req_rail
                )
            })?
    } else {
        methods
            .iter()
            .find(|m| matches!(m, PaymentMethod::Lightning { .. }))
            .or_else(|| {
                methods
                    .iter()
                    .find(|m| matches!(m, PaymentMethod::Onchain { .. }))
            })
            .or_else(|| {
                methods
                    .iter()
                    .find(|m| matches!(m, PaymentMethod::Ark { .. }))
            })
            .ok_or_else(|| {
                anyhow::anyhow!("no receive methods -- add one via POST /v1/profile/methods")
            })?
            .clone()
    };

    let mut payload = receive_payload_for(&method)?;

    // Append amount if requested
    if let Some(sats) = req.amount_sats {
        if matches!(method, PaymentMethod::Onchain { .. }) {
            payload = format!("{}?amount={}", payload, fmt_btc(sats));
        } else if matches!(method, PaymentMethod::Ark { .. }) {
            payload = format!("{}&amount={}", payload, sats);
        }
        // Note: Lightning Address/LNURL doesn't support amount in the static string.
    }

    Ok(ReceiveView {
        alias: mask_identifier(&alias),
        rail: method.method_name().to_string(),
        qr_svg: qr_svg(&payload)?,
        payload,
    })
}

/// A public, amount-less receive pointer for a method.
pub(crate) fn receive_payload_for(method: &PaymentMethod) -> Result<String> {
    let payload = match method {
        PaymentMethod::Lightning {
            lightning_address: Some(addr),
            ..
        } => addr.clone(),
        PaymentMethod::Lightning {
            lnurl: Some(url), ..
        } => url.clone(),
        PaymentMethod::Onchain {
            address,
            silent_payment_pubkey,
            ..
        } => {
            let target = silent_payment_pubkey
                .clone()
                .unwrap_or_else(|| address.clone().unwrap_or_default());
            format!("bitcoin:{target}")
        }
        PaymentMethod::Ark { server, pubkey, .. } => {
            format!("satspath:ark?server={server}&pubkey={pubkey}")
        }
        _ => anyhow::bail!("selected method has no receive pointer"),
    };
    assert_no_private_material(&payload)?;
    Ok(payload)
}

/// Resolve the recipient, pick a rail by priority, and return the best QR.
/// Only a recipient that is genuinely not registered gets an EXPERIMENTAL email
/// invite; any other resolution failure (revoked profile, BIP-353 name,
/// verification error) fails closed with `NoRoute` and creates no invite.
pub(crate) async fn send_response(state: &AppState, body: SendRequest) -> SendResponse {
    if let Err(e) = validate_amount_sats(body.amount_sats) {
        return SendResponse::NoRoute {
            reason: e.to_string(),
        };
    }
    let resolver = resolver_chain(&state.home);
    match resolver.resolve_alias(&body.recipient).await {
        Ok(signed) => {
            if !matches!(
                satspath_core::crypto::verify_signed_profile(&signed),
                Ok(true)
            ) {
                return SendResponse::InvalidSignature {
                    recipient: mask_identifier(&body.recipient),
                };
            }
            let fee = fetch_fee_estimate().await;
            let routing_ok = body.routing_ok.unwrap_or(true);
            match select_priority_route(
                body.amount_sats,
                &fee.unwrap_or_default(),
                &signed.profile.methods,
                routing_ok,
            ) {
                Some(decision) => {
                    let payload = match send_payload_for(&decision.method, body.amount_sats) {
                        Ok(p) => p,
                        Err(e) => {
                            return SendResponse::NoRoute {
                                reason: e.to_string(),
                            }
                        }
                    };
                    let qr = match qr_svg(&payload) {
                        Ok(q) => q,
                        Err(e) => {
                            return SendResponse::NoRoute {
                                reason: e.to_string(),
                            }
                        }
                    };
                    SendResponse::Ok {
                        mode: "preview_only",
                        rail: decision.rail.to_string(),
                        reason: decision.reason,
                        recipient: mask_identifier(&body.recipient),
                        profile_signature_verified: true,
                        identifier_verified: false,
                        identifier_verification:
                            "identifier-only; no inbox/domain ownership proof in this response",
                        amount_sats: body.amount_sats,
                        payload,
                        qr_svg: qr,
                        safety: safety_status(),
                    }
                }
                None => SendResponse::NoRoute {
                    reason: "recipient exposes no usable rail".to_string(),
                },
            }
        }
        Err(SatsPathError::ProfileRevoked(_)) => SendResponse::NoRoute {
            reason: "Profile revoked by its owner.".to_string(),
        },
        Err(SatsPathError::Bip353(_)) => SendResponse::NoRoute {
            reason: "BIP-353 names resolve to DNS payment instructions, not SatsPath \
                     profiles; resolve them with `satspath dns resolve`."
                .to_string(),
        },
        Err(e) if !matches!(e, SatsPathError::AliasNotFound(_)) => SendResponse::NoRoute {
            reason: "recipient could not be resolved safely; no invite was created".to_string(),
        },
        Err(_) => {
            let secret_opt = load_wallet(&state.home).ok().and_then(|w| {
                w.identity_pubkey.and_then(|pk| {
                    crate::handlers::wallet::load_identity_key(&state.home, &pk).ok()
                })
            });
            let invite = satspath_core::create_invite(
                &body.recipient,
                body.amount_sats,
                secret_opt.as_ref(),
                86400,
            );

            // Persist invite record to InviteStore
            if let Ok(mut store) = satspath_core::InviteStore::open(&state.home) {
                let sender_fp = secret_opt
                    .as_ref()
                    .map(|sk| {
                        let secp = secp256k1::Secp256k1::new();
                        let pk = secp256k1::PublicKey::from_secret_key(&secp, sk);
                        hex::encode(pk.serialize())
                    })
                    .unwrap_or_else(|| "local-sender".to_string());

                let mut record = satspath_core::create_signed_invite_record(
                    &body.recipient,
                    body.amount_sats,
                    None,
                    sender_fp,
                    86400,
                    secret_opt.as_ref(),
                );
                if let Some(ref iid) = invite.invite_id {
                    record.invite_id = iid.clone();
                }
                let _ = store.insert(record);
            }

            let email = build_email_invite(&body.recipient, body.amount_sats, &invite.claim_url);
            SendResponse::Invite {
                mode: "preview_only",
                experimental: true,
                recipient_hint: mask_identifier(&body.recipient),
                amount_sats: body.amount_sats,
                claim_url: invite.claim_url,
                email,
                safety: safety_status(),
            }
        }
    }
}

pub(crate) fn build_email_invite(
    recipient: &str,
    amount_sats: u64,
    claim_url: &str,
) -> EmailInvite {
    let subject = "You were sent Bitcoin with SatsPath".to_string();
    let body = format!(
        r"Someone wants to send you {amount_sats} sats with SatsPath.

Press the button to download the SatsPath wallet and receive your funds
locally. You generate your own keys; nobody custodies them:

{claim_url}

[EXPERIMENTAL] SatsPath does not move funds or sign transactions for you."
    );
    let mailto = format!(
        "mailto:{}?subject={}&body={}",
        recipient,
        pct(&subject),
        pct(&body)
    );
    EmailInvite {
        to: recipient.to_string(),
        subject,
        body,
        mailto,
    }
}

/// A payable pointer for a method, including the amount where the URI supports it.
pub(crate) fn send_payload_for(method: &PaymentMethod, amount_sats: u64) -> Result<String> {
    let payload = match method {
        PaymentMethod::Lightning {
            lightning_address: Some(a),
            ..
        } => a.clone(),
        PaymentMethod::Lightning { lnurl: Some(u), .. } => u.clone(),
        PaymentMethod::Onchain {
            address,
            silent_payment_pubkey,
            ..
        } => {
            let target = silent_payment_pubkey
                .clone()
                .unwrap_or_else(|| address.clone().unwrap_or_default());
            format!("bitcoin:{target}?amount={}", fmt_btc(amount_sats))
        }
        PaymentMethod::Ark { server, pubkey, .. } => {
            format!("satspath:ark?server={server}&pubkey={pubkey}&amount={amount_sats}")
        }
        _ => anyhow::bail!("selected method has no payable pointer"),
    };
    assert_no_private_material(&payload)?;
    Ok(payload)
}

/// P2P is now exclusively Nostr. The broadcast endpoint triggers a re-sign.
pub(crate) fn broadcast(state: &AppState) -> Result<serde_json::Value> {
    let mut wallet = load_wallet(&state.home)?;
    if wallet.alias.is_none() {
        anyhow::bail!("set your profile first (alias + methods) before broadcasting");
    }
    ensure_signed_profile(&state.home, &mut wallet, &state.network)?;
    Ok(
        serde_json::json!({ "broadcasting": true, "status": "Nostr is the exclusive P2P layer. Profile saved." }),
    )
}
