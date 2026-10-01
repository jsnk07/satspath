//! HTTP request router: dispatches (method, path) pairs to handler functions.

use anyhow::Result;
use tiny_http::{Method, Request, StatusCode};

use crate::auth::check_auth;
use crate::config::AppState;
use crate::handlers::{
    claim::{
        claim_invite_handler, inspect_invite_handler, list_invites_handler,
        list_notifications_handler, mark_all_notifications_read_handler,
        mark_notification_read_handler,
    },
    profile::{
        create_challenge, profile_response, rotate_profile_key, update_profile,
        update_profile_methods, verify_challenge,
    },
    quote::{pay_response, quote_response},
    resolve::{dns_resolve_response, resolve_profile, resolve_v2_envelope},
    send::{broadcast, receive_view, send_response},
    status::{node_response, status_response},
    transparency::{
        anchor_latest_checkpoint, consistency_from_query, namespace_descriptor, paginated,
        query_str, transparency_log,
    },
};
use crate::http::{
    empty_response, handle_read_error, is_loopback_host, json_error, json_response, json_result,
    read_json,
};
use crate::rate_limit;
use crate::types::{
    safety_warnings, AliasRequest, ClaimRequest, ConsistencyVerifyRequest, DnsResolveRequest,
    InclusionVerifyRequest, PayRequest, PreviewResponse, ProfileUpdateRequest, QuoteRequest,
    ReceiveRequest, SendRequest, VerifyRequest,
};
use crate::ui::{html_response, INDEX_HTML};
use crate::v2_api;

pub(crate) async fn handle_request(mut request: Request, state: &AppState) -> Result<()> {
    let method = request.method().clone();
    let raw_url = request.url().to_string();
    let path = raw_url.split('?').next().unwrap_or("/").to_string();

    // 0. DNS-rebinding guard: a loopback-bound daemon only answers loopback Host names.
    // Behind a trusted reverse proxy the public Host is forwarded and the proxy's
    // server_name matching is what validates it.
    if state.bind.ip().is_loopback()
        && !state.rate_limiter.trust_proxy_headers()
        && !is_loopback_host(&request)
    {
        let _ = request.respond(json_error(
            StatusCode(403),
            anyhow::anyhow!("Forbidden: Host header must name a loopback address"),
        ));
        return Ok(());
    }

    // 1. Guard against oversized request bodies (HTTP 413 Payload Too Large)
    let max_body = state.rate_limiter.max_body_bytes();
    if let Some(body_len) = request.body_length() {
        if body_len > max_body {
            state.rate_limiter.record_payload_too_large();
            eprintln!(
                "[rate_limit] payload too large: {} bytes (limit: {}) on {} {}",
                body_len, max_body, method, path
            );
            let _ = request.respond(rate_limit::payload_too_large_response(max_body));
            return Ok(());
        }
    }

    // 2. Client IP extraction and rate limiting (HTTP 429 Too Many Requests)
    let client_ip = rate_limit::extract_client_ip(
        request.remote_addr(),
        request.headers(),
        state.rate_limiter.trust_proxy_headers(),
    );

    match state.rate_limiter.check(&client_ip) {
        rate_limit::RateLimitResult::Allowed { remaining: _ } => {}
        rate_limit::RateLimitResult::RateLimited { retry_after_secs } => {
            eprintln!(
                "[rate_limit] client IP {} exceeded rate limit on {} {}, retry after {}s",
                client_ip, method, path, retry_after_secs
            );
            let _ = request.respond(rate_limit::rate_limit_response(retry_after_secs));
            return Ok(());
        }
    }

    let is_mutation = !matches!(method, Method::Get | Method::Head | Method::Options);
    let is_public_mutation = path == "/v1/receive"
        || path == "/v1/send"
        || path == "/v1/claim"
        || path == "/v1/dns/resolve"
        || path == "/v1/transparency/verify/inclusion"
        || path == "/v2/resolve";

    if is_mutation && !is_public_mutation {
        if let Err(e) = check_auth(&request, &state.auth_token) {
            let _ = request.respond(json_error(StatusCode(401), e));
            return Ok(());
        }
    }

    let response = match (method.clone(), path.as_str()) {
        (Method::Options, _) => empty_response(StatusCode(204)),
        (Method::Get, "/") | (Method::Get, "/claim") => html_response(INDEX_HTML),
        (Method::Get, "/v1/diagnostics/rate_limit") => {
            json_response(StatusCode(200), &state.rate_limiter.stats())
        }
        (Method::Post, "/v1/receive") => match read_json::<ReceiveRequest>(&mut request) {
            Ok(body) => json_result(StatusCode(200), receive_view(state, body)),
            Err(e) => handle_read_error(e),
        },
        (Method::Post, "/v1/send") => match read_json::<SendRequest>(&mut request) {
            Ok(body) => json_response(StatusCode(200), &send_response(state, body).await),
            Err(e) => handle_read_error(e),
        },
        (Method::Post, "/v1/broadcast") => json_result(StatusCode(200), broadcast(state)),
        (Method::Get, "/health") => {
            json_response(StatusCode(200), &serde_json::json!({"ok": true}))
        }
        (Method::Get, v2_api::routes::HEALTH) => {
            let (checkpoint_age, log_ok) = match transparency_log(state) {
                Ok(log) => {
                    let latest = log.checkpoints().last().map(|c| c.created_at).unwrap_or(0);
                    let now = chrono::Utc::now().timestamp();
                    let age = if latest == 0 { 0 } else { now - latest };
                    (age, true)
                }
                Err(_) => (-1, false),
            };
            let resp = v2_api::build_health_response(checkpoint_age, log_ok, 1);
            let status = if resp.status == "healthy" {
                StatusCode(200)
            } else {
                StatusCode(503)
            };
            json_response(status, &resp)
        }
        (Method::Get, "/.well-known/satspath-authority")
        | (Method::Get, v2_api::routes::NAMESPACE) => {
            json_result(StatusCode(200), namespace_descriptor(state))
        }
        (Method::Get, v2_api::routes::RESOLVE) => {
            let identifier = match crate::handlers::transparency::query_str(&raw_url, "identifier")
            {
                Some(id) if !id.trim().is_empty() => id,
                _ => {
                    return Ok(request.respond(json_error(
                        StatusCode(400),
                        anyhow::anyhow!("missing or empty 'identifier' query parameter"),
                    ))?)
                }
            };
            match resolve_v2_envelope(state, &identifier) {
                Ok(envelope) => json_response(StatusCode(200), &envelope),
                Err(e) => {
                    let status = if e.to_string().contains("not found") {
                        StatusCode(404)
                    } else {
                        StatusCode(400)
                    };
                    json_error(status, e)
                }
            }
        }
        (Method::Post, v2_api::routes::RESOLVE) => {
            match read_json::<satspath_core::transparency::ResolutionRequest>(&mut request) {
                Ok(body) => match resolve_v2_envelope(state, &body.identifier) {
                    Ok(envelope) => json_response(StatusCode(200), &envelope),
                    Err(e) => {
                        let status = if e.to_string().contains("not found") {
                            StatusCode(404)
                        } else {
                            StatusCode(400)
                        };
                        json_error(status, e)
                    }
                },
                Err(e) => handle_read_error(e),
            }
        }
        (Method::Get, "/v1/node") => json_result(StatusCode(200), node_response(state)),
        (Method::Get, "/v1/status") => json_result(StatusCode(200), status_response(state)),
        (Method::Get, "/v1/profile") => json_result(StatusCode(200), profile_response(state)),
        (Method::Get, "/v1/transparency/status") => json_result(
            StatusCode(200),
            transparency_log(state).and_then(|log| log.status().map_err(Into::into)),
        ),
        (Method::Get, "/v1/transparency/checkpoints") => json_result(
            StatusCode(200),
            transparency_log(state).map(|log| paginated(&raw_url, log.checkpoints())),
        ),
        (Method::Get, "/v1/transparency/events") => json_result(
            StatusCode(200),
            transparency_log(state).map(|log| paginated(&raw_url, log.events())),
        ),
        (Method::Get, p) if p.starts_with("/v1/transparency/checkpoints/") => {
            let hash = p.trim_start_matches("/v1/transparency/checkpoints/");
            json_result(
                StatusCode(200),
                transparency_log(state).and_then(|log| {
                    log.checkpoints()
                        .iter()
                        .find(|c| c.checkpoint_hash().ok().as_deref() == Some(hash))
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("checkpoint not found"))
                }),
            )
        }
        (Method::Get, p) if p.starts_with("/v1/transparency/events/") => {
            let hash = p.trim_start_matches("/v1/transparency/events/");
            json_result(
                StatusCode(200),
                transparency_log(state).and_then(|log| {
                    log.event(hash).map_err(Into::into).and_then(|e| {
                        e.cloned()
                            .ok_or_else(|| satspath_core::SatsPathError::AliasNotFound(hash.into()))
                            .map_err(Into::into)
                    })
                }),
            )
        }
        (Method::Get, p) if p.starts_with("/v1/transparency/identifiers/") => {
            let identifier = p.trim_start_matches("/v1/transparency/identifiers/");
            json_result(
                StatusCode(200),
                transparency_log(state).map(|log| {
                    let events: Vec<_> =
                        log.history(identifier).into_iter().cloned().collect();
                    serde_json::json!({"identifier_hash": identifier, "latest": events.last(), "history": events})
                }),
            )
        }
        (Method::Get, p) if p.starts_with("/v1/transparency/inclusion/") => {
            let hash = p.trim_start_matches("/v1/transparency/inclusion/");
            json_result(
                StatusCode(200),
                transparency_log(state)
                    .and_then(|log| log.inclusion(hash, None).map_err(Into::into)),
            )
        }
        (Method::Get, p) if p.starts_with("/v1/transparency/anchors/") => {
            let txid = p.trim_start_matches("/v1/transparency/anchors/");
            json_result(
                StatusCode(200),
                transparency_log(state).and_then(|log| {
                    log.checkpoints()
                        .iter()
                        .filter_map(|c| c.bitcoin_anchor.as_ref())
                        .find(|a| a.txid == txid)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("anchor not found"))
                }),
            )
        }
        (Method::Post, "/v1/transparency/anchors") => match anchor_latest_checkpoint(state).await {
            Ok(anchor) => json_response(StatusCode(200), &anchor),
            Err(e) => json_error(StatusCode(400), e),
        },
        (Method::Get, "/v1/transparency/consistency") => {
            json_result(StatusCode(200), consistency_from_query(state, &raw_url))
        }
        (Method::Post, "/v1/transparency/verify/inclusion") => {
            match read_json::<InclusionVerifyRequest>(&mut request).and_then(|body| {
                satspath_core::transparency::verify_checkpoint_inclusion(
                    &body.event_hash,
                    &body.proof,
                    &body.checkpoint,
                )
                .map(|_| true)
                .map_err(Into::into)
            }) {
                Ok(valid) => json_response(StatusCode(200), &serde_json::json!({"valid": valid})),
                Err(e) => json_error(StatusCode(400), e),
            }
        }
        (Method::Post, "/v1/transparency/verify/consistency") => {
            match read_json::<ConsistencyVerifyRequest>(&mut request).and_then(|body| {
                satspath_core::transparency::verify_consistency_proof(&body.proof)
                    .map_err(Into::into)
            }) {
                Ok(valid) => json_response(StatusCode(200), &serde_json::json!({"valid": valid})),
                Err(e) => json_error(StatusCode(400), e),
            }
        }
        (Method::Put, "/v1/profile") | (Method::Post, "/v1/profile") => {
            let _guard = state.mutation_lock.lock().await;
            match read_json::<ProfileUpdateRequest>(&mut request)
                .and_then(|body| update_profile(state, body))
            {
                Ok(resp) => json_response(StatusCode(200), &resp),
                Err(e) => json_error(StatusCode(400), e),
            }
        }
        (Method::Post, "/v1/profile/challenge") => {
            match read_json::<AliasRequest>(&mut request)
                .and_then(|body| create_challenge(state, body))
            {
                Ok(resp) => json_response(StatusCode(200), &resp),
                Err(e) => json_error(StatusCode(400), e),
            }
        }
        (Method::Post, "/v1/profile/verify") => {
            let _guard = state.mutation_lock.lock().await;
            match read_json::<VerifyRequest>(&mut request)
                .and_then(|body| verify_challenge(state, body))
            {
                Ok(resp) => json_response(StatusCode(200), &resp),
                Err(e) => json_error(StatusCode(400), e),
            }
        }
        (Method::Post, "/v1/profile/methods") => {
            let _guard = state.mutation_lock.lock().await;
            match read_json::<ProfileUpdateRequest>(&mut request)
                .and_then(|body| update_profile_methods(state, body))
            {
                Ok(resp) => json_response(StatusCode(200), &resp),
                Err(e) => json_error(StatusCode(400), e),
            }
        }
        (Method::Post, "/v1/profile/rotate-key") => {
            let _guard = state.mutation_lock.lock().await;
            match rotate_profile_key(state) {
                Ok(response) => json_response(StatusCode(200), &response),
                Err(error) => json_error(StatusCode(400), error),
            }
        }
        (Method::Post, "/v1/resolve") => {
            match read_json::<AliasRequest>(&mut request)
                .and_then(|body| resolve_profile(state, &body.alias))
            {
                Ok(profile) => json_response(StatusCode(200), &profile),
                Err(e) => json_error(StatusCode(404), e),
            }
        }
        (Method::Post, "/v1/quote") => match read_json::<QuoteRequest>(&mut request) {
            Ok(body) => json_response(StatusCode(200), &quote_response(state, body).await),
            Err(e) => json_error(StatusCode(400), e),
        },
        (Method::Post, "/v1/pay") => match read_json::<PayRequest>(&mut request) {
            Ok(body) => json_response(StatusCode(200), &pay_response(state, body).await),
            Err(e) => json_error(StatusCode(400), e),
        },
        (Method::Post, "/v1/dns/resolve") => match read_json::<DnsResolveRequest>(&mut request) {
            Ok(body) => json_response(StatusCode(200), &dns_resolve_response(body).await),
            Err(e) => handle_read_error(e),
        },
        (Method::Post, "/v1/preview") => match read_json::<QuoteRequest>(&mut request) {
            Ok(body) => {
                let quote = quote_response(state, body).await;
                json_response(
                    StatusCode(200),
                    &PreviewResponse {
                        mode: "preview_only",
                        warnings: safety_warnings(),
                        quote,
                    },
                )
            }
            Err(e) => json_error(StatusCode(400), e),
        },
        (Method::Get, p) if p.starts_with("/v1/claim") => {
            let invite_id = query_str(&raw_url, "invite_id").or_else(|| {
                let sub = p.trim_start_matches("/v1/claim").trim_start_matches('/');
                if !sub.is_empty() {
                    Some(sub.to_string())
                } else {
                    None
                }
            });
            match invite_id {
                Some(id) => json_result(StatusCode(200), inspect_invite_handler(state, &id)),
                None => json_error(
                    StatusCode(400),
                    anyhow::anyhow!("missing 'invite_id' query parameter or path segment"),
                ),
            }
        }
        (Method::Post, "/v1/claim") => {
            let _guard = state.mutation_lock.lock().await;
            match read_json::<ClaimRequest>(&mut request) {
                Ok(body) => match claim_invite_handler(state, body) {
                    Ok(resp) => json_response(StatusCode(200), &resp),
                    Err(e) => {
                        let err_str = e.to_string();
                        let status = if err_str.contains("not found") {
                            StatusCode(404)
                        } else if err_str.contains("already been claimed") {
                            StatusCode(409)
                        } else {
                            StatusCode(400)
                        };
                        json_error(status, e)
                    }
                },
                Err(e) => handle_read_error(e),
            }
        }
        (Method::Get, "/v1/invites") => json_result(StatusCode(200), list_invites_handler(state)),
        (Method::Get, "/v1/invites/notifications") => {
            json_result(StatusCode(200), list_notifications_handler(state))
        }
        (Method::Post, "/v1/invites/notifications/read-all") => {
            json_result(StatusCode(200), mark_all_notifications_read_handler(state))
        }
        (Method::Post, p) if p.starts_with("/v1/invites/notifications/") => {
            let id = p
                .trim_start_matches("/v1/invites/notifications/")
                .trim_end_matches("/read");
            json_result(StatusCode(200), mark_notification_read_handler(state, id))
        }
        _ => json_error(StatusCode(404), anyhow::anyhow!("endpoint not found")),
    };
    request.respond(response)?;
    Ok(())
}
