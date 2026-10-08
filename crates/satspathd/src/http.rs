//! HTTP response helpers: JSON, HTML, CORS, and error utilities.

use std::io::Read;

use anyhow::Result;
use serde::Serialize;
use tiny_http::{Header, Request, Response, StatusCode};

use crate::types::ErrorResponse;

pub(crate) const MAX_JSON_BODY_BYTES: u64 = 65_536; // 64 KB limit to prevent DoS

/// A request-body rejection that carries its own HTTP status. [`json_error`] uses
/// this status in place of the route's default, so every JSON route reports
/// 415/413 for body problems while keeping its own status for handler errors.
#[derive(Debug)]
pub(crate) struct BodyError {
    status: u16,
    message: &'static str,
}

impl std::fmt::Display for BodyError {
    /// Show the client-facing error message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for BodyError {}

/// Read and parse a JSON request body, enforcing Content-Type and size limits.
pub(crate) fn read_json<T: for<'de> serde::Deserialize<'de>>(request: &mut Request) -> Result<T> {
    // Browsers send text/plain, form and multipart POSTs cross-origin without a CORS
    // preflight. Requiring application/json forces a preflight, so a hostile page cannot
    // drive mutations on a local daemon.
    if !has_json_content_type(request) {
        return Err(BodyError {
            status: 415,
            message: "unsupported media type: Content-Type must be application/json",
        }
        .into());
    }
    let mut body = String::new();
    let mut reader = request.as_reader().take(MAX_JSON_BODY_BYTES + 1);
    reader.read_to_string(&mut body)?;
    if body.len() as u64 > MAX_JSON_BODY_BYTES {
        return Err(BodyError {
            status: 413,
            message: "payload too large: maximum allowed request body is 65536 bytes",
        }
        .into());
    }
    if body.trim().is_empty() {
        anyhow::bail!("request body must be JSON");
    }
    Ok(serde_json::from_str(&body)?)
}

/// Whether the request declares `application/json` (parameters such as charset allowed).
fn has_json_content_type(request: &Request) -> bool {
    request.headers().iter().any(|h| {
        h.field.equiv("Content-Type")
            && h.value
                .as_str()
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
    })
}

/// Whether a request's Host header names a loopback host. A DNS-rebinding page arrives
/// with its own domain in Host even though the connection lands on 127.0.0.1.
pub(crate) fn is_loopback_host(request: &Request) -> bool {
    let Some(host) = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Host"))
        .map(|h| h.value.as_str().trim().to_ascii_lowercase())
    else {
        return false;
    };
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        host.rsplit_once(':')
            .map_or(host.as_str(), |(name, _)| name)
    };
    name == "localhost"
        || name
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

pub(crate) fn json_result<T: Serialize>(
    status: StatusCode,
    result: Result<T>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    match result {
        Ok(value) => json_response(status, &value),
        Err(e) => json_error(status, e),
    }
}

pub(crate) fn json_response<T: Serialize>(
    status: StatusCode,
    value: &T,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body =
        serde_json::to_vec_pretty(value).unwrap_or_else(|_| b"{\"error\":\"json\"}".to_vec());
    Response::from_data(body)
        .with_status_code(status)
        .with_header(json_header())
        .with_header(cors_origin_header())
        .with_header(cors_methods_header())
        .with_header(cors_headers_header())
}

/// A response with the given status and no body.
pub(crate) fn empty_response(status: StatusCode) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_data(Vec::new())
        .with_status_code(status)
        .with_header(cors_origin_header())
        .with_header(cors_methods_header())
        .with_header(cors_headers_header())
}

/// JSON error response. A [`BodyError`] overrides `status` with its own.
pub(crate) fn json_error(
    status: StatusCode,
    error: anyhow::Error,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let status = error
        .downcast_ref::<BodyError>()
        .map_or(status, |body| StatusCode(body.status));
    json_response(
        status,
        &ErrorResponse {
            error: error.to_string(),
        },
    )
}

/// Response for a request body that could not be read: 415/413 for
/// [`BodyError`]s, 400 for anything else (e.g. malformed JSON).
pub(crate) fn handle_read_error(e: anyhow::Error) -> Response<std::io::Cursor<Vec<u8>>> {
    json_error(StatusCode(400), e)
}

pub(crate) fn json_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("valid static header")
}

pub(crate) fn cors_origin_header() -> Header {
    // SEC-CORS: Restrict to local daemon UI and Arkade wallet origins.
    // Override via SATSPATHD_CORS_ORIGIN env var for custom deployments.
    let origin = std::env::var("SATSPATHD_CORS_ORIGIN").unwrap_or_else(|_| {
        "http://localhost:5173, http://localhost:3000, http://127.0.0.1:5173, https://app.arkade.money".to_string()
    });
    // Note: Access-Control-Allow-Origin only supports a single origin value or '*'.
    // For multiple origins, the server should echo back the request Origin if it's
    // in the allowed list. Since tiny_http doesn't give us per-request headers easily,
    // we use the first allowed origin as default. In production, use a reverse proxy
    // (nginx/caddy) for proper multi-origin CORS.
    let first_origin = origin
        .split(',')
        .next()
        .unwrap_or("http://localhost:5173")
        .trim();
    Header::from_bytes(&b"Access-Control-Allow-Origin"[..], first_origin.as_bytes())
        .expect("valid static header")
}

pub(crate) fn cors_methods_header() -> Header {
    Header::from_bytes(
        &b"Access-Control-Allow-Methods"[..],
        &b"GET, POST, OPTIONS"[..],
    )
    .expect("valid static header")
}

pub(crate) fn cors_headers_header() -> Header {
    Header::from_bytes(
        &b"Access-Control-Allow-Headers"[..],
        &b"Content-Type, Authorization, X-Request-Id"[..],
    )
    .expect("valid static header")
}

/// Write a file atomically with owner-only permissions (0600 on Unix).
pub(crate) fn write_owner_only_file(path: &std::path::Path, content: &[u8]) -> anyhow::Result<()> {
    use std::path::Path;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    use secp256k1::rand::RngCore;
    let mut rand_bytes = [0u8; 16];
    secp256k1::rand::thread_rng().fill_bytes(&mut rand_bytes);
    let tmp_path = parent.join(format!(".tmp-{}", hex::encode(rand_bytes)));
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp_path)?;
        file.write_all(content)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp_path, content)?;
    }
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}
