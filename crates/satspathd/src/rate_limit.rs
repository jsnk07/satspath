//! Rate limiting and DDoS protection for `satspathd`.
//!
//! Provides defense-in-depth protection against denial-of-service (DoS) attacks,
//! brute-force enumeration, and memory exhaustion:
//! 1. Per-IP token bucket rate limiting with configurable burst capacity and refill rate.
//! 2. Request body size enforcement (default 64 KB) returning HTTP 413 Payload Too Large.
//! 3. Client IP extraction supporting direct socket connections or trusted reverse proxies
//!    (X-Forwarded-For, X-Real-IP).
//! 4. HTTP 429 Too Many Requests responses including standard Retry-After headers.
//! 5. Rate limiting metrics and diagnostic status reporting.

use std::collections::HashMap;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tiny_http::{Header, Response, StatusCode};

use crate::http::{cors_headers_header, cors_methods_header, cors_origin_header};

/// Default maximum request body size in bytes (64 KB).
pub const DEFAULT_MAX_BODY_BYTES: usize = 65_536;

/// Default burst capacity per IP (tokens).
pub const DEFAULT_BURST_CAPACITY: u32 = 60;

/// Default refill rate per second per IP (tokens/sec).
/// 10.0 tokens/sec allows up to 600 requests per minute sustained.
pub const DEFAULT_REFILL_RATE: f64 = 10.0;

/// Default stale bucket cleanup interval in seconds (5 minutes).
pub const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 300;

/// Configuration options for the IP rate limiter and body size guard.
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Maximum burst tokens allowed for a single IP.
    pub burst_capacity: u32,
    /// Number of tokens replenished per second for each IP.
    pub refill_rate_per_sec: f64,
    /// Maximum request body size in bytes.
    pub max_body_bytes: usize,
    /// Whether to trust reverse proxy headers (X-Forwarded-For, X-Real-IP).
    /// False by default to prevent IP spoofing unless satspathd is explicitly
    /// deployed behind a trusted reverse proxy (e.g. Nginx, Caddy).
    pub trust_proxy_headers: bool,
    /// Interval in seconds after which idle buckets with full tokens are pruned.
    pub cleanup_interval_secs: u64,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            burst_capacity: DEFAULT_BURST_CAPACITY,
            refill_rate_per_sec: DEFAULT_REFILL_RATE,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            trust_proxy_headers: false,
            cleanup_interval_secs: DEFAULT_CLEANUP_INTERVAL_SECS,
        }
    }
}

/// Result of evaluating a request against the rate limiter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitResult {
    /// Request is allowed. Contains the remaining token count (floored).
    Allowed { remaining: u32 },
    /// Request is rate-limited. Contains the recommended Retry-After delay in seconds.
    RateLimited { retry_after_secs: u64 },
}

/// Token bucket state for a single client IP address.
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_update: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, now: Instant) -> Self {
        Self {
            tokens: capacity,
            last_update: now,
        }
    }

    fn try_consume(
        &mut self,
        burst_capacity: f64,
        refill_rate: f64,
        now: Instant,
    ) -> RateLimitResult {
        let elapsed = now
            .saturating_duration_since(self.last_update)
            .as_secs_f64();
        self.last_update = now;
        self.tokens = (self.tokens + elapsed * refill_rate).min(burst_capacity);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            RateLimitResult::Allowed {
                remaining: self.tokens.floor() as u32,
            }
        } else {
            let missing = 1.0 - self.tokens;
            let wait_secs = if refill_rate > 0.0 {
                (missing / refill_rate).ceil() as u64
            } else {
                60
            };
            RateLimitResult::RateLimited {
                retry_after_secs: wait_secs.max(1),
            }
        }
    }
}

/// Internal counters for telemetry and diagnostics.
#[derive(Debug, Default)]
struct RateLimiterStatsInner {
    total_allowed: u64,
    total_blocked: u64,
    total_payload_too_large: u64,
}

/// Snapshot of rate limiter operational statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimiterStats {
    /// Number of distinct IP addresses currently tracked in memory.
    pub tracked_ips: usize,
    /// Total number of requests permitted since daemon start.
    pub total_allowed: u64,
    /// Total number of requests rejected due to rate limiting (HTTP 429).
    pub total_blocked: u64,
    /// Total number of requests rejected due to oversized body (HTTP 413).
    pub total_payload_too_large: u64,
    /// Configured burst capacity per IP.
    pub burst_capacity: u32,
    /// Configured refill rate per second per IP.
    pub refill_rate_per_sec: f64,
    /// Whether reverse proxy header trust is currently enabled.
    pub trust_proxy_headers: bool,
    /// Maximum configured request body limit in bytes.
    pub max_body_bytes: usize,
}

/// Per-IP rate limiter and body size guard.
pub struct RateLimiter {
    config: RateLimiterConfig,
    buckets: Mutex<HashMap<IpAddr, TokenBucket>>,
    stats: Mutex<RateLimiterStatsInner>,
    last_cleanup: Mutex<Instant>,
}

impl RateLimiter {
    /// Create a new RateLimiter with the specified configuration.
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
            stats: Mutex::new(RateLimiterStatsInner::default()),
            last_cleanup: Mutex::new(Instant::now()),
        }
    }

    /// Check if a request from the given IP address is allowed.
    pub fn check(&self, ip: &IpAddr) -> RateLimitResult {
        self.check_at(ip, Instant::now())
    }

    /// Internal check with explicit timestamp for deterministic testing.
    fn check_at(&self, ip: &IpAddr, now: Instant) -> RateLimitResult {
        self.maybe_prune(now);

        let burst = self.config.burst_capacity as f64;
        let rate = self.config.refill_rate_per_sec;

        let mut buckets = self.buckets.lock().expect("lock rate limiter buckets");
        let bucket = buckets
            .entry(*ip)
            .or_insert_with(|| TokenBucket::new(burst, now));

        let result = bucket.try_consume(burst, rate, now);

        let mut stats = self.stats.lock().expect("lock rate limiter stats");
        match &result {
            RateLimitResult::Allowed { .. } => {
                stats.total_allowed = stats.total_allowed.saturating_add(1);
            }
            RateLimitResult::RateLimited { .. } => {
                stats.total_blocked = stats.total_blocked.saturating_add(1);
            }
        }

        result
    }

    /// Record a payload size violation (HTTP 413).
    pub fn record_payload_too_large(&self) {
        let mut stats = self.stats.lock().expect("lock rate limiter stats");
        stats.total_payload_too_large = stats.total_payload_too_large.saturating_add(1);
    }

    /// Retrieve current statistics for diagnostics and monitoring.
    pub fn stats(&self) -> RateLimiterStats {
        let buckets = self.buckets.lock().expect("lock rate limiter buckets");
        let stats = self.stats.lock().expect("lock rate limiter stats");
        RateLimiterStats {
            tracked_ips: buckets.len(),
            total_allowed: stats.total_allowed,
            total_blocked: stats.total_blocked,
            total_payload_too_large: stats.total_payload_too_large,
            burst_capacity: self.config.burst_capacity,
            refill_rate_per_sec: self.config.refill_rate_per_sec,
            trust_proxy_headers: self.config.trust_proxy_headers,
            max_body_bytes: self.config.max_body_bytes,
        }
    }

    /// Prune stale IP entries whose token bucket is completely full and has been idle.
    fn maybe_prune(&self, now: Instant) {
        let mut last_cleanup = self.last_cleanup.lock().expect("lock last_cleanup");
        let elapsed = now.saturating_duration_since(*last_cleanup).as_secs();
        if elapsed < self.config.cleanup_interval_secs {
            return;
        }
        *last_cleanup = now;
        drop(last_cleanup);

        let burst = self.config.burst_capacity as f64;
        let mut buckets = self.buckets.lock().expect("lock rate limiter buckets");
        buckets.retain(|_, bucket| {
            let idle = now.saturating_duration_since(bucket.last_update).as_secs();
            !(idle >= self.config.cleanup_interval_secs && bucket.tokens >= burst)
        });
    }

    /// Explicitly force pruning of idle buckets.
    #[allow(dead_code)]
    pub fn prune(&self) {
        let now = Instant::now();
        let burst = self.config.burst_capacity as f64;
        let mut buckets = self.buckets.lock().expect("lock rate limiter buckets");
        buckets.retain(|_, bucket| {
            let idle = now.saturating_duration_since(bucket.last_update).as_secs();
            !(idle >= self.config.cleanup_interval_secs && bucket.tokens >= burst)
        });
    }

    /// Maximum request body size in bytes.
    pub fn max_body_bytes(&self) -> usize {
        self.config.max_body_bytes
    }

    /// Whether reverse proxy headers are trusted.
    pub fn trust_proxy_headers(&self) -> bool {
        self.config.trust_proxy_headers
    }
}

/// Extract the effective client IP address from socket address or reverse proxy headers.
///
/// Security:
/// - If `trust_proxy_headers` is FALSE, headers like `X-Forwarded-For` and `X-Real-IP`
///   are strictly ignored to prevent client IP spoofing attacks. The peer socket IP is returned.
/// - If `trust_proxy_headers` is TRUE, the rightmost IP in the last `X-Forwarded-For`
///   header is used: that is the address the trusted proxy itself observed and appended
///   (nginx `$proxy_add_x_forwarded_for`) or set (Caddy `{remote_host}`). Every entry to
///   its left is client-supplied, so taking the leftmost would let a client pick its own
///   rate-limit bucket. If absent, `X-Real-IP` is checked. If both are absent or invalid,
///   it falls back to the peer socket IP.
pub fn extract_client_ip(
    remote_addr: Option<&SocketAddr>,
    headers: &[Header],
    trust_proxy_headers: bool,
) -> IpAddr {
    if trust_proxy_headers {
        // Priority 1: X-Forwarded-For (client-supplied..., proxy-observed peer)
        let proxy_observed = headers
            .iter()
            .rev()
            .find(|h| h.field.equiv("x-forwarded-for"))
            .and_then(|h| h.value.as_str().rsplit(',').next())
            .and_then(|last| last.trim().parse::<IpAddr>().ok());
        if let Some(ip) = proxy_observed {
            return ip;
        }

        // Priority 2: X-Real-IP
        for header in headers {
            if header.field.equiv("x-real-ip") {
                let trimmed = header.value.as_str().trim();
                if let Ok(ip) = trimmed.parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    // Default fallback: socket peer address
    remote_addr
        .map(|sa| sa.ip())
        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::LOCALHOST))
}

/// Construct an HTTP 429 Too Many Requests response with a standard Retry-After header.
pub fn rate_limit_response(retry_after_secs: u64) -> Response<Cursor<Vec<u8>>> {
    let body = serde_json::json!({
        "error": "Too Many Requests: rate limit exceeded",
        "retry_after": retry_after_secs
    });
    let data = serde_json::to_vec_pretty(&body).unwrap_or_default();

    let retry_header = Header::from_bytes(
        &b"Retry-After"[..],
        format!("{retry_after_secs}").as_bytes(),
    )
    .expect("valid retry-after header");

    let content_type =
        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("valid header");

    Response::from_data(data)
        .with_status_code(StatusCode(429))
        .with_header(content_type)
        .with_header(retry_header)
        .with_header(cors_origin_header())
        .with_header(cors_methods_header())
        .with_header(cors_headers_header())
}

/// Construct an HTTP 413 Payload Too Large response.
pub fn payload_too_large_response(max_bytes: usize) -> Response<Cursor<Vec<u8>>> {
    let body = serde_json::json!({
        "error": format!("Payload Too Large: request body exceeds limit of {max_bytes} bytes"),
        "max_bytes": max_bytes
    });
    let data = serde_json::to_vec_pretty(&body).unwrap_or_default();

    let content_type =
        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("valid header");

    Response::from_data(data)
        .with_status_code(StatusCode(413))
        .with_header(content_type)
        .with_header(cors_origin_header())
        .with_header(cors_methods_header())
        .with_header(cors_headers_header())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    #[test]
    fn test_token_bucket_burst_and_refill() {
        let config = RateLimiterConfig {
            burst_capacity: 5,
            refill_rate_per_sec: 1.0,
            max_body_bytes: 1024,
            trust_proxy_headers: false,
            cleanup_interval_secs: 300,
        };
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let start = Instant::now();

        // 5 consecutive requests should be allowed (burst = 5)
        for i in 0..5 {
            let res = limiter.check_at(&ip, start);
            assert!(
                matches!(res, RateLimitResult::Allowed { .. }),
                "request {i} should be allowed"
            );
        }

        // 6th immediate request should be rate-limited
        let res6 = limiter.check_at(&ip, start);
        match res6 {
            RateLimitResult::RateLimited { retry_after_secs } => {
                assert!(retry_after_secs >= 1, "retry_after must be at least 1s");
            }
            RateLimitResult::Allowed { .. } => panic!("6th immediate request should be blocked"),
        }

        // After 2 seconds, 2 tokens should be refilled
        let two_secs_later = start + Duration::from_secs(2);
        let res_refill_1 = limiter.check_at(&ip, two_secs_later);
        assert!(matches!(res_refill_1, RateLimitResult::Allowed { .. }));
        let res_refill_2 = limiter.check_at(&ip, two_secs_later);
        assert!(matches!(res_refill_2, RateLimitResult::Allowed { .. }));

        // 3rd request without further time should be rate-limited again
        let res_refill_3 = limiter.check_at(&ip, two_secs_later);
        assert!(matches!(res_refill_3, RateLimitResult::RateLimited { .. }));

        // Check stats
        let stats = limiter.stats();
        assert_eq!(stats.tracked_ips, 1);
        assert_eq!(stats.total_allowed, 7);
        assert_eq!(stats.total_blocked, 2);
    }

    #[test]
    fn test_multiple_independent_ips() {
        let config = RateLimiterConfig {
            burst_capacity: 2,
            refill_rate_per_sec: 0.1,
            max_body_bytes: 1024,
            trust_proxy_headers: false,
            cleanup_interval_secs: 300,
        };
        let limiter = RateLimiter::new(config);
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let now = Instant::now();

        // Exhaust IP A
        assert!(matches!(
            limiter.check_at(&ip_a, now),
            RateLimitResult::Allowed { .. }
        ));
        assert!(matches!(
            limiter.check_at(&ip_a, now),
            RateLimitResult::Allowed { .. }
        ));
        assert!(matches!(
            limiter.check_at(&ip_a, now),
            RateLimitResult::RateLimited { .. }
        ));

        // IP B must still be fresh with full burst
        assert!(matches!(
            limiter.check_at(&ip_b, now),
            RateLimitResult::Allowed { .. }
        ));
        assert!(matches!(
            limiter.check_at(&ip_b, now),
            RateLimitResult::Allowed { .. }
        ));
        assert!(matches!(
            limiter.check_at(&ip_b, now),
            RateLimitResult::RateLimited { .. }
        ));

        let stats = limiter.stats();
        assert_eq!(stats.tracked_ips, 2);
        assert_eq!(stats.total_allowed, 4);
        assert_eq!(stats.total_blocked, 2);
    }

    #[test]
    fn test_client_ip_extraction_spoofing_protection() {
        let peer_addr: SocketAddr = "192.168.1.50:8080".parse().unwrap();
        let headers = vec![
            Header::from_bytes(&b"X-Forwarded-For"[..], &b"203.0.113.195, 10.0.0.1"[..]).unwrap(),
            Header::from_bytes(&b"X-Real-IP"[..], &b"198.51.100.22"[..]).unwrap(),
        ];

        // When trust_proxy_headers is false, spoofed headers must be ignored
        let extracted_untrusted = extract_client_ip(Some(&peer_addr), &headers, false);
        assert_eq!(
            extracted_untrusted,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))
        );

        // When trust_proxy_headers is true, the proxy-appended (rightmost) entry is used;
        // the client-supplied leftmost entry is ignored.
        let extracted_trusted = extract_client_ip(Some(&peer_addr), &headers, true);
        assert_eq!(extracted_trusted, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        // With multiple headers, the last one (added by the trusted proxy) wins.
        let multi = vec![
            Header::from_bytes(&b"X-Forwarded-For"[..], &b"1.2.3.4"[..]).unwrap(),
            Header::from_bytes(&b"X-Forwarded-For"[..], &b"5.6.7.8, 203.0.113.9"[..]).unwrap(),
        ];
        assert_eq!(
            extract_client_ip(Some(&peer_addr), &multi, true),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))
        );
    }

    #[test]
    fn test_client_ip_extraction_real_ip_and_fallback() {
        let peer_addr: SocketAddr = "192.168.1.50:8080".parse().unwrap();

        // X-Real-IP only
        let headers_real_ip =
            vec![Header::from_bytes(&b"X-Real-IP"[..], &b"198.51.100.44"[..]).unwrap()];
        let ip_real = extract_client_ip(Some(&peer_addr), &headers_real_ip, true);
        assert_eq!(ip_real, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 44)));

        // Malformed IP fallback to peer address
        let headers_malformed =
            vec![
                Header::from_bytes(&b"X-Forwarded-For"[..], &b"10.0.0.1, invalid-ip"[..]).unwrap(),
            ];
        let ip_fallback = extract_client_ip(Some(&peer_addr), &headers_malformed, true);
        assert_eq!(ip_fallback, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));

        // IPv6 address parsing
        let headers_ipv6 =
            vec![Header::from_bytes(&b"X-Real-IP"[..], &b"2001:db8::1"[..]).unwrap()];
        let ip_v6 = extract_client_ip(Some(&peer_addr), &headers_ipv6, true);
        assert_eq!(
            ip_v6,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn test_responses_status_and_headers() {
        let resp_429 = rate_limit_response(15);
        assert_eq!(resp_429.status_code(), StatusCode(429));
        let retry_header = resp_429
            .headers()
            .iter()
            .find(|h| h.field.equiv("retry-after"));
        assert!(retry_header.is_some());
        assert_eq!(retry_header.unwrap().value.as_str(), "15");

        let resp_413 = payload_too_large_response(65536);
        assert_eq!(resp_413.status_code(), StatusCode(413));
    }

    #[test]
    fn test_rate_limiter_pruning() {
        let config = RateLimiterConfig {
            burst_capacity: 10,
            refill_rate_per_sec: 1.0,
            max_body_bytes: 1024,
            trust_proxy_headers: false,
            cleanup_interval_secs: 10,
        };
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99));
        let start = Instant::now();

        assert!(matches!(
            limiter.check_at(&ip, start),
            RateLimitResult::Allowed { .. }
        ));
        assert_eq!(limiter.stats().tracked_ips, 1);

        // Explicitly prune (no change since not idle long enough)
        limiter.prune();
        assert_eq!(limiter.stats().tracked_ips, 1);
    }
}
