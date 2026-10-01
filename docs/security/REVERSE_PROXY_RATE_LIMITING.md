# Reverse Proxy and DDoS Protection Guide for SatsPathd

## Overview

`satspathd` implements native per-IP rate limiting and request body size enforcement. For production mainnet deployments, a defense-in-depth model combining an edge reverse proxy (such as Nginx, Caddy, or Cloudflare) with `satspathd`'s application-level safeguards is strongly recommended.

This document describes:
1. Native `satspathd` rate limiting and DoS mitigation architecture.
2. Recommended Nginx production configuration.
3. Recommended Caddy production configuration.
4. Edge WAF / Cloudflare recommendations.
5. Operational monitoring and diagnostics.

---

## 1. Native satspathd Protections

`satspathd` includes built-in protections against denial-of-service, enumeration, and memory exhaustion attacks:

### Token Bucket Rate Limiting
- **Algorithm:** Per-IP token bucket with configurable burst capacity and replenishment rate.
- **Default Burst Capacity:** 60 requests per IP (`DEFAULT_BURST_CAPACITY`).
- **Default Refill Rate:** 10.0 tokens/second per IP (`DEFAULT_REFILL_RATE`), allowing sustained throughput up to 600 requests/minute.
- **Rate Limit Response:** HTTP `429 Too Many Requests` containing standard `Retry-After: <seconds>` header and JSON error payload.
- **Automatic Cleanup:** Idle buckets with full token capacities are automatically pruned after 300 seconds to bound memory consumption.

### Request Body Size Limits
- **Maximum Body Size:** 64 KB (65,536 bytes) by default (`DEFAULT_MAX_BODY_BYTES`).
- **Rejection Status:** HTTP `413 Payload Too Large` returned immediately upon inspecting the `Content-Length` header or when reading streaming requests exceeding 64 KB.

### Reverse Proxy IP Extraction & Spoofing Protection
- By default, `satspathd` strictly uses the peer socket address (`remote_addr`) to prevent client IP spoofing attacks via forged headers.
- When deployed behind a trusted reverse proxy, pass `--behind-proxy` or set `SATSPATHD_BEHIND_PROXY=1`.
- When enabled, `satspathd` inspects `X-Forwarded-For` (taking the rightmost entry, which the trusted proxy appended; entries to its left are client-supplied and ignored) and `X-Real-IP`, falling back to the peer socket IP if headers are missing or malformed.

### Configuration Flags and Environment Variables
- `--behind-proxy` or `SATSPATHD_BEHIND_PROXY=1`: Enable reverse proxy header trust.
- `--rate-limit-burst <N>` or `SATSPATHD_RATE_LIMIT_BURST=<N>`: Set burst token capacity per IP (default: 60).
- `--rate-limit-rate <F>` or `SATSPATHD_RATE_LIMIT_RATE=<F>`: Set refill rate in tokens/sec per IP (default: 10.0).

---

## 2. Nginx Reverse Proxy Configuration

Nginx provides high-performance connection throttling, SSL/TLS termination, request buffering, and edge rate limiting before traffic reaches `satspathd`.

### Example `/etc/nginx/sites-available/satspathd.conf`:

```nginx
# Rate limiting zones: 10MB state zone tracks ~160,000 IP addresses
limit_req_zone $binary_remote_addr zone=satspathd_req:10m rate=15r/s;
limit_conn_zone $binary_remote_addr zone=satspathd_conn:10m;

# Upstream satspathd daemon
upstream satspathd_backend {
    server 127.0.0.1:9737;
    keepalive 32;
}

server {
    listen 80;
    server_name node.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name node.example.com;

    # SSL / TLS Modern Configuration
    ssl_certificate /etc/letsencrypt/live/node.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/node.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # Request body limit matching satspathd 64 KB enforcement
    client_max_body_size 64k;
    client_body_buffer_size 64k;

    # Edge connection and request throttling
    limit_conn satspathd_conn 20;
    limit_req zone=satspathd_req burst=30 nodelay;
    limit_req_status 429;

    # Timeouts to mitigate Slowloris and connection starvation
    client_body_timeout 10s;
    client_header_timeout 10s;
    keepalive_timeout 30s;
    send_timeout 10s;

    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass http://satspathd_backend;
        proxy_http_version 1.1;

        # Forward authentic client IP
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Proxy timeouts
        proxy_connect_timeout 5s;
        proxy_read_timeout 15s;
        proxy_send_timeout 15s;

        # Disable proxy buffering for low-latency resolution
        proxy_buffering off;
    }

    # Custom 429 JSON response matching SatsPath schema
    error_page 429 /429.json;
    location = /429.json {
        default_type application/json;
        return 429 '{"error":"Too Many Requests: edge rate limit exceeded","retry_after":2}';
    }

    # Custom 413 JSON response matching SatsPath schema
    error_page 413 /413.json;
    location = /413.json {
        default_type application/json;
        return 413 '{"error":"Payload Too Large: request body exceeds 64 KB limit","max_bytes":65536}';
    }
}
```

---

## 3. Caddy Reverse Proxy Configuration

Caddy provides automatic HTTPS with Let's Encrypt / ZeroSSL, modern HTTP/3 support, and concise configuration.

### Example `Caddyfile`:

```caddy
node.example.com {
    # Automatic TLS with modern ciphers
    tls admin@example.com

    # Enforce request body size limit (64 KB)
    request_body {
        max_size 64KB
    }

    # Security headers
    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
    }

    # Reverse proxy to satspathd
    reverse_proxy 127.0.0.1:9737 {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}

        transport http {
            dial_timeout 5s
            response_header_timeout 15s
        }
    }
}
```

---

## 4. Edge WAF / Cloudflare Recommendations

When fronting `satspathd` with Cloudflare or an edge Web Application Firewall (WAF):
1. **DDoS Protection:** Enable Cloudflare Managed Rules and "Under Attack" mode during sustained attacks.
2. **Rate Limiting Rule:**
   - URL: `node.example.com/*`
   - Threshold: 100 requests per 10 seconds per IP.
   - Action: Managed Challenge or Block (429).
3. **Payload Inspection:** Restrict maximum request body size to 64 KB in Cloudflare Transform / Firewall rules.
4. **Header Trust:** When using Cloudflare, configure Nginx to set `X-Forwarded-For` using Cloudflare IP ranges (`set_real_ip_from`) and configure `satspathd` with `--behind-proxy`.

---

## 5. Monitoring & Operational Diagnostics

`satspathd` provides runtime diagnostics to observe rate limiter activity:

### GET /v1/status
The node status response includes active rate limit metrics:
```json
{
  "daemon": "satspathd",
  "version": "0.1.0",
  "rate_limit": {
    "tracked_ips": 14,
    "total_allowed": 10580,
    "total_blocked": 12,
    "total_payload_too_large": 0,
    "burst_capacity": 60,
    "refill_rate_per_sec": 10.0,
    "trust_proxy_headers": true,
    "max_body_bytes": 65536
  }
}
```

### GET /v1/diagnostics/rate_limit
Dedicated metrics endpoint returning the operational state:
```json
{
  "tracked_ips": 14,
  "total_allowed": 10580,
  "total_blocked": 12,
  "total_payload_too_large": 0,
  "burst_capacity": 60,
  "refill_rate_per_sec": 10.0,
  "trust_proxy_headers": true,
  "max_body_bytes": 65536
}
```

### Daemon Log Output
Rate limit and payload size violations log diagnostic lines to stderr:
```text
[rate_limit] client IP 198.51.100.22 exceeded rate limit on GET /v1/status, retry after 2s
[rate_limit] payload too large: 78240 bytes (limit: 65536) on POST /v1/receive
```
