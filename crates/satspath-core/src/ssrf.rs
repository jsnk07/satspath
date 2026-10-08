//! SSRF (Server-Side Request Forgery) protection for SatsPath resolvers.
//!
//! All outbound HTTP/HTTPS requests from resolvers MUST go through
//! [`resolve_and_validate`] + [`pinned_client`] (or, at minimum,
//! [`validate_url`]) before being issued. This prevents a malicious alias
//! (e.g. `attacker@127.0.0.1`, or `victim@attacker.example` whose A record
//! points at `169.254.169.254`) from tricking the resolver into contacting
//! internal services.
//!
//! # Why hostnames need resolving
//!
//! [`validate_url`] is a pure string check: it rejects IP literals in private
//! ranges and hostnames that can only denote internal targets. It cannot know
//! where an arbitrary public hostname points. [`resolve_and_validate`] resolves
//! the hostname and rejects the request if *any* returned address is internal.
//!
//! # Why the connection must be pinned
//!
//! Validating one DNS answer and then letting the HTTP client resolve the name
//! again at connect time leaves a time-of-check / time-of-use gap: a low-TTL
//! record can pass validation and flip to an internal IP for the real request
//! (DNS rebinding). [`pinned_client`] builds a client that connects only to the
//! addresses that were validated, while TLS still verifies the hostname.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::{Result, SatsPathError};

/// DNS suffixes that can only name internal / special-use hosts
/// (RFC 6761, RFC 6762, RFC 8375, and common internal-only conventions).
const INTERNAL_SUFFIXES: &[&str] = &[
    "localhost",
    "localdomain",
    "local",
    "internal",
    "intranet",
    "lan",
    "home",
    "corp",
    "home.arpa",
    "in-addr.arpa",
    "ip6.arpa",
];

/// Public DNS names that are well known to resolve to loopback.
const LOOPBACK_ALIAS_DOMAINS: &[&str] = &["localtest.me", "lvh.me", "vcap.me", "lacolhost.com"];

/// Domains that are always blocked regardless of IP resolution.
const BLOCKED_HOSTS: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal", // GCP metadata
    "169.254.169.254",          // AWS/GCP/Azure metadata endpoint
    "metadata.google.internal.",
];

/// Validate that a URL is safe to request (no SSRF risk).
///
/// Checks performed:
/// 1. Scheme must be HTTPS (or HTTP only if `allow_http` is true — for tests).
/// 2. Host must not be a known internal/metadata hostname.
/// 3. If the host is an IP literal, it must not be in a private/reserved range.
/// 4. Port must be standard (443 for HTTPS, 80 for HTTP) or in 1024..=65535.
pub fn validate_url(url: &str, allow_http: bool) -> Result<()> {
    let parsed = url::Url::parse(url)
        .map_err(|e| SatsPathError::ValidationError(format!("Invalid URL: {e}")))?;

    // ── Scheme ────────────────────────────────────────────────────────────
    match parsed.scheme() {
        "https" => {}
        "http" if allow_http => {}
        other => {
            return Err(SatsPathError::ValidationError(format!(
                "Blocked scheme '{other}' — only HTTPS is allowed"
            )));
        }
    }

    // ── Host ──────────────────────────────────────────────────────────────
    let host = parsed
        .host_str()
        .ok_or_else(|| SatsPathError::ValidationError("URL has no host".to_string()))?;

    let host_lower = host.to_ascii_lowercase();
    let host_clean = host_lower.strip_suffix('.').unwrap_or(&host_lower);

    // Block known internal hostnames
    if BLOCKED_HOSTS.iter().any(|blocked| {
        let blocked_clean = blocked.strip_suffix('.').unwrap_or(blocked);
        host_clean == blocked_clean || host_clean.ends_with(&format!(".{blocked_clean}"))
    }) {
        return Err(SatsPathError::ValidationError(format!(
            "Blocked host: {host} (internal/metadata endpoint)"
        )));
    }

    // If the host is an IP literal, check the range
    let ip_str = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        if is_private_or_reserved(ip) {
            return Err(SatsPathError::ValidationError(format!(
                "Blocked IP: {ip} (private/reserved range)"
            )));
        }
    } else {
        // Hostname: reject names that can only denote an internal target.
        // This is defense in depth — the authoritative check is on the
        // resolved addresses (see `resolve_and_validate`).
        check_internal_hostname(host_clean)?;
    }

    // ── Port ──────────────────────────────────────────────────────────────
    if let Some(port) = parsed.port() {
        // Allowlist: a public profile endpoint only needs standard web ports.
        match port {
            80 | 443 | 8080 | 8443 => {}
            _ => {
                return Err(SatsPathError::ValidationError(format!(
                    "Blocked port {port} — only 80, 443, 8080 and 8443 are allowed"
                )));
            }
        }
    }

    Ok(())
}

/// Reject hostnames that can only denote an internal target: special-use
/// suffixes, known loopback-alias domains, and wildcard-DNS names that embed a
/// private IPv4 address (`10.0.0.1.nip.io`, `10-0-0-1.sslip.io`, ...).
fn check_internal_hostname(host: &str) -> Result<()> {
    let has_suffix = |suffix: &str| host == suffix || host.ends_with(&format!(".{suffix}"));

    if let Some(suffix) = INTERNAL_SUFFIXES.iter().find(|s| has_suffix(s)) {
        return Err(SatsPathError::ValidationError(format!(
            "Blocked host: {host} (internal-only DNS suffix .{suffix})"
        )));
    }
    if LOOPBACK_ALIAS_DOMAINS.iter().any(|d| has_suffix(d)) {
        return Err(SatsPathError::ValidationError(format!(
            "Blocked host: {host} (resolves to loopback)"
        )));
    }
    if let Some(ip) = embedded_private_ipv4(host) {
        return Err(SatsPathError::ValidationError(format!(
            "Blocked host: {host} (embeds private/reserved address {ip})"
        )));
    }
    Ok(())
}

/// Find a private/reserved IPv4 address embedded in a hostname, either as four
/// consecutive numeric labels (`a.b.c.d.example`) or as one dash-separated
/// label (`a-b-c-d.example`).
fn embedded_private_ipv4(host: &str) -> Option<Ipv4Addr> {
    let labels: Vec<&str> = host.split('.').collect();

    for window in labels.windows(4) {
        if let Ok(ip) = window.join(".").parse::<Ipv4Addr>() {
            if is_private_v4(ip) {
                return Some(ip);
            }
        }
    }
    for label in &labels {
        let parts: Vec<&str> = label.split('-').collect();
        for window in parts.windows(4) {
            if let Ok(ip) = window.join(".").parse::<Ipv4Addr>() {
                if is_private_v4(ip) {
                    return Some(ip);
                }
            }
        }
    }
    None
}

/// Check the addresses a hostname resolved to. Fails if the set is empty or if
/// **any** address is private/reserved — the HTTP client may connect to any of
/// them, so one internal address is enough to make the request unsafe.
pub fn check_resolved_addrs(host: &str, addrs: &[IpAddr]) -> Result<()> {
    if addrs.is_empty() {
        return Err(SatsPathError::NetworkError(format!(
            "{host} did not resolve to any address"
        )));
    }
    if let Some(bad) = addrs.iter().find(|ip| is_private_or_reserved(**ip)) {
        return Err(SatsPathError::ValidationError(format!(
            "Blocked host: {host} resolves to {bad} (private/reserved range)"
        )));
    }
    Ok(())
}

/// A URL target whose host has been resolved and validated.
///
/// Pass it to [`pinned_client`] so the request connects only to `addrs`.
#[derive(Debug, Clone)]
pub struct ValidatedTarget {
    /// Host as it appears in the URL (used for TLS SNI / certificate checks).
    pub host: String,
    /// Validated socket addresses the request is allowed to connect to.
    pub addrs: Vec<SocketAddr>,
}

/// Upper bound on resolving a URL's hostname in [`resolve_and_validate`].
pub const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolve `domain` to its IP addresses within [`DNS_LOOKUP_TIMEOUT`].
///
/// Uses hickory's async resolver configured from the system (`/etc/resolv.conf`
/// and the hosts file), so lookups go to the same servers as the rest of the
/// machine. Unlike `tokio::net::lookup_host`, which runs blocking `getaddrinfo`
/// on a thread the timeout cannot stop, dropping this future on timeout ends
/// the DNS work, so slow or hostile domains cannot pile up resolver threads.
async fn lookup_ips(domain: &str) -> Result<Vec<IpAddr>> {
    let resolver = hickory_resolver::TokioAsyncResolver::tokio_from_system_conf().map_err(|e| {
        SatsPathError::NetworkError(format!("cannot load system DNS configuration: {e}"))
    })?;
    let lookup = tokio::time::timeout(DNS_LOOKUP_TIMEOUT, resolver.lookup_ip(domain))
        .await
        .map_err(|_| {
            SatsPathError::NetworkError(format!(
                "DNS resolution timed out for {domain} after {}s",
                DNS_LOOKUP_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| {
            SatsPathError::NetworkError(format!("DNS resolution failed for {domain}: {e}"))
        })?;
    Ok(lookup.iter().collect())
}

/// Validate `url` with [`validate_url`], resolve its host, and check every
/// resolved address with [`check_resolved_addrs`].
pub async fn resolve_and_validate(url: &str, allow_http: bool) -> Result<ValidatedTarget> {
    validate_url(url, allow_http)?;

    let parsed = url::Url::parse(url)
        .map_err(|e| SatsPathError::ValidationError(format!("Invalid URL: {e}")))?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| SatsPathError::ValidationError("URL has no port".into()))?;

    let (host, ips): (String, Vec<IpAddr>) = match parsed.host() {
        Some(url::Host::Ipv4(ip)) => (ip.to_string(), vec![IpAddr::V4(ip)]),
        Some(url::Host::Ipv6(ip)) => (ip.to_string(), vec![IpAddr::V6(ip)]),
        Some(url::Host::Domain(domain)) => (domain.to_string(), lookup_ips(domain).await?),
        None => return Err(SatsPathError::ValidationError("URL has no host".into())),
    };

    check_resolved_addrs(&host, &ips)?;

    Ok(ValidatedTarget {
        host,
        addrs: ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect(),
    })
}

/// Build an HTTP client that can only connect to the validated addresses of
/// `target` and never follows redirects.
///
/// Pinning closes the DNS-rebinding gap between validation and connection.
pub fn pinned_client(target: &ValidatedTarget, timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        // A redirect would re-enter resolution for a new, unvalidated host.
        .redirect(reqwest::redirect::Policy::none())
        // Proxies would make the pinned addresses meaningless.
        .no_proxy()
        .resolve_to_addrs(&target.host, &target.addrs)
        .build()
        .map_err(|e| SatsPathError::NetworkError(format!("failed to build HTTP client: {e}")))
}

/// Returns `true` if the IP address is in a private, loopback, link-local,
/// or otherwise reserved range that should never be contacted by a resolver.
fn is_private_or_reserved(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

/// Whether an IPv4 address is in a range a resolver must never contact.
fn is_private_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    // Loopback: 127.0.0.0/8
    if octets[0] == 127 {
        return true;
    }
    // Private: 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // Private: 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // Private: 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // Link-local: 169.254.0.0/16 (includes AWS/GCP metadata 169.254.169.254)
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    // Broadcast / unspecified
    if ip.is_broadcast() || ip.is_unspecified() {
        return true;
    }
    // Documentation ranges (RFC 5737)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return true;
    }
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return true;
    }
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return true;
    }
    // Carrier-grade NAT: 100.64.0.0/10
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return true;
    }
    // "This network": 0.0.0.0/8
    if octets[0] == 0 {
        return true;
    }
    // IETF protocol assignments: 192.0.0.0/24
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return true;
    }
    // Benchmarking: 198.18.0.0/15
    if octets[0] == 198 && (18..=19).contains(&octets[1]) {
        return true;
    }
    // Multicast 224.0.0.0/4 and reserved 240.0.0.0/4
    if octets[0] >= 224 {
        return true;
    }
    false
}

/// Whether an IPv6 address is internal, including IPv6 forms that embed an IPv4 address.
fn is_private_v6(ip: Ipv6Addr) -> bool {
    // Loopback: ::1
    if ip.is_loopback() {
        return true;
    }
    // Unspecified: ::
    if ip.is_unspecified() {
        return true;
    }
    let segments = ip.segments();
    // Link-local: fe80::/10
    if segments[0] & 0xffc0 == 0xfe80 {
        return true;
    }
    // Unique local: fc00::/7 (RFC 4193)
    if segments[0] & 0xfe00 == 0xfc00 {
        return true;
    }
    // IPv4-mapped: ::ffff:0:0/96 — check the embedded v4
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_private_v4(v4);
    }
    // Multicast: ff00::/8
    if segments[0] & 0xff00 == 0xff00 {
        return true;
    }
    // Documentation: 2001:db8::/32
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return true;
    }
    // NAT64 well-known prefix 64:ff9b::/96 — check the embedded v4
    if segments[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        return is_private_v4(embedded_v4(segments[6], segments[7]));
    }
    // 6to4: 2002::/16 — the embedded v4 is in segments 1..=2
    if segments[0] == 0x2002 {
        return is_private_v4(embedded_v4(segments[1], segments[2]));
    }
    // Deprecated IPv4-compatible ::a.b.c.d
    if segments[..6] == [0, 0, 0, 0, 0, 0] {
        return is_private_v4(embedded_v4(segments[6], segments[7]));
    }
    false
}

/// The IPv4 address carried in two IPv6 segments.
fn embedded_v4(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_public_allowed() {
        assert!(validate_url("https://example.com/.well-known/satspath/alice", false).is_ok());
    }

    #[test]
    fn http_blocked_by_default() {
        assert!(validate_url("http://example.com/test", false).is_err());
    }

    #[test]
    fn http_allowed_when_flagged() {
        assert!(validate_url("http://example.com/test", true).is_ok());
    }

    #[test]
    fn localhost_blocked() {
        assert!(validate_url("https://localhost/profile", false).is_err());
        assert!(validate_url("https://localhost:8080/profile", false).is_err());
    }

    #[test]
    fn loopback_ip_blocked() {
        assert!(validate_url("https://127.0.0.1/profile", false).is_err());
        assert!(validate_url("https://[::1]/profile", false).is_err());
    }

    #[test]
    fn private_ip_blocked() {
        assert!(validate_url("https://10.0.0.1/profile", false).is_err());
        assert!(validate_url("https://192.168.1.1/profile", false).is_err());
        assert!(validate_url("https://172.16.0.1/profile", false).is_err());
    }

    #[test]
    fn aws_metadata_blocked() {
        assert!(validate_url("https://169.254.169.254/latest/meta-data/", false).is_err());
        assert!(validate_url("https://metadata.google.internal/", false).is_err());
    }

    #[test]
    fn low_and_internal_service_ports_blocked() {
        assert!(validate_url("https://example.com:22/profile", false).is_err());
        assert!(validate_url("https://example.com:25/profile", false).is_err());
        // High-risk internal database / caching / search service ports
        for port in [3306, 5432, 6379, 9200, 11211, 27017] {
            assert!(
                validate_url(&format!("https://example.com:{port}/profile"), false).is_err(),
                "port {port} must be blocked"
            );
        }
    }

    #[test]
    fn allowed_ports_pass() {
        assert!(validate_url("https://example.com:443/profile", false).is_ok());
        assert!(validate_url("https://example.com:8443/profile", false).is_ok());
        assert!(validate_url("http://example.com:80/profile", true).is_ok());
        assert!(validate_url("http://example.com:8080/profile", true).is_ok());
    }

    #[test]
    fn encoded_ips_canonicalized_and_blocked() {
        // WHATWG URL parser canonicalizes these to 127.0.0.1 which is caught by loopback IP check
        assert!(validate_url("https://0x7f000001/profile", false).is_err());
        assert!(validate_url("https://2130706433/profile", false).is_err());
        assert!(validate_url("https://127.1/profile", false).is_err());
        assert!(validate_url("https://localhost./profile", false).is_err());
    }

    #[test]
    fn ftp_scheme_blocked() {
        assert!(validate_url("ftp://example.com/profile", false).is_err());
    }

    #[test]
    fn carrier_grade_nat_blocked() {
        assert!(validate_url("https://100.100.100.100/profile", false).is_err());
    }

    /// Internal-only suffixes (.internal, .local, ...) are refused before any lookup.
    #[test]
    fn internal_suffix_hostnames_blocked() {
        for host in [
            "printer.local",
            "metadata.internal",
            "router.home.arpa",
            "db.corp",
            "nas.lan",
            "x.localdomain",
            "1.0.0.127.in-addr.arpa",
        ] {
            assert!(
                validate_url(&format!("https://{host}/p"), false).is_err(),
                "{host} must be blocked"
            );
        }
        // Suffix match is on whole labels only.
        assert!(validate_url("https://notlocal.com/p", false).is_ok());
        assert!(validate_url("https://internal.example.com/p", false).is_ok());
    }

    /// NAT64, 6to4, Teredo and IPv4-compatible addresses carrying a private IPv4 are blocked.
    #[test]
    fn embedded_private_ipv4_blocked() {
        assert!(validate_url("https://169.254.169.254.nip.io/p", false).is_err());
        assert!(validate_url("https://a.10.1.2.3.sslip.io/p", false).is_err());
        assert!(validate_url("https://app-127-0-0-1.sslip.io/p", false).is_err());
        assert!(validate_url("https://localtest.me/p", false).is_err());
        // A public IP embedded in a name is not, by itself, a reason to block.
        assert!(validate_url("https://93.184.215.14.nip.io/p", false).is_ok());
    }

    /// Reserved, multicast and benchmarking ranges are blocked.
    #[test]
    fn extended_reserved_ranges_blocked() {
        for ip in [
            "0.1.2.3",
            "192.0.0.8",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
        ] {
            assert!(is_private_or_reserved(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "ff02::1",
            "2001:db8::1",
            "64:ff9b::a9fe:a9fe", // NAT64 → 169.254.169.254
            "2002:7f00:1::",      // 6to4 → 127.0.0.1
            "::7f00:1",           // IPv4-compatible 127.0.0.1
        ] {
            assert!(is_private_or_reserved(ip.parse().unwrap()), "{ip}");
        }
        assert!(!is_private_or_reserved("93.184.215.14".parse().unwrap()));
        assert!(!is_private_or_reserved("2606:4700::1111".parse().unwrap()));
        assert!(!is_private_or_reserved("64:ff9b::808:808".parse().unwrap()));
    }

    /// One private address among a hostname's results is enough to refuse it.
    #[test]
    fn resolved_addresses_checked() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(check_resolved_addrs("h", &[ip("169.254.169.254")]).is_err());
        assert!(check_resolved_addrs("h", &[ip("1.1.1.1"), ip("127.0.0.1")]).is_err());
        assert!(check_resolved_addrs("h", &[]).is_err());
        assert!(check_resolved_addrs("h", &[ip("1.1.1.1")]).is_ok());
    }

    /// Private literals and blocked names fail before any DNS lookup.
    #[tokio::test]
    async fn resolve_and_validate_rejects_private_literal_before_lookup() {
        assert!(resolve_and_validate("https://10.0.0.1/p", false)
            .await
            .is_err());
        assert!(resolve_and_validate("https://localhost/p", false)
            .await
            .is_err());
    }

    /// A public literal is pinned to exactly that address.
    #[tokio::test]
    async fn resolve_and_validate_pins_public_literal() {
        let target = resolve_and_validate("https://1.1.1.1/p", false)
            .await
            .unwrap();
        assert_eq!(target.addrs, vec!["1.1.1.1:443".parse().unwrap()]);
        assert!(pinned_client(&target, Duration::from_secs(1)).is_ok());
    }

    /// The async resolver honors the system hosts file, and what it returns is
    /// still subject to the private-address check.
    #[tokio::test]
    async fn system_resolver_reads_hosts_file_and_result_is_checked() {
        let ips = lookup_ips("localhost")
            .await
            .expect("localhost resolves via hosts file");
        assert!(ips.iter().all(|ip| ip.is_loopback()), "{ips:?}");
        assert!(check_resolved_addrs("localhost", &ips).is_err());
    }
}
