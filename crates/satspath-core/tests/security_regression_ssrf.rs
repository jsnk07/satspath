//! Security regression — Finding #2: the SSRF guard must cover hostnames, not
//! only IP literals.
//!
//! An attacker who controls a domain's DNS can point a hostname at an internal
//! address (cloud metadata, loopback, RFC 1918). Checking the URL string alone
//! is not enough: the guard has to (a) reject hostnames that can only denote an
//! internal target and (b) check — and pin — the addresses a public hostname
//! actually resolves to.
//!
//! These tests exercise only the pure predicates. They never open a connection
//! to an internal address.

use std::net::IpAddr;

use satspath_core::ssrf::{check_resolved_addrs, validate_url};

#[test]
fn ssrf_guard_must_cover_internal_hostnames() {
    // Baseline: the metadata IP literal is blocked.
    assert!(validate_url("https://169.254.169.254/latest/meta-data/", false).is_err());

    // Hostnames that can only denote an internal target must be rejected the
    // same way, before any request is issued.
    for url in [
        // Wildcard DNS services that echo an embedded IP back as the A record.
        "https://169.254.169.254.nip.io/.well-known/satspath/victim",
        "https://127.0.0.1.sslip.io/.well-known/satspath/victim",
        "https://10-0-0-1.sslip.io/.well-known/satspath/victim",
        "https://www.192.168.1.1.nip.io/.well-known/satspath/victim",
        // Public names that are well known to resolve to loopback.
        "https://localtest.me/.well-known/satspath/victim",
        "https://api.lvh.me/.well-known/satspath/victim",
        // Special-use / internal-only DNS suffixes.
        "https://metadata.internal/.well-known/satspath/victim",
        "https://printer.local/.well-known/satspath/victim",
        "https://router.home.arpa/.well-known/satspath/victim",
        "https://svc.localhost/.well-known/satspath/victim",
    ] {
        assert!(
            validate_url(url, false).is_err(),
            "internal-denoting hostname must be blocked: {url}"
        );
    }

    // Ordinary public hostnames keep working.
    assert!(validate_url("https://example.com/.well-known/satspath/alice", false).is_ok());
    assert!(validate_url("https://pay.satspath.dev/.well-known/satspath/alice", false).is_ok());
}

#[test]
fn ssrf_guard_must_check_resolved_addresses() {
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();

    // A public-looking hostname whose A record points at cloud metadata.
    assert!(check_resolved_addrs("internal.attacker.example", &[ip("169.254.169.254")]).is_err());
    // Loopback, RFC 1918, IPv6 ULA and IPv4-mapped loopback.
    for bad in [
        "127.0.0.1",
        "10.0.0.7",
        "192.168.0.10",
        "fd00::1",
        "::ffff:127.0.0.1",
    ] {
        assert!(
            check_resolved_addrs("attacker.example", &[ip(bad)]).is_err(),
            "{bad} must be rejected"
        );
    }
    // One internal address among public ones is enough to reject: the client
    // could connect to any address in the set.
    assert!(
        check_resolved_addrs("attacker.example", &[ip("93.184.215.14"), ip("10.0.0.1")]).is_err()
    );
    // An empty answer must not be treated as "nothing to block".
    assert!(check_resolved_addrs("attacker.example", &[]).is_err());

    // Public answers pass.
    assert!(check_resolved_addrs("example.com", &[ip("93.184.215.14")]).is_ok());
}
