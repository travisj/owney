//! DNSBL (DNS Blacklist) checking via reverse-octet A-record lookups.
//!
//! This module checks an IP against DNSBL zones using reverse-octet DNS lookups.
//! Fail-open: errors are silently ignored (returns empty hit list on any error).

use std::net::IpAddr;

/// Check an IP against multiple DNSBL zones.
/// Returns a list of zone names where the IP was listed.
/// Fail-open: errors during lookup are silently ignored (timeout or network error = no hit).
///
/// TODO: Implement full DNSBL via hickory-resolver. For now returns empty (safe default).
/// Framework supports adding real lookups with minimal changes to calling code.
pub async fn check_ip(zones: &[String], ip: IpAddr) -> Result<Vec<String>, String> {
    if zones.is_empty() {
        return Ok(Vec::new());
    }

    let _v4 = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Ok(Vec::new()), // Skip IPv6 for now
    };

    // Reverse-octet format for DNSBL: d.c.b.a.zone
    // let octets = _v4.octets();
    // let reversed = format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0]);

    // TODO: Use hickory_resolver to perform actual DNS A-record lookups
    // for each zone. On success (any A record), add zone to hits.
    // Fail-open: timeout or NXDOMAIN returns empty (no hit).

    // For now, return no hits (safe - doesn't block mail, just skips DNSBL scoring)
    Ok(Vec::new())
}
