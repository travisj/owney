//! DNSBL (DNS Blacklist) checking via reverse-octet A-record lookups.
//!
//! This module checks an IP against DNSBL zones using reverse-octet DNS lookups.
//! Fail-open: errors are silently ignored (returns empty hit list on any error).

use std::net::{IpAddr, Ipv4Addr};

/// Check an IP against multiple DNSBL zones.
/// Returns a list of zone names where the IP was listed.
/// Fail-open: errors during lookup are silently ignored.
///
/// TODO: Implement real DNSBL checking via hickory-resolver.
/// For now, this is a stub that returns empty (never triggers DNSBL blocks).
pub async fn check_ip(zones: &[String], ip: IpAddr) -> Result<Vec<String>, String> {
    if zones.is_empty() {
        return Ok(Vec::new());
    }

    let v4 = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Ok(Vec::new()), // Skip IPv6 for now
    };

    // Reverse-octet format for DNSBL: d.c.b.a.zone
    let octets = v4.octets();
    let _reversed = format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0]);

    // Stub: return no hits for now
    // TODO: Use hickory_resolver::TokioAsyncResolver to perform actual lookups
    Ok(Vec::new())
}
