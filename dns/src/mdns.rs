// SPDX-License-Identifier: MIT OR Apache-2.0
//! Multicast DNS reverse lookup for LAN device naming ("Things").
//!
//! Sends a unicast-response query (QU bit set, RFC 6762 section 5.4) straight to the device's
//! port 5353, so no multicast group membership is needed. Only answers from the queried address
//! are accepted, and a silent device is not an error: it simply has no name.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::wire::{self, RData};
use crate::{DnsError, Result};

pub const MDNS_PORT: u16 = 5353;

/// Build a PTR query for `ip` with the QU (unicast response) bit set.
pub fn encode_reverse_query(id: u16, ip: IpAddr) -> Result<Vec<u8>> {
    let name = match ip {
        IpAddr::V4(v4) => wire::ptr_name_v4(v4),
        IpAddr::V6(v6) => wire::ptr_name_v6(v6),
    };
    let mut query = wire::encode_query(id, &name, wire::TYPE_PTR)?;
    // The question's QCLASS is the final two bytes; set its top bit.
    let n = query.len();
    query[n - 2] |= 0x80;
    Ok(query)
}

/// Ask one device for its mDNS name. `Ok(None)` when it does not answer or has no PTR record.
pub fn reverse_lookup(ip: IpAddr, timeout: Duration) -> Result<Option<String>> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| DnsError::Transport(e.to_string()))?;
    let id = 0x4D44;
    let query = encode_reverse_query(id, ip)?;
    socket
        .send_to(&query, SocketAddr::new(ip, MDNS_PORT))
        .map_err(|e| DnsError::Transport(e.to_string()))?;

    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 1500];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        socket
            .set_read_timeout(Some(remaining))
            .map_err(|e| DnsError::Transport(e.to_string()))?;
        match socket.recv_from(&mut buf) {
            Ok((len, from)) if from.ip() == ip => {
                let Ok(resp) = wire::parse_response(&buf[..len]) else {
                    continue;
                };
                if resp.id != id {
                    continue;
                }
                let name = resp.answers.into_iter().find_map(|a| match a.data {
                    RData::Ptr(host) => Some(host),
                    _ => None,
                });
                return Ok(name.map(clean_name));
            }
            Ok(_) => continue,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None)
            }
            Err(e) => return Err(DnsError::Transport(e.to_string())),
        }
    }
}

/// Drop the trailing root dot and the `.local` domain: "printer.local." becomes "printer".
pub fn clean_name(raw: String) -> String {
    let trimmed = raw.trim_end_matches('.');
    trimmed
        .strip_suffix(".local")
        .unwrap_or(trimmed)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_sets_unicast_response_bit() {
        let q = encode_reverse_query(1, "192.0.2.7".parse().unwrap()).unwrap();
        let n = q.len();
        assert_eq!(q[n - 2] & 0x80, 0x80);
        assert_eq!(q[n - 1], 1); // class IN
    }

    #[test]
    fn names_are_cleaned() {
        assert_eq!(clean_name("printer.local.".into()), "printer");
        assert_eq!(clean_name("nas.example.".into()), "nas.example");
    }
}
