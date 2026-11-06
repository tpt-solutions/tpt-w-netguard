// SPDX-License-Identifier: MIT OR Apache-2.0
//! NetBIOS Name Service node-status (NBSTAT) lookup for Windows and Samba devices.
//!
//! Sends the wildcard `*` node-status query to UDP port 137. The reply lists the device's
//! NetBIOS names; the workstation name (suffix 0x00) is returned.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use crate::{DnsError, Result};

pub const NBNS_PORT: u16 = 137;
const TYPE_NBSTAT: u16 = 0x0021;
const HEADER_LEN: usize = 12;

/// Build the wildcard node-status request.
pub fn encode_node_status_query(id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(50);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0, 0]); // flags: query, no recursion
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // qdcount = 1
                                                      // The wildcard name "*" padded with NULs to 16 bytes, first-level encoded
                                                      // (each byte becomes two letters: high nibble + 'A', low nibble + 'A').
    let mut name = [0u8; 16];
    name[0] = b'*';
    out.push(32);
    for b in name {
        out.push((b >> 4) + b'A');
        out.push((b & 0x0F) + b'A');
    }
    out.push(0);
    out.extend_from_slice(&TYPE_NBSTAT.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // class IN
    out
}

/// Parse a node-status reply and return the workstation name, if present.
pub fn parse_node_status_response(msg: &[u8], id: u16) -> Result<Option<String>> {
    if msg.len() < HEADER_LEN {
        return Err(DnsError::Malformed("NBSTAT header truncated"));
    }
    if u16::from_be_bytes([msg[0], msg[1]]) != id {
        return Err(DnsError::IdMismatch);
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);
    let mut pos = HEADER_LEN;
    for _ in 0..qdcount {
        pos = skip_name(msg, pos)?
            .checked_add(4)
            .ok_or(DnsError::Malformed("overflow"))?;
    }
    for _ in 0..ancount {
        pos = skip_name(msg, pos)?;
        let fixed = msg
            .get(pos..pos + 10)
            .ok_or(DnsError::Malformed("NBSTAT answer truncated"))?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let rdlen = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        pos += 10;
        let rdata = msg
            .get(pos..pos + rdlen)
            .ok_or(DnsError::Malformed("NBSTAT rdata truncated"))?;
        pos += rdlen;
        if rtype != TYPE_NBSTAT || rdata.is_empty() {
            continue;
        }
        let count = rdata[0] as usize;
        for entry in 0..count {
            let start = 1 + entry * 18;
            let Some(record) = rdata.get(start..start + 18) else {
                break;
            };
            if record[15] == 0x00 {
                let raw = String::from_utf8_lossy(&record[..15]).into_owned();
                let name = raw.trim_end_matches([' ', '\0']).to_string();
                if !name.is_empty() {
                    return Ok(Some(name));
                }
            }
        }
    }
    Ok(None)
}

/// Skip a (possibly compressed) domain name, returning the offset just after it.
fn skip_name(msg: &[u8], mut pos: usize) -> Result<usize> {
    loop {
        let len = *msg.get(pos).ok_or(DnsError::Malformed("name truncated"))? as usize;
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            if pos + 2 > msg.len() {
                return Err(DnsError::Malformed("pointer truncated"));
            }
            return Ok(pos + 2);
        }
        pos += 1 + len;
        if pos > msg.len() {
            return Err(DnsError::Malformed("label past end of message"));
        }
    }
}

/// Query one device. `Ok(None)` when it does not answer or reports no workstation name.
pub fn node_status(ip: Ipv4Addr, timeout: Duration) -> Result<Option<String>> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| DnsError::Transport(e.to_string()))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| DnsError::Transport(e.to_string()))?;
    let id = 0x4E42;
    socket
        .send_to(
            &encode_node_status_query(id),
            SocketAddr::from((ip, NBNS_PORT)),
        )
        .map_err(|e| DnsError::Transport(e.to_string()))?;
    let mut buf = [0u8; 1024];
    match socket.recv_from(&mut buf) {
        Ok((len, from)) if from.ip() == IpAddr::V4(ip) => {
            parse_node_status_response(&buf[..len], id)
        }
        Ok(_) => Ok(None),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Ok(None)
        }
        Err(e) => Err(DnsError::Transport(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reply that copies the query question, then one NBSTAT answer listing `names`.
    fn reply(id: u16, names: &[(&str, u8)]) -> Vec<u8> {
        let query = encode_node_status_query(id);
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&[0x84, 0x00]); // response, authoritative
        out.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]); // qd=1, an=1
        out.extend_from_slice(&query[HEADER_LEN..]); // question
        out.extend_from_slice(&[0xC0, 0x0C]); // answer name -> question
        out.extend_from_slice(&TYPE_NBSTAT.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        let rdlen = 1 + names.len() * 18;
        out.extend_from_slice(&(rdlen as u16).to_be_bytes());
        out.push(names.len() as u8);
        for (name, suffix) in names {
            let mut field = [b' '; 15];
            field[..name.len()].copy_from_slice(name.as_bytes());
            out.extend_from_slice(&field);
            out.push(*suffix);
            out.extend_from_slice(&[0x04, 0x00]); // flags
        }
        out
    }

    #[test]
    fn query_is_wildcard_nbstat() {
        let q = encode_node_status_query(7);
        assert_eq!(q[12], 32);
        assert_eq!(&q[q.len() - 4..q.len() - 2], &TYPE_NBSTAT.to_be_bytes());
    }

    #[test]
    fn picks_workstation_name() {
        let msg = reply(9, &[("SERVICE", 0x20), ("HOMEPC", 0x00)]);
        assert_eq!(
            parse_node_status_response(&msg, 9).unwrap().as_deref(),
            Some("HOMEPC")
        );
    }

    #[test]
    fn no_workstation_name_yields_none() {
        let msg = reply(9, &[("SERVICE", 0x20)]);
        assert_eq!(parse_node_status_response(&msg, 9).unwrap(), None);
    }

    #[test]
    fn rejects_wrong_id_and_truncation() {
        let msg = reply(9, &[("X", 0x00)]);
        assert_eq!(
            parse_node_status_response(&msg, 10),
            Err(DnsError::IdMismatch)
        );
        assert!(parse_node_status_response(&msg[..20], 9).is_err());
    }
}
