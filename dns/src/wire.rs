// SPDX-License-Identifier: MIT OR Apache-2.0
//! RFC 1035 wire format: encoding queries and parsing responses defensively.
//!
//! Every read is bounds-checked, compression pointers must be backward-pointing, and the
//! number of pointer jumps per name is capped, so hostile responses cannot loop or overrun.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{DnsError, Result};

pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;
pub const RCODE_OK: u8 = 0;
pub const RCODE_NXDOMAIN: u8 = 3;

const HEADER_LEN: usize = 12;
/// Upper bound on compression pointer jumps while reading one name.
const MAX_POINTER_JUMPS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ptr(String),
    /// Any other record type, kept raw.
    Other(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: RData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub id: u16,
    pub rcode: u8,
    pub answers: Vec<Answer>,
}

/// Encode a domain name as length-prefixed labels (no compression on output).
pub fn encode_name(name: &str) -> Result<Vec<u8>> {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    let mut out = Vec::with_capacity(trimmed.len() + 2);
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(DnsError::InvalidName(name.to_string()));
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    if out.len() > 255 {
        return Err(DnsError::InvalidName(name.to_string()));
    }
    Ok(out)
}

/// Build a recursive query for one question.
pub fn encode_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x00]); // RD set, standard query
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // qd=1, others 0
    out.extend_from_slice(&encode_name(name)?);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

/// `1.2.0.192.in-addr.arpa` for `192.0.2.1`.
pub fn ptr_name_v4(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

/// Nibble-reversed `ip6.arpa` name.
pub fn ptr_name_v6(ip: Ipv6Addr) -> String {
    let mut nibbles: Vec<String> = ip
        .octets()
        .iter()
        .flat_map(|b| [format!("{:x}", b >> 4), format!("{:x}", b & 0xF)])
        .collect();
    nibbles.reverse();
    format!("{}.ip6.arpa", nibbles.join("."))
}

/// Parse a response. Authority and additional sections are ignored.
pub fn parse_response(msg: &[u8]) -> Result<Response> {
    if msg.len() < HEADER_LEN {
        return Err(DnsError::Malformed("shorter than header"));
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if flags & 0x8000 == 0 {
        return Err(DnsError::Malformed("not a response (QR=0)"));
    }
    let rcode = (flags & 0x000F) as u8;
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);

    let mut pos = HEADER_LEN;
    for _ in 0..qdcount {
        let (_, next) = read_name(msg, pos)?;
        pos = next
            .checked_add(4)
            .ok_or(DnsError::Malformed("question overflow"))?;
        if pos > msg.len() {
            return Err(DnsError::Malformed("question truncated"));
        }
    }

    let mut answers = Vec::with_capacity(ancount as usize);
    for _ in 0..ancount {
        let (name, next) = read_name(msg, pos)?;
        let fixed = msg
            .get(next..next + 10)
            .ok_or(DnsError::Malformed("answer header truncated"))?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let rdlen = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        let rdata_start = next + 10;
        let rdata_end = rdata_start
            .checked_add(rdlen)
            .filter(|end| *end <= msg.len())
            .ok_or(DnsError::Malformed("rdata truncated"))?;
        let rdata = &msg[rdata_start..rdata_end];

        let data = match (rtype, rdlen) {
            (TYPE_A, 4) => RData::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
            (TYPE_AAAA, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                RData::Aaaa(Ipv6Addr::from(octets))
            }
            (TYPE_PTR, _) => RData::Ptr(read_name(msg, rdata_start)?.0),
            (TYPE_A, _) | (TYPE_AAAA, _) => return Err(DnsError::Malformed("bad address length")),
            _ => RData::Other(rdata.to_vec()),
        };
        answers.push(Answer {
            name,
            rtype,
            ttl,
            data,
        });
        pos = rdata_end;
    }

    Ok(Response { id, rcode, answers })
}

/// Read a (possibly compressed) name at `start`. Returns the name and the offset just past
/// the name's encoding in the original stream (not past any pointer target).
fn read_name(msg: &[u8], start: usize) -> Result<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut end: Option<usize> = None;
    let mut jumps = 0usize;
    loop {
        let len = *msg.get(pos).ok_or(DnsError::Malformed("name truncated"))?;
        match len {
            0 => {
                let end = end.unwrap_or(pos + 1);
                return Ok((labels.join("."), end));
            }
            l if l & 0xC0 == 0xC0 => {
                let lo = *msg
                    .get(pos + 1)
                    .ok_or(DnsError::Malformed("pointer truncated"))?;
                if end.is_none() {
                    end = Some(pos + 2);
                }
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return Err(DnsError::Malformed("compression pointer loop"));
                }
                let target = (((l & 0x3F) as usize) << 8) | lo as usize;
                // Pointers must go backwards; this also rules out self-loops.
                if target >= pos {
                    return Err(DnsError::Malformed("forward compression pointer"));
                }
                pos = target;
            }
            l if l & 0xC0 != 0 => return Err(DnsError::Malformed("reserved label type")),
            l => {
                let l = l as usize;
                let bytes = msg
                    .get(pos + 1..pos + 1 + l)
                    .ok_or(DnsError::Malformed("label truncated"))?;
                labels.push(String::from_utf8_lossy(bytes).into_owned());
                pos += 1 + l;
                if labels.iter().map(|s| s.len() + 1).sum::<usize>() > 255 {
                    return Err(DnsError::Malformed("name too long"));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_names_with_root_and_trailing_dot() {
        assert_eq!(encode_name("a.b").unwrap(), b"\x01a\x01b\x00".to_vec());
        assert_eq!(encode_name("a.b.").unwrap(), b"\x01a\x01b\x00".to_vec());
        assert_eq!(encode_name("").unwrap(), vec![0]);
    }

    #[test]
    fn query_has_expected_header_and_question() {
        let q = encode_query(0xBEEF, "a.b", TYPE_A).unwrap();
        assert_eq!(&q[0..2], &[0xBE, 0xEF]);
        assert_eq!(&q[2..4], &[0x01, 0x00]); // RD
        assert_eq!(&q[4..6], &[0, 1]); // qdcount
        assert_eq!(&q[q.len() - 4..], &[0, 1, 0, 1]); // A, IN
    }

    #[test]
    fn rejects_truncated_header_and_non_responses() {
        assert!(parse_response(&[0; 5]).is_err());
        // QR bit clear.
        let q = encode_query(1, "a.b", TYPE_A).unwrap();
        assert!(parse_response(&q).is_err());
    }

    #[test]
    fn parses_a_record_with_pointer() {
        let mut msg = vec![0, 2, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        msg.extend_from_slice(&encode_name("a.b").unwrap());
        msg.extend_from_slice(&[0, 1, 0, 1]);
        msg.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 7]);
        let resp = parse_response(&msg).unwrap();
        assert_eq!(resp.answers[0].name, "a.b");
        assert_eq!(resp.answers[0].ttl, 60);
        assert_eq!(resp.answers[0].data, RData::A(Ipv4Addr::new(10, 0, 0, 7)));
    }

    #[test]
    fn rejects_forward_and_self_pointers() {
        // Answer name is a pointer to itself at offset 12.
        let mut msg = vec![0, 3, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0];
        msg.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0]);
        assert!(matches!(parse_response(&msg), Err(DnsError::Malformed(_))));
    }

    #[test]
    fn rejects_wrong_address_length() {
        let mut msg = vec![0, 4, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0];
        msg.extend_from_slice(&encode_name("a.b").unwrap());
        msg.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 1, 0, 2, 9, 9]);
        assert!(parse_response(&msg).is_err());
    }
}
