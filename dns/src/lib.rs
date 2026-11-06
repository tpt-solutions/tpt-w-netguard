// SPDX-License-Identifier: MIT OR Apache-2.0
//! App-scoped DNS for tpt-netguard's own hostname and reverse-DNS lookups (connection list,
//! "Things" labelling). Not a system resolver: nothing here reconfigures OS DNS.
//!
//! * [`wire`]: RFC 1035 message encoding and defensive parsing (compression pointers,
//!   bounds checks, loop protection).
//! * [`Resolver`]: ordered upstreams with fallback. Transports are pluggable so DoH/DoT
//!   clients can be added without touching the logic here.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

pub mod mdns;
pub mod netbios;
pub mod transport;
pub mod wire;

pub use transport::{parse_upstream, DohTransport, DotTransport};
pub use wire::{Answer, RData, Response};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// The name cannot be encoded (empty label, label > 63 bytes, name > 255 bytes).
    InvalidName(String),
    /// The response violates the wire format.
    Malformed(&'static str),
    /// The response id does not match the query (possible spoofing); never accepted.
    IdMismatch,
    /// A transport failed or timed out.
    Transport(String),
    /// Every configured upstream failed.
    AllUpstreamsFailed(Vec<String>),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::InvalidName(n) => write!(f, "invalid DNS name: {n}"),
            DnsError::Malformed(what) => write!(f, "malformed DNS response: {what}"),
            DnsError::IdMismatch => write!(f, "DNS response id mismatch"),
            DnsError::Transport(msg) => write!(f, "DNS transport error: {msg}"),
            DnsError::AllUpstreamsFailed(errs) => {
                write!(f, "all DNS upstreams failed: {}", errs.join("; "))
            }
        }
    }
}

impl std::error::Error for DnsError {}

pub type Result<T> = std::result::Result<T, DnsError>;

/// Sends one encoded query and returns the raw response bytes. DoH and DoT clients implement
/// this; timeouts are the implementation's responsibility.
pub trait Transport: Send + Sync {
    fn exchange(&self, query: &[u8]) -> Result<Vec<u8>>;
}

impl<F> Transport for F
where
    F: Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync,
{
    fn exchange(&self, query: &[u8]) -> Result<Vec<u8>> {
        self(query)
    }
}

/// Build a resolver from configuration strings (`https://...` or `tls://...`), in order.
pub fn resolver_from_specs(specs: &[String], timeout: Duration) -> Result<Resolver> {
    let upstreams = specs
        .iter()
        .map(|spec| parse_upstream(spec, timeout))
        .collect::<Result<Vec<_>>>()?;
    Ok(Resolver::new(upstreams))
}

/// A named upstream resolver.
pub struct Upstream {
    pub name: String,
    pub transport: Box<dyn Transport>,
}

pub struct Resolver {
    upstreams: Vec<Upstream>,
    next_id: std::sync::atomic::AtomicU16,
}

impl Resolver {
    /// Upstreams are tried in order; the first usable answer wins.
    pub fn new(upstreams: Vec<Upstream>) -> Self {
        Self {
            upstreams,
            next_id: std::sync::atomic::AtomicU16::new(1),
        }
    }

    fn query(&self, name: &str, qtype: u16) -> Result<Response> {
        if self.upstreams.is_empty() {
            return Err(DnsError::AllUpstreamsFailed(vec![
                "no upstreams configured".into(),
            ]));
        }
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let query = wire::encode_query(id, name, qtype)?;

        let mut failures = Vec::new();
        for upstream in &self.upstreams {
            let attempt = upstream
                .transport
                .exchange(&query)
                .and_then(|bytes| wire::parse_response(&bytes))
                .and_then(|resp| {
                    if resp.id != id {
                        Err(DnsError::IdMismatch)
                    } else {
                        Ok(resp)
                    }
                });
            match attempt {
                // NXDOMAIN is an authoritative answer: do not ask other upstreams.
                Ok(resp) if resp.rcode == wire::RCODE_OK || resp.rcode == wire::RCODE_NXDOMAIN => {
                    return Ok(resp)
                }
                Ok(resp) => failures.push(format!("{}: rcode {}", upstream.name, resp.rcode)),
                Err(e) => failures.push(format!("{}: {e}", upstream.name)),
            }
        }
        Err(DnsError::AllUpstreamsFailed(failures))
    }

    /// Reverse lookup. `Ok(None)` means the address has no PTR record.
    pub fn reverse_lookup(&self, ip: std::net::IpAddr) -> Result<Option<String>> {
        let name = match ip {
            std::net::IpAddr::V4(v4) => wire::ptr_name_v4(v4),
            std::net::IpAddr::V6(v6) => wire::ptr_name_v6(v6),
        };
        let resp = self.query(&name, wire::TYPE_PTR)?;
        Ok(resp.answers.into_iter().find_map(|a| match a.data {
            RData::Ptr(host) => Some(host),
            _ => None,
        }))
    }

    /// Forward lookup of IPv4 addresses for `name`.
    pub fn lookup_a(&self, name: &str) -> Result<Vec<Ipv4Addr>> {
        let resp = self.query(name, wire::TYPE_A)?;
        Ok(resp
            .answers
            .into_iter()
            .filter_map(|a| match a.data {
                RData::A(ip) => Some(ip),
                _ => None,
            })
            .collect())
    }

    /// Forward lookup of IPv6 addresses for `name`.
    pub fn lookup_aaaa(&self, name: &str) -> Result<Vec<Ipv6Addr>> {
        let resp = self.query(name, wire::TYPE_AAAA)?;
        Ok(resp
            .answers
            .into_iter()
            .filter_map(|a| match a.data {
                RData::Aaaa(ip) => Some(ip),
                _ => None,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    /// Build a response to `query` (copying its id and question) carrying one PTR answer
    /// that uses a compression pointer back to the question name.
    fn ptr_response(query: &[u8], host: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&query[0..2]); // id
        out.extend_from_slice(&[0x81, 0x80]); // QR=1, RD=1, RA=1, rcode 0
        out.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]); // qd=1 an=1
        out.extend_from_slice(&query[12..]); // question section, copied verbatim
        out.extend_from_slice(&[0xC0, 0x0C]); // answer name -> offset 12
        out.extend_from_slice(&wire::TYPE_PTR.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // class IN
        out.extend_from_slice(&300u32.to_be_bytes());
        let rdata = wire::encode_name(host).unwrap();
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
        out
    }

    fn fixed(bytes: Vec<u8>) -> impl Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync {
        move |query: &[u8]| {
            let mut resp = bytes.clone();
            resp[0..2].copy_from_slice(&query[0..2]);
            Ok(resp)
        }
    }

    #[test]
    fn reverse_lookup_decodes_compressed_ptr() {
        let resolver = Resolver::new(vec![Upstream {
            name: "fake".into(),
            transport: Box::new(|q: &[u8]| Ok(ptr_response(q, "host.example"))),
        }]);
        let host = resolver
            .reverse_lookup("192.0.2.1".parse::<IpAddr>().unwrap())
            .unwrap();
        assert_eq!(host.as_deref(), Some("host.example"));
    }

    #[test]
    fn falls_back_to_next_upstream_on_transport_error() {
        let resolver = Resolver::new(vec![
            Upstream {
                name: "down".into(),
                transport: Box::new(|_: &[u8]| Err(DnsError::Transport("timeout".into()))),
            },
            Upstream {
                name: "up".into(),
                transport: Box::new(|q: &[u8]| Ok(ptr_response(q, "fallback.example"))),
            },
        ]);
        let host = resolver
            .reverse_lookup("192.0.2.1".parse::<IpAddr>().unwrap())
            .unwrap();
        assert_eq!(host.as_deref(), Some("fallback.example"));
    }

    #[test]
    fn id_mismatch_is_rejected_and_falls_back() {
        // A spoofed response with the wrong id must not be accepted.
        let spoofed = |q: &[u8]| {
            let mut r = ptr_response(q, "evil.example");
            r[0] ^= 0xFF;
            Ok(r)
        };
        let resolver = Resolver::new(vec![Upstream {
            name: "spoofer".into(),
            transport: Box::new(spoofed),
        }]);
        let err = resolver
            .reverse_lookup("192.0.2.1".parse::<IpAddr>().unwrap())
            .unwrap_err();
        assert!(matches!(err, DnsError::AllUpstreamsFailed(_)));
    }

    #[test]
    fn nxdomain_is_authoritative_and_yields_none() {
        // Header (id 0, QR=1, rcode=3 NXDOMAIN, qd=1, an=0) plus the echoed question.
        let mut bytes = vec![0, 0, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0];
        bytes.extend_from_slice(&wire::encode_name("1.2.0.192.in-addr.arpa").unwrap());
        bytes.extend_from_slice(&[0, 12, 0, 1]);

        let resolver = Resolver::new(vec![
            Upstream {
                name: "authoritative".into(),
                transport: Box::new(fixed(bytes)),
            },
            Upstream {
                name: "never-asked".into(),
                transport: Box::new(|_: &[u8]| -> Result<Vec<u8>> {
                    panic!("NXDOMAIN must not fall through")
                }),
            },
        ]);
        assert_eq!(
            resolver
                .reverse_lookup("192.0.2.1".parse::<IpAddr>().unwrap())
                .unwrap(),
            None
        );
    }

    #[test]
    fn malformed_responses_are_rejected() {
        let truncated = |q: &[u8]| {
            let mut r = ptr_response(q, "host.example");
            r.truncate(20);
            Ok(r)
        };
        let loop_ptr = |q: &[u8]| {
            // Question name that points to itself forever.
            let mut r = q[0..2].to_vec();
            r.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0]);
            r.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
            Ok(r)
        };
        let resolver = Resolver::new(vec![
            Upstream {
                name: "truncated".into(),
                transport: Box::new(truncated),
            },
            Upstream {
                name: "loop".into(),
                transport: Box::new(loop_ptr),
            },
        ]);
        assert!(resolver
            .reverse_lookup("192.0.2.1".parse::<IpAddr>().unwrap())
            .is_err());
    }

    #[test]
    fn name_encoding_rejects_bad_labels() {
        assert!(wire::encode_name("a..b").is_err());
        assert!(wire::encode_name(&"a".repeat(64)).is_err());
        assert!(wire::encode_name(&format!("{}.example", "a".repeat(63))).is_ok());
    }

    #[test]
    fn ptr_names_are_reversed() {
        assert_eq!(
            wire::ptr_name_v4(Ipv4Addr::new(192, 0, 2, 1)),
            "1.2.0.192.in-addr.arpa"
        );
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let name = wire::ptr_name_v6(v6);
        assert!(name.starts_with("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0."));
        assert!(name.ends_with(".8.b.d.0.1.0.0.2.ip6.arpa"));
    }

    #[test]
    fn no_upstreams_is_an_error() {
        let resolver = Resolver::new(Vec::new());
        assert!(resolver.lookup_a("example.com").is_err());
    }
}
