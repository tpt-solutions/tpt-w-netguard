// SPDX-License-Identifier: MIT OR Apache-2.0
//! Encrypted DNS transports: DNS-over-HTTPS (RFC 8484) and DNS-over-TLS (RFC 7858).
//!
//! Both transports enforce a timeout on every network operation and cap response sizes, so a
//! hostile or stalled upstream cannot hang the app or exhaust memory. Certificate validation
//! uses the bundled Mozilla root set (`webpki-roots`); nothing is trusted implicitly.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use crate::{DnsError, Result, Transport, Upstream};

/// Largest DNS message accepted over either transport (the TCP length prefix is 16 bits).
pub const MAX_MESSAGE: usize = 65_535;
/// Default port for DNS-over-TLS.
pub const DOT_PORT: u16 = 853;

fn transport_err(e: impl std::fmt::Display) -> DnsError {
    DnsError::Transport(e.to_string())
}

/// Prefix a DNS message with its 2-byte big-endian length (DNS over TCP / TLS framing).
pub fn frame(message: &[u8]) -> Result<Vec<u8>> {
    if message.len() > MAX_MESSAGE {
        return Err(DnsError::Malformed("message too large to frame"));
    }
    let mut out = Vec::with_capacity(message.len() + 2);
    out.extend_from_slice(&(message.len() as u16).to_be_bytes());
    out.extend_from_slice(message);
    Ok(out)
}

/// Read one length-prefixed DNS message.
pub fn read_framed<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    reader.read_exact(&mut len).map_err(transport_err)?;
    let len = u16::from_be_bytes(len) as usize;
    if len == 0 {
        return Err(DnsError::Malformed("empty framed message"));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).map_err(transport_err)?;
    Ok(buf)
}

/// DNS over HTTPS: POST of the raw query with `application/dns-message`.
pub struct DohTransport {
    url: String,
    agent: ureq::Agent,
}

impl DohTransport {
    /// `url` is the full endpoint, for example `https://cloudflare-dns.com/dns-query`.
    pub fn new(url: impl Into<String>, timeout: Duration) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(timeout)
            .redirects(0)
            .build();
        Self {
            url: url.into(),
            agent,
        }
    }
}

impl Transport for DohTransport {
    fn exchange(&self, query: &[u8]) -> Result<Vec<u8>> {
        let response = self
            .agent
            .post(&self.url)
            .set("Content-Type", "application/dns-message")
            .set("Accept", "application/dns-message")
            .send_bytes(query)
            .map_err(transport_err)?;
        let mut body = Vec::new();
        response
            .into_reader()
            .take(MAX_MESSAGE as u64 + 1)
            .read_to_end(&mut body)
            .map_err(transport_err)?;
        if body.len() > MAX_MESSAGE {
            return Err(DnsError::Malformed("DoH response too large"));
        }
        Ok(body)
    }
}

/// DNS over TLS on a persistent-per-query TCP connection.
pub struct DotTransport {
    host: String,
    port: u16,
    server_name: ServerName<'static>,
    config: Arc<ClientConfig>,
    timeout: Duration,
}

impl DotTransport {
    pub fn new(host: impl Into<String>, port: u16, timeout: Duration) -> Result<Self> {
        Self::with_config(host, port, default_client_config(), timeout)
    }

    /// Use a custom TLS configuration (for example one that trusts a private test CA).
    pub fn with_config(
        host: impl Into<String>,
        port: u16,
        config: Arc<ClientConfig>,
        timeout: Duration,
    ) -> Result<Self> {
        let host = host.into();
        let server_name = ServerName::try_from(host.clone())
            .map_err(|_| DnsError::InvalidName(host.clone()))?
            .to_owned();
        Ok(Self {
            host,
            port,
            server_name,
            config,
            timeout,
        })
    }
}

impl Transport for DotTransport {
    fn exchange(&self, query: &[u8]) -> Result<Vec<u8>> {
        // Try every resolved address in turn (IPv6 may be listed first but unreachable).
        let mut last_error = None;
        let mut tcp = None;
        for addr in (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(transport_err)?
        {
            match TcpStream::connect_timeout(&addr, self.timeout) {
                Ok(stream) => {
                    tcp = Some(stream);
                    break;
                }
                Err(e) => last_error = Some(e),
            }
        }
        let tcp = tcp.ok_or_else(|| match last_error {
            Some(e) => transport_err(e),
            None => DnsError::Transport(format!("no address for {}", self.host)),
        })?;
        tcp.set_read_timeout(Some(self.timeout))
            .map_err(transport_err)?;
        tcp.set_write_timeout(Some(self.timeout))
            .map_err(transport_err)?;

        let conn = ClientConnection::new(Arc::clone(&self.config), self.server_name.clone())
            .map_err(transport_err)?;
        let mut tls = StreamOwned::new(conn, tcp);
        tls.write_all(&frame(query)?).map_err(transport_err)?;
        tls.flush().map_err(transport_err)?;
        read_framed(&mut tls)
    }
}

/// TLS client configuration trusting the bundled Mozilla root set. Built once and shared.
pub fn default_client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

/// Build an [`Upstream`] from a configuration string:
/// `https://host/path` for DoH, or `tls://host[:port]` for DoT.
pub fn parse_upstream(spec: &str, timeout: Duration) -> Result<Upstream> {
    if let Some(rest) = spec.strip_prefix("https://") {
        let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
        if host.is_empty() {
            return Err(DnsError::InvalidName(spec.to_string()));
        }
        return Ok(Upstream {
            name: host.to_string(),
            transport: Box::new(DohTransport::new(spec, timeout)),
        });
    }
    if let Some(rest) = spec.strip_prefix("tls://") {
        let (host, port) =
            split_host_port(rest).ok_or_else(|| DnsError::InvalidName(spec.to_string()))?;
        return Ok(Upstream {
            name: host.clone(),
            transport: Box::new(DotTransport::new(host, port, timeout)?),
        });
    }
    Err(DnsError::Transport(format!(
        "unsupported upstream scheme (use https:// or tls://): {spec}"
    )))
}

/// Split `host[:port]`, supporting bracketed IPv6 literals. Defaults the port to 853.
fn split_host_port(s: &str) -> Option<(String, u16)> {
    if s.is_empty() {
        return None;
    }
    if let Some(stripped) = s.strip_prefix('[') {
        let (host, tail) = stripped.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if tail.is_empty() => DOT_PORT,
            None => return None,
        };
        return Some((host.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Some((host.to_string(), port.parse().ok()?)),
        Some(_) => Some((s.to_string(), DOT_PORT)), // bare IPv6 literal
        None => Some((s.to_string(), DOT_PORT)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn framing_round_trips() {
        let msg = b"\x12\x34query-bytes";
        let framed = frame(msg).unwrap();
        assert_eq!(&framed[..2], &(msg.len() as u16).to_be_bytes());
        let back = read_framed(&mut Cursor::new(framed)).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn framing_rejects_oversize_and_truncated_input() {
        assert!(frame(&vec![0u8; MAX_MESSAGE + 1]).is_err());
        assert!(read_framed(&mut Cursor::new(vec![0u8])).is_err());
        // Declares 10 bytes but supplies 2.
        assert!(read_framed(&mut Cursor::new(vec![0, 10, 1, 2])).is_err());
        // Zero-length message is not a valid DNS message.
        assert!(read_framed(&mut Cursor::new(vec![0, 0])).is_err());
    }

    #[test]
    fn upstream_specs_are_parsed() {
        let t = Duration::from_secs(2);
        let doh = parse_upstream("https://cloudflare-dns.com/dns-query", t).unwrap();
        assert_eq!(doh.name, "cloudflare-dns.com");
        let dot = parse_upstream("tls://dns.quad9.net", t).unwrap();
        assert_eq!(dot.name, "dns.quad9.net");
        assert!(parse_upstream("udp://8.8.8.8:53", t).is_err());
        assert!(parse_upstream("https://", t).is_err());
    }

    #[test]
    fn host_port_splitting() {
        assert_eq!(
            split_host_port("dns.example"),
            Some(("dns.example".into(), 853))
        );
        assert_eq!(
            split_host_port("dns.example:8853"),
            Some(("dns.example".into(), 8853))
        );
        assert_eq!(
            split_host_port("[2001:db8::1]:853"),
            Some(("2001:db8::1".into(), 853))
        );
        assert_eq!(
            split_host_port("2001:db8::1"),
            Some(("2001:db8::1".into(), 853))
        );
        assert_eq!(split_host_port(""), None);
        assert_eq!(split_host_port("host:notaport"), None);
    }
}
