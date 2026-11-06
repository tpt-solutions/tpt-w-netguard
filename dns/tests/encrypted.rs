// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end tests for the encrypted transports against local servers.
//!
//! * DoH: a plain-HTTP stand-in server (ureq follows the same request path as HTTPS).
//! * DoT: a real rustls server with a self-signed certificate, trusted explicitly.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use tpt_netguard_dns::transport::{frame, read_framed};
use tpt_netguard_dns::{wire, DnsError, DohTransport, DotTransport, Resolver, Upstream};

const TIMEOUT: Duration = Duration::from_secs(5);

/// Answer `query` with a single A record `addr`, copying its id and question.
fn a_response(query: &[u8], addr: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&query[0..2]);
    out.extend_from_slice(&[0x81, 0x80]);
    out.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
    out.extend_from_slice(&query[12..]);
    out.extend_from_slice(&[0xC0, 0x0C]);
    out.extend_from_slice(&wire::TYPE_A.to_be_bytes());
    out.extend_from_slice(&wire::CLASS_IN.to_be_bytes());
    out.extend_from_slice(&60u32.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&addr);
    out
}

fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap();
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).unwrap();
    body
}

#[test]
fn doh_resolves_a_record_over_http_post() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let query = read_http_request(&mut stream);
        let body = a_response(&query, [192, 0, 2, 33]);
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(&body).unwrap();
    });

    let url = format!("http://127.0.0.1:{port}/dns-query");
    let resolver = Resolver::new(vec![Upstream {
        name: "local-doh".into(),
        transport: Box::new(DohTransport::new(url, TIMEOUT)),
    }]);
    let addrs = resolver.lookup_a("example.test").unwrap();
    assert_eq!(addrs, vec![Ipv4Addr::new(192, 0, 2, 33)]);
    server.join().unwrap();
}

#[test]
fn doh_falls_back_when_first_upstream_is_down() {
    // Port 1 on loopback is closed: the first upstream fails fast.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let query = read_http_request(&mut stream);
        let body = a_response(&query, [198, 51, 100, 7]);
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(&body).unwrap();
    });

    let resolver = Resolver::new(vec![
        Upstream {
            name: "dead".into(),
            transport: Box::new(DohTransport::new("http://127.0.0.1:1/dns-query", TIMEOUT)),
        },
        Upstream {
            name: "live".into(),
            transport: Box::new(DohTransport::new(
                format!("http://127.0.0.1:{port}/dns-query"),
                TIMEOUT,
            )),
        },
    ]);
    assert_eq!(
        resolver.lookup_a("fallback.test").unwrap(),
        vec![Ipv4Addr::new(198, 51, 100, 7)]
    );
    server.join().unwrap();
}

#[test]
fn doh_http_error_is_reported_as_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = read_http_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
    });
    let resolver = Resolver::new(vec![Upstream {
        name: "broken".into(),
        transport: Box::new(DohTransport::new(
            format!("http://127.0.0.1:{port}/dns-query"),
            TIMEOUT,
        )),
    }]);
    assert!(matches!(
        resolver.lookup_a("err.test"),
        Err(DnsError::AllUpstreamsFailed(_))
    ));
}

#[test]
fn dot_resolves_over_tls_with_length_framing() {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(certified.cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());

    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der.into())
            .unwrap(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(TIMEOUT)).unwrap();
        let conn = ServerConnection::new(server_config).unwrap();
        let mut tls = StreamOwned::new(conn, tcp);
        let query = read_framed(&mut tls).unwrap();
        let answer = a_response(&query, [203, 0, 113, 99]);
        tls.write_all(&frame(&answer).unwrap()).unwrap();
        tls.flush().unwrap();
        // Let the client read the response before the TLS stream is dropped.
        thread::sleep(Duration::from_millis(100));
    });

    let mut roots = RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let resolver = Resolver::new(vec![Upstream {
        name: "local-dot".into(),
        transport: Box::new(
            DotTransport::with_config("localhost", port, client_config, TIMEOUT).unwrap(),
        ),
    }]);
    assert_eq!(
        resolver.lookup_a("tls.test").unwrap(),
        vec![Ipv4Addr::new(203, 0, 113, 99)]
    );
    server.join().unwrap();
}

#[test]
fn dot_rejects_untrusted_server_certificate() {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(certified.cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der.into())
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((tcp, _)) = listener.accept() {
            let conn = ServerConnection::new(server_config).unwrap();
            let mut tls = StreamOwned::new(conn, tcp);
            let _ = read_framed(&mut tls);
        }
    });

    // Client trusts only the public root set, not the self-signed certificate.
    let transport = DotTransport::new("localhost", port, TIMEOUT).unwrap();
    let query = wire::encode_query(1, "x.test", wire::TYPE_A).unwrap();
    assert!(matches!(
        tpt_netguard_dns::Transport::exchange(&transport, &query),
        Err(DnsError::Transport(_))
    ));
}
