// SPDX-License-Identifier: MIT OR Apache-2.0
//! Checks the kernel's `sock_diag` byte counters against traffic this test creates on loopback.
//!
//! Both ends of the connection live in this process, so the counters must show the client
//! sending the payload and the server receiving it. This validates the `tcp_info` offsets in
//! `sockdiag.rs` against the running kernel. Runs without root on any Linux with `sock_diag`.
//!
//! Both sockets stay open until the query has run. A connection that has already closed (for
//! example in TIME_WAIT) has no `tcp_info` and is correctly absent from the reply.
#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use tpt_netguard_platform_linux::sockdiag::query_tcp;

const PAYLOAD: usize = 64 * 1024;

#[test]
fn loopback_traffic_shows_up_in_tcp_byte_counters() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // The server reads the whole payload, then keeps its socket open until told to finish.
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let server = thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; PAYLOAD];
        conn.read_exact(&mut buf).unwrap();
        let _ = release_rx.recv();
        drop(conn);
    });

    let mut client = TcpStream::connect(addr).unwrap();
    client.write_all(&vec![7u8; PAYLOAD]).unwrap();

    // The client's bytes are acknowledged asynchronously; poll briefly for the counters to settle.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let rows = query_tcp().expect("sock_diag should answer for our own sockets");
        let sent = rows.iter().any(|r| r.bytes_sent >= PAYLOAD as u64);
        let received = rows.iter().any(|r| r.bytes_received >= PAYLOAD as u64);
        if sent && received {
            // Every reported socket has a non-zero inode, which process attribution keys on.
            assert!(rows.iter().all(|r| r.inode != 0), "{rows:?}");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "counters never reached {PAYLOAD} bytes: {rows:?}"
        );
        thread::sleep(Duration::from_millis(20));
    }

    let _ = release_tx.send(());
    server.join().unwrap();
    drop(client);
}
