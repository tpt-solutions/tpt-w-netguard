// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end: loopback traffic from this process is attributed to this process's executable by
//! `LinuxMonitor::sample_byte_deltas`. Runs without root.
#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use tpt_netguard_core::traits::TrafficMonitor;
use tpt_netguard_platform_linux::LinuxMonitor;

const PAYLOAD: usize = 128 * 1024;

#[test]
fn per_app_deltas_are_attributed_to_the_process_that_moved_the_bytes() {
    let mut monitor = LinuxMonitor::new();
    // The first snapshot is only a baseline, so the sockets below must be created after it.
    monitor.sample_byte_deltas(0).unwrap();
    assert!(
        monitor.bandwidth_available(),
        "{}",
        monitor.bandwidth_status()
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let server = thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; PAYLOAD];
        conn.read_exact(&mut buf).unwrap();
        conn.write_all(b"ok").unwrap();
        let _ = release_rx.recv();
    });
    let mut client = TcpStream::connect(addr).unwrap();
    client.write_all(&vec![1u8; PAYLOAD]).unwrap();
    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).unwrap();

    let me = std::env::current_exe()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let (mut sent, mut received) = (0u64, 0u64);
    let deadline = Instant::now() + Duration::from_secs(5);
    while sent < PAYLOAD as u64 || received < PAYLOAD as u64 {
        for sample in monitor.sample_byte_deltas(1).unwrap() {
            if sample.app == me {
                sent += sample.bytes_sent;
                received += sample.bytes_received;
            }
        }
        assert!(
            Instant::now() < deadline,
            "attributed sent={sent} received={received}, expected at least {PAYLOAD} each"
        );
        thread::sleep(Duration::from_millis(20));
    }

    let _ = release_tx.send(());
    server.join().unwrap();
    drop(client);
}
