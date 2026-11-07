// SPDX-License-Identifier: MIT OR Apache-2.0
//! Scale check for the socket-table parsers: a busy host can have tens of thousands of sockets
//! (torrent clients, browsers, container hosts). Every row must survive parsing, and inode
//! attribution must stay exact at that size. Runs on every host; no kernel access.

use std::fmt::Write as _;

use tpt_netguard_core::model::Protocol;
use tpt_netguard_platform_linux::proc_net::{map_inodes, parse_table};

const ROWS: usize = 50_000;

fn table(rows: usize) -> String {
    let mut text = String::from(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
    );
    for i in 0..rows {
        // Spread ports across the range; inodes are unique and well above zero.
        let local_port = 1024 + (i % 60_000);
        let _ = writeln!(
            text,
            "{:4}: 0100007F:{:04X} 0100007F:{:04X} 01 00000000:00000000 00:00000000 00000000  1000        0 {} 1 0000000000000000 100 0 0 10 0",
            i,
            local_port,
            80,
            100_000 + i
        );
    }
    text
}

#[test]
fn fifty_thousand_socket_rows_all_parse_in_order() {
    let rows = parse_table(&table(ROWS), Protocol::Tcp, false);
    assert_eq!(rows.len(), ROWS);
    assert_eq!(rows[0].inode, 100_000);
    assert_eq!(rows[ROWS - 1].inode, 100_000 + ROWS as u64 - 1);
    assert!(rows.iter().all(|r| r.state == 0x01));
}

#[test]
fn inode_attribution_is_exact_at_scale() {
    // 200 processes, each holding 250 socket fds: 50,000 inodes in total.
    let processes: Vec<(u32, Vec<String>)> = (0..200u32)
        .map(|pid| {
            let links = (0..250u64)
                .map(|n| format!("socket:[{}]", 100_000 + u64::from(pid) * 250 + n))
                .collect();
            (1_000 + pid, links)
        })
        .collect();
    let owners = map_inodes(&processes);
    assert_eq!(owners.len(), ROWS);

    let rows = parse_table(&table(ROWS), Protocol::Tcp, false);
    let unattributed = rows
        .iter()
        .filter(|r| !owners.contains_key(&r.inode))
        .count();
    assert_eq!(unattributed, 0);
    // The first 250 sockets belong to pid 1000, and so on.
    assert_eq!(owners[&rows[0].inode], 1_000);
    assert_eq!(owners[&rows[249].inode], 1_000);
    assert_eq!(owners[&rows[250].inode], 1_001);
}
