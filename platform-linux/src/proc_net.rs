// SPDX-License-Identifier: MIT OR Apache-2.0
//! Parsers for the kernel's socket tables. Pure text processing, so it is tested on every host.
//!
//! * `/proc/net/{tcp,tcp6,udp,udp6}`: one socket per line, addresses as host-order hex words.
//! * `/proc/[pid]/fd/*`: symlinks of the form `socket:[<inode>]` tie a socket inode to a PID.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use tpt_netguard_core::model::Protocol;

/// One row from a `/proc/net` socket table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketRow {
    pub protocol: Protocol,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    /// Kernel TCP state number (1 = ESTABLISHED, 10 = LISTEN); UDP sockets report 7.
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
}

/// Parse one table. `v6` selects the 128-bit address format.
pub fn parse_table(text: &str, protocol: Protocol, v6: bool) -> Vec<SocketRow> {
    text.lines()
        .skip(1)
        .filter_map(|line| parse_line(line, protocol, v6))
        .collect()
}

fn parse_line(line: &str, protocol: Protocol, v6: bool) -> Option<SocketRow> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 10 {
        return None;
    }
    let local = parse_endpoint(cols[1], v6)?;
    let remote = parse_endpoint(cols[2], v6)?;
    let state = u8::from_str_radix(cols[3], 16).ok()?;
    let uid: u32 = cols[7].parse().ok()?;
    let inode: u64 = cols[9].parse().ok()?;
    Some(SocketRow {
        protocol,
        local,
        remote,
        state,
        uid,
        inode,
    })
}

/// Parse `HEXADDR:HEXPORT`.
pub fn parse_endpoint(raw: &str, v6: bool) -> Option<SocketAddr> {
    let (addr_hex, port_hex) = raw.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = if v6 {
        if addr_hex.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for word in 0..4 {
            let w = u32::from_str_radix(&addr_hex[word * 8..word * 8 + 8], 16).ok()?;
            // Each 32-bit word is printed in host order; on little-endian hosts that is
            // least-significant byte first.
            bytes[word * 4..word * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        std::net::IpAddr::V6(Ipv6Addr::from(bytes))
    } else {
        if addr_hex.len() != 8 {
            return None;
        }
        let w = u32::from_str_radix(addr_hex, 16).ok()?;
        std::net::IpAddr::V4(Ipv4Addr::from(w.to_le_bytes()))
    };
    Some(SocketAddr::new(ip, port))
}

/// Extract the inode from a `socket:[N]` fd link. Other fd kinds return `None`.
pub fn parse_socket_link(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Build inode → PID from `(pid, fd link targets)` pairs.
pub fn map_inodes(processes: &[(u32, Vec<String>)]) -> HashMap<u64, u32> {
    let mut map = HashMap::new();
    for (pid, links) in processes {
        for link in links {
            if let Some(inode) = parse_socket_link(link) {
                map.entry(inode).or_insert(*pid);
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP_SAMPLE: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0CEA 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0000000000000000 100 0 0 10 0
   2: 0100007F:0050 0A00000A:BB01 01 00000000:00000000 00:00000000 00000000     0        0 33333 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn decodes_ipv4_endpoints_and_states() {
        let rows = parse_table(TCP_SAMPLE, Protocol::Tcp, false);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].local, "127.0.0.1:3306".parse().unwrap());
        assert_eq!(rows[0].state, 0x0A); // LISTEN
        assert_eq!(rows[1].remote, "127.0.0.1:54321".parse().unwrap());
        assert_eq!(rows[1].state, 0x01); // ESTABLISHED
        assert_eq!(rows[2].remote, "10.0.0.10:47873".parse().unwrap());
        assert_eq!(rows[2].uid, 0);
        assert_eq!(rows[1].inode, 22222);
    }

    #[test]
    fn decodes_ipv6_endpoints() {
        // ::1 is printed as four host-order words; loopback is the last word = 1.
        let raw = "00000000000000000000000001000000:1F90";
        let addr = parse_endpoint(raw, true).unwrap();
        assert_eq!(addr, "[::1]:8080".parse().unwrap());
    }

    #[test]
    fn rejects_malformed_rows() {
        assert!(parse_table("header\n garbage line\n", Protocol::Tcp, false).is_empty());
        assert!(parse_endpoint("01:0050", false).is_none());
        assert!(parse_endpoint("0100007F", false).is_none());
    }

    #[test]
    fn socket_links_map_to_inodes_and_pids() {
        assert_eq!(parse_socket_link("socket:[22222]"), Some(22222));
        assert_eq!(parse_socket_link("pipe:[99]"), None);
        assert_eq!(parse_socket_link("socket:[abc]"), None);
        let map = map_inodes(&[
            (100, vec!["socket:[22222]".into(), "/dev/null".into()]),
            (200, vec!["socket:[22222]".into()]),
        ]);
        // First owner wins; a shared inode (inherited fd) is attributed once.
        assert_eq!(map.get(&22222), Some(&100));
    }
}
