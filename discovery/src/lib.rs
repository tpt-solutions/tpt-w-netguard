// SPDX-License-Identifier: MIT OR Apache-2.0
//! LAN device discovery ("Things").
//!
//! One scan does four things:
//! 1. **Probe**: send a small UDP datagram to every host in the local IPv4 subnet. The kernel
//!    must resolve each address with ARP to send it, so this fills the neighbour table without
//!    needing raw sockets or elevation.
//! 2. **Read**: parse the neighbour table (`/proc/net/arp` on Linux, `arp -a` on Windows).
//! 3. **Name**: for devices seen for the first time, ask for a name over mDNS, then NetBIOS.
//! 4. **Classify**: fold the snapshot into the [`DeviceRegistry`]. New MACs become alerts,
//!    except on the very first scan of an empty registry, which only establishes a baseline.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use tpt_netguard_core::devices::{
    normalize_mac, parse_proc_net_arp, parse_windows_arp, ArpEntry, DeviceRegistry, OuiTable,
};

/// Largest subnet scanned in one pass (a /22 is 1022 hosts). Larger networks are refused.
pub const MAX_HOSTS: u32 = 1022;

/// Resolves a friendly name for an address. Injected so scans are testable offline.
pub trait NameResolver {
    fn resolve(&self, ip: IpAddr) -> Option<String>;
}

/// Name lookup over the LAN: mDNS first, then NetBIOS for IPv4 devices.
pub struct NetworkNameResolver {
    pub timeout: Duration,
}

impl Default for NetworkNameResolver {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(400),
        }
    }
}

impl NameResolver for NetworkNameResolver {
    fn resolve(&self, ip: IpAddr) -> Option<String> {
        if let Ok(Some(name)) = tpt_netguard_dns::mdns::reverse_lookup(ip, self.timeout) {
            return Some(name);
        }
        match ip {
            IpAddr::V4(v4) => tpt_netguard_dns::netbios::node_status(v4, self.timeout)
                .ok()
                .flatten(),
            IpAddr::V6(_) => None,
        }
    }
}

/// Hosts in an IPv4 subnet, excluding the network and broadcast addresses.
pub fn subnet_hosts(base: Ipv4Addr, prefix: u8) -> Result<Vec<Ipv4Addr>, String> {
    if !(22..=30).contains(&prefix) {
        return Err(format!(
            "subnet /{prefix} is outside the scannable range /22-/30"
        ));
    }
    let size: u32 = 1 << (32 - prefix);
    let network = u32::from(base) & !(size - 1);
    Ok((1..size - 1)
        .map(|offset| Ipv4Addr::from(network + offset))
        .collect())
}

/// Send one datagram to each host so the OS resolves its MAC address. Replies are not expected.
pub fn probe(hosts: &[Ipv4Addr]) -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    for host in hosts {
        // Discard port: nothing listens there, and nothing needs to.
        let _ = socket.send_to(&[0u8], SocketAddr::from((*host, 9)));
    }
    Ok(())
}

/// Parse neighbour-table text for the current platform.
pub fn parse_neighbours(text: &str) -> Vec<ArpEntry> {
    if cfg!(windows) {
        parse_windows_arp(text)
    } else {
        parse_proc_net_arp(text)
    }
}

/// Read the platform neighbour table as text.
pub fn read_neighbours() -> Result<String, String> {
    if cfg!(windows) {
        let out = std::process::Command::new("arp")
            .arg("-a")
            .output()
            .map_err(|e| format!("cannot run arp: {e}"))?;
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        std::fs::read_to_string("/proc/net/arp").map_err(|e| format!("cannot read ARP table: {e}"))
    }
}

/// Outcome of one scan.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ScanReport {
    /// Every MAC first seen in this scan.
    pub new_macs: Vec<String>,
    /// The subset of `new_macs` that should raise a "new device" alert. Empty on baseline scans.
    pub alert_macs: Vec<String>,
    /// Devices in the neighbour table this scan.
    pub seen: usize,
}

pub struct LanScanner {
    registry: DeviceRegistry,
    oui: OuiTable,
    /// True when the registry started empty: the next scan only records what is already there.
    baseline: bool,
}

impl LanScanner {
    pub fn new(registry: DeviceRegistry, oui: OuiTable) -> Self {
        let baseline = registry.all().next().is_none();
        Self {
            registry,
            oui,
            baseline,
        }
    }

    pub fn registry(&self) -> &DeviceRegistry {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut DeviceRegistry {
        &mut self.registry
    }

    /// Fold a neighbour snapshot into the registry, naming new devices through `names`.
    pub fn scan_entries(
        &mut self,
        entries: &[ArpEntry],
        now_ms: u64,
        names: &dyn NameResolver,
    ) -> ScanReport {
        let new_macs = self.registry.observe(entries, &self.oui, now_ms);
        for mac in &new_macs {
            let ip = entries.iter().find(|e| &e.mac == mac).map(|e| e.ip);
            if let Some(name) = ip.and_then(|ip| names.resolve(ip)) {
                self.registry.set_label(mac, Some(name));
            }
        }
        let alert_macs = if self.baseline {
            Vec::new()
        } else {
            new_macs.clone()
        };
        self.baseline = false;
        ScanReport {
            new_macs,
            alert_macs,
            seen: entries.len(),
        }
    }

    /// Full scan: probe the subnet, read the neighbour table, then fold it in.
    pub fn scan(
        &mut self,
        local: Ipv4Addr,
        prefix: u8,
        now_ms: u64,
        names: &dyn NameResolver,
    ) -> Result<ScanReport, String> {
        let hosts = subnet_hosts(local, prefix)?;
        probe(&hosts).map_err(|e| format!("probe failed: {e}"))?;
        // Give the kernel a moment to finish ARP resolution before reading the table.
        std::thread::sleep(Duration::from_millis(750));
        let text = read_neighbours()?;
        let entries: Vec<ArpEntry> = parse_neighbours(&text)
            .into_iter()
            .filter(|e| matches!(e.ip, IpAddr::V4(v4) if hosts.contains(&v4)))
            .filter(|e| normalize_mac(&e.mac).is_some())
            .collect();
        Ok(self.scan_entries(&entries, now_ms, names))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct FakeNames(HashMap<IpAddr, String>);

    impl NameResolver for FakeNames {
        fn resolve(&self, ip: IpAddr) -> Option<String> {
            self.0.get(&ip).cloned()
        }
    }

    fn entry(ip: &str, mac: &str) -> ArpEntry {
        ArpEntry {
            ip: ip.parse().unwrap(),
            mac: mac.into(),
        }
    }

    #[test]
    fn subnet_enumeration_excludes_network_and_broadcast() {
        let hosts = subnet_hosts("192.168.1.77".parse().unwrap(), 24).unwrap();
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts[253], Ipv4Addr::new(192, 168, 1, 254));
        assert_eq!(
            subnet_hosts("10.0.0.1".parse().unwrap(), 30).unwrap().len(),
            2
        );
    }

    #[test]
    fn subnet_size_is_bounded() {
        assert!(subnet_hosts("10.0.0.1".parse().unwrap(), 16).is_err());
        assert!(subnet_hosts("10.0.0.1".parse().unwrap(), 31).is_err());
        assert!(subnet_hosts("10.0.0.1".parse().unwrap(), 32).is_err());
    }

    #[test]
    fn first_scan_is_a_silent_baseline() {
        let mut scanner = LanScanner::new(DeviceRegistry::new(), OuiTable::default());
        let names = FakeNames(HashMap::new());
        let entries = [entry("192.168.1.1", "aa:bb:cc:00:00:01")];
        let report = scanner.scan_entries(&entries, 1, &names);
        assert_eq!(report.new_macs.len(), 1);
        assert!(report.alert_macs.is_empty());
    }

    #[test]
    fn later_new_device_raises_alert_and_gets_a_name() {
        let mut scanner = LanScanner::new(DeviceRegistry::new(), OuiTable::default());
        let mut map = HashMap::new();
        map.insert(
            "192.168.1.50".parse().unwrap(),
            "living-room-tv".to_string(),
        );
        let names = FakeNames(map);

        scanner.scan_entries(&[entry("192.168.1.1", "aa:bb:cc:00:00:01")], 1, &names);
        let report = scanner.scan_entries(
            &[
                entry("192.168.1.1", "aa:bb:cc:00:00:01"),
                entry("192.168.1.50", "aa:bb:cc:00:00:02"),
            ],
            2,
            &names,
        );
        assert_eq!(report.alert_macs, vec!["aa:bb:cc:00:00:02".to_string()]);
        let dev = scanner.registry().get("aa:bb:cc:00:00:02").unwrap();
        assert_eq!(dev.display_label(), "living-room-tv");
    }

    #[test]
    fn known_devices_do_not_alert_again() {
        let mut scanner = LanScanner::new(DeviceRegistry::new(), OuiTable::default());
        let names = FakeNames(HashMap::new());
        let e = [entry("192.168.1.1", "aa:bb:cc:00:00:01")];
        scanner.scan_entries(&e, 1, &names);
        scanner.scan_entries(&e, 2, &names);
        let report = scanner.scan_entries(&e, 3, &names);
        assert!(report.new_macs.is_empty());
        assert!(report.alert_macs.is_empty());
    }
}
