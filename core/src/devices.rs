// SPDX-License-Identifier: MIT OR Apache-2.0
//! LAN device discovery ("Things"): ARP parsing, MAC/OUI handling, and new-vs-known tracking.
//!
//! Only parsing and classification live here. Platform code runs the actual ARP read
//! (`/proc/net/arp` on Linux, `GetIpNetTable` or `arp -a` on Windows) and feeds the text in.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

/// One neighbour-table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpEntry {
    pub ip: IpAddr,
    /// Normalised lowercase `aa:bb:cc:dd:ee:ff`.
    pub mac: String,
}

/// Normalise a MAC written with `:` or `-` separators. Rejects anything else, including
/// all-zero addresses that ARP uses for incomplete entries.
pub fn normalize_mac(raw: &str) -> Option<String> {
    let parts: Vec<&str> = raw.split([':', '-']).collect();
    if parts.len() != 6 || parts.iter().any(|p| p.len() != 2) {
        return None;
    }
    if !parts
        .iter()
        .all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return None;
    }
    let mac = parts
        .iter()
        .map(|p| p.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(":");
    if mac == "00:00:00:00:00:00" {
        return None;
    }
    Some(mac)
}

/// Parse `/proc/net/arp`. Entries without the "complete" flag (0x2) are skipped.
pub fn parse_proc_net_arp(text: &str) -> Vec<ArpEntry> {
    text.lines()
        .skip(1) // header
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 {
                return None;
            }
            let ip: IpAddr = cols[0].parse().ok()?;
            let flags = u32::from_str_radix(cols[2].trim_start_matches("0x"), 16).ok()?;
            if flags & 0x2 == 0 {
                return None;
            }
            let mac = normalize_mac(cols[3])?;
            Some(ArpEntry { ip, mac })
        })
        .collect()
}

/// Parse `arp -a` output (Windows). Interface headers and malformed lines are skipped.
pub fn parse_windows_arp(text: &str) -> Vec<ArpEntry> {
    text.lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 3 {
                return None;
            }
            let ip: IpAddr = cols[0].parse().ok()?;
            let mac = normalize_mac(cols[1])?;
            // Only dynamic/static entries are real neighbours; "invalid" is not.
            if !matches!(cols[2], "dynamic" | "static") {
                return None;
            }
            Some(ArpEntry { ip, mac })
        })
        .collect()
}

/// IEEE OUI (vendor prefix) table.
#[derive(Debug, Default, Clone)]
pub struct OuiTable {
    vendors: HashMap<[u8; 3], String>,
}

impl OuiTable {
    /// Parse the IEEE `oui.txt` format, e.g. `00-00-0C   (hex)\t\tCisco Systems, Inc`.
    /// Other lines are ignored, so the full file can be passed in unchanged.
    pub fn parse_ieee(text: &str) -> Self {
        let mut vendors = HashMap::new();
        for line in text.lines() {
            let Some((prefix, rest)) = line.split_once("(hex)") else {
                continue;
            };
            let hex: String = prefix.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if hex.len() != 6 {
                continue;
            }
            let bytes = [
                u8::from_str_radix(&hex[0..2], 16).unwrap_or(0),
                u8::from_str_radix(&hex[2..4], 16).unwrap_or(0),
                u8::from_str_radix(&hex[4..6], 16).unwrap_or(0),
            ];
            let vendor = rest.trim().to_string();
            if !vendor.is_empty() {
                vendors.insert(bytes, vendor);
            }
        }
        Self { vendors }
    }

    /// Vendor for a normalised MAC, if its prefix is registered.
    pub fn lookup(&self, mac: &str) -> Option<&str> {
        let prefix = mac.get(0..8)?;
        let mut bytes = [0u8; 3];
        for (i, chunk) in prefix.split(':').enumerate().take(3) {
            bytes[i] = u8::from_str_radix(chunk, 16).ok()?;
        }
        self.vendors.get(&bytes).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.vendors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vendors.is_empty()
    }
}

/// A device seen on the LAN.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Device {
    pub mac: String,
    pub ip: Option<IpAddr>,
    pub vendor: Option<String>,
    /// User-assigned name ("rename device"), falling back to vendor when unset.
    pub label: Option<String>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    /// Trusted devices never raise new-device alerts again.
    pub trusted: bool,
}

impl Device {
    pub fn display_label(&self) -> &str {
        self.label
            .as_deref()
            .or(self.vendor.as_deref())
            .unwrap_or(&self.mac)
    }
}

/// Tracks known devices and reports which ones are new.
#[derive(Debug, Default)]
pub struct DeviceRegistry {
    devices: BTreeMap<String, Device>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load previously stored devices. They count as known.
    pub fn from_devices(devices: impl IntoIterator<Item = Device>) -> Self {
        Self {
            devices: devices.into_iter().map(|d| (d.mac.clone(), d)).collect(),
        }
    }

    /// Fold one ARP snapshot into the registry. Returns MACs seen for the first time.
    pub fn observe(&mut self, entries: &[ArpEntry], oui: &OuiTable, now_ms: u64) -> Vec<String> {
        let mut new = Vec::new();
        for entry in entries {
            match self.devices.get_mut(&entry.mac) {
                Some(dev) => {
                    dev.last_seen_ms = now_ms;
                    dev.ip = Some(entry.ip);
                }
                None => {
                    self.devices.insert(
                        entry.mac.clone(),
                        Device {
                            mac: entry.mac.clone(),
                            ip: Some(entry.ip),
                            vendor: oui.lookup(&entry.mac).map(String::from),
                            label: None,
                            first_seen_ms: now_ms,
                            last_seen_ms: now_ms,
                            trusted: false,
                        },
                    );
                    new.push(entry.mac.clone());
                }
            }
        }
        new
    }

    /// Mark a device as trusted (or not). Returns false if the MAC is unknown.
    pub fn set_trusted(&mut self, mac: &str, trusted: bool) -> bool {
        self.devices
            .get_mut(mac)
            .map(|d| d.trusted = trusted)
            .is_some()
    }

    /// Rename a device. Returns false if the MAC is unknown.
    pub fn set_label(&mut self, mac: &str, label: Option<String>) -> bool {
        self.devices.get_mut(mac).map(|d| d.label = label).is_some()
    }

    pub fn get(&self, mac: &str) -> Option<&Device> {
        self.devices.get(mac)
    }

    pub fn all(&self) -> impl Iterator<Item = &Device> {
        self.devices.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUI_FIXTURE: &str = "OUI/MA-L\tCompany\n\n\
        00-00-0C   (hex)\t\tCisco Systems, Inc\n\
        00000C     (base 16)\t\tCisco Systems, Inc\n\
        B8-27-EB   (hex)\t\tRaspberry Pi Foundation\n";

    const PROC_ARP: &str =
        "IP address       HW type     Flags       HW address            Mask     Device\n\
        192.168.1.1      0x1         0x2         00:00:0c:12:34:56     *        eth0\n\
        192.168.1.20     0x1         0x0         00:00:00:00:00:00     *        eth0\n\
        192.168.1.30     0x1         0x2         b8:27:eb:aa:bb:cc     *        eth0\n";

    const WIN_ARP: &str = "\nInterface: 192.168.1.5 --- 0x12\n  Internet Address      Physical Address      Type\n  192.168.1.1           00-00-0c-12-34-56     dynamic\n  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n  192.168.1.9           00-00-00-00-00-00     invalid\n";

    #[test]
    fn normalizes_macs() {
        assert_eq!(
            normalize_mac("AA-BB-CC-DD-EE-FF").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(normalize_mac("aa:bb:cc:dd:ee"), None);
        assert_eq!(normalize_mac("zz:bb:cc:dd:ee:ff"), None);
        assert_eq!(normalize_mac("00:00:00:00:00:00"), None);
    }

    #[test]
    fn parses_proc_net_arp_skipping_incomplete() {
        let entries = parse_proc_net_arp(PROC_ARP);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].mac, "00:00:0c:12:34:56");
        assert_eq!(entries[1].ip.to_string(), "192.168.1.30");
    }

    #[test]
    fn parses_windows_arp_output() {
        let entries = parse_windows_arp(WIN_ARP);
        // Only the dynamic line: broadcast is "static" but a real neighbour is not required,
        // so it is kept too; the "invalid" zero-MAC line is dropped.
        let macs: Vec<&str> = entries.iter().map(|e| e.mac.as_str()).collect();
        assert_eq!(macs, vec!["00:00:0c:12:34:56", "ff:ff:ff:ff:ff:ff"]);
    }

    #[test]
    fn oui_lookup_uses_three_byte_prefix() {
        let oui = OuiTable::parse_ieee(OUI_FIXTURE);
        assert_eq!(oui.len(), 2);
        assert_eq!(oui.lookup("00:00:0c:12:34:56"), Some("Cisco Systems, Inc"));
        assert_eq!(
            oui.lookup("b8:27:eb:00:00:01"),
            Some("Raspberry Pi Foundation")
        );
        assert_eq!(oui.lookup("de:ad:be:ef:00:00"), None);
    }

    #[test]
    fn registry_reports_only_new_devices() {
        let oui = OuiTable::parse_ieee(OUI_FIXTURE);
        let mut reg = DeviceRegistry::new();
        let snap = parse_proc_net_arp(PROC_ARP);

        let first = reg.observe(&snap, &oui, 100);
        assert_eq!(first.len(), 2);
        assert_eq!(
            reg.get(&first[0]).unwrap().vendor.as_deref(),
            Some("Cisco Systems, Inc")
        );

        let second = reg.observe(&snap, &oui, 200);
        assert!(second.is_empty());
        assert_eq!(reg.get("00:00:0c:12:34:56").unwrap().last_seen_ms, 200);
        assert_eq!(reg.get("00:00:0c:12:34:56").unwrap().first_seen_ms, 100);
    }

    #[test]
    fn stored_devices_are_known_and_labels_override_vendor() {
        let oui = OuiTable::parse_ieee(OUI_FIXTURE);
        let stored = Device {
            mac: "00:00:0c:12:34:56".into(),
            ip: None,
            vendor: Some("Cisco Systems, Inc".into()),
            label: None,
            first_seen_ms: 1,
            last_seen_ms: 1,
            trusted: true,
        };
        let mut reg = DeviceRegistry::from_devices([stored]);
        assert!(reg.observe(&parse_proc_net_arp(PROC_ARP), &oui, 5).len() == 1);
        assert!(reg.set_label("00:00:0c:12:34:56", Some("Router".into())));
        assert_eq!(
            reg.get("00:00:0c:12:34:56").unwrap().display_label(),
            "Router"
        );
        assert!(!reg.set_trusted("ff:ff:ff:ff:ff:ff", true));
    }
}
