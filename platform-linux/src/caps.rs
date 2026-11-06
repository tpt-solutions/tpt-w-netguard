// SPDX-License-Identifier: MIT OR Apache-2.0
//! Capability checks. The Linux backend needs `CAP_NET_ADMIN` for nftables and `CAP_BPF`
//! (plus `CAP_PERFMON` on some kernels) for eBPF. Root has both; a packaged install can grant
//! them with `setcap` or a systemd unit's `AmbientCapabilities=` instead.

/// Bit numbers from `include/uapi/linux/capability.h`.
pub const CAP_NET_ADMIN: u32 = 12;
pub const CAP_NET_RAW: u32 = 13;
pub const CAP_PERFMON: u32 = 38;
pub const CAP_BPF: u32 = 39;

/// Parse the effective capability mask from the text of `/proc/self/status`.
pub fn effective_caps(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
}

pub fn has_cap(mask: u64, bit: u32) -> bool {
    bit < 64 && mask & (1u64 << bit) != 0
}

/// Which parts of the Linux backend the current process can use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub nftables: bool,
    pub ebpf: bool,
    pub raw_capture: bool,
}

pub fn assess(mask: u64) -> Capabilities {
    Capabilities {
        nftables: has_cap(mask, CAP_NET_ADMIN),
        ebpf: has_cap(mask, CAP_BPF) && has_cap(mask, CAP_NET_ADMIN),
        raw_capture: has_cap(mask, CAP_NET_RAW),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str = "Name:\tapp\nCapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\n";

    #[test]
    fn parses_effective_mask() {
        assert_eq!(effective_caps(STATUS), Some(0x0000_01ff_ffff_ffff));
        assert_eq!(effective_caps("Name:\tapp\n"), None);
    }

    #[test]
    fn root_has_everything() {
        let caps = assess(effective_caps(STATUS).unwrap());
        assert!(caps.nftables && caps.ebpf && caps.raw_capture);
    }

    #[test]
    fn unprivileged_has_nothing() {
        let caps = assess(0);
        assert!(!caps.nftables && !caps.ebpf && !caps.raw_capture);
    }

    #[test]
    fn ebpf_needs_both_bpf_and_net_admin() {
        assert!(!assess(1u64 << CAP_BPF).ebpf);
        assert!(assess((1u64 << CAP_BPF) | (1u64 << CAP_NET_ADMIN)).ebpf);
    }
}
