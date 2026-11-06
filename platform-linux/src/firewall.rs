// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Linux firewall backend the app uses: nftables for the panic button, eBPF for per-app
//! rules. When eBPF cannot load, the panic button still works and per-app rules fail with the
//! reason, so the UI never shows an app as blocked when it is not.

use tpt_netguard_core::error::{Error, Result};
use tpt_netguard_core::traits::{AppRule, FirewallBackend};

use crate::ebpf::EbpfEnforcer;
use crate::NftFirewall;

pub struct LinuxFirewall {
    nft: NftFirewall,
    ebpf: Option<EbpfEnforcer>,
    /// Why per-app rules are unavailable, when they are.
    ebpf_unavailable: Option<String>,
}

impl LinuxFirewall {
    /// Opens both mechanisms. Never fails: eBPF problems are recorded and reported instead.
    pub fn open() -> Self {
        let (ebpf, ebpf_unavailable) = match EbpfEnforcer::open() {
            Ok(enforcer) => (Some(enforcer), None),
            Err(e) => (None, Some(e.to_string())),
        };
        Self {
            nft: NftFirewall::new(),
            ebpf,
            ebpf_unavailable,
        }
    }

    /// Human-readable description of what is enforced, for the Settings screen.
    pub fn mechanism(&self) -> String {
        match &self.ebpf_unavailable {
            None => "nftables (panic button) and eBPF (per-app rules)".into(),
            Some(reason) => {
                format!("nftables (panic button only; per-app rules unavailable: {reason})")
            }
        }
    }

    /// The reason per-app rules are unavailable, or `None` when they are enforced.
    pub fn ebpf_unavailable(&self) -> Option<&str> {
        self.ebpf_unavailable.as_deref()
    }
}

impl FirewallBackend for LinuxFirewall {
    fn list_rules(&self) -> Result<Vec<AppRule>> {
        Ok(self
            .ebpf
            .as_ref()
            .map(EbpfEnforcer::list_rules)
            .unwrap_or_default())
    }

    fn apply_rule(&mut self, rule: &AppRule) -> Result<()> {
        match (&mut self.ebpf, &self.ebpf_unavailable) {
            (Some(enforcer), _) => enforcer.apply_rule(rule),
            (None, Some(reason)) => Err(Error::Backend(format!(
                "per-app rules unavailable: {reason}"
            ))),
            (None, None) => Err(Error::Unsupported("per-app rules")),
        }
    }

    fn remove_rule(&mut self, id: i64) -> Result<()> {
        match &mut self.ebpf {
            Some(enforcer) => enforcer.remove_rule(id),
            None => Err(Error::InvalidInput(format!("no rule with id {id}"))),
        }
    }

    fn set_block_all(&mut self, enabled: bool) -> Result<()> {
        self.nft.set_block_all(enabled)
    }

    fn block_all_enabled(&self) -> Result<bool> {
        self.nft.block_all_enabled()
    }
}
