// SPDX-License-Identifier: MIT OR Apache-2.0
//! Linux backend for tpt-netguard (Phase 4).
//!
//! What is implemented:
//! * [`proc_net`]: socket-table parsing and inode-to-PID attribution (tested on every host).
//! * [`caps`]: detection of the capabilities the enforcement path needs (tested on every host).
//! * [`nft`]: the panic-button nftables ruleset and the runner that applies it.
//! * [`LinuxMonitor`] (Linux only): connection enumeration from `/proc`.
//! * [`NftFirewall`]: `FirewallBackend` that enforces the panic button through nftables.
//!
//! * [`ebpf`] and [`firewall::LinuxFirewall`]: per-app allow/block through eBPF `cgroup/sock_addr`
//!   and tracepoint programs (see `ebpf/` and `docs/linux-ebpf.md`). The panic button stays on
//!   nftables, which overrides per-app rules.
//!
//! What is still not implemented:
//! * Per-connection byte counters. `/proc` has no byte totals; they still need packet capture
//!   or an eBPF accounting program.

pub mod app_rules;
pub mod caps;
pub mod ebpf_abi;
pub mod nft;
pub mod proc_net;

#[cfg(target_os = "linux")]
pub mod ebpf;
#[cfg(target_os = "linux")]
pub mod firewall;
#[cfg(target_os = "linux")]
pub mod monitor;

#[cfg(target_os = "linux")]
pub use firewall::LinuxFirewall;
#[cfg(target_os = "linux")]
pub use monitor::LinuxMonitor;

use std::collections::BTreeMap;

use tpt_netguard_core::error::{Error, Result};
use tpt_netguard_core::traits::{AppRule, FirewallBackend};

use crate::nft::{CommandRunner, SystemRunner};

/// Name of the nftables binary.
pub const NFT_BIN: &str = "nft";

/// Enforces the global panic button through nftables. Per-app rules are rejected until eBPF
/// enforcement exists, so callers cannot believe an app is blocked when it is not.
pub struct NftFirewall {
    runner: Box<dyn CommandRunner>,
    block_all: bool,
    rules: BTreeMap<i64, AppRule>,
}

impl NftFirewall {
    pub fn new() -> Self {
        Self::with_runner(Box::new(SystemRunner))
    }

    pub fn with_runner(runner: Box<dyn CommandRunner>) -> Self {
        Self {
            runner,
            block_all: false,
            rules: BTreeMap::new(),
        }
    }

    fn apply_script(&mut self, script: &str) -> Result<()> {
        self.runner.run(NFT_BIN, &["-f", "-"], script)
    }
}

impl Default for NftFirewall {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallBackend for NftFirewall {
    fn list_rules(&self) -> Result<Vec<AppRule>> {
        Ok(self.rules.values().cloned().collect())
    }

    fn apply_rule(&mut self, _rule: &AppRule) -> Result<()> {
        Err(Error::Unsupported(
            "per-app rules need eBPF cgroup enforcement (not implemented yet)",
        ))
    }

    fn remove_rule(&mut self, id: i64) -> Result<()> {
        if self.rules.remove(&id).is_some() {
            Ok(())
        } else {
            Err(Error::InvalidInput(format!("no rule with id {id}")))
        }
    }

    fn set_block_all(&mut self, enabled: bool) -> Result<()> {
        let script = nft::render(enabled);
        self.apply_script(&script)?;
        self.block_all = enabled;
        Ok(())
    }

    fn block_all_enabled(&self) -> Result<bool> {
        Ok(self.block_all)
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tpt_netguard_core::traits::RuleAction;

    /// Records every command instead of running it.
    struct Recorder(Arc<Mutex<Vec<(String, String)>>>);

    impl CommandRunner for Recorder {
        fn run(&mut self, program: &str, args: &[&str], stdin: &str) -> Result<()> {
            self.0
                .lock()
                .unwrap()
                .push((format!("{program} {}", args.join(" ")), stdin.to_string()));
            Ok(())
        }
    }

    #[test]
    fn panic_button_sends_ruleset_to_nft() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut fw = NftFirewall::with_runner(Box::new(Recorder(Arc::clone(&log))));
        fw.set_block_all(true).unwrap();
        assert!(fw.block_all_enabled().unwrap());
        let calls = log.lock().unwrap();
        assert_eq!(calls[0].0, "nft -f -");
        assert!(calls[0].1.contains("drop"));
    }

    #[test]
    fn per_app_rules_are_reported_unsupported_not_silently_ignored() {
        let mut fw = NftFirewall::with_runner(Box::new(Recorder(Default::default())));
        let rule = AppRule {
            id: 1,
            app: "/usr/bin/curl".into(),
            action: RuleAction::Block,
            profile: None,
        };
        assert!(matches!(fw.apply_rule(&rule), Err(Error::Unsupported(_))));
        assert!(fw.list_rules().unwrap().is_empty());
    }
}
