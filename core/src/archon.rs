// SPDX-License-Identifier: MIT OR Apache-2.0
//! Archon backend stubs (Phase 12, design only). Compiled only with the `archon` feature.
//!
//! No upstream network capability exists yet (see `docs/archon-design.md`). Until it does,
//! every method reports `Error::Unsupported`, and `is_available()` is `false`, so the UI can
//! hide Archon-specific controls and the app runs unchanged.

use crate::error::{Error, Result};
use crate::model::{ByteSample, Connection};
use crate::traits::{AppRule, FirewallBackend, NewConnectionHandler, TrafficMonitor};

const REASON: &str = "Archon network capability (not available upstream yet)";

/// Whether any Archon network primitive is usable. Always `false` for now.
pub const fn is_available() -> bool {
    false
}

#[derive(Debug, Default)]
pub struct ArchonTrafficMonitor;

impl TrafficMonitor for ArchonTrafficMonitor {
    fn enumerate_connections(&mut self) -> Result<Vec<Connection>> {
        Err(Error::Unsupported(REASON))
    }

    fn sample_byte_deltas(&mut self, _now_ms: u64) -> Result<Vec<ByteSample>> {
        Err(Error::Unsupported(REASON))
    }

    fn subscribe_new_connections(&mut self, _handler: NewConnectionHandler) -> Result<()> {
        Err(Error::Unsupported(REASON))
    }
}

#[derive(Debug, Default)]
pub struct ArchonFirewallBackend;

impl FirewallBackend for ArchonFirewallBackend {
    fn list_rules(&self) -> Result<Vec<AppRule>> {
        Err(Error::Unsupported(REASON))
    }

    fn apply_rule(&mut self, _rule: &AppRule) -> Result<()> {
        Err(Error::Unsupported(REASON))
    }

    fn remove_rule(&mut self, _id: i64) -> Result<()> {
        Err(Error::Unsupported(REASON))
    }

    fn set_block_all(&mut self, _enabled: bool) -> Result<()> {
        Err(Error::Unsupported(REASON))
    }

    fn block_all_enabled(&self) -> Result<bool> {
        Err(Error::Unsupported(REASON))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archon_is_unavailable_and_every_call_is_unsupported() {
        assert!(!is_available());
        let mut m = ArchonTrafficMonitor;
        assert!(matches!(
            m.enumerate_connections(),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            m.subscribe_new_connections(Box::new(|_| {})),
            Err(Error::Unsupported(_))
        ));
        let mut fw = ArchonFirewallBackend;
        assert!(matches!(fw.set_block_all(true), Err(Error::Unsupported(_))));
        assert!(matches!(fw.block_all_enabled(), Err(Error::Unsupported(_))));
    }
}
