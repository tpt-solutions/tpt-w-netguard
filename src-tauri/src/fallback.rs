// SPDX-License-Identifier: MIT OR Apache-2.0
//! Monitor-only firewall backend, used when enforcement cannot start (not elevated, missing
//! capabilities, unsupported platform). Every change is refused with the reason, so the UI can
//! say exactly why a block did not take effect instead of pretending it did.

use tpt_netguard_core::error::{Error, Result};
use tpt_netguard_core::traits::{AppRule, FirewallBackend};

pub struct Unenforced {
    pub reason: String,
}

impl Unenforced {
    fn refuse<T>(&self) -> Result<T> {
        Err(Error::Backend(format!(
            "firewall enforcement unavailable: {}",
            self.reason
        )))
    }
}

impl FirewallBackend for Unenforced {
    fn list_rules(&self) -> Result<Vec<AppRule>> {
        Ok(Vec::new())
    }

    fn apply_rule(&mut self, _rule: &AppRule) -> Result<()> {
        self.refuse()
    }

    fn remove_rule(&mut self, _id: i64) -> Result<()> {
        self.refuse()
    }

    fn set_block_all(&mut self, _enabled: bool) -> Result<()> {
        self.refuse()
    }

    fn block_all_enabled(&self) -> Result<bool> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpt_netguard_core::traits::RuleAction;

    #[test]
    fn refuses_changes_and_says_why() {
        let mut fw = Unenforced {
            reason: "not elevated".into(),
        };
        let rule = AppRule {
            id: 1,
            app: "a.exe".into(),
            action: RuleAction::Block,
            profile: None,
        };
        let err = fw.apply_rule(&rule).unwrap_err().to_string();
        assert!(err.contains("not elevated"));
        assert!(fw.set_block_all(true).is_err());
        assert!(!fw.block_all_enabled().unwrap());
    }
}
