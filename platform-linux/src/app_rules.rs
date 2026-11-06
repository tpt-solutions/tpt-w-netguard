// SPDX-License-Identifier: MIT OR Apache-2.0
//! Turns the active per-app rules into the set of executables that must be blocked.
//!
//! The manager hands backends only the rules that apply to the current network profile, so the
//! decision here is simpler than `policy::decide`: rules scoped to a profile win over unscoped
//! ones, and a block wins a tie. That matches `policy::decide` for the active profile.

use std::collections::{BTreeMap, BTreeSet};

use tpt_netguard_core::traits::{AppRule, RuleAction};

/// Whether traffic from `rules` (all for one app, all active) must be blocked.
fn blocked_by(rules: &[&AppRule]) -> bool {
    let scoped = rules.iter().any(|r| r.profile.is_some());
    rules
        .iter()
        .filter(|r| r.profile.is_some() == scoped)
        .any(|r| r.action == RuleAction::Block)
}

/// Executables (the rule's `app` key) whose traffic is blocked under `rules`.
pub fn blocked_apps(rules: &[AppRule]) -> BTreeSet<String> {
    let mut by_app: BTreeMap<&str, Vec<&AppRule>> = BTreeMap::new();
    for rule in rules {
        by_app.entry(rule.app.as_str()).or_default().push(rule);
    }
    by_app
        .into_iter()
        .filter(|(_, rules)| blocked_by(rules))
        .map(|(app, _)| app.to_string())
        .collect()
}

/// Whether `app` is an absolute executable path, the only form the kernel side can match.
pub fn is_exec_path(app: &str) -> bool {
    app.starts_with('/') && !app.contains('\0')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: i64, app: &str, action: RuleAction, profile: Option<&str>) -> AppRule {
        AppRule {
            id,
            app: app.into(),
            action,
            profile: profile.map(String::from),
        }
    }

    #[test]
    fn a_block_rule_blocks_its_app_only() {
        let rules = [
            rule(1, "/usr/bin/curl", RuleAction::Block, None),
            rule(2, "/usr/bin/wget", RuleAction::Allow, None),
        ];
        let blocked = blocked_apps(&rules);
        assert!(blocked.contains("/usr/bin/curl"));
        assert!(!blocked.contains("/usr/bin/wget"));
    }

    #[test]
    fn a_scoped_allow_overrides_an_unscoped_block() {
        let rules = [
            rule(1, "/usr/bin/curl", RuleAction::Block, None),
            rule(2, "/usr/bin/curl", RuleAction::Allow, Some("home")),
        ];
        assert!(blocked_apps(&rules).is_empty());
    }

    #[test]
    fn a_scoped_block_is_enforced() {
        let rules = [rule(1, "/usr/bin/curl", RuleAction::Block, Some("public"))];
        assert!(blocked_apps(&rules).contains("/usr/bin/curl"));
    }

    #[test]
    fn same_specificity_block_wins() {
        let rules = [
            rule(1, "/usr/bin/curl", RuleAction::Allow, None),
            rule(2, "/usr/bin/curl", RuleAction::Block, None),
        ];
        assert!(blocked_apps(&rules).contains("/usr/bin/curl"));
    }

    #[test]
    fn only_absolute_paths_can_be_enforced() {
        assert!(is_exec_path("/usr/bin/curl"));
        assert!(!is_exec_path("curl"));
        assert!(!is_exec_path("/usr/bin/cu\0rl"));
    }
}
