// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pure translation from firewall rules to WFP filter specifications.
//!
//! The Windows enforcement layer uses one sublayer and relies on WFP's rule that the
//! highest-weight matching filter decides. The weights below encode the precedence in
//! `tpt_netguard_core::policy`:
//!
//! 1. panic button (block everything) beats everything;
//! 2. profile-scoped rules beat unscoped rules;
//! 3. within the same scope, Block beats Allow (fail closed).
//!
//! This module has no OS calls, so the ordering is tested on every host.

use tpt_netguard_core::traits::{AppRule, RuleAction};

/// Weight of the panic-button filter: above every app rule.
pub const PANIC_WEIGHT: u64 = 100;
/// Profile-scoped block.
pub const SCOPED_BLOCK_WEIGHT: u64 = 41;
/// Profile-scoped allow.
pub const SCOPED_ALLOW_WEIGHT: u64 = 40;
/// Unscoped block.
pub const UNSCOPED_BLOCK_WEIGHT: u64 = 21;
/// Unscoped allow.
pub const UNSCOPED_ALLOW_WEIGHT: u64 = 20;

/// The ALE connect layers a filter is installed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    ConnectV4,
    ConnectV6,
}

pub const BOTH_LAYERS: [Layer; 2] = [Layer::ConnectV4, Layer::ConnectV6];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterAction {
    Block,
    Permit,
}

/// One WFP filter to install. `app` is `None` for the panic button (matches every process).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterSpec {
    pub layer: Layer,
    pub action: FilterAction,
    pub weight: u64,
    pub app: Option<String>,
}

pub fn rule_weight(rule: &AppRule) -> u64 {
    match (rule.profile.is_some(), rule.action) {
        (true, RuleAction::Block) => SCOPED_BLOCK_WEIGHT,
        (true, RuleAction::Allow) => SCOPED_ALLOW_WEIGHT,
        (false, RuleAction::Block) => UNSCOPED_BLOCK_WEIGHT,
        (false, RuleAction::Allow) => UNSCOPED_ALLOW_WEIGHT,
    }
}

/// Filters that implement one app rule: one per layer.
pub fn plan_rule(rule: &AppRule) -> Vec<FilterSpec> {
    let action = match rule.action {
        RuleAction::Block => FilterAction::Block,
        RuleAction::Allow => FilterAction::Permit,
    };
    BOTH_LAYERS
        .iter()
        .map(|&layer| FilterSpec {
            layer,
            action,
            weight: rule_weight(rule),
            app: Some(rule.app.clone()),
        })
        .collect()
}

/// Filters for the panic button: block all connects on both layers.
pub fn plan_panic() -> Vec<FilterSpec> {
    BOTH_LAYERS
        .iter()
        .map(|&layer| FilterSpec {
            layer,
            action: FilterAction::Block,
            weight: PANIC_WEIGHT,
            app: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(action: RuleAction, profile: Option<&str>) -> AppRule {
        AppRule {
            id: 1,
            app: r"C:\Apps\a.exe".into(),
            action,
            profile: profile.map(String::from),
        }
    }

    #[test]
    fn weights_follow_policy_precedence() {
        let scoped_block = rule_weight(&rule(RuleAction::Block, Some("home")));
        let scoped_allow = rule_weight(&rule(RuleAction::Allow, Some("home")));
        let unscoped_block = rule_weight(&rule(RuleAction::Block, None));
        let unscoped_allow = rule_weight(&rule(RuleAction::Allow, None));
        assert!(PANIC_WEIGHT > scoped_block);
        assert!(scoped_block > scoped_allow);
        // A scoped allow must beat an unscoped block (specificity first).
        assert!(scoped_allow > unscoped_block);
        assert!(unscoped_block > unscoped_allow);
    }

    #[test]
    fn each_rule_is_installed_on_both_layers() {
        let specs = plan_rule(&rule(RuleAction::Block, None));
        assert_eq!(specs.len(), 2);
        assert!(specs.iter().any(|s| s.layer == Layer::ConnectV4));
        assert!(specs.iter().any(|s| s.layer == Layer::ConnectV6));
        assert!(specs.iter().all(|s| s.action == FilterAction::Block));
        assert!(specs
            .iter()
            .all(|s| s.app.as_deref() == Some(r"C:\Apps\a.exe")));
    }

    #[test]
    fn allow_rules_become_permit_filters() {
        let specs = plan_rule(&rule(RuleAction::Allow, Some("home")));
        assert!(specs.iter().all(|s| s.action == FilterAction::Permit));
    }

    #[test]
    fn panic_matches_all_processes_at_top_weight() {
        let specs = plan_panic();
        assert_eq!(specs.len(), 2);
        assert!(specs.iter().all(|s| s.app.is_none()));
        assert!(specs.iter().all(|s| s.weight == PANIC_WEIGHT));
    }
}
