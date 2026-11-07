// SPDX-License-Identifier: MIT OR Apache-2.0
//! Firewall decision logic: how per-app rules, network profile and the panic button combine.
//!
//! Precedence, highest first:
//! 1. **Panic button** (`block_all`) blocks everything, including explicit allow rules. It is a
//!    fail-closed emergency switch, so no per-app rule can override it.
//! 2. **Most specific app rule**: a rule scoped to the current network profile beats an
//!    unscoped rule for the same app.
//! 3. Among rules of equal specificity, **Block wins** (fail closed).
//! 4. No matching rule: **Allow** (default-allow, as in GlassWire).

use crate::error::{Error, Result};
use crate::traits::{AppRule, RuleAction};

/// Longest app key accepted in a rule. Paths on Linux and Windows are well under this.
pub const MAX_APP_KEY_LEN: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReason {
    PanicButton,
    AppRule(i64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow { rule_id: Option<i64> },
    Block { reason: BlockReason },
}

impl Decision {
    pub fn is_block(&self) -> bool {
        matches!(self, Decision::Block { .. })
    }
}

/// Check a rule before it is stored or applied.
pub fn validate_rule(rule: &AppRule) -> Result<()> {
    if rule.app.trim().is_empty() {
        return Err(Error::InvalidInput("rule app key must not be empty".into()));
    }
    if rule.app.contains(['\n', '\r', '\0']) {
        return Err(Error::InvalidInput(
            "rule app key must not contain control characters".into(),
        ));
    }
    if rule.app.len() > MAX_APP_KEY_LEN {
        return Err(Error::InvalidInput(format!(
            "rule app key must be at most {MAX_APP_KEY_LEN} bytes"
        )));
    }
    if matches!(&rule.profile, Some(p) if p.trim().is_empty()) {
        return Err(Error::InvalidInput(
            "profile scope must be omitted or non-empty".into(),
        ));
    }
    Ok(())
}

/// Decide the fate of traffic from `app` on network `profile` under `rules`.
pub fn decide(rules: &[AppRule], app: &str, profile: Option<&str>, block_all: bool) -> Decision {
    if block_all {
        return Decision::Block {
            reason: BlockReason::PanicButton,
        };
    }

    // Specificity: 2 = scoped to this profile, 1 = unscoped, 0 = scoped to another profile.
    let specificity = |rule: &AppRule| match (&rule.profile, profile) {
        (Some(p), Some(current)) if p == current => 2,
        (None, _) => 1,
        _ => 0,
    };

    let best = rules
        .iter()
        .filter(|r| r.app == app && specificity(r) > 0)
        .max_by(|a, b| {
            specificity(a)
                .cmp(&specificity(b))
                // Equal specificity: Block sorts greater, so max_by picks it.
                .then_with(|| block_rank(a.action).cmp(&block_rank(b.action)))
        });

    match best {
        Some(rule) if rule.action == RuleAction::Block => Decision::Block {
            reason: BlockReason::AppRule(rule.id),
        },
        Some(rule) => Decision::Allow {
            rule_id: Some(rule.id),
        },
        None => Decision::Allow { rule_id: None },
    }
}

fn block_rank(action: RuleAction) -> u8 {
    match action {
        RuleAction::Allow => 0,
        RuleAction::Block => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlong_app_keys_are_refused() {
        let long = "/".to_string() + &"a".repeat(MAX_APP_KEY_LEN);
        assert!(validate_rule(&rule(1, &long, RuleAction::Block, None)).is_err());
        assert!(validate_rule(&rule(1, "/usr/bin/curl", RuleAction::Block, None)).is_ok());
    }

    fn rule(id: i64, app: &str, action: RuleAction, profile: Option<&str>) -> AppRule {
        AppRule {
            id,
            app: app.into(),
            action,
            profile: profile.map(String::from),
        }
    }

    #[test]
    fn default_is_allow() {
        assert_eq!(
            decide(&[], "a.exe", None, false),
            Decision::Allow { rule_id: None }
        );
    }

    #[test]
    fn panic_button_overrides_explicit_allow() {
        let rules = [rule(1, "a.exe", RuleAction::Allow, None)];
        assert_eq!(
            decide(&rules, "a.exe", None, true),
            Decision::Block {
                reason: BlockReason::PanicButton
            }
        );
    }

    #[test]
    fn profile_scoped_rule_beats_unscoped() {
        let rules = [
            rule(1, "a.exe", RuleAction::Block, None),
            rule(2, "a.exe", RuleAction::Allow, Some("home")),
        ];
        assert_eq!(
            decide(&rules, "a.exe", Some("home"), false),
            Decision::Allow { rule_id: Some(2) }
        );
        // On a public network only the unscoped block applies.
        assert_eq!(
            decide(&rules, "a.exe", Some("public"), false),
            Decision::Block {
                reason: BlockReason::AppRule(1)
            }
        );
    }

    #[test]
    fn equal_specificity_fails_closed() {
        let rules = [
            rule(1, "a.exe", RuleAction::Allow, None),
            rule(2, "a.exe", RuleAction::Block, None),
        ];
        assert_eq!(
            decide(&rules, "a.exe", None, false),
            Decision::Block {
                reason: BlockReason::AppRule(2)
            }
        );
    }

    #[test]
    fn other_apps_are_unaffected() {
        let rules = [rule(1, "a.exe", RuleAction::Block, None)];
        assert!(!decide(&rules, "b.exe", None, false).is_block());
    }

    #[test]
    fn validation_rejects_bad_rules() {
        assert!(validate_rule(&rule(1, "  ", RuleAction::Block, None)).is_err());
        assert!(validate_rule(&rule(1, "a\n.exe", RuleAction::Block, None)).is_err());
        assert!(validate_rule(&rule(1, "a.exe", RuleAction::Block, Some(" "))).is_err());
        assert!(validate_rule(&rule(1, "a.exe", RuleAction::Block, Some("home"))).is_ok());
    }
}
