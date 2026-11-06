// SPDX-License-Identifier: MIT OR Apache-2.0
//! Firewall state manager: owns the desired rule set and panic-button state, and reconciles
//! them onto a [`FirewallBackend`].
//!
//! The manager keeps the full rule table (including rules scoped to other network profiles).
//! Only rules that apply to the current profile are pushed to the backend; everything else
//! is removed from the enforcement layer. Backends therefore never need to know about
//! profiles, but they must honour specificity when two rules match the same app: a
//! profile-scoped rule must outrank an unscoped one (see [`crate::policy`]).

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::policy::{decide, validate_rule, Decision};
use crate::traits::{AppRule, FirewallBackend};

/// What a reconcile pass changed on the backend.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReconcileReport {
    pub applied: usize,
    pub removed: usize,
    pub block_all_changed: bool,
}

pub struct FirewallManager<B: FirewallBackend> {
    backend: B,
    rules: BTreeMap<i64, AppRule>,
    block_all: bool,
    profile: Option<String>,
}

impl<B: FirewallBackend> FirewallManager<B> {
    /// Build a manager and push the initial state to the backend.
    pub fn new(
        backend: B,
        rules: impl IntoIterator<Item = AppRule>,
        block_all: bool,
        profile: Option<String>,
    ) -> Result<Self> {
        let mut manager = Self {
            backend,
            rules: BTreeMap::new(),
            block_all,
            profile,
        };
        for rule in rules {
            validate_rule(&rule)?;
            manager.rules.insert(rule.id, rule);
        }
        manager.reconcile()?;
        Ok(manager)
    }

    /// Insert or replace a rule and push the change to the backend.
    ///
    /// If the backend refuses the change, the manager's state is restored to what it was
    /// before the call, so a rejected rule is never retried silently.
    pub fn upsert_rule(&mut self, rule: AppRule) -> Result<ReconcileReport> {
        validate_rule(&rule)?;
        let previous = self.rules.insert(rule.id, rule.clone());
        self.reconcile_or_restore(|m| match previous {
            Some(prev) => {
                m.rules.insert(prev.id, prev);
            }
            None => {
                m.rules.remove(&rule.id);
            }
        })
    }

    /// Delete a rule. Returns `Ok(false)` when no rule has that id.
    pub fn remove_rule(&mut self, id: i64) -> Result<bool> {
        let Some(removed) = self.rules.remove(&id) else {
            return Ok(false);
        };
        self.reconcile_or_restore(|m| {
            m.rules.insert(removed.id, removed);
        })?;
        Ok(true)
    }

    /// Toggle the panic button.
    pub fn set_block_all(&mut self, enabled: bool) -> Result<ReconcileReport> {
        let previous = self.block_all;
        self.block_all = enabled;
        self.reconcile_or_restore(|m| m.block_all = previous)
    }

    /// Switch the active network profile (`None` = unknown network).
    pub fn set_profile(&mut self, profile: Option<String>) -> Result<ReconcileReport> {
        if matches!(&profile, Some(p) if p.trim().is_empty()) {
            return Err(Error::InvalidInput(
                "profile must be omitted or non-empty".into(),
            ));
        }
        let previous = std::mem::replace(&mut self.profile, profile);
        self.reconcile_or_restore(|m| m.profile = previous)
    }

    /// Reconcile; on failure run `restore` to undo the in-memory change, then try once more to
    /// bring the backend back in line with the restored state.
    fn reconcile_or_restore(&mut self, restore: impl FnOnce(&mut Self)) -> Result<ReconcileReport> {
        match self.reconcile() {
            Ok(report) => Ok(report),
            Err(err) => {
                restore(self);
                let _ = self.reconcile();
                Err(err)
            }
        }
    }

    pub fn rules(&self) -> impl Iterator<Item = &AppRule> {
        self.rules.values()
    }

    pub fn block_all(&self) -> bool {
        self.block_all
    }

    pub fn profile(&self) -> Option<&str> {
        self.profile.as_deref()
    }

    /// The verdict the manager expects for `app` right now. Mirrors what the backend must enforce.
    pub fn decide(&self, app: &str) -> Decision {
        let rules: Vec<AppRule> = self.rules.values().cloned().collect();
        decide(&rules, app, self.profile.as_deref(), self.block_all)
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Rules that should be enforced for the current profile.
    fn active_rules(&self) -> Vec<&AppRule> {
        self.rules
            .values()
            .filter(|r| match (&r.profile, &self.profile) {
                (None, _) => true,
                (Some(scope), Some(current)) => scope == current,
                (Some(_), None) => false,
            })
            .collect()
    }

    /// Make the backend match the desired state. Idempotent: a second call changes nothing.
    pub fn reconcile(&mut self) -> Result<ReconcileReport> {
        let mut report = ReconcileReport::default();
        let actual = self.backend.list_rules()?;
        // Owned copy: the backend is borrowed mutably below.
        let desired: Vec<AppRule> = self.active_rules().into_iter().cloned().collect();

        // Remove anything enforced that is no longer desired (or differs from desired).
        for stale in &actual {
            if !desired.contains(stale) {
                self.backend.remove_rule(stale.id)?;
                report.removed += 1;
            }
        }
        // Install desired rules that are missing or differ.
        for want in &desired {
            if !actual.contains(want) {
                self.backend.apply_rule(want)?;
                report.applied += 1;
            }
        }

        let enforced = self.backend.block_all_enabled()?;
        if enforced != self.block_all {
            self.backend.set_block_all(self.block_all)?;
            report.block_all_changed = true;
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockBackend;
    use crate::traits::RuleAction;

    fn rule(id: i64, app: &str, action: RuleAction, profile: Option<&str>) -> AppRule {
        AppRule {
            id,
            app: app.into(),
            action,
            profile: profile.map(String::from),
        }
    }

    #[test]
    fn upsert_pushes_rule_and_is_idempotent() {
        let mut m = FirewallManager::new(MockBackend::new(), [], false, None).unwrap();
        let report = m
            .upsert_rule(rule(1, "a.exe", RuleAction::Block, None))
            .unwrap();
        assert_eq!(report.applied, 1);
        assert_eq!(m.backend().list_rules().unwrap().len(), 1);
        assert_eq!(m.reconcile().unwrap(), ReconcileReport::default());
    }

    #[test]
    fn profile_switch_swaps_scoped_rules_on_backend() {
        let rules = [
            rule(1, "a.exe", RuleAction::Block, None),
            rule(2, "b.exe", RuleAction::Block, Some("public")),
        ];
        let mut m =
            FirewallManager::new(MockBackend::new(), rules, false, Some("home".into())).unwrap();
        // Only the unscoped rule is enforced on "home".
        let ids: Vec<i64> = m
            .backend()
            .list_rules()
            .unwrap()
            .iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(ids, vec![1]);

        m.set_profile(Some("public".into())).unwrap();
        let mut ids: Vec<i64> = m
            .backend()
            .list_rules()
            .unwrap()
            .iter()
            .map(|r| r.id)
            .collect();
        ids.sort();
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn panic_button_is_pushed_and_cleared() {
        let mut m = FirewallManager::new(MockBackend::new(), [], false, None).unwrap();
        assert!(m.set_block_all(true).unwrap().block_all_changed);
        assert!(m.backend().block_all_enabled().unwrap());
        assert!(!m.set_block_all(true).unwrap().block_all_changed);
        m.set_block_all(false).unwrap();
        assert!(!m.backend().block_all_enabled().unwrap());
    }

    #[test]
    fn reconcile_repairs_drift_on_backend() {
        let mut m = FirewallManager::new(
            MockBackend::new(),
            [rule(1, "a.exe", RuleAction::Block, None)],
            false,
            None,
        )
        .unwrap();
        // Something outside the manager removes the OS rule.
        m.backend_mut().remove_rule(1).unwrap();
        let report = m.reconcile().unwrap();
        assert_eq!(report.applied, 1);
        assert_eq!(m.backend().list_rules().unwrap().len(), 1);
    }

    #[test]
    fn remove_rule_reports_missing_ids() {
        let mut m = FirewallManager::new(MockBackend::new(), [], false, None).unwrap();
        assert!(!m.remove_rule(9).unwrap());
    }

    #[test]
    fn decision_matches_policy_including_panic() {
        let mut m = FirewallManager::new(
            MockBackend::new(),
            [rule(1, "a.exe", RuleAction::Allow, None)],
            false,
            None,
        )
        .unwrap();
        assert!(!m.decide("a.exe").is_block());
        m.set_block_all(true).unwrap();
        assert!(m.decide("a.exe").is_block());
    }

    /// Backend whose rule installs can be made to fail on demand.
    #[derive(Default)]
    struct Flaky {
        inner: MockBackend,
        fail_apply: bool,
    }

    impl FirewallBackend for Flaky {
        fn list_rules(&self) -> Result<Vec<AppRule>> {
            self.inner.list_rules()
        }
        fn apply_rule(&mut self, rule: &AppRule) -> Result<()> {
            if self.fail_apply {
                return Err(Error::Backend("WFP refused".into()));
            }
            self.inner.apply_rule(rule)
        }
        fn remove_rule(&mut self, id: i64) -> Result<()> {
            self.inner.remove_rule(id)
        }
        fn set_block_all(&mut self, enabled: bool) -> Result<()> {
            self.inner.set_block_all(enabled)
        }
        fn block_all_enabled(&self) -> Result<bool> {
            self.inner.block_all_enabled()
        }
    }

    #[test]
    fn refused_change_is_rolled_back() {
        let mut m = FirewallManager::new(Flaky::default(), [], false, None).unwrap();
        m.backend_mut().fail_apply = true;
        assert!(m
            .upsert_rule(rule(1, "a.exe", RuleAction::Block, None))
            .is_err());
        assert_eq!(m.rules().count(), 0, "rejected rule must not stay desired");
        assert!(m.backend().list_rules().unwrap().is_empty());

        m.backend_mut().fail_apply = false;
        m.upsert_rule(rule(1, "a.exe", RuleAction::Block, None))
            .unwrap();
        assert_eq!(m.rules().count(), 1);
    }

    #[test]
    fn invalid_rules_are_rejected_before_touching_backend() {
        let mut m = FirewallManager::new(MockBackend::new(), [], false, None).unwrap();
        assert!(m
            .upsert_rule(rule(1, "  ", RuleAction::Block, None))
            .is_err());
        assert!(m.backend().list_rules().unwrap().is_empty());
    }
}
