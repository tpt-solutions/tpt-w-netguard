// SPDX-License-Identifier: MIT OR Apache-2.0
//! Platform-neutral interfaces implemented by `platform-windows` and `platform-linux`.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::model::{ByteSample, Connection};

/// Callback invoked for each newly observed connection.
pub type NewConnectionHandler = Box<dyn FnMut(&Connection) + Send>;

/// Observes network activity. One implementation per OS backend.
pub trait TrafficMonitor: Send {
    /// Enumerate currently active connections with owning process attribution.
    fn enumerate_connections(&mut self) -> Result<Vec<Connection>>;

    /// Return byte deltas per application since the previous call.
    fn sample_byte_deltas(&mut self, now_ms: u64) -> Result<Vec<ByteSample>>;

    /// Register a handler for connections first seen by the backend.
    /// Backends without an event source return `Error::Unsupported`.
    fn subscribe_new_connections(&mut self, handler: NewConnectionHandler) -> Result<()>;
}

/// Action applied to traffic matching a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Block,
}

/// A per-application firewall rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRule {
    /// Stable identifier, assigned by the caller (rule table primary key).
    pub id: i64,
    /// Application key matching `ByteSample::app` / executable path.
    pub app: String,
    pub action: RuleAction,
    /// Optional network-profile scope ("home", "public"); `None` means all networks.
    pub profile: Option<String>,
}

/// Enforces firewall decisions. One implementation per OS backend.
pub trait FirewallBackend: Send {
    /// Rules currently active in the OS enforcement layer.
    fn list_rules(&self) -> Result<Vec<AppRule>>;

    /// Install or replace a per-app rule.
    fn apply_rule(&mut self, rule: &AppRule) -> Result<()>;

    /// Remove a per-app rule by id.
    fn remove_rule(&mut self, id: i64) -> Result<()>;

    /// Enable or disable the global "block all internet" panic button.
    fn set_block_all(&mut self, enabled: bool) -> Result<()>;

    /// Whether the panic button is currently active.
    fn block_all_enabled(&self) -> Result<bool>;
}

/// Persistence hook so rules survive restarts independently of the backend.
pub trait RulePersistence: Send {
    fn load_rules(&self) -> Result<Vec<AppRule>>;
    fn save_rules(&mut self, rules: &[AppRule]) -> Result<()>;
}

/// Lets a boxed backend (for example chosen at runtime per OS) be used wherever a backend is.
impl<T: FirewallBackend + ?Sized> FirewallBackend for Box<T> {
    fn list_rules(&self) -> Result<Vec<AppRule>> {
        (**self).list_rules()
    }

    fn apply_rule(&mut self, rule: &AppRule) -> Result<()> {
        (**self).apply_rule(rule)
    }

    fn remove_rule(&mut self, id: i64) -> Result<()> {
        (**self).remove_rule(id)
    }

    fn set_block_all(&mut self, enabled: bool) -> Result<()> {
        (**self).set_block_all(enabled)
    }

    fn block_all_enabled(&self) -> Result<bool> {
        (**self).block_all_enabled()
    }
}
