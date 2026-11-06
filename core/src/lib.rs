// SPDX-License-Identifier: MIT OR Apache-2.0
//! tpt-netguard core: platform-neutral traffic model, firewall rule engine primitives,
//! per-app aggregation, sampling policy, and the persistent history store.
//!
//! Platform code (`platform-windows`, `platform-linux`) implements [`TrafficMonitor`] and
//! [`FirewallBackend`]; everything here is testable without touching the network stack.

pub mod aggregate;
pub mod alerts;
#[cfg(feature = "archon")]
pub mod archon;
pub mod crashlog;
pub mod devices;
pub mod error;
pub mod ipc;
pub mod manager;
pub mod mock;
pub mod model;
pub mod notify;
pub mod policy;
pub mod scheduler;
#[cfg(feature = "sqlite")]
pub mod service;
pub mod settings;
pub mod traits;

#[cfg(feature = "sqlite")]
pub mod store;

pub use aggregate::{Aggregator, HourlyRollup};
pub use alerts::{Alert, AlertEngine, AlertKind, Severity};
pub use devices::{ArpEntry, Device, DeviceRegistry, OuiTable};
pub use error::{Error, Result};
pub use manager::{FirewallManager, ReconcileReport};
pub use model::{ByteSample, Connection, ConnectionState, Direction, Protocol, Totals};
pub use notify::{AlertPipeline, AlertSink, Notifier};
pub use policy::{decide, BlockReason, Decision};
pub use scheduler::SamplingScheduler;
#[cfg(feature = "sqlite")]
pub use service::{Service, Snapshot};
pub use settings::Settings;
pub use traits::{AppRule, FirewallBackend, RuleAction, RulePersistence, TrafficMonitor};
