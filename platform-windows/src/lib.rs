// SPDX-License-Identifier: MIT OR Apache-2.0
//! Windows backend for tpt-netguard (Phase 3).
//!
//! * [`plan`]: platform-neutral mapping from firewall rules to WFP filter weights (tested
//!   everywhere).
//! * `iphelper` (Windows only): connection attribution and per-app byte counters.
//! * `wfp` (Windows only): user-mode WFP ALE enforcement with crash-safe dynamic filters.
//!
//! ETW (Microsoft-Windows-TCPIP) is not implemented yet; new-connection events are currently
//! produced by polling the IP Helper tables.

pub mod plan;

#[cfg(windows)]
pub mod iphelper;
#[cfg(windows)]
pub mod wfp;

#[cfg(windows)]
pub use iphelper::{BandwidthSource, IpHelperMonitor};
#[cfg(windows)]
pub use wfp::WfpEnforcer;
