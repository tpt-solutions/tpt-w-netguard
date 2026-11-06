// SPDX-License-Identifier: MIT OR Apache-2.0
//! In-memory backend implementing both platform traits. Used by core tests and by
//! higher layers (alerts, IPC) that must run without OS enforcement.

use std::collections::{BTreeMap, VecDeque};

use crate::error::{Error, Result};
use crate::model::{ByteSample, Connection};
use crate::traits::{AppRule, FirewallBackend, NewConnectionHandler, TrafficMonitor};

#[derive(Default)]
pub struct MockBackend {
    /// Connections returned by `enumerate_connections`.
    pub connections: Vec<Connection>,
    /// Queue of per-tick samples; one batch is popped per `sample_byte_deltas` call.
    pub pending_samples: VecDeque<Vec<ByteSample>>,
    handlers: Vec<NewConnectionHandler>,
    rules: BTreeMap<i64, AppRule>,
    block_all: bool,
    /// When true, subscription is reported as unsupported (simulates ETW-less platforms).
    pub no_event_source: bool,
}

impl MockBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Deliver a new connection to every registered handler.
    pub fn emit_new_connection(&mut self, conn: &Connection) {
        for handler in &mut self.handlers {
            handler(conn);
        }
    }
}

impl TrafficMonitor for MockBackend {
    fn enumerate_connections(&mut self) -> Result<Vec<Connection>> {
        Ok(self.connections.clone())
    }

    fn sample_byte_deltas(&mut self, _now_ms: u64) -> Result<Vec<ByteSample>> {
        Ok(self.pending_samples.pop_front().unwrap_or_default())
    }

    fn subscribe_new_connections(&mut self, handler: NewConnectionHandler) -> Result<()> {
        if self.no_event_source {
            return Err(Error::Unsupported("new-connection events"));
        }
        self.handlers.push(handler);
        Ok(())
    }
}

impl FirewallBackend for MockBackend {
    fn list_rules(&self) -> Result<Vec<AppRule>> {
        Ok(self.rules.values().cloned().collect())
    }

    fn apply_rule(&mut self, rule: &AppRule) -> Result<()> {
        if rule.app.is_empty() {
            return Err(Error::InvalidInput("rule app key must not be empty".into()));
        }
        self.rules.insert(rule.id, rule.clone());
        Ok(())
    }

    fn remove_rule(&mut self, id: i64) -> Result<()> {
        self.rules
            .remove(&id)
            .map(|_| ())
            .ok_or_else(|| Error::InvalidInput(format!("no rule with id {id}")))
    }

    fn set_block_all(&mut self, enabled: bool) -> Result<()> {
        self.block_all = enabled;
        Ok(())
    }

    fn block_all_enabled(&self) -> Result<bool> {
        Ok(self.block_all)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ConnectionState, Direction, Protocol};
    use crate::traits::RuleAction;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    fn conn(pid: u32) -> Connection {
        Connection {
            pid,
            process_name: "app.exe".into(),
            exe_path: None,
            local: "127.0.0.1:5000".parse::<SocketAddr>().unwrap(),
            remote: "10.0.0.1:443".parse::<SocketAddr>().unwrap(),
            protocol: Protocol::Tcp,
            direction: Direction::Outbound,
            bytes_sent: 0,
            bytes_received: 0,
            state: ConnectionState::Established,
            first_seen_ms: 1,
            last_seen_ms: 1,
        }
    }

    #[test]
    fn samples_are_returned_one_batch_per_tick() {
        let mut m = MockBackend::new();
        m.pending_samples.push_back(vec![ByteSample {
            app: "a".into(),
            timestamp_ms: 1,
            bytes_sent: 1,
            bytes_received: 2,
        }]);
        assert_eq!(m.sample_byte_deltas(1).unwrap().len(), 1);
        assert!(m.sample_byte_deltas(2).unwrap().is_empty());
    }

    #[test]
    fn new_connection_handlers_receive_events() {
        let mut m = MockBackend::new();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        m.subscribe_new_connections(Box::new(move |c: &Connection| {
            sink.lock().unwrap().push(c.pid);
        }))
        .unwrap();
        m.emit_new_connection(&conn(42));
        assert_eq!(*seen.lock().unwrap(), vec![42]);
    }

    #[test]
    fn subscription_reports_unsupported_without_event_source() {
        let mut m = MockBackend::new();
        m.no_event_source = true;
        let err = m
            .subscribe_new_connections(Box::new(|_: &Connection| {}))
            .unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)));
    }

    #[test]
    fn firewall_rule_crud_and_block_all() {
        let mut m = MockBackend::new();
        let rule = AppRule {
            id: 7,
            app: "chrome.exe".into(),
            action: RuleAction::Block,
            profile: None,
        };
        m.apply_rule(&rule).unwrap();
        assert_eq!(m.list_rules().unwrap(), vec![rule]);
        m.remove_rule(7).unwrap();
        assert!(m.remove_rule(7).is_err());

        assert!(!m.block_all_enabled().unwrap());
        m.set_block_all(true).unwrap();
        assert!(m.block_all_enabled().unwrap());
    }

    #[test]
    fn empty_app_key_is_rejected() {
        let mut m = MockBackend::new();
        let rule = AppRule {
            id: 1,
            app: String::new(),
            action: RuleAction::Allow,
            profile: None,
        };
        assert!(matches!(m.apply_rule(&rule), Err(Error::InvalidInput(_))));
    }
}
