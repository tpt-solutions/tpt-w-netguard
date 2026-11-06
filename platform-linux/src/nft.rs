// SPDX-License-Identifier: MIT OR Apache-2.0
//! Coarse nftables rules: the panic button ("block all internet") and similar global policy.
//!
//! The ruleset lives in its own table (`inet tpt_netguard`), so it never touches rules the
//! user or distribution already has. Applying is idempotent: the table is created if missing,
//! flushed, and redefined from scratch.
//!
//! Application uses the `nft` command with the ruleset on stdin rather than a netlink crate.
//! That keeps the dependency surface small; the plan's preferred `rustables`/`nftnl` path can
//! replace [`CommandRunner`] later without changing the rule text.

use tpt_netguard_core::error::{Error, Result};

pub const TABLE: &str = "tpt_netguard";

/// Ruleset that blocks all traffic except loopback when `block_all` is set, and nothing
/// otherwise. Returns the full script to load with `nft -f -`.
pub fn render(block_all: bool) -> String {
    let mut script = String::new();
    // Creating the table first makes flush/delete safe on a fresh system.
    script.push_str(&format!("add table inet {TABLE}\n"));
    script.push_str(&format!("flush table inet {TABLE}\n"));
    if block_all {
        script.push_str(&format!("table inet {TABLE} {{\n"));
        for (chain, hook, direction) in [
            ("output", "output", "oifname"),
            ("input", "input", "iifname"),
        ] {
            script.push_str(&format!(
                "  chain {chain} {{\n    type filter hook {hook} priority -150; policy accept;\n    {direction} != \"lo\" drop\n  }}\n"
            ));
        }
        script.push_str("}\n");
    }
    script
}

/// Script that removes the whole table. Safe to run when the table does not exist.
pub fn remove() -> String {
    format!("add table inet {TABLE}\ndelete table inet {TABLE}\n")
}

/// Runs an external program with optional stdin. Injected so tests can capture scripts.
pub trait CommandRunner: Send {
    fn run(&mut self, program: &str, args: &[&str], stdin: &str) -> Result<()>;
}

/// Production runner: spawns the real binary.
#[derive(Debug, Default)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&mut self, program: &str, args: &[&str], stdin: &str) -> Result<()> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::Backend(format!("cannot run {program}: {e}")))?;
        if let Some(mut pipe) = child.stdin.take() {
            pipe.write_all(stdin.as_bytes())
                .map_err(|e| Error::Backend(format!("cannot write to {program}: {e}")))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| Error::Backend(format!("{program} failed: {e}")))?;
        if out.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&out.stderr);
            Err(Error::Backend(format!(
                "{program} exited with {}: {}",
                out.status,
                stderr.trim()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_all_renders_both_directions_and_keeps_loopback() {
        let script = render(true);
        assert!(script.contains("add table inet tpt_netguard"));
        assert!(script.contains("flush table inet tpt_netguard"));
        assert!(script.contains("chain output"));
        assert!(script.contains("chain input"));
        assert!(script.contains("oifname != \"lo\" drop"));
        assert!(script.contains("iifname != \"lo\" drop"));
        // Default policy stays accept so disabling the panic button needs no extra steps.
        assert!(!script.contains("policy drop"));
    }

    #[test]
    fn disabling_leaves_an_empty_table() {
        let script = render(false);
        assert!(!script.contains("drop"));
        assert!(script.contains("flush table inet tpt_netguard"));
    }

    #[test]
    fn remove_is_idempotent_script() {
        let script = remove();
        // "add" before "delete" so the delete never fails on a missing table.
        let add = script.find("add table").unwrap();
        let del = script.find("delete table").unwrap();
        assert!(add < del);
    }
}
