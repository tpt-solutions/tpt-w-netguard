// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end check of per-app eBPF enforcement against the running kernel.
//!
//! The test binary is its own probe: copies of it are installed as the "blocked" and "control"
//! applications, and each one attempts TCP and UDP traffic, plus a forked child doing the same.
//! That keeps the test free of any interpreter or other runtime dependency.
//!
//! Needs root (or CAP_BPF + CAP_NET_ADMIN), cgroup v2 at /sys/fs/cgroup, tracefs, and the eBPF
//! object built by build.rs. It runs in the initial PID namespace; see docs/linux-ebpf.md.
//! Ignored by default:
//!
//! ```text
//! cargo test -p tpt-netguard-platform-linux --test enforcement -- --ignored --nocapture
//! ```
#![cfg(target_os = "linux")]

use std::fs;
use std::io::{self, ErrorKind};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use tpt_netguard_core::traits::{AppRule, FirewallBackend, RuleAction};
use tpt_netguard_platform_linux::LinuxFirewall;

/// Environment variable that turns this test binary into the probe. Its value is the port to
/// contact, and the probe waits the number of milliseconds given after it (`port:delay_ms`).
const PROBE_ENV: &str = "TPT_NETGUARD_PROBE";
/// Test name the probe runs; the harness is asked to run only this one.
const PROBE_TEST: &str = "probe_entry";

fn outcome(result: io::Result<()>) -> &'static str {
    match result {
        Ok(()) => "connected",
        Err(e) if e.kind() == ErrorKind::PermissionDenied => "blocked",
        Err(_) => "error",
    }
}

fn tcp(tag: &str, addr: SocketAddr) {
    let result = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).map(|_| ());
    println!("PROBE {tag} tcp {}", outcome(result));
}

fn udp(tag: &str, addr: SocketAddr) {
    let result = UdpSocket::bind("127.0.0.1:0").and_then(|s| s.send_to(b"x", addr).map(|_| ()));
    println!("PROBE {tag} udp {}", outcome(result));
}

/// Runs inside the probe process: attempts every kind of traffic, then a forked child does too.
fn run_probe(spec: &str) {
    let (port, delay) = spec.split_once(':').expect("probe spec is port:delay_ms");
    let port: u16 = port.parse().expect("probe port");
    let delay: u64 = delay.parse().expect("probe delay");
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    std::thread::sleep(Duration::from_millis(delay));

    tcp("self", addr);
    udp("self", addr);

    // SAFETY: the child only performs a connect and then exits without returning into the
    // harness, so no lock or allocator state from the parent is used after the fork.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        tcp("child", addr);
        unsafe { libc::_exit(0) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
}

/// Entry point used only when this binary runs as the probe. The normal test run skips it.
#[test]
fn probe_entry() {
    if let Ok(spec) = std::env::var(PROBE_ENV) {
        run_probe(&spec);
        std::process::exit(0);
    }
}

/// Starts `app` as a probe and returns its reported outcomes, one line per attempt.
fn probe(app: &Path, port: u16, delay_ms: u64) -> Vec<String> {
    let out = Command::new(app)
        .env(PROBE_ENV, format!("{port}:{delay_ms}"))
        .args([PROBE_TEST, "--exact", "--nocapture", "--test-threads=1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("probe starts");
    assert!(
        out.status.success(),
        "probe failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        // The harness prints "test name ... " without a newline, so a probe line can follow it on
        // the same line; the marker is what identifies the line, wherever it starts.
        .filter_map(|l| l.find("PROBE ").map(|i| l[i..].to_owned()))
        .collect()
}

fn has(lines: &[String], expected: &str) -> bool {
    lines.iter().any(|l| l == expected)
}

fn rule(id: i64, app: &Path, action: RuleAction) -> AppRule {
    AppRule {
        id,
        app: app.to_string_lossy().into_owned(),
        action,
        profile: None,
    }
}

#[test]
#[ignore = "needs root, cgroup v2, tracefs and the eBPF object; run with --ignored"]
fn per_app_rules_are_enforced_by_the_kernel() {
    let mut fw = LinuxFirewall::open();
    assert!(
        fw.ebpf_unavailable().is_none(),
        "per-app eBPF not available: {:?}",
        fw.ebpf_unavailable()
    );

    let dir: PathBuf = std::env::temp_dir().join(format!("tpt-enforcement-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let this = std::env::current_exe().expect("test binary path");
    let app = dir.join("blocked-app");
    let control = dir.join("control-app");
    fs::copy(&this, &app).expect("copy probe");
    fs::copy(&this, &control).expect("copy control");

    // A throwaway listener; connections only need the handshake to reach the kernel.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || for _ in listener.incoming() {});

    // Before any rule everything connects.
    let before = probe(&app, port, 0);
    assert!(has(&before, "PROBE self tcp connected"), "{before:?}");
    assert!(has(&before, "PROBE child tcp connected"), "{before:?}");

    // A probe that is already running when the rule arrives; it connects after a delay.
    let running = {
        let app = app.clone();
        std::thread::spawn(move || probe(&app, port, 1000))
    };
    std::thread::sleep(Duration::from_millis(200));

    // The block takes effect at once, for the running probe and for a fresh one.
    fw.apply_rule(&rule(1, &app, RuleAction::Block)).unwrap();
    let late = running.join().unwrap();
    assert!(
        has(&late, "PROBE self tcp blocked"),
        "running process: {late:?}"
    );

    let blocked = probe(&app, port, 0);
    println!("blocked run: {blocked:?}");
    assert!(has(&blocked, "PROBE self tcp blocked"), "{blocked:?}");
    assert!(has(&blocked, "PROBE self udp blocked"), "{blocked:?}");
    assert!(has(&blocked, "PROBE child tcp blocked"), "{blocked:?}");

    // Other programs are not affected.
    // A short delay keeps this functional check clear of the first-connect window, which is
    // measured separately below.
    let other = probe(&control, port, 50);
    assert!(has(&other, "PROBE self tcp connected"), "{other:?}");

    // Removing the rule restores access.
    fw.remove_rule(1).unwrap();
    let restored = probe(&app, port, 0);
    assert!(has(&restored, "PROBE self tcp connected"), "{restored:?}");
    assert!(fw.list_rules().unwrap().is_empty());

    // Cost of the exec gap, measured: with a rule active, how often does a fresh, unblocked
    // program get its first connect refused (false positive), and how often does a fresh blocked
    // program get through (leak)? Set NETGUARD_MEASURE=n to run n trials of each.
    if let Some(n) = std::env::var("NETGUARD_MEASURE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
    {
        fw.apply_rule(&rule(3, &app, RuleAction::Block)).unwrap();
        let mut control_refused = 0;
        let mut blocked_through = 0;
        for _ in 0..n {
            let c = probe(&control, port, 0);
            if !has(&c, "PROBE self tcp connected") {
                control_refused += 1;
            }
            let b = probe(&app, port, 0);
            if has(&b, "PROBE self tcp connected") {
                blocked_through += 1;
            }
        }
        println!("MEASURE trials={n} unblocked_refused={control_refused} blocked_through={blocked_through}");
        fw.remove_rule(3).unwrap();
    }

    // The kernel cannot match relative paths, so they are refused rather than ignored.
    let relative = AppRule {
        id: 2,
        app: "blocked-app".into(),
        action: RuleAction::Block,
        profile: None,
    };
    assert!(fw.apply_rule(&relative).is_err());

    let _ = fs::remove_dir_all(&dir);
}
