// SPDX-License-Identifier: MIT OR Apache-2.0
//! Builds the kernel-side eBPF object (`ebpf/`) when the host can do it.
//!
//! The object needs a nightly toolchain with `rust-src` and `bpf-linker` on the PATH. When any
//! of those is missing, the build still succeeds: the crate is compiled without `ebpf_built`,
//! per-app rules report why they are unavailable, and the panic button keeps working.
//! Set `TPT_SKIP_EBPF=1` to skip the object build on purpose.

use std::env;
use std::path::PathBuf;
use std::process::Command;

const EBPF_TARGET: &str = "bpfel-unknown-none";

fn main() {
    println!("cargo:rustc-check-cfg=cfg(ebpf_built)");
    println!("cargo:rerun-if-changed=ebpf");
    println!("cargo:rerun-if-changed=src/ebpf_abi.rs");
    println!("cargo:rerun-if-env-changed=TPT_SKIP_EBPF");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    match build_object() {
        Ok(path) => {
            println!("cargo:rustc-env=TPT_EBPF_OBJECT={}", path.display());
            println!("cargo:rustc-cfg=ebpf_built");
        }
        Err(reason) => {
            println!("cargo:warning=per-app eBPF rules disabled: {reason}");
        }
    }
}

fn build_object() -> Result<PathBuf, String> {
    if env::var_os("TPT_SKIP_EBPF").is_some() {
        return Err("TPT_SKIP_EBPF is set".into());
    }
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").map_err(|e| e.to_string())?);
    let out = PathBuf::from(env::var("OUT_DIR").map_err(|e| e.to_string())?);
    let target_dir = out.join("ebpf-target");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(manifest.join("ebpf"))
        .arg("+nightly")
        .args([
            "build",
            "--release",
            "--target",
            EBPF_TARGET,
            "--target-dir",
        ])
        .arg(&target_dir);
    // Variables set by the outer build (toolchain pins, rustc overrides, feature flags) must not
    // leak into the nested build, or it would compile with the wrong compiler for BPF.
    for (key, _) in env::vars_os() {
        let name = key.to_string_lossy();
        // Includes RUSTC_WORKSPACE_WRAPPER and RUSTC_WRAPPER, which clippy and sccache set.
        let outer = name.starts_with("CARGO_")
            || name.starts_with("RUSTC")
            || name == "RUSTDOC"
            || name == "RUSTFLAGS";
        if outer && name != "CARGO_HOME" {
            cmd.env_remove(&key);
        }
    }

    let status = cmd.status().map_err(|e| {
        format!("cannot run `cargo +nightly` ({e}); install a nightly toolchain with rust-src")
    })?;
    if !status.success() {
        return Err(
            "building the eBPF object failed (needs nightly, rust-src and bpf-linker)".into(),
        );
    }
    let object = target_dir
        .join(EBPF_TARGET)
        .join("release")
        .join("tpt-netguard-ebpf");
    if object.exists() {
        Ok(object)
    } else {
        Err(format!("eBPF object not found at {}", object.display()))
    }
}
