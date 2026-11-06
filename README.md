# tpt-netguard

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![CI](https://github.com/tpt-solutions/tpt-netguard/actions/workflows/ci.yml/badge.svg)](https://github.com/tpt-solutions/tpt-netguard/actions/workflows/ci.yml)

A visual, easy-to-understand network activity monitor and firewall — an open-source alternative
to GlassWire. Real-time per-app bandwidth, persistent history, one-click per-app allow/block, and
a panic-button "block all internet" toggle.

Built by TPT Solutions. Targets Windows and Linux for v1. See [spec.txt](spec.txt) for the
concept and [todo.md](todo.md) for the roadmap and current status.

## Layout

| Crate / dir          | Purpose                                                              |
|----------------------|----------------------------------------------------------------------|
| `core/`              | Traffic model, `TrafficMonitor` / `FirewallBackend` traits, aggregation, sampling policy, SQLite history store |
| `platform-windows/`  | Windows backend (ETW + IP Helper monitoring, WFP ALE enforcement) — not yet implemented |
| `platform-linux/`    | Linux backend (`/proc` attribution, nftables + eBPF enforcement) — not yet implemented |
| `geoip/`             | Offline GeoLite2-City loader and updater — not yet implemented        |
| `dns/`               | App-scoped DoH/DoT resolver — not yet implemented                     |

## Building

Requirements:

- Rust toolchain. `rust-toolchain.toml` pins the version and components; `rustup` installs it
  automatically on first use.
- A C toolchain for the bundled SQLite build: MSVC Build Tools on Windows, `gcc`/`clang` on Linux.

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Licensing

tpt-netguard is dual-licensed under either of

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.

### Source file headers

Every source file starts with an SPDX identifier line:

```rust
// SPDX-License-Identifier: MIT OR Apache-2.0
```

Use the comment syntax of the file type (`#` for TOML/YAML/shell, `//` for Rust/TypeScript).
Copyright notices are carried by the `LICENSE-*` files rather than repeated per file.

### Third-party data

Geo-IP lookups use the MaxMind GeoLite2-City database, which requires a free license key and
attribution. See the Phase 7 and Phase 15 items in [todo.md](todo.md).
