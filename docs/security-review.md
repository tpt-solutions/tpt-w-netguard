# Security review (pre-release)

Roadmap item: Phase 14, "Security review". Reviewed 2026-11-07 against the code on `master`.

## Scope

- The IPC boundary: the closed `Command` set, its validation, and the Tauri commands and capability.
- Frontend exposure: the Tauri permission set and the content security policy.
- Settings and the GeoLite2 path, which the UI can set.
- Network clients: DNS over HTTPS and TLS (`dns/`), and the GeoLite2 downloader (`geoip/`).
- Enforcement backends: WFP on Windows, nftables and eBPF on Linux, and their cleanup behaviour.
- Every `unsafe` block in the workspace.

Out of scope: the MaxMind licence and the IEEE OUI terms, which are legal questions, and a
live penetration test. The runtime checks listed under "Still open" need a running system.

## Findings

| # | Area | Finding | Severity | Status |
|---|------|---------|----------|--------|
| 1 | Settings / GeoLite2 path | The UI could set `geo_db_path` to any path. The updater writes the database there with the app's rights, which are administrator by default, so a setting could overwrite an arbitrary file. | Medium | **Fixed.** `validate_geo_db_path` (in `core/src/settings.rs`) requires an absolute path to a `.mmdb` file, with no `..` components and no control characters. It runs on load and on save. |
| 2 | Settings / sampling | Sampling intervals had no upper bound, and a base of 1 ms would make the sampler consume a core. | Low | **Fixed.** Intervals must be 100 ms to 1 hour, and the maximum must be at least the base. |
| 3 | Rules | App keys had no length limit. | Low | **Fixed.** Keys are capped at 4096 bytes (`MAX_APP_KEY_LEN` in `core/src/policy.rs`). |
| 4 | Linux firewall cleanup | The block-all nftables table survived package removal, which could leave the machine offline. | Medium | **Fixed.** `packaging/linux/prerm.sh` deletes the table on `remove` and `purge` (wired in `src-tauri/tauri.conf.json`). A test in `platform-linux/src/nft.rs` checks that the script and the code use the same table name. |
| 5 | Windows firewall cleanup | Whether WFP filters outlive the process, including after a crash or uninstall. | Medium | **Verified by design, no change needed.** The engine session is dynamic (`FWPM_SESSION_FLAG_DYNAMIC`, `platform-windows/src/wfp.rs`), so every filter the app adds is removed by the engine when the session ends, including after a crash. Nothing persists across uninstall. The runtime confirmation needs an elevated run (see "Still open"). |
| 6 | Linux eBPF | Per-app programs could outlive the app. | Low | **Verified by design.** The programs are attached through the loader process, and the cgroup attachments end with it. The short exec-time gap is an accepted decision, documented in `docs/linux-ebpf.md`. |
| 7 | Network: TLS | Certificate verification could be bypassed. | High if present | **Not present.** DNS over TLS uses rustls with the bundled Mozilla root set (`dns/src/transport.rs`). DNS over HTTPS and the GeoLite2 download use `ureq` with its rustls backend. No code disables verification. |
| 8 | Network: what leaves the machine | Local addresses could be sent to a resolver or a map service. | Medium | **Not present.** Remote name lookups are filtered to routable addresses in the sampler (`src-tauri/src/sampler.rs`, the `is_routable` filter), and the map uses the same filter (`src-tauri/src/main.rs`). Local network addresses are never sent. |
| 9 | IPC | The UI could send arbitrary commands or values. | High if present | **Not present.** `Command` is a closed enum with `deny_unknown_fields`. `validate_command` checks each value before any backend is touched, and the upstream DNS specs are checked for scheme and shape. |
| 10 | Tauri surface | Extra plugins or permissions could expose the filesystem, shell or network to the page. | Medium | **Not present.** The only capability is `core:default`. No filesystem, shell or HTTP plugins are included. The CSP is `default-src 'self'` with `connect-src` limited to IPC. |
| 11 | Secrets | The GeoLite2 licence key could leak through logs, `Debug` output or error messages. | Medium | **Mitigated.** `Settings`' `Debug` output redacts the key, the crash log's `redact` and `scrub` remove it, and a test checks that errors never contain it. **Accepted:** the key is stored in plain text in `settings.json` in the user's app-data directory. Moving it to the OS credential store is a possible later change. |
| 12 | Crash log | The crash log could collect sensitive data. | Low | **Mitigated.** The log is opt-in, off by default, and scrubs the stored key before writing. |
| 13 | Elevation | The app runs with administrator or root rights. | Accepted | **By design.** The Windows manifest requests administrator, and the Linux launch path uses `pkexec` with a polkit policy. The onboarding walkthrough says so. |
| 14 | Remote names | Remote addresses and their hostnames go to the chosen encrypted resolver. | Accepted | **By design, documented.** `docs/privacy.md` describes this and the resolver setting. |
| 15 | `unsafe` code | Undocumented `unsafe` blocks. | Low | **Partly fixed.** The userspace FFI blocks in `platform-windows` (`iphelper.rs`) and the new `sockdiag` module now have SAFETY notes. The kernel-side eBPF blocks in `platform-linux/ebpf/src/main.rs` still lack per-block notes. **Open** (cosmetic, but tracked). |

## Tests added or extended for this review

- `core/src/settings.rs`: the GeoLite2 path rules, the sampling bounds, and the bad-path cases.
- `core/src/policy.rs`: the app-key length limit.
- `platform-linux/src/nft.rs`: the uninstall hook stays in step with the table name.
- `platform-linux/src/sockdiag.rs` and `platform-linux/tests/sockdiag_live.rs`: the kernel reply parser, including truncated and hostile lengths.

Existing tests that cover the review's other points: `ipc.rs` (command validation), `geoip/src/update.rs`
(errors never contain the licence key), `dns` (fallback and malformed responses), and
`platform-linux/src/app_rules.rs` (only absolute executable paths are enforced).

## Still open

- **Elevated Windows run:** confirm that the WFP block filters apply and that they are gone after exit and after a forced kill. This is the runtime half of finding 5.
- **Linux kernel run:** the enforcement test (`platform-linux/tests/enforcement.rs`) needs root, cgroup v2 and the eBPF object. See `docs/linux-ebpf.md`.
- **eBPF SAFETY notes** (finding 15).
- **Crash while block-all is on:** the app stays fail-closed on the next launch, because the saved setting re-applies the block. The user must switch block-all off to restore access. This is the intended behaviour, and the user guide should say so.
