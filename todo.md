# tpt-netguard — Project Checklist

TPT Solutions — dual-licensed under MIT OR Apache-2.0.
Visual, easy-to-understand network activity monitor and firewall (GlassWire alternative). Rust
core (packet/connection inspection, per-app bandwidth attribution, firewall enforcement) + Tauri
UI (plain TS/HTML frontend, GlassWire-style fixed tabs). Targets Windows and Linux for v1; Archon
(via tpt-archon-kernel's capability/IPC model) is design-only until a network capability primitive
exists upstream.

Reference: Archon platform — https://github.com/tpt-solutions/tpt-archon

Decisions locked in for this roadmap:
- Scope is **full GlassWire parity** in v1: real-time bandwidth graph, persistent per-app history,
  one-click per-app firewall block/allow + a panic-button "block all internet" toggle, LAN device
  discovery ("Things"), a geo-IP connection map, remote-connection/VPN alerts, and encrypted DNS
  for the app's own lookups. Nothing GlassWire-equivalent is pushed to backlog for v1.
- UI is **Tauri + plain TS/HTML** with fixed GlassWire-style tabs (Graph / Usage / Firewall /
  Things / Map / Alerts / Settings) — not a customizable widget grid.
- **No custom kernel driver on Windows.** Firewall blocking uses WFP's user-mode Application Layer
  Enforcement (ALE) API (`FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`, matched via
  `FWPM_CONDITION_ALE_APP_ID`); per-app bandwidth uses an ETW real-time trace session
  (Microsoft-Windows-TCPIP provider) with IP Helper API (`GetExtendedTcpTable`/
  `GetPerTcpConnectionEStats`) polling as fallback/supplement. Avoids driver-signing/WHQL entirely.
- **Elevate by default**: the app requests admin (Windows UAC manifest) / documents a root-launch
  path (Linux) at startup, matching tpt-monitor.
- **Linux enforcement splits responsibilities**: nftables (via netlink) for coarse/global rules
  (panic-button "block all", port/protocol rules) and eBPF (via the pure-Rust `aya` crate,
  `cgroup/connect4`/`connect6` hooks) for per-app allow/block decisions. Per-app bandwidth
  attribution uses `/proc/net/{tcp,udp}` + `/proc/[pid]/fd` inode matching (nethogs-style),
  mirroring tpt-monitor's existing Linux technique.
- **Geo-IP is fully offline**: embedded MaxMind GeoLite2-City database (free license key required,
  scheduled update job — MaxMind's EULA requires attribution and refresh at least every 30 days).
  No per-connection lookups sent to a third-party API.
- **Encrypted DNS is app-scoped only**: tpt-netguard resolves hostnames/reverse-DNS for its own
  connection list via DoH/DoT. It does not proxy or reconfigure system-wide DNS.
- **History is persistent**: on-disk SQLite store for per-app bandwidth history and the
  connection/alert log, with a configurable retention window (unlike tpt-monitor's
  in-memory-only history — "historical data" is an explicit spec requirement here).

---

## Status Summary

| Phase | Area | Progress |
|-------|------|----------|
| 0  | Project Setup & Licensing                          | 🟡 Partial (MaxMind key and repo hosting are user actions) |
| 1  | Core Data Model & Traffic Engine                   | ✅ Complete (core crate) |
| 2  | Historical Data Store                              | ✅ Complete (core crate) |
| 3  | Windows Backend                                    | 🟡 IP Helper monitoring and WFP enforcement done; ETW not started |
| 4  | Linux Backend                                      | 🟡 Attribution and nftables panic button done; eBPF and byte counters pending |
| 5  | Firewall Rule Engine & Panic Button                | 🟡 Windows wired end to end; Linux enforces the panic button only |
| 6  | LAN Device Discovery ("Things")                    | 🟡 Scanning, naming and alerts done; OUI vendor data not bundled |
| 7  | Geo-IP & Connection Map                            | 🟡 Loader, refresh job and map model done; ASN not in UI |
| 8  | Encrypted DNS for App Lookups                      | 🟡 DoH/DoT transports done; not yet used for connection names |
| 9  | Alerts Engine                                      | 🟡 Engine and in-app feed done; OS notifications pending |
| 10 | Tauri Shell & IPC Layer                            | 🟡 Shell, commands, events and tray done; tray recent alerts pending |
| 11 | Frontend (Graph/Usage/Firewall/Things/Map/Alerts)  | 🟡 All seven tabs built; per-app graph pending |
| 12 | Archon Support (Design Only)                       | 🟡 Design draft and feature stubs; open questions need the tpt-archon team |
| 13 | Performance & Polish                               | 🟡 Onboarding, opt-in log and placeholder icon done; profiling pending |
| 14 | Testing & QA                                       | 🟡 Unit and wire-contract tests done; integration and manual QA pending |
| 15 | Release v1                                         | 🟡 Docs, notices and triage done; installers not built; tag and publish excluded |

---

## Phase 0 — Project Setup & Licensing
- [x] Init git repo, `.gitignore` (Rust + Node/Tauri targets + Windows build artifacts)
- [x] Add `LICENSE-MIT` and `LICENSE-APACHE` (dual license, TPT Solutions copyright)
- [x] Add SPDX dual-license header/notice convention for source files (documented in README)
- [x] Cargo workspace: `core/` (traffic model, firewall-rule trait, alert engine, history store),
      *(all crates now exist: core, dns, geoip, discovery, platform-windows, platform-linux, src-tauri, src/)*
      `platform-windows/`, `platform-linux/`, `geoip/` (MaxMind DB loader/updater), `dns/`
      (DoH/DoT resolver), `src-tauri/`, `src/` (TS/HTML frontend, Vite); shared
      `[workspace.package]` (`license`, `authors = ["TPT Solutions"]`, `repository`)
- [x] `rust-toolchain.toml` (MSRV pin), `rustfmt.toml`, `clippy.toml`
- [x] Configure `tauri.conf.json` (app id, window defaults, bundle identifiers,
      `windows.requireAdministrator` manifest setting)
- [x] TypeScript config (tsconfig, Vite, no framework)
- [x] `README.md` (from spec.txt), build instructions, license badges
- [x] Set up CI (GitHub Actions, fmt + clippy + test on Windows + Linux runners) —
      `.github/workflows/ci.yml`; not yet run on GitHub
- [ ] Obtain MaxMind GeoLite2 license key (dev/CI secrets), document redistribution/attribution
      obligations *(blocked: needs a MaxMind account — user action)*
- [ ] Repo hosting under `tpt-solutions` GitHub org *(user action: the README already links to
      `tpt-solutions/tpt-netguard`)*

## Phase 1 — Core Data Model & Traffic Engine
- [x] Connection/traffic data model: process, executable path, remote IP/port, protocol,
      direction, bytes sent/received, connection state, first-seen/last-seen timestamps
- [x] Shared `trait TrafficMonitor` (enumerate active connections, sample per-app byte deltas,
      subscribe to new-connection events) so Windows/Linux backends share one interface
- [x] Shared `trait FirewallBackend` (list rules, add/remove per-app allow/block rule, block-all
      toggle, rule persistence hook) so Windows/Linux enforcement share one interface
- [x] Per-app aggregation: rolling totals (session, hourly, daily) feeding both live graphs and
      the history store
- [x] Sampling scheduler: configurable interval, adaptive slow-down when UI unfocused/minimized
- [x] Core unit tests (mocked backend implementing both traits)

## Phase 2 — Historical Data Store
- [x] SQLite schema: per-app bandwidth time series (hourly/daily rollups), connection log,
      alert log, device log (Phase 6), firewall rule table
- [x] Rollup job: raw samples → hourly → daily aggregates, configurable retention window
      (default matches GlassWire's ~30-day window)
- [x] Query layer for frontend: per-app history range queries, top-talkers, totals
      *(done: `top_talkers`, `app_totals`, and `history` time series at hourly/daily granularity)*
- [x] Migration/versioning strategy for the schema (`PRAGMA user_version` + ordered migrations)
- [x] Unit tests: rollup correctness, retention pruning

## Phase 3 — Windows Backend
- [ ] Per-app bandwidth via ETW real-time trace session (Microsoft-Windows-TCPIP provider),  *(IP Helper path done; ETW not started)*
      falling back to IP Helper API (`GetExtendedTcpTable`/`GetExtendedUdpTable` owning-PID
      mapping + `GetPerTcpConnectionEStats` byte counters) where ETW data is unavailable
- [x] Firewall enforcement via WFP user-mode ALE API: add/remove block filters at  *(implemented; runtime check needs an elevated run)*
      `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` keyed on `FWPM_CONDITION_ALE_APP_ID` (per-executable)
- [x] Block-all "panic button" via a catch-all ALE filter  *(implemented; runtime check needs an elevated run)*
- [ ] New-connection notification hook (ALE classify callback) feeding the Alerts engine  *(poll-based substitute in place; ALE hook not started)*
      (Phase 9)
- [x] UAC elevation manifest (`requireAdministrator`) wired into the Tauri/MSVC build; verify  *(release builds only; unelevated fallback covered by a unit test, not an interactive launch)*
      unelevated-launch fallback messaging
- [x] Unit/integration tests against a mockable WFP/ETW boundary (CI-safe)  *(plan tests run everywhere; live tests are read-only or ignored)*

## Phase 4 — Linux Backend
- [ ] Per-app bandwidth via `/proc/net/{tcp,udp}` + `/proc/[pid]/fd` inode matching  *(attribution done; byte counters need eBPF or capture, not started)*
      (nethogs-style), mirroring tpt-monitor's existing technique
- [x] Firewall enforcement, coarse rules: nftables via netlink (`rustables`/`nftnl` crate) for  *(done through the `nft` CLI instead of netlink; see platform-linux/src/nft.rs)*
      block-all panic button and port/protocol rules
- [ ] Firewall enforcement, per-app rules: eBPF via `aya` (pure Rust, no libbpf/clang runtime
      dependency), `cgroup/connect4`/`connect6` programs consulting a userspace-maintained BPF
      map keyed by PID/cgroup id
- [x] Document/implement root-launch elevation path (`pkexec`/`sudo`; polkit policy file for GUI
      launch) plus `CAP_NET_ADMIN`/`CAP_BPF` capability requirements
- [ ] Verify behavior across at least one major distro (X11 + Wayland), and across cgroup v1/v2
      hosts

## Phase 5 — Firewall Rule Engine & Panic Button
- [ ] Wire `FirewallBackend` trait to Windows/Linux implementations (Phases 3/4)  *(Windows done; Linux enforces the panic button only)*
- [x] Per-app rule model: allow/block, optional per-network-profile (home/public) scoping,
      persisted in the rule table (Phase 2)
- [x] Block-all "panic button" toggle wired to both backends
- [x] Rule conflict/precedence resolution (explicit app rule vs block-all)
- [x] Unit tests: rule CRUD, precedence resolution, persistence round-trip

## Phase 6 — LAN Device Discovery ("Things")
- [x] ARP table scan (active + periodic sweep) to enumerate devices on the local subnet
- [x] Hostname resolution via mDNS/NetBIOS where available; MAC vendor OUI lookup for device  *(OUI lookup reads an `oui.txt` file; no vendor database is bundled)*
      labeling
- [x] Device fingerprint/identity model (MAC, vendor, hostname, first-seen/last-seen, "known"
      flag)
- [x] New-device-on-network detection feeding the Alerts engine (Phase 9)
- [x] Unit tests: ARP parsing, OUI lookup, new-vs-known device classification

## Phase 7 — Geo-IP & Connection Map
- [x] MaxMind GeoLite2-City database loader (license key config, local storage path)
- [x] Scheduled update job (respecting MaxMind's redistribution/refresh terms)  *(City edition only; ASN is not refreshed yet)*
- [ ] IP → location + ASN/org lookup for remote connection endpoints  *(ASN reader exists; not surfaced in the UI yet)*
- [x] Map data model (aggregated connections by location) for the frontend Map tab
- [x] Graceful degradation when no license key/DB is configured (map tab disabled, rest of app
      unaffected)
- [x] Unit tests: DB lookup, missing-DB fallback

## Phase 8 — Encrypted DNS for App Lookups
- [x] DoH/DoT client for the app's own hostname/reverse-DNS resolution needs (connection list,  *(transports tested against local servers; not yet used for connection-list names)*
      Things labeling)
- [x] Configurable upstream resolver (default + user override), timeout/fallback handling
- [x] Explicitly scoped: no system DNS proxying or OS resolver reconfiguration
- [x] Unit tests: resolver fallback, malformed-response handling

## Phase 9 — Alerts Engine
- [x] Alert types: new app's first network connection, new device on LAN (Phase 6), per-app/
      system usage-spike threshold, inbound remote-connection detection (RDP on Windows;
      SSH/VNC port + process heuristics on Linux)
- [x] Alert model: rationale, affected app/device, timestamp, severity; persisted to the alert
      log (Phase 2)
- [ ] Notification delivery (OS-native notification + in-app Alerts tab)  *(in-app feed done; OS toast not wired)*
- [x] Per-rule mute/dismiss + "don't alert again for this app/device" overrides
- [x] Unit tests: fixture connection/device histories → expected alerts, mute suppression

## Phase 10 — Tauri Shell & IPC Layer
- [x] Tauri app scaffold wired to `core` sampling scheduler
- [x] Event push from Rust sampling/alert loops to frontend (Tauri events/channels), throttled
      for high-connection-count machines
- [x] Command layer for firewall actions, rule CRUD, alert dismiss/mute, Things device labeling
- [ ] System tray icon with quick actions (panic button, open dashboard, recent alerts)  *(panic, open and quit done; recent-alerts entries missing)*
- [x] IPC boundary tests (command validation, no arbitrary rule/action injection beyond intended
      surface)

## Phase 11 — Frontend (Graph / Usage / Firewall / Things / Map / Alerts / Settings)
- [x] App shell (plain TS/HTML + Vite), light/dark theme, GlassWire-style fixed tabs
- [ ] Graph tab: real-time total + per-app bandwidth graph (up/down)  *(total graph and connection list done; per-app graph missing)*
- [x] Usage tab: per-app historical bandwidth (sortable/filterable, date-range picker over
      Phase 2 rollups)
- [x] Firewall tab: per-app allow/block list, panic button, rule management UI
- [x] Things tab: LAN device list, new/known device labeling, rename/trust device
- [x] Map tab: geo-IP connection map visualization
- [x] Alerts tab: alert feed, mute/dismiss controls
- [x] Settings: elevation status, retention window, GeoLite2 license key entry, DoH/DoT resolver
      config, alert thresholds

## Phase 12 — Archon Support (Design Only)
- [ ] `docs/archon-design.md`: design sketch for an Archon backend *(draft written; the
      `Resource::Page`/`Resource::Channel` claim below is NOT verified — the tpt-archon source was
      unreachable, and the README names `Resource::Device`)*, explicitly noting that no
      network/socket capability primitive exists yet in `tpt-archon`'s capability system
      (`Resource::Page`/`Resource::Channel` only, confirmed against the current `tpt-archon`
      source)
- [ ] Open Questions (pending tpt-archon team): does a `Resource::Socket`/`Resource::Network`
      capability type get added; what IPC/channel shape would carry connection and bandwidth
      telemetry; how would per-app firewall decisions map onto capability grants/revocation;
      performance target vs the current cooperative single-threaded-per-task scheduler
- [x] Post-v1 `archon` Cargo feature flag plan (`ArchonTrafficMonitor`/`ArchonFirewallBackend`
      stubs, `is_available() -> false`, `Unsupported` errors until upstream primitives exist)

## Phase 13 — Performance & Polish
- [ ] Profile the sampling/enforcement loops (CPU/RAM footprint, ETW/eBPF overhead under load)
- [ ] Adaptive sampling interval tuning (unfocused/minimized window)
- [ ] App icon, branding assets (TPT Solutions)  *(placeholder icon generated; real branding is a design task)*
- [x] First-run onboarding (explain elevation prompt, GeoLite2 license key setup, panic button)
- [x] Crash reporting / local error logging (opt-in only)  *(opt-in local log only; no crash handler or upload)*
- [ ] Accessibility pass (keyboard navigation, screen reader labels across all tabs)

## Phase 14 — Testing & QA
- [x] Unit tests: traffic engine, firewall rule engine, alerts engine, geo-IP lookup, DNS
      resolver (mocked per-platform backends)
- [ ] Integration tests: end-to-end block/allow against a spawned test process and real socket
      connections
- [ ] Manual QA: Windows 10/11 (elevated + unelevated launch, WFP filter cleanup on exit/crash)
- [ ] Manual QA: Linux (X11 + Wayland, at least one major distro; cgroup v1 and v2; root and
      non-root launch)
- [ ] Stress test: connection list + graphs responsiveness under many simultaneous connections
      (e.g. torrent client, busy browser)
- [ ] Security review: elevated-process attack surface, IPC command validation, WFP/eBPF filter
      cleanup guarantees (no orphaned block rules after crash/uninstall), GeoLite2/DoH network
      calls audited against the stated privacy scope

## Phase 15 — Release v1
- [x] Finalize versioning scheme (SemVer) and changelog process (`docs/versioning.md`, `CHANGELOG.md`)
- [ ] Windows installer (MSI/NSIS via Tauri bundler) with UAC manifest embedded, code-signing  *(bundle config ready; not built; code-signing decision open)*
      decision, WFP filter cleanup on uninstall
- [ ] Linux packaging (.deb/.rpm/AppImage via Tauri bundler), documented elevation launch path,
      nftables/eBPF cleanup on uninstall
- [x] Publish LICENSE files + notices in release artifacts, including MaxMind GeoLite2
      attribution notice
- [x] User-facing docs (install guide, firewall/panic-button guide, GeoLite2 license key setup,
      privacy explainer for DoH/DNS and geo-IP)
      *(partial: privacy explainer done in `docs/privacy.md`; the rest needs the installers and UI)*
- [ ] Tag v1.0.0 release, publish to GitHub (tpt-solutions org)
- [x] Post-release triage process for bug reports

---

## Backlog / Future Phases (post-v1)
- [ ] macOS support
- [ ] Server/remote-host monitoring agent mode (GlassWire "Server" style)
- [ ] ARP-spoofing / suspicious-network-behavior detection beyond basic new-device alerts
- [ ] CLI (scriptable connection list/rule management)
- [ ] Archon backend implementation (post design-only phase, pending public network-capability
      primitives in `tpt-archon`)
