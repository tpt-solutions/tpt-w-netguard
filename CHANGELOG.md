# Changelog

All notable changes to tpt-netguard are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[SemVer](docs/versioning.md).

## [Unreleased]

### Added
- Cargo workspace with `core`, `dns`, `geoip` and placeholder platform crates.
- Core: connection/traffic model; `TrafficMonitor` and `FirewallBackend` traits; per-app
  aggregation; sampling scheduler with unfocused slow-down.
- Core: firewall decision logic (panic button, profile-scoped rules, fail-closed conflicts).
- Core: alerts engine (new app, new device, usage spike, inbound RDP/SSH/VNC) with mutes.
- Core: LAN device parsing (`/proc/net/arp`, `arp -a`), OUI vendor lookup, new-vs-known tracking.
- Core: SQLite history store with migrations, raw → hourly → daily rollups and retention.
- DNS: RFC 1035 wire format with defensive parsing; resolver with upstream fallback.
- Geo-IP: offline GeoLite2-City loading that degrades to disabled; connection-map aggregation.
- Frontend: TypeScript/Vite shell with the seven fixed tabs, keyboard navigation and a theme toggle.
- CI workflow (fmt, clippy, test on Windows and Linux).
- Documentation: README, privacy explainer, Archon design draft.

- Windows backend: IP Helper connection attribution and per-connection byte counters; WFP ALE
  enforcement with crash-safe dynamic filters and a panic-button filter.
- Linux backend: `/proc` socket attribution, capability detection, nftables panic button.
- Firewall manager with reconcile and rollback; service layer for validated UI commands.
- LAN discovery: subnet probing, neighbour reading, mDNS and NetBIOS naming, new-device alerts
  with a first-scan baseline.
- Encrypted DNS: DoH and DoT transports (tested against local servers), upstream configuration.
- Geo-IP: scheduled GeoLite2-City and GeoLite2-ASN refresh with validation and atomic replacement;
  an Owner column on the Graph tab names the network behind each remote address.
- Alerts: delivery pipeline (persist, then notify) and in-app feed.
- OS notifications for warning and critical alerts (Windows toast, Linux desktop notification).
- Linux per-app firewall rules through eBPF: connect and datagram-send hooks on the cgroup v2
  root, fork inheritance, exec-event checks with a 5 ms pending window, a kernel-level enforcement
  test, and an MIT-licensed object (no GPL-only helpers). See
  `docs/linux-ebpf.md`.
- Linux per-app bandwidth: TCP byte counters from the kernel's `sock_diag` interface, attributed
  to processes the same way connections are. Tested against live loopback traffic in a Linux
  container. UDP byte counters are not available.
- Map tab: each location shows the network owner (GeoLite2-ASN) that appears most often there.
- Accessibility: skip link to the active panel; the first-run walkthrough traps focus, closes
  with Escape (for this session only), returns focus afterwards, and makes the page behind it inert.
- Linux package removal deletes the block-all nftables table (`packaging/linux/prerm.sh`).
- Security review (`docs/security-review.md`) and the fixes it led to.
- Tests: parser scale test (50,000 sockets), monitor end-to-end attribution test, and the
  focus-cycle and settings-validation tests.
- Tray menu: "Recent alerts" submenu with the newest undismissed alerts.
- Graph tab: busiest-programs chart with a text legend.
- Connection list shows reverse-DNS names for routable remote addresses, looked up through the
  configured DoH/DoT resolver on worker threads and cached.
- Tauri desktop shell: commands, background sampler, throttled events, tray, first-run walkthrough,
  elevation manifest (release builds).
- Frontend: Graph, Usage, Firewall, Things, Map, Alerts and Settings tabs.
- Settings persistence, opt-in local error log (secrets redacted), Archon feature stubs.
- Linux elevation: polkit policy file and documentation.
- User guide, GeoLite2 setup guide, triage process, NOTICE with MaxMind attribution.
- CI: frontend job; Linux runners install WebKitGTK for the Tauri crate.

### Changed
- Core: `FirewallBackend` is implemented for boxed backends; manager rolls back refused changes.
- Platform crates depend on core without the SQLite feature.

### Not yet implemented
- ETW per-app bandwidth (deferred to post-v1); ALE classify-callback new-connection events
  (polling is used instead).
- UDP byte counters on Linux (no per-socket kernel counter exists; needs capture or eBPF).
- Installers built (unsigned by decision); tagged release (publishing is a separate step).
