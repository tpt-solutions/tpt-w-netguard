# Linux: running with the rights it needs

tpt-netguard needs two kinds of privilege on Linux:

| Feature | Needs | Why |
|---|---|---|
| Panic button (block all) | `CAP_NET_ADMIN` | nftables rules in `inet tpt_netguard` |
| Per-app rules (future eBPF) | `CAP_BPF`, `CAP_NET_ADMIN`, sometimes `CAP_PERFMON` | cgroup `connect4`/`connect6` programs |
| Connection list | none | `/proc/net` and `/proc/<pid>/fd` are readable for your own processes; other users' processes show as unowned |

The app checks its own capabilities at startup (`CapEff` in `/proc/self/status`). If a
capability is missing, the app starts in monitor-only mode and the Settings tab says why.

## Option 1: launch with polkit (desktop users)

Install the policy file so graphical launches ask for authentication:

```sh
sudo install -m 644 packaging/linux/com.tpt.netguard.policy /usr/share/polkit-1/actions/
```

The desktop entry should start the app through `pkexec`:

```
Exec=pkexec /usr/bin/tpt-netguard
```

polkit then shows the standard authentication dialog. The action id is `com.tpt.netguard.run`.

## Option 2: grant capabilities to the binary (no root at run time)

```sh
sudo setcap cap_net_admin,cap_bpf,cap_perfmon,cap_net_raw+ep /usr/bin/tpt-netguard
```

Check with `getcap /usr/bin/tpt-netguard`. Capabilities on a file are lost when the file is
replaced, so re-apply after every upgrade (the package scripts should do this). Drop
`cap_bpf` and `cap_perfmon` if you only want the panic button.

## Option 3: systemd unit with ambient capabilities

For a long-running background monitor, a unit file can grant capabilities without setting
them on the binary:

```ini
[Service]
ExecStart=/usr/bin/tpt-netguard --headless
AmbientCapabilities=CAP_NET_ADMIN CAP_BPF CAP_PERFMON CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_BPF CAP_PERFMON CAP_NET_RAW
NoNewPrivileges=yes
```

`--headless` is not implemented yet; this option is documented for the planned service mode.

## Root

Running as root (`sudo tpt-netguard`) grants everything. It is the simplest option and the one
used during development. Prefer options 1 or 2 for everyday use.

## Verifying

```sh
grep CapEff /proc/$(pgrep -n tpt-netguard)/status
```

Decode the hex mask: bit 12 is `CAP_NET_ADMIN`, bit 39 is `CAP_BPF`, bit 38 is `CAP_PERFMON`.

## Packages

- `.deb` and `.rpm` bundles declare a dependency on `nftables`.
- The installer should not set capabilities automatically; choose option 1 or 2 explicitly.
