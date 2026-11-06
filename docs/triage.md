# Post-release bug triage

Written for: maintainers.

## Intake

- Bugs come in through the issue tracker. Use the **Bug report** template: version, OS, what
  happened, what was expected, steps to reproduce.
- Security problems never go in a public issue. Report them privately to the maintainers (see
  `SECURITY` contact in the README once published). Do not paste exploit details in public.
- Logs: ask for `tpt-netguard.log` only after the reporter has read it. It can contain program
  paths. Never ask for the MaxMind license key; it should never appear in a log.

## Severity

| Severity | Meaning | Example | Target |
|---|---|---|---|
| S1 security or data | Traffic is exposed, a rule is silently not enforced, filters survive uninstall, or private data leaves the machine | Block rule shows "active" but traffic passes | Patch release within 7 days |
| S2 core broken | Monitoring stops, the app will not start, the panic button does not work | Panic button has no effect on Linux | Next patch release |
| S3 degraded | A feature works partly or with a workaround | Map off after GeoLite2 refresh | Next minor release |
| S4 cosmetic | Layout, wording, minor accessibility issues | Label cut off at narrow width | Backlog |

When in doubt, rate it one level higher and downgrade after reproduction.

## Triage steps

1. **Reproduce** on the stated version. If it does not reproduce within a week of asking, close
   it as "needs info" and say what would change that.
2. **Label**: severity, platform (`windows`, `linux`), area (`firewall`, `monitor`, `dns`,
   `geoip`, `alerts`, `ui`, `docs`).
3. **Confirm the root cause** in code, or record what was ruled out.
4. **Regression test first.** Add a test in the crate that owns the behaviour (core for policy,
   dns for wire parsing, and so on), then fix.
5. **Update the CHANGELOG** under the next version.

## Enforcement bugs need extra care

Anything that touches blocking is at least S2. Before closing, verify on the affected platform
with an elevated run:

- The block takes effect (the connection fails).
- Removing the rule restores connectivity.
- A crash or kill of the app removes the filters (Windows WFP filters are dynamic; Linux nftables
  table `tpt_netguard` is removed by `nft delete table inet tpt_netguard`).

## Releases

- Patch releases contain fixes only. No new features, no config format changes.
- Settings and history database migrations must be backward compatible within a minor series.

## Closing

Close with the version that contains the fix, and say whether a workaround remains. Link the
changelog entry.
