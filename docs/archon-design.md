# Archon backend — design sketch (draft)

Status: **design only**. No Archon code exists in this repository, and none will ship until the
open questions below are answered by the tpt-archon team.

Reference: https://github.com/tpt-solutions/tpt-archon

## Premise

tpt-netguard's core is platform-neutral: `TrafficMonitor` and `FirewallBackend` in
`core/src/traits.rs` are the only seams an Archon backend has to satisfy. The Windows and Linux
backends are the reference points for behaviour; Archon would be a third implementation of the
same two traits.

## Capability gap (must be resolved upstream)

Both traits need the kernel to expose network state and network enforcement to a user-space
service:

- `TrafficMonitor` needs read access to active connections, per-connection byte counters and new
  connection events.
- `FirewallBackend` needs the ability to allow or block a connection per application.

**Unverified claim:** an earlier draft stated that tpt-archon's capability system has only
`Resource::Page` and `Resource::Channel`, "confirmed against source". Re-checking the public
repository page (the source tree was not browsable from here) found that the README names a
`Resource::Device` capability for the user-space driver framework, and mentions neither `Page`
nor `Channel`. The "confirmed" wording has been removed. Until the `Resource` enum is read from
`tpt-archon-kernel` source by someone with access, treat its variants as unknown. Nothing in the
README describes a socket or network capability.

## Open questions (for the tpt-archon team)

1. Is a `Resource::Socket` or `Resource::Network` capability planned? Which operations would it
   gate: observe, enumerate, or enforce?
2. What IPC or channel shape would carry connection and bandwidth telemetry? Is a streaming
   channel with backpressure available, or do we poll?
3. How would per-application firewall decisions map onto capability grants and revocation? Is a
   block a revoked grant, or a separate policy object?
4. Performance target against the current cooperative, single-threaded-per-task scheduler: how
   often can a sampler run without starving the UI, and does the scheduler support timers?

## Planned shape (post-v1)

- Cargo feature `archon`, off by default.
- `ArchonTrafficMonitor` and `ArchonFirewallBackend` stubs.
- `is_available()` returns `false` and every method returns `Error::Unsupported` until the
  upstream primitives exist, so the app runs unchanged on Archon.
- The UI's Archon mode is hidden while `is_available()` is `false`.
