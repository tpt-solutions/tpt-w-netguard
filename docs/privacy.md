# Privacy explainer

tpt-netguard watches the network activity of this machine. This page says exactly what data
leaves the machine, and what does not. It describes the code as it is in this repository; if a
feature in this document is not yet implemented, it says so.

## What stays on this machine

- **Traffic history**: per-app byte counts, connection logs and alerts are stored in a local
  SQLite file. Retention defaults to 30 days and is configurable.
- **Connection attribution**: which process owns which connection is read from the local operating
  system.
- **LAN devices**: MAC addresses, vendor names and any labels you assign are stored locally. The
  app reads the local neighbour (ARP) table; it does not scan networks beyond what the OS already
  lists.
- **Firewall rules**: stored locally and enforced by the operating system (WFP on Windows,
  nftables and eBPF on Linux).

## Geo-IP is offline

The connection map uses a local copy of the MaxMind GeoLite2-City database. Connection addresses
are looked up on your machine. **No per-connection lookup is sent to any third party.** Without a
database, the Map tab is disabled and nothing else changes.

## Encrypted DNS is only for the app

When the app needs a hostname for a remote address (to label the connection list or a device), it
asks a DNS-over-HTTPS or DNS-over-TLS resolver that you configure. **This applies only to the
app's own lookups.** The app does not proxy, intercept or reconfigure the system's DNS, and your
other applications keep using whatever resolver the OS is set to.

Status: the resolver logic (message format, fallback, rejection of spoofed responses) is
implemented. The DoH and DoT network transports are not yet implemented, so today the app makes
no DNS queries of its own.

## What the app never does

- It does not send telemetry, crash reports or usage data anywhere. Crash reporting, when added,
  is opt-in and stored locally (roadmap Phase 13).
- It does not require an account.
- It does not inspect packet contents. It records byte counts and connection metadata only.

## Your control (the Settings and Alerts UI is not built yet; these are the planned controls)

- Clear or shorten the retention window in Settings.
- Mute or dismiss any alert, and mark devices as trusted or rename them.
- Use the panic button to block all internet access for every application at once.
