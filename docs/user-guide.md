# tpt-netguard user guide

Written for: people using the app, not developers.

## Installing

Download the installer for your system from the release page:

- **Windows**: the `.msi` or `-setup.exe` installer. Windows asks for administrator permission
  at launch. Say yes: blocking programs and reading per-connection byte counts need it. If you
  say no, the app still opens and shows what is monitored, with a note explaining that blocking
  is off.
- **Linux**: the `.deb`, `.rpm` or `.AppImage`. Blocking needs the `CAP_NET_ADMIN` capability
  (or root). See [linux-elevation.md](linux-elevation.md) for the three ways to grant it.

## The tabs

- **Graph**: live bandwidth and the connections using the most data.
- **Usage**: how much each program has used over the last hour, day, week or month. Click a
  program to see its history.
- **Firewall**: block or allow a program, optionally only on a particular network. The header
  **Block all internet** button overrides every rule until you press it again.
- **Things**: devices found on your local network. Give them names, and mark devices you trust
  so they stop raising new-device alerts.
- **Map**: where your connections go, drawn from a local database. Needs a GeoLite2 file; see
  [geolite2-setup.md](geolite2-setup.md).
- **Alerts**: things worth a look, such as a new program connecting for the first time, a new
  device on your network, unusually heavy use, or someone connecting to remote desktop (or SSH
  and VNC on Linux). You can dismiss an alert or stop alerts for that program or device.
- **Settings**: how long history is kept, the DNS resolvers the app uses for names, the usage
  alert threshold, and the optional local error log.

## Privacy

- Nothing about your activity is sent to anyone. History stays in a database on your computer.
- The map uses a database stored on your computer. No connection is looked up online.
- Names for addresses are looked up through the encrypted DNS resolvers you choose in
  Settings. The app does not change your system's DNS.
- The optional error log is off by default and stays on your computer. It never contains your
  MaxMind license key.

For the technical details, see [privacy.md](privacy.md).

## When something does not work

- **"Firewall enforcement unavailable"** on Windows: run the app as administrator.
- **Per-program byte counts are zero on Windows**: the byte counters need administrator
  rights. Blocking may still work if you have them.
- **Linux per-program byte counts are not shown**: not implemented yet. Connections and the
  block-all switch work.
- **No devices or map yet**: the first device scan runs a few minutes after start, and the map
  needs a GeoLite2 database.

If you want to send a bug report, turn on the error log in Settings, reproduce the problem, and
attach `tpt-netguard.log` from the app data folder. Read it first: it contains program paths.
