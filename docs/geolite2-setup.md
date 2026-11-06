# Setting up the map (GeoLite2)

Written for: people using the app, not developers.

The Map tab uses MaxMind's free GeoLite2 City database, which tpt-netguard downloads and keeps
on your computer. The map stays off until you complete these steps. Nothing else in the app
depends on it.

## 1. Get a free MaxMind license key

1. Create a free account at MaxMind.
2. Open the account page and generate a **license key** for GeoLite2.
3. Copy the key. Keep it private.

## 2. Enter the key in tpt-netguard

Open **Settings** and paste the key into **MaxMind license key**, then choose a location for
**GeoLite2 database file**, for example `C:\ProgramData\tpt-netguard\GeoLite2-City.mmdb` on
Windows or `~/.local/share/tpt-netguard/GeoLite2-City.mmdb` on Linux. Press **Save settings**.

The app then downloads the database. It checks at least every six hours and refreshes it once it
is more than a week old. MaxMind requires refreshing at least every 30 days.

If a refresh fails, the app keeps the copy it already has and records the error in the local
log (if you turned that on).

## 3. License and attribution

GeoLite2 data is provided by MaxMind under their end user license agreement. tpt-netguard shows
the required attribution in its NOTICE file and does not redistribute the database. Your key
and the database stay on your computer.

## Removing it

In Settings, tick **Remove the stored key** and clear the **GeoLite2 database file** path, then press **Save settings**.
The map switches off. Delete the `.mmdb` file to reclaim the space.

## Troubleshooting

- **"no GeoLite2 database configured"**: the path is blank. Set it in Settings.
- **"invalid MaxMind database"**: the file is damaged or is not a GeoLite2 City file. Delete it;
  the app downloads a fresh copy when the key is set.
- **Map shows no points**: connections to private addresses (your own network) are not placed on
  the map. Only public addresses with a known location appear.
