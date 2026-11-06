# Versioning and release process

## Version scheme

tpt-netguard uses [Semantic Versioning](https://semver.org/). Until 1.0.0 the public surface
(IPC commands, history database schema, rule format) may change between minor versions, and every
such change is listed under **Changed** or **Removed** in `CHANGELOG.md`.

- **MAJOR**: incompatible changes to the IPC surface, or a database schema change that cannot be
  migrated automatically.
- **MINOR**: new features, new platform support, backwards-compatible schema migrations.
- **PATCH**: bug and security fixes only.

The history database carries its own schema version (`PRAGMA user_version`, see
`core/src/store.rs`). The app refuses to open a database written by a newer schema rather than
risk corrupting it.

## Changelog process

1. Every change that is visible to a user, or that affects the IPC surface, the database, or the
   rule format, adds a line under `## [Unreleased]` in `CHANGELOG.md` in the same pull request.
2. Entries use the Keep a Changelog headings: Added, Changed, Deprecated, Removed, Fixed, Security.
3. Releasing moves the Unreleased entries under a new `## [x.y.z] - YYYY-MM-DD` heading and
   updates the version in `Cargo.toml` (workspace) and `package.json`.

## Release checklist

- [ ] `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, and
      `cargo fmt --all -- --check` pass on Windows and Linux CI.
- [ ] Frontend `npm run build` and `npm test` pass.
- [ ] `CHANGELOG.md` is updated and the version is bumped.
- [ ] Release artifacts include `LICENSE-MIT`, `LICENSE-APACHE`, and the MaxMind GeoLite2
      attribution notice (required whenever the geo-IP database is bundled or downloaded).
- [ ] The tag `vX.Y.Z` is created on the release commit.
