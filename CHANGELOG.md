# Changelog

All notable changes to `plat` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.2] - 2026-08-02

### Added
- `--no-color` flag, equivalent to the existing `NO_COLOR` environment
  variable.
- `-q`/`--quiet` flag: a one-line summary per domain (lock status,
  expiry, conflict count) instead of the full view. Ignored for `-o
  json`/`-o ndjson`.

### Fixed
- `.eu` domains: the registrar name wasn't parsed out of EURid's nested
  WHOIS structure (`Registrar:` header with the name on an indented
  `Name:` line beneath it).

## [0.1.1] - 2026-08-01

### Fixed
- `plat version` (and the release binaries generally) embedded the full
  40-character git commit SHA instead of the short form.
- The Homebrew tap push now uses its own cross-repo token — the default
  Actions token can't push to a separate repository.
- The Homebrew formula now publishes into the tap's `Formula/` directory
  instead of the repo root, where `brew` couldn't find it.

### Added
- `--version` flag on the root command, equivalent to `plat version`.
- `plat version -o json` for machine-readable version output.
- `plat version --full` to include the Go compiler version and target
  platform.

## [0.1.0] - 2026-08-01

Initial public release.

### Added
- Domain lookup via RDAP and WHOIS, queried concurrently from both
  registry and registrar, merged into one record with per-field source
  provenance.
- Styled human terminal view, plain-text output, and a versioned
  JSON/NDJSON schema.
- GDPR-aware redaction handling and explicit conflict detection.
- `goreleaser`-based release pipeline: binaries, checksums, and a
  Homebrew tap.
- Man pages and shell completions generated at build time.

[Unreleased]: https://github.com/patramsey/plat/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/patramsey/plat/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/patramsey/plat/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/patramsey/plat/releases/tag/v0.1.0
