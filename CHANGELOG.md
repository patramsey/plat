# Changelog

All notable changes to `plat` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- IP-address lookups. `plat 8.8.8.8` (or any IPv4/IPv6 address) now
  finds the RIR holding the containing netblock and queries its RDAP
  and WHOIS, merging the result with the same per-field provenance as
  a domain lookup. There's no registrar leg -- only `registry-rdap`/
  `registry-whois` ever appear as sources -- and the record's fields are
  a netblock's own (handle, CIDR, start/end address, parent handle,
  holding organization) rather than a domain's. `-o json` sets
  `"objectType": "ip"` to distinguish the shape from a domain record's
  `"objectType": "domain"`. This supersedes 0.1.5's IP-input rejection
  below: reserved/private addresses (`10.0.0.1`, `127.0.0.1`, `::1`,
  ...) still exit 2 with a friendly error, since no RIR allocates them
  to an organization, but an ordinary public address now returns real
  data instead of exiting 2 outright.

### Removed
- The hidden `plat whois` and `plat merge` debug subcommands, dev-only
  scaffolding used to prove the WHOIS engine and merge engine end to end
  before `--source`/`-o` existed. Both were `Hidden: true` (never in
  `--help`) and strictly inferior to `--source whois -o plain -v`, which
  supersedes them with full parsed output and provenance. No documented
  interface changes. See #45.

## [0.1.5] - 2026-08-05

### Fixed
- IP-address input is now rejected with a clear error instead of
  producing a meaningless record. `plat 8.8.8.8` previously exited 0 and
  emitted a schema-clean record built from a WHOIS response about the
  "TLD" `8`; bare IPv6 leaked an IDNA library internal rather than a
  friendly message. IPv4, IPv6, bracketed IPv6, and CIDR input now exit 2
  and point at the issue tracking real RDAP IP-object support. Domains
  whose labels are numeric (`123.com`) are unaffected.
- Lifecycle stage text misattributed two of its three timeline durations
  to ICANN policy. Only the 30-day Redemption Grace Period is actually
  ICANN-mandated (Expired Registration Recovery Policy §3.1); the 45-day
  Auto-Renew Grace and 5-day Pending Delete figures are common registry
  conventions. The Auto-Renew Grace description now also states plainly
  that ICANN leaves the timing of that stage entirely to the registrar's
  discretion.

## [0.1.4] - 2026-08-04

### Added
- Lifecycle interpretation for expired gTLD domains: a plain-language
  explanation of where a domain sits in ICANN's Expired Domain Deletion
  Policy timeline (Auto-Renew Grace / Redemption Grace / Pending Restore
  / Pending Delete), with a clearly-labeled, estimated end date where one
  can be computed. Shown in JSON (`lifecycle`), the human view, and the
  plain view. Not shown for ccTLDs or internationalized (IDN) TLDs, which
  set or can't be reliably classified against ICANN's gTLD policy.

### Fixed
- Some registrar RDAP servers (e.g. GoDaddy's) report a bare, ambiguous
  status alongside the properly client/server-prefixed EPP status for the
  same restriction (e.g. both `transferProhibited` and
  `clientTransferProhibited`) — `status` now drops the redundant bare
  form when a prefixed variant is already present.

## [0.1.3] - 2026-08-02

### Changed
- Release archive filenames no longer include the version number (e.g.
  `plat_darwin_arm64.tar.gz` instead of `plat_0.1.2_darwin_arm64.tar.gz`),
  so the Releases page's "latest" download links stay valid across
  releases.

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

[Unreleased]: https://github.com/patramsey/plat/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/patramsey/plat/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/patramsey/plat/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/patramsey/plat/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/patramsey/plat/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/patramsey/plat/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/patramsey/plat/releases/tag/v0.1.0
