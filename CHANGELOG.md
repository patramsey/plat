# Changelog

All notable changes to `plat` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `EncodeJSON` and `EncodeNDJSON` produce the plat CLI's exact
  `schemaVersion: 1` JSON from a `Result` -- byte-identical to `-o json`
  for the same lookup, with `EncodeOptions{Raw}` to include embedded
  source payloads. `EncodeNDJSON` writes the same document as a single
  newline-delimited record; for one `Result` it emits the same bytes as
  `EncodeJSON`. NDJSON's value is streaming many `Result`s into one
  stream, mirroring the CLI's `-o ndjson` across multiple names -- not
  a different encoding of a single record. The schema version is
  exposed as the `SchemaVersion` constant.
- `Options.HTTPClient` now also covers the IANA bootstrap fetch that
  `New` performs, not just RDAP queries. Previously, a caller who set
  `HTTPClient` to route requests through a proxy still had `New` reach
  `data.iana.org` directly; a hung or blocked direct request fell back
  silently to the bootstrap snapshot embedded in the binary.

### Changed
- **Breaking:** `NewIPResolver` and `NewASNResolver` are removed.
  `NewResolver` now takes a single `ResolverConfig{Domains, Prefixes,
  ASNs}`, each field optional, in place of one constructor per object
  kind: `NewResolver(m)` becomes
  `NewResolver(ResolverConfig{Domains: m})`. The previous per-kind
  constructors made it easy to point plat at a private RDAP deployment
  for domains and, without noticing, lose RDAP coverage for every IP
  and ASN lookup -- a `Resolver` built from `NewResolver` alone reports
  no coverage for those kinds, so lookups of them fall back to
  WHOIS-only, silently. Nothing in this repo's CI catches a break like
  this automatically, so a consumer finds out at their own `go build`.
  The API remains v0 and may still change before 1.0.

## [0.4.0] - 2026-08-19

### Added
- `--file <path>` reads names from a file, one per line, with blank lines
  and `#` comments skipped; `--file -` reads stdin. `--concurrency N`
  (default 4) controls how many names are looked up in parallel, and
  applies to names given on the command line too. Results are emitted in
  input order regardless of which lookups finish first, so two runs of the
  same list produce identical output. WHOIS queries are paced per server
  -- including referral hops to registrar servers -- so a large single-TLD
  list cannot hammer one server; the pace is a fixed conservative interval
  that no CLI flag changes (the Go library added below can tune it).
  `--timeout` bounds the time a lookup spends
  talking to servers, so a name waiting its turn for a paced server is
  never timed out before it gets to ask -- pacing costs wall time, never
  a source. A single name is unaffected: no pacing, no pool, no progress
  output.
- `--diff <snapshot.json>` compares a fresh lookup against a previously
  saved `-o json` snapshot and reports what changed -- expiry,
  nameservers, status, and every other merged field. Exits 4 when
  anything changed, 0 when nothing did; exit codes 1, 2, and 3 keep
  their existing meanings. Works for domains, IPs, and ASNs. Compares
  values only: source provenance and conflicts are ignored, so a source
  simply dropping out of one run does not by itself register as a
  change. It can still surface one if the remaining sources disagree on
  a field's precision, or if the dropped source was the only one
  supplying a field -- e.g. an ASN lookup losing registry-rdap falls
  back to registry-whois's date-only `Registered`/`Updated` timestamps
  (`2000-03-30T05:00:00Z` -> `2000-03-30T00:00:00Z`) and loses `Status`
  entirely, since only RDAP supplies it; both are real differences
  between the two merged records, not noise.
  Snapshots saved before v0.3.1 (whose nameserver and status lists were
  unsorted) compare correctly, since lists are compared as sets.
- The lookup engine is now importable as a Go library, at
  `github.com/patramsey/plat` (`go get github.com/patramsey/plat`), with
  no need to shell out to the `plat` binary. `plat.New` builds a
  `Client`; `Client.Lookup` runs one domain, IP, or ASN lookup and
  returns a merged, provenance-annotated record. A `Client` should be
  built once and reused across lookups -- it holds the IANA bootstrap
  data and a per-server WHOIS pacing limiter, and constructing a fresh
  one per name throws both away. Per-field provenance, the CLI's core
  idea, comes through unchanged: every field is a `Field[T]` carrying
  its merged value and the sources that supplied it. A failing source
  is not an error -- `Lookup` returns successfully as long as one
  source answers, with per-source detail in the record's `Sources`
  field. The record types (`Record`, `IPRecord`, `ASNRecord`, and their
  component types) are aliases to internal types, so `internal/` stays
  private and free to change underneath the public API. The JSON,
  human, and plain renderers are not exposed by this package, so a
  library consumer cannot currently produce plat's documented
  `schemaVersion: 1` output from a `Result` -- that remains CLI-only.
  Per-server WHOIS pacing is on by default and is tunable here, unlike
  from the CLI: `Options.WHOISInterval` sets the interval and
  `Options.DisableWHOISPacing` turns it off. Pacing is not free for
  every single lookup -- when one lookup's referral chain queries the
  same WHOIS host twice, which happens when a registry refers the
  registrar query back to that host, the second query waits the full
  interval. That is why the option exists, and why plat's own CLI
  disables pacing for single-name runs, leaving single lookups exactly
  as fast as before. This API is v0 and may change before 1.0.

### Changed
- Internal maintenance: the RDAP fetch path and two merge helpers each
  existed as separate near-identical copies per object type -- three
  copies of the fetch-and-parse core, three of the source-record filter,
  and two of the status union. Each is now a single generic. No behavior
  change: output for a domain, an IP, and an ASN is byte-identical to the
  previous build across `-o json`. Domain status merging deliberately
  keeps its own EPP-specific step and is not shared with IP/ASN status,
  since RIR status strings use no `client`/`server` prefix convention;
  a test pins that asymmetry in both directions.

## [0.3.2] - 2026-08-12

### Fixed
- IP and ASN lookups no longer advertise source codes that cannot apply
  to them. Both renderers printed the same fixed four-source legend
  (`RR registrar-rdap  GR registry-rdap  RW registrar-whois  GW
  registry-whois`) for every object type, but an IP allocation or an
  autonomous system is registered directly with an RIR and has no
  registrar at all -- so `RR`/`RW` explained badges that could never
  appear, reading as "plat failed to reach the registrar" rather than
  "no such source exists". IP and ASN records now show only
  `GR registry-rdap  GW registry-whois`. Domain output is unchanged, and
  all four codes remain correct there. Affects the human and plain
  renderers; JSON/NDJSON carry full source names and were never
  affected.

## [0.3.1] - 2026-08-12

### Fixed
- LACNIC-held IP lookups (`plat 200.3.12.1`, etc.) no longer silently
  drop registry-WHOIS data. `internal/whois/parse/ip.go` was missing
  LACNIC's RPSL vocabulary for org name (`owner`), org ID (`ownerid`),
  and last-modified (`changed`) -- the identical gap already fixed for
  ASN lookups in `internal/whois/parse/asn.go`, but never ported to the
  IP parser. Organization and Updated now correctly show both
  `registry-rdap` and `registry-whois` provenance instead of appearing
  RDAP-only with no conflict to reveal the missing source.
- `-o json` and `-o ndjson` are now byte-reproducible across runs. The
  `nameservers` and `status` arrays are sorted, so repeated lookups of an
  unchanged domain, IP, or ASN produce identical output. Previously the
  order tracked whatever the highest-precedence source returned, and at
  least one registrar's RDAP server returns nameservers in a different
  order on every request -- so diffing two runs, or hashing the output,
  saw spurious changes. Values and source attribution are unaffected;
  only ordering changed, so `schemaVersion` stays 1.

### Changed
- Internal maintenance: `internal/whois/parse`'s IP and ASN WHOIS parsers
  shared the same vocabulary (org name, org ID, country, dates, abuse
  contacts) in two separately maintained lookup tables that had already
  drifted out of sync twice -- once for `status`, once for LACNIC's
  `owner`/`ownerid`/`changed` keys (see above). The shared vocabulary is
  now declared once (`commonFields`) and lifted into both parsers' tables,
  and `TestCommonVocabularyReachesBothParsers` fails if a future shared
  key is ever added for only one of them. No behavior change: outputs for
  `example.com`, `8.8.8.8`, `193.0.6.139`, `200.3.12.1`, `AS15169`,
  `AS3333`, and `AS28573` are byte-identical to the pre-refactor build.
  One latent difference: `ParseASN` now also recognizes `ownerid` (the
  pre-refactor `asnSynonyms` lacked it, unlike its IP counterpart). No
  ASN golden response carries that key today, so nothing observable
  changes; it's noted here because a future LACNIC ASN response that
  does carry it will now be parsed correctly instead of silently
  dropped.

## [0.3.0] - 2026-08-11

### Added
- ASN lookups. `plat AS15169` (the `AS` prefix is required) now finds the
  RIR holding the autonomous system and queries its RDAP and WHOIS,
  merging the result with the same per-field provenance as a domain or IP
  lookup. There's no registrar leg -- only `registry-rdap`/
  `registry-whois` ever appear as sources -- and the record's fields are
  an autonomous system's own (handle, AS name, start/end autnum range,
  holding organization) rather than a domain's or netblock's. `-o json`
  sets `"objectType": "asn"` to distinguish the shape from a domain or IP
  record's, an additive change that leaves `schemaVersion` at 1 and
  existing output otherwise unchanged. A bare number (`plat 15169`) is
  not treated as an ASN lookup, since it's likelier a typo'd domain.

## [0.2.0] - 2026-08-10

### Added
- IP-address lookups. `plat 8.8.8.8` (or any IPv4/IPv6 address) now
  finds the RIR holding the containing netblock and queries its RDAP
  and WHOIS, merging the result with the same per-field provenance as
  a domain lookup. There's no registrar leg -- only `registry-rdap`/
  `registry-whois` ever appear as sources -- and the record's fields are
  a netblock's own (handle, CIDR, start/end address, parent handle,
  holding organization) rather than a domain's. `-o json` sets
  `"objectType": "ip"` to distinguish the shape from a domain record's
  `"objectType": "domain"`, an additive change that leaves
  `schemaVersion` at 1 and domain output otherwise unchanged.
  Reserved/private addresses (`10.0.0.1`, `127.0.0.1`, `::1`, ...) exit
  2 with a friendly error, since no RIR allocates them to an
  organization.

### Removed
- The hidden `plat whois` and `plat merge` debug subcommands, dev-only
  scaffolding used to prove the WHOIS engine and merge engine end to end
  before `--source`/`-o` existed. Both were `Hidden: true` (never in
  `--help`) and strictly inferior to `--source whois -o plain -v`, which
  supersedes them with full parsed output and provenance. No documented
  interface changes. See #45.

### Fixed
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

[Unreleased]: https://github.com/patramsey/plat/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/patramsey/plat/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/patramsey/plat/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/patramsey/plat/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/patramsey/plat/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/patramsey/plat/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/patramsey/plat/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/patramsey/plat/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/patramsey/plat/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/patramsey/plat/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/patramsey/plat/releases/tag/v0.1.0
