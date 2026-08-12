# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

Shipped and released — latest tag `v0.3.1`. The module is scaffolded, 14 packages under `cmd/` and `internal/`, released via goreleaser (binaries, checksums, Homebrew tap).

Working today: domain lookups, IP-address lookups, and ASN lookups — each merged from RDAP and WHOIS with per-field provenance, rendered human/plain/JSON/NDJSON.

`plat-plan.md` is the original design document. It remains useful for the *reasoning* behind the architecture, data model, and CLI surface, but it is **no longer authoritative on current state** — it predates the IP and ASN features and describes work as unstarted that has since shipped. Where the plan and the code disagree, the code wins. Prefer reading the code, `README.md`, and `CHANGELOG.md` for what exists now.

## What plat is

A Go CLI that looks up ownership of a **domain, IP address, or autonomous system** by querying WHOIS and RDAP concurrently, merges the results into one record with **per-field provenance** (which source supplied each value, and where sources conflict), and renders it via a styled terminal UI (Lip Gloss v2) or stable JSON.

For domains the two sources are registry and registrar; for IPs and ASNs they are the responsible RIR's RDAP and WHOIS. All three object types share the same merge engine, provenance model, and renderers.

## Commands

Standard Go tooling:
- Build: `go build ./...`
- Test: `go test ./...` (single package: `go test ./internal/merge/...`)
- Lint: `golangci-lint run`
- Release: `goreleaser` (binaries + checksums + Homebrew tap)
- Demo GIF: `vhs` (charmbracelet/vhs)

Live/integration tests are opt-in via build tag: `go test -tags=live ./...` — excluded from CI, hits real WHOIS/RDAP infra.

## Architecture

```
cmd/plat/                # main.go, cobra root command, gendocs (man/completions)
internal/
  domain/                # input normalization: lowercase, IDN -> punycode, validation
  bootstrap/             # IANA RDAP bootstrap (dns.json) fetch + cache + go:embed fallback
  rdap/                  # RDAP client: registry query + registrar link-following
  whois/                 # WHOIS client: port-43 dialer + referral chasing
    parse/               # heuristic key/value parser + per-registry quirks
  collect/               # concurrent fan-out: registry/registrar RDAP + WHOIS -> SourceRecords
  model/                 # unified Record types, provenance types
  merge/                 # merge engine: source records -> unified Record
  render/
    human/                # lipgloss-styled TTY output
    plain/                # no-frills text for pipes
    machine/              # JSON / NDJSON encoders
  spinner/               # animated progress indicator for long-running lookups
testdata/                # golden files: recorded RDAP JSON + WHOIS blobs
```

Each RDAP/WHOIS client (`internal/rdap`, `internal/whois`) carries its own
small timeout/dialer/user-agent defaults rather than sharing a `netx`
package — their retry and connection-handling needs (HTTP client vs. raw
`net.Dialer`) diverged enough that a shared abstraction wasn't worth it.

### Lookup flow (`plat example.com`)

1. Normalize input (lowercase, strip scheme, IDN -> punycode via `golang.org/x/net/idna`; keep Unicode for display).
2. Resolve the TLD's RDAP base URL from the cached IANA bootstrap file.
3. Fan out concurrently (`errgroup`, per-source contexts, 5s default timeout):
   - Registry RDAP (`GET {bootstrap-url}/domain/{name}`)
   - Registry WHOIS (resolve TLD server via `whois.iana.org`)
   - Registrar RDAP and registrar WHOIS are **dependent second hops** (followed from the registry responses' `related` link / `Registrar WHOIS Server:` referral), not parallel branches.
4. Each source yields a `SourceRecord` (normalized fields + raw payload + latency + errors) — a source erroring is normal, not fatal.
5. The merge engine combines sources into one `Record` with provenance and a conflict list.
6. The renderer selected by flags/TTY detection emits output.

### Data model

Every field is a `Field[T]` carrying both its value and the list of sources that supplied it (`registry-rdap | registrar-rdap | registry-whois | registrar-whois`) — this per-field provenance is the core differentiator of the tool, not an afterthought. Dates normalize to UTC RFC 3339 (WHOIS needs a tolerant multi-format parser). Status codes normalize to EPP names across RDAP (RFC 8056) and WHOIS vocabularies. GDPR redaction is modeled explicitly (not treated as a literal contact name) — recognize RDAP remarks/RFC 9537 `redacted` extension signals.

### Merge precedence

Most to least trusted, per field: **registrar RDAP → registry RDAP → registrar WHOIS → registry WHOIS** (RDAP is structured; registrar data is thick where registry data is thin, e.g. .com). Exceptions:
- A redacted value never beats a populated value regardless of source rank.
- Timestamp disagreements beyond ~24h clock-skew tolerance become a recorded `Conflict`, keeping the highest-precedence value.
- Nameserver sets union together; genuinely differing sets (not just case/trailing-dot) are flagged as conflicts.
- Disagreements are never silently dropped — they surface in both human and JSON output.

### Protocol quirks to preserve

- **WHOIS server quirks** (Verisign domain-prefix handling, .jp `/e` suffix, DENIC `-T dn,ace`, etc.) belong in a per-server rules table, not scattered `if` statements.
- **WHOIS parsing**: generic `key: value` extraction with a synonym table, then per-registry template overrides for irregular formats (.de, .uk indentation, .jp brackets). Templates should be data-driven (embedded YAML) so adding registry coverage is a small PR, not a code change.
- **RDAP client**: `Accept: application/rdap+json`, follow redirects, distinguish 404 (not found) from network errors, handle 429 + `Retry-After` with one polite retry. Prefer hand-rolling (~300 lines, RFC 9083 structs) over `github.com/openrdap/rdap` to avoid its cache/bootstrap opinions.
- Reject single-label input, reject private/reserved TLDs (.internal, .local) with a friendly error, handle trailing dots and `xn--` input.

### Exit codes

`0` any source returned data · `1` domain-not-found on all sources · `2` usage error · `3` total lookup failure.

## Rendering (Lip Gloss v2)

This is a render-and-exit tool for v1 — **not** an interactive Bubble Tea app (that's a stretch goal). Key v2-specific constraints from the plan:
- Print via Lip Gloss writer functions (`lipgloss.Println`/`Sprint`/`Fprint`), not raw `fmt` — they handle color downsampling and strip ANSI on non-TTY automatically, which is most of the pipe-safety requirement.
- Detect background explicitly once at startup via `lipgloss.HasDarkBackground(os.Stdin, os.Stdout)`. Do **not** use the v2 `compat` adaptive-color package — it's a v1-migration shim, not for new code.
- Respect `NO_COLOR` and non-TTY by routing to the `plain` renderer (aligned `key: value`, zero ANSI) rather than trying to strip ANSI after the fact.
- Import path is `charm.land/lipgloss/v2`.

## Machine output contract

`-o json` emits the unified `Record` (camelCase, `"schemaVersion": 1`, provenance per field, RFC 3339 timestamps) — treat this schema as a public API; breaking changes bump `schemaVersion`. `--raw` adds embedded raw source payloads. `-o ndjson` for multi-domain invocations. Errors in machine mode still go to stderr as JSON; stdout stays schema-clean.

## Testing approach

- Golden files in `testdata/` (recorded real RDAP JSON + WHOIS blobs) covering ~20 representative domains: thin .com, thick .org, GDPR-redacted .eu/.de, no-RDAP ccTLD, IDN, expired domain, rate-limited response. Parser/merge tests run fully offline against these.
- `httptest` for mocking RDAP; a small local TCP listener for WHOIS to test referral chasing, timeouts, and per-server quirks.
- Merge engine gets table-driven tests over precedence, redaction override, and conflict detection.
- Renderer snapshot tests run with color forced off.
- Goldens for IP/ASN cover all five RIRs (ARIN, RIPE, APNIC, LACNIC, AFRINIC), whose WHOIS vocabularies genuinely differ. **Every serious bug in the IP and ASN features surfaced only past ARIN** — verify live against multiple RIRs, not just the first one that works.
- CI enforces a 90% whole-project coverage floor (`go tool cover`, actual ~95%). Codecov's `project` status does not post on this repo, so that floor is the real gate — see the comments in `.github/workflows/ci.yml` and `codecov.yml`, which explain why the two numbers there are not interchangeable.

## Demo GIF maintenance

`README.md`'s demo GIF is recorded from `docs/demo.tape` via `vhs docs/demo.tape` (requires `vhs`, plus its `ffmpeg`/`ttyd` runtime deps). Regenerate it whenever a change touches what the commands in that script print — flags, output formatting, or the sample domains' field values — so the GIF never goes stale relative to the tool it's demonstrating.

**Known gap:** the tape's three commands are all domain lookups. IP and ASN lookups shipped after it was written and are not demonstrated, so the GIF undersells the tool. Adding them means re-recording, which needs `vhs` installed locally.

## Non-goals

**IP and ASN lookups were once listed here and have since shipped** (v0.2.0 and v0.3.0) — don't re-add them.

Still out of scope: availability monitoring, watch mode, historical WHOIS archiving, acting as a WHOIS/RDAP server. Design internals to not preclude these, but don't build them.

Deferred rather than rejected, each tracked as an open issue: `--diff` between runs (#33), bulk mode (#34), interactive Bubble Tea mode (#35), extracting `internal/` as a public library (#36). #50 tracks the remaining duplication across the three object types — the parser vocabulary half is done; the fetch trio, `presentSorted`×3, `status`×3, and the two adapters are deliberately left alone, since none has ever caused a bug.
