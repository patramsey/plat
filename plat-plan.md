# plat — Project Plan

A unified domain ownership lookup CLI that queries both legacy WHOIS and modern RDAP, merges the fragmented results into a single coherent record with per-field provenance, and presents it through a polished terminal UI. Written in Go.

**Name:** `plat` — a plat is a surveyor's official map of land parcels showing boundaries and ownership. That's exactly what this tool draws for a domain: one authoritative ownership picture assembled from fragmented sources. Four letters, impossible to misspell, satisfying to type.

Alternate candidates if a collision surfaces: `terrier` (archaic term for a register of land holdings; also a dog that digs relentlessly), `folio` (the individual property record in Torrens-style land registries). **First task: verify no meaningful GitHub/pkg.go.dev/Homebrew collision for `plat` before scaffolding the module path.** Note: `rdapper`, `whodis`, and `whodap` are already taken by existing WHOIS/RDAP tools; avoid those.

---

## 1. Problem Statement

Domain registration data lives in two parallel worlds:

- **WHOIS** (RFC 3912): plaintext over TCP port 43, no schema, wildly inconsistent formats per registry/registrar, referral chains you must follow manually (IANA → registry → registrar).
- **RDAP** (RFC 7480–7484, 9082, 9083): JSON over HTTPS, structured, bootstrapped via IANA — but coverage is incomplete (many ccTLDs have no RDAP), registrar RDAP quality varies, and contact data is often GDPR-redacted differently than WHOIS.

No single source is complete. Registry data and registrar data differ (thin vs. thick). RDAP and WHOIS for the same domain often disagree or redact different fields. Users today run `whois`, squint at unparseable text, then try an RDAP client, then diff mentally.

**plat queries all four sources in parallel — registry RDAP, registrar RDAP, registry WHOIS, registrar WHOIS — merges them into one unified record, and shows you where every field came from.**

## 2. Goals

1. Single command (`plat example.com`) returns the most complete picture of domain ownership available.
2. Query all applicable sources concurrently; degrade gracefully when any source is missing, slow, or garbage.
3. Unified data model with **per-field provenance** (which source(s) supplied each value, and whether sources conflict).
4. Human output: modern, styled terminal rendering (Charm ecosystem). Machine output: stable JSON schema, plus raw pass-through of source payloads.
5. Correct behavior in pipes/CI: auto-detect TTY, honor `NO_COLOR`, meaningful exit codes.
6. Single static binary, cross-platform (linux/darwin/windows, amd64/arm64), installable via `go install`, Homebrew, and GitHub Releases.

### Non-Goals (v1)

- IP address / ASN lookups (design the internals so this can be added later, but don't build it).
- Domain availability monitoring, bulk lookups from files, or watch mode (stretch goals, see §12).
- Historical WHOIS / data archiving.
- Acting as a WHOIS/RDAP *server*.

## 3. Architecture

```
plat/
├── cmd/plat/            # main.go, cobra root command
├── internal/
│   ├── bootstrap/           # IANA RDAP bootstrap (dns.json) fetch + cache
│   ├── rdap/                # RDAP client: registry query + registrar link-following
│   ├── whois/               # WHOIS client: port-43 dialer + referral chasing
│   │   └── parse/           # heuristic key/value parser + per-registry quirks
│   ├── model/               # unified Record types, provenance types
│   ├── merge/               # merge engine: source records → unified Record
│   ├── render/
│   │   ├── human/           # lipgloss-styled TTY output
│   │   ├── plain/           # no-frills text for pipes
│   │   └── machine/         # JSON / NDJSON encoders
│   └── netx/                # shared dialer, timeouts, proxy support, retries
├── testdata/                # golden files: recorded RDAP JSON + WHOIS blobs
└── .github/workflows/       # CI + goreleaser
```

**Flow for `plat example.com`:**

1. Normalize input: lowercase, strip scheme/path if a URL was pasted, IDN → punycode (`golang.org/x/net/idna`). Keep the Unicode form for display.
2. Resolve the TLD's RDAP base URL from the IANA bootstrap file (cached locally, see §6).
3. Fan out concurrently (errgroup, per-source contexts, default 5s timeout each):
   - **Registry RDAP**: `GET {bootstrap-url}/domain/{name}`
   - **Registrar RDAP**: from the registry RDAP response, follow the `links` entry with `rel: "related"` pointing at the registrar's RDAP server (ICANN-required for gTLDs). This is a dependent second hop, not a fourth parallel branch.
   - **Registry WHOIS**: resolve TLD server via `whois.iana.org`, query it.
   - **Registrar WHOIS**: follow the `Registrar WHOIS Server:` referral from the registry response (thin registries like .com) — also a dependent hop.
4. Each source produces a `SourceRecord` (normalized fields + raw payload + latency + errors).
5. Merge engine produces one `Record` with provenance annotations and a conflict list.
6. Renderer selected by flags/TTY detection emits output.

## 4. Unified Data Model

```go
type Record struct {
    Domain        Field[string]      // punycode + unicode forms
    Handle        Field[string]      // registry handle / ROID
    Registrar     RegistrarInfo      // name, IANA ID, abuse contact, URL
    Status        Field[[]string]    // normalized EPP status codes
    Created       Field[time.Time]
    Updated       Field[time.Time]
    Expires       Field[time.Time]
    Nameservers   Field[[]string]
    DNSSEC        Field[bool]        // + DS data if present
    Contacts      map[Role]Contact   // registrant, admin, tech, billing
    Redacted      []RedactionNotice  // what was withheld and by whom
    Sources       []SourceResult     // per-source status, latency, raw payload
    Conflicts     []Conflict         // fields where sources disagree
}

type Field[T any] struct {
    Value   T
    Sources []SourceID // registry-rdap | registrar-rdap | registry-whois | registrar-whois
}
```

Design notes:

- **Every field carries its sources.** This is the core differentiator — the UI renders a small source badge next to each value.
- Dates normalize to UTC RFC 3339. WHOIS date parsing needs a tolerant multi-format parser (registries use at least a dozen formats).
- Status codes normalize to EPP names (`clientTransferProhibited` etc.); map RDAP status vocabulary (RFC 8056) and WHOIS strings (often with ICANN URLs appended) to the same set.
- Contacts come from RDAP jCard (RFC 7095 — a genuinely unpleasant format; parse defensively) and WHOIS key/value lines. Model GDPR redaction explicitly rather than treating "REDACTED FOR PRIVACY" as a name. Recognize RDAP redaction signals: remarks with redaction titles and the RFC 9537 `redacted` extension.
- Keep raw payloads (RDAP JSON bytes, WHOIS text) in `SourceResult` so `--raw` and debugging cost nothing extra.

## 5. Merge Strategy

Precedence, most→least trusted per field: **registrar RDAP → registry RDAP → registrar WHOIS → registry WHOIS.** Rationale: RDAP is structured (no parse ambiguity) and registrar data is thick (registry is thin for e.g. .com). But:

- A redacted value never beats a populated value. If registrar RDAP redacts registrant name but registry WHOIS somehow has it, the populated value wins and provenance shows it.
- Timestamps: if sources disagree by more than clock-skew tolerance (~24h for date-only WHOIS formats), record a `Conflict` and keep the highest-precedence value.
- Nameserver sets: union, but flag as a conflict if sets genuinely differ (not just case/trailing-dot).
- Never silently drop a disagreement — conflicts render as a warning section in human output and as an array in JSON.

## 6. Protocol Details & Edge Cases

**RDAP bootstrap:** fetch `https://data.iana.org/rdap/dns.json`, cache at `${XDG_CACHE_HOME:-~/.cache}/plat/bootstrap.json` with a 7-day TTL and `--refresh-bootstrap` to force. Ship an embedded copy (go:embed) as a fallback so first-run works offline-ish and air-gapped CI doesn't need IANA. If the TLD has no RDAP entry, skip RDAP branches without treating it as an error.

**RDAP client:** set `Accept: application/rdap+json`, follow redirects (many registries redirect), handle 404 = domain not found (distinguish from network error), 429 with Retry-After (one polite retry). Consider `github.com/openrdap/rdap` as a reference or dependency, but a hand-rolled client is ~300 lines and avoids dragging in its cache/bootstrap opinions — recommend hand-rolling with the RDAP JSON structs defined per RFC 9083.

**WHOIS client:** raw TCP dial to port 43, write `domain\r\n`, read until EOF. Quirks to handle: Verisign needs `domain example.com` prefix to avoid nameserver matches (use `=example.com` or `domain ` prefix); .jp wants `/e` suffix for English; DENIC (.de) wants `-T dn,ace` for full output. Encode quirks as a small per-server rules table, not scattered ifs.

**WHOIS parsing:** generic `key: value` extractor with a synonym table (`Creation Date` / `created` / `Registered on` / `Domain Registration Date` → Created, etc.), then per-registry template overrides for the weird ones (.de, .uk's indented format, .jp's bracketed format). Ship with solid gTLD coverage plus the top ~15 ccTLDs; make templates data-driven (embedded YAML) so adding one is a PR-sized change. `github.com/likexian/whois` + `whois-parser` exist as references — evaluate the parser, but its accuracy on ccTLDs is mixed; owning the parser is likely worth it since it's the heart of the tool.

**Failure semantics:** a source erroring out is normal, not fatal. Human output shows a compact per-source status line (✓ 142ms / ✗ timeout / – no RDAP for TLD). Exit code 0 if *any* source returned data; 1 for domain-not-found on all sources; 2 for usage errors; 3 for total lookup failure.

**Also handle:** trailing dots, `xn--` input, single-label input (reject with a helpful message), rate-limited WHOIS servers (surface the registry's rate-limit text rather than a parse failure), private/reserved TLDs (.internal, .local → immediate friendly error).

## 7. CLI Surface

Cobra-based. Keep the surface small:

```
plat <domain>                  # human output (TTY) or plain text (pipe)
plat <domain> -o json          # unified record as JSON (stable schema)
plat <domain> -o json --raw    # include raw source payloads
plat <domain> --source rdap    # restrict to rdap|whois|registry|registrar
plat <domain> --no-follow      # registry sources only, skip registrar hops
plat <domain> --timeout 10s
plat <domain> -q               # quiet: just registrant + registrar + expiry
plat version | completion | man
```

Flags: `-o/--output human|plain|json|ndjson`, `--no-color`, `--refresh-bootstrap`, `-v/--verbose` (per-source timing + referral chain to stderr). Multiple domains as args → sequential human output or NDJSON (one record per line) for machine mode.

## 8. Human Output (the "slick UI" part)

Use **Lip Gloss v2** (import path `charm.land/lipgloss/v2` — stable as of Feb 2026) for styling, and a spinner during lookups (Bubbles v2 if stable at build time, otherwise a hand-rolled ~30-line spinner to avoid a beta dependency). This is a render-and-exit tool — do *not* build a full interactive Bubble Tea app for v1; a styled static output is faster, pipes cleanly, and still looks great. (An interactive TUI is a stretch goal, §12.)

Lip Gloss v2 specifics that shape the implementation:

- **Print through Lip Gloss writers, not `fmt`**: `lipgloss.Println` / `lipgloss.Sprint` / `lipgloss.Fprint` handle color downsampling per terminal capability and strip ANSI entirely when stdout is not a TTY. This gives us most of the pipe-safety requirements for free — the `plain` renderer is then mostly about layout, not ANSI hygiene.
- **Background detection is explicit in v2**: call `lipgloss.HasDarkBackground(os.Stdin, os.Stdout)` once at startup and pick the light/dark palette from the result. Do NOT use the `v2/compat` adaptive-color package — it exists for v1 migrations and Charm advises against it for new code.
- v2's improved `table` package is a good fit for multi-domain summary output; its layer/canvas compositing is not needed for v1.
- Point Claude Code at Charm's v2 upgrade guide in the lipgloss repo — it's written to be LLM-consumable and documents the full API delta.

Layout sketch:

```
 plat · example.com

 ┃ Registrant    Example Corp (registrar-rdap)
 ┃ Organization  Example Corp
 ┃ Registrar     Example Registrar, Inc. — IANA 1234
 ┃ Abuse         abuse@registrar.example · +1.5555550100

 ┃ Created       1995-08-14   (30.9 years ago)
 ┃ Updated       2025-08-14
 ┃ Expires       2026-08-13   (in 33 days) ⚠

 ┃ Status        clientTransferProhibited · serverDeleteProhibited
 ┃ Nameservers   a.iana-servers.net · b.iana-servers.net
 ┃ DNSSEC        signed ✓

 Sources  registry-rdap ✓ 89ms · registrar-rdap ✓ 214ms · registry-whois ✓ 130ms · registrar-whois ✗ timeout
 Conflicts: none · Redacted: admin/tech contact (GDPR, registrar policy)
```

Design rules: relative time hints next to dates; expiry gets a color ramp (green >90d, yellow <90d, red <30d); source badges rendered dim so they inform without shouting; adaptive colors for light/dark terminals (lipgloss handles this); graceful width handling down to 80 cols. Respect `NO_COLOR` and non-TTY → the `plain` renderer (aligned `key: value`, zero ANSI).

## 9. Machine Output

- `-o json`: the unified `Record`, camelCase keys, versioned with a top-level `"schemaVersion": 1`. Provenance included per field. Conflicts and redactions as arrays. Timestamps RFC 3339.
- `--raw`: adds `sources[].raw` (RDAP JSON embedded as-is, WHOIS as a string).
- `-o ndjson`: one record per line for multi-domain invocations.
- Errors in machine mode go to stderr as JSON too (`{"error": ..., "domain": ...}`), stdout stays schema-clean.
- Treat the JSON schema as a public API: document it in `docs/schema.md`, breaking changes bump `schemaVersion`.

## 10. Testing

- **Golden files**: recorded real RDAP responses and WHOIS blobs in `testdata/` for ~20 representative domains (thin .com, thick .org, GDPR-redacted .eu/.de, no-RDAP ccTLD, IDN, expired domain, rate-limit response). Parser and merge tests run entirely offline.
- **Local mock servers**: httptest for RDAP; a tiny TCP listener for WHOIS to test referral chasing, timeouts, and quirks.
- Merge engine table tests: precedence, redaction override, conflict detection.
- Renderer snapshot tests with color forced off.
- One opt-in integration test (`-tags=live`) hitting real infra for a stable domain, excluded from CI.

## 11. Delivery Milestones

Sized for incremental Claude Code sessions; each ends green and demoable.

1. **M1 — Skeleton + RDAP happy path.** Repo scaffold, cobra, bootstrap fetch/cache/embed, registry RDAP query, minimal plain output for a .com domain. CI (lint via golangci-lint, test, build matrix).
2. **M2 — WHOIS engine.** Port-43 client, IANA → registry → registrar referral chasing, quirks table, generic parser + gTLD synonym table.
3. **M3 — Registrar RDAP hop + merge engine.** Follow `related` links; unified model, precedence merge, provenance, conflicts, redaction handling. This is the hardest milestone — budget it accordingly.
4. **M4 — Renderers.** JSON/NDJSON with stable schema; plain renderer; TTY detection and exit codes.
5. **M5 — Human UI polish.** Lipgloss layout, spinner, color ramps, NO_COLOR, width handling.
6. **M6 — Edge cases + parser breadth.** ccTLD templates, IDN, date-format torture tests, golden-file suite filled out.
7. **M7 — Release.** goreleaser (binaries + checksums + Homebrew tap), `go install` verified, README with animated demo (vhs from Charm makes great CLI GIFs), man page + completions, schema docs.

## 12. Stretch Goals (post-v1)

- Interactive Bubble Tea mode (`plat -i`): tabbed view per source, raw payload viewer, copy-to-clipboard.
- IP / ASN / nameserver object lookups (RDAP already supports these; the bootstrap layer just needs ipv4/ipv6/asn registries).
- `--diff` between two runs or against a cached previous result (expiry/NS-change detection).
- Bulk mode with a worker pool + rate limiting per WHOIS server.
- Library extraction: publish `internal/` core as a public Go package once the API settles.

## 13. Key Dependencies

- `github.com/spf13/cobra` — CLI framework
- `charm.land/lipgloss/v2` — styling (v2 stable; use writer functions, explicit background detection)
- Spinner: `charmbracelet/bubbles` v2 if stable at build time, else hand-rolled
- `golang.org/x/net/idna` — IDN handling
- `golang.org/x/sync/errgroup` — concurrent fan-out
- Reference (evaluate, don't blindly adopt): `github.com/openrdap/rdap`, `github.com/likexian/whois-parser`
- Tooling: golangci-lint, goreleaser, charmbracelet/vhs (demo GIF)

## 14. Definition of Done (v1)

`plat google.com`, `plat example.de`, `plat nic.jp`, and `plat <some-random-ccTLD-without-RDAP>` all return sensible unified records with correct provenance; `plat example.com -o json | jq .expires.value` works in a pipe with no ANSI garbage; a source timing out never fails the command; binary size reasonable (<15MB); README demo GIF exists; tagged v0.1.0 release with binaries for 6 platform/arch combos.
