# Contributing to plat

Thanks for considering a contribution. `plat` is a small Go CLI — the
bar for a good change here is: it's correct, it's tested, and it doesn't
grow the tool beyond what a domain-lookup tool needs.

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

Requires Go 1.26+.

```bash
git clone https://github.com/patramsey/plat.git
cd plat
go build ./...
go test ./...
```

## Before opening a PR

```bash
go build ./...
go vet ./...
golangci-lint run          # see https://golangci-lint.run/ for install
go test -race ./...
```

All of these must be clean. CI runs the same checks (`lint`, `test -race`,
and a 6-platform `build` matrix) on every pull request, and fails if
whole-project coverage drops below 90%. Codecov also checks that the
lines a PR changes are at least 90% covered.

Live/integration tests that hit real WHOIS/RDAP infrastructure are opt-in
via a build tag and excluded from CI:

```bash
go test -tags=live ./...
```

`internal/whois/parse` has Go fuzz tests (`FuzzParse`, `FuzzParseDate`) —
its parser runs on untrusted network text, so a change there is worth a
quick local fuzz run, not just the seed corpus in CI:

```bash
go test -fuzz='^FuzzParse$' -fuzztime=30s ./internal/whois/parse/...
```

## Workflow

- Branch off `main`, open a PR — direct pushes to `main` aren't used here.
- Keep commits focused; prefer several small, well-scoped commits over one
  large one.
- Commit messages follow a `type: summary` convention (`feat:`, `fix:`,
  `docs:`, `chore:`, `test:`), with a body explaining *why* when the
  reasoning isn't obvious from the diff alone.
- Add tests for behavior changes — this codebase leans heavily on
  table-driven tests and golden fixtures under `testdata/`.

## Adding or fixing a registry

Most contributions are one registry answering in a way plat misreads: a
date format it can't parse, a "not found" wording it doesn't recognise,
nameservers it misses. The fix is usually small. The test is what takes
care.

**1. Record the real answer.** Fixtures under `testdata/` are
recordings of what a server actually sent, never examples written by
hand. A hand-written fixture doesn't just fail to catch a bug: it
asserts the bug is correct. One shipped claiming a `Status:` line the
`.eu` registry never sends, and its test passed while real `.eu`
lookups returned no nameservers. Capture exactly what plat received:

```bash
plat nic.xx --source whois -o json --raw \
  | jq -r '.sources[] | select(.source=="registry-whois") | .raw' \
  > testdata/whois/<registry>-xx-recorded.txt
```

You may trim the legal preamble. Never edit a key, reflow a line or
add a field. If the server sends CRLF line endings, keep them. Name the
file `<registry>-<tld>-<what>-recorded.txt`; a not-found, refused,
rate-limited or restricted answer must have that word in its name (see
step 4).

**2. Make the parser read it**, most specific fix first:

- **A key with a different name** (`registered:` for `created:`): add a
  synonym to `defaultSynonyms` in `internal/whois/parse/parse.go`. If
  the key means something else at other registries, scope it to that
  TLD's entry in `internal/whois/parse/templates.yaml` instead.
- **A layout the generic `key: value` reader can't follow** (indented
  sections, `[bracketed]` keys): give the TLD a `format:` in
  `templates.yaml`. Every `templates.yaml` entry is data, not code.
  Two more options there: `continuationLines` for values carried on
  indented lines with no key (`.pl`'s nameservers), and `dateLayouts`
  for a date format that would be ambiguous anywhere else (`.il`'s
  day-first dates).
- **The server needs a different query** (a prefix, a flag, a suffix):
  add a row to the table in `internal/whois/quirks.go`.
- **IANA lists no WHOIS server but the registry runs one**: add it to
  `registryFallback` in the same file.

**3. Test against the recording.** Add a row to the table test that
fits: `TestParse_CCTLDFormats` (`formats_test.go`) for fields, and the
tests in `notfound_test.go` for not-found, refused, rate-limited or
restricted wording.

**4. Make sure a new marker can't fire on a registered domain.** A
not-found or refusal phrase that also appears in some *registered*
domain's answer makes a taken domain look free, which is worse than the
bug being fixed. `.bo` shipped exactly that: a footer on every `.bo`
answer was mistaken for a refusal. Record a registered answer from the
same registry too (`nic.xx` is usually registered).
`TestParse_NoRegisteredFixtureTripsAMarker` checks every fixture whose
name doesn't say otherwise against every marker.

**5. Check it live** with `plat -v` on a registered name and a
surely-free one. If plat's exit code for either changes, say so in the
PR: exit-code changes are treated as breaking.

## Design context

Before touching `internal/merge` (precedence/conflict/redaction),
`internal/whois` (parsing/referral chasing), or the renderers, skim
[`CLAUDE.md`](CLAUDE.md) — it documents the merge precedence rules, the
provenance model, and the per-registry WHOIS quirks system, which aren't
obvious from the code alone.

For the JSON/NDJSON output contract specifically, see
[`docs/schema.md`](docs/schema.md) — it's a versioned, stable schema;
backward-incompatible changes require a `schemaVersion` bump.

## Reporting bugs / requesting features

Open an issue. For a bug, include the exact command you ran and, if you
can share it, the `-v` diagnostic output (`plat <domain> -v`) — it shows
which sources were attempted and how each one responded.

## Scope

Non-goals for now: availability monitoring, watch mode, historical
WHOIS archiving, or acting as a WHOIS/RDAP server itself. (IP, ASN and
bulk lookups were once on this list; they have since shipped.) If you want to propose one of these, open an issue to discuss
before sending a PR — it's a bigger conversation than a typical fix.
