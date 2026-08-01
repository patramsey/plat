# Contributing to plat

Thanks for considering a contribution. `plat` is a small Go CLI — the
bar for a good change here is: it's correct, it's tested, and it doesn't
grow the tool beyond what a domain-lookup tool needs.

## Development setup

Requires Go 1.25+.

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
go test ./...
go test ./... -race        # for anything touching internal/collect or internal/whois
```

All of these must be clean. CI runs the same checks (`lint`, `test`, and
a 6-platform `build` matrix) on every pull request.

Live/integration tests that hit real WHOIS/RDAP infrastructure are opt-in
via a build tag and excluded from CI:

```bash
go test -tags=live ./...
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

Non-goals for now: IP/ASN lookups, availability monitoring, bulk lookups,
watch mode, historical WHOIS archiving, or acting as a WHOIS/RDAP server
itself. If you want to propose one of these, open an issue to discuss
before sending a PR — it's a bigger conversation than a typical fix.
