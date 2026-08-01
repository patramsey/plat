# Version/Build-Info CLI Improvements Design

**Goal:** Fix the release binary's overly-long commit hash in `plat version`, add a `--version` flag to the root command, and add machine-readable and verbose build-info modes to the `version` subcommand.

## Background / problem

- `.goreleaser.yaml`'s ldflags use goreleaser's `{{.Commit}}` template variable — the full 40-character git SHA, not the conventional short form. Confirmed in the actual v0.1.0 release binary:
  ```
  $ plat version
  plat 0.1.0 (7faa7fa31990f8985522f5045f533389937cac96, built 2026-08-01T20:17:33Z by goreleaser)
  ```
  Hard to read/scan, and not what users expect from a version line.
- There's no `--version` flag on the root command — only the `version` subcommand. Most CLI users reach for `--version` before checking `--help`.
- No machine-readable version output exists, unlike domain lookups, which already support `-o json`.
- No way to see the Go compiler version or target platform a release binary was built with, which matters for bug reports.

## Design

### 1. Short commit hash (bug fix)

`.goreleaser.yaml`: change `-X main.commit={{.Commit}}` to `-X main.commit={{.ShortCommit}}` in `builds[].ldflags`.

### 2. `--version` flag on the root command

- A plain boolean flag on `root` (`root.Flags().Bool("version", false, ...)`), not cobra's built-in `Command.Version` auto-flag mechanism — that would need `SetVersionTemplate` gymnastics to reproduce the exact existing line, plus its own quirks around shorthand allocation. A manually checked flag is more predictable and easier to test.
- Behavior: if set, print the same line `plat version`'s default (human, non-`--full`) output produces, to stdout, and exit 0 — checked and handled *before* the root command's `Args` validator runs, so it works with zero positional arguments and does not trigger the existing "show help on a bare `plat`" path.
- No shorthand (`-v` is already `--verbose`).

### 3. `plat version -o/--output human|json`

- New local flag on the `version` subcommand only (root's existing `-o` flag is local to root, not inherited by subcommands, so this is a separate registration). Accepts `human` (default) or `json`. Any other value is a usage error (exit code 2), matching the root command's existing `-o` validation.
- `human`: the existing formatted line (with the short hash now).
- `json`: compact, single-line JSON to stdout: `{"version":"...","commit":"...","date":"...","builtBy":"..."}`.

### 4. `plat version --full`

- New local boolean flag on the `version` subcommand.
- Adds two extra fields, sourced from the standard library (no new dependency):
  - Go version: `runtime.Version()` (e.g. `"go1.25.0"`) — simpler than `debug.ReadBuildInfo().GoVersion` and needs no error handling; both report the same value for a normally built binary.
  - Platform: `runtime.GOOS + "/" + runtime.GOARCH` (e.g. `"darwin/arm64"`).
- Human output with `--full` appends two lines:
  ```
  go:       go1.25.0
  platform: darwin/arm64
  ```
- JSON output with `-o json --full` adds two keys: `"goVersion"` and `"platform"`. The two flags compose independently — `--full` always means "include these two fields," regardless of output format.
- `--full` has no effect on the root `--version` flag, which always prints the same fixed line as `plat version`'s default (non-`--full`) output. Deliberate scope limit: the root flag stays a single, predictable convenience alias, not a second surface with its own flag set.

## Components touched

- `cmd/plat/main.go`:
  - `runtime` stdlib import for Go version/platform.
  - New `--version` bool flag + early-exit check on `root`, before `Args` validation.
  - New `-o`/`--full` flags on the `version` subcommand; its `RunE` grows a small branch for human vs. JSON, full vs. non-full.
  - A small unexported helper to build the version line/JSON payload once, shared between the root `--version` flag and the subcommand's default path, so the two can never drift out of byte-for-byte sync.
- `.goreleaser.yaml`: one-line ldflags change.
- `README.md`: a line or two added to `## Usage` documenting `--version` and the new `version` subcommand flags, matching the existing comment-per-example style.

## Error handling

- `-o` value other than `human`/`json` on the `version` subcommand: usage error, exit code 2 (existing `usageError` type, same as root's `-o` validation).
- `--version` and the `version` subcommand ignore every other flag/argument (`--timeout`, `--source`, positional domains, etc.) — neither ever reaches the lookup path.

## Testing

Extend `cmd/plat/main_test.go` (which already covers `TestRun_VersionSubcommandIncludesBuildMetadata`):

- `plat --version` produces byte-identical output to `plat version`'s default output.
- `plat --version` works with zero positional args, and does not trigger the no-args help path.
- `plat version -o json` produces valid JSON with exactly the 4 core fields.
- `plat version -o bogus` is a usage error (exit 2).
- `plat version --full` includes `go:`/`platform:` lines; without `--full`, it doesn't.
- `plat version --full -o json` includes `goVersion`/`platform` keys; `-o json` alone doesn't.

No changes to `docs/schema.md` (that documents the domain-lookup JSON schema, not this).

## Out of scope

- Update-checking ("a newer version is available") — not requested; adds a network dependency and complexity disproportionate to what a v0.1.0 CLI needs.
- VCS dirty-state or module checksum details — not requested; `--full`'s Go version + platform already covers the practical "what exactly did you build" bug-report need.
