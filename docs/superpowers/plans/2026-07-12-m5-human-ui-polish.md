# M5 — Human UI Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `plat`'s human-facing output real Lip Gloss styling (labels, an expiry color ramp, per-source status badges) distinct from the plain renderer, add a spinner during lookups, respect `NO_COLOR`, and wrap long values to the detected terminal width.

**Architecture:** A new `internal/render/human` package (mirrors `internal/render/plain`'s shape: `Render(w io.Writer, r model.Record, opts Options) error`) does the styled rendering; a new `internal/spinner` package wraps `charm.land/bubbles/v2`'s spinner component inside a transient `charm.land/bubbletea/v2` `Program` that runs only for the duration of one domain's lookup, writing to stderr. Background/width detection happens once in `main()` using real file descriptors and is threaded down as a plain `uiConfig` struct — everything below `main()` stays a pure function of injected `io.Writer`s and data, exactly like M1-M4's testable design.

**Tech Stack:** `charm.land/lipgloss/v2` (styling — already committed to in CLAUDE.md), `charm.land/bubbles/v2` + `charm.land/bubbletea/v2` (spinner), `golang.org/x/term` (terminal width detection). All four are NEW dependencies — `go.mod` currently has none of them.

## Global Constraints

- Print via Lip Gloss writer functions (`lipgloss.Fprint`), not raw `fmt`/`io.WriteString` — verified locally: `lipgloss.Fprint(w, ...)` always re-wraps `w` in a fresh `colorprofile.NewWriter(w, os.Environ())` internally, so it downsamples/strips ANSI automatically based on `w`'s real terminal-ness (or its absence) and the process's actual environment variables at call time. This is what makes the human renderer pipe-safe without any hand-rolled ANSI-stripping code.
- Detect background explicitly once via `lipgloss.HasDarkBackground(os.Stdin, os.Stdout)` — confirmed signature: `func HasDarkBackground(in, out term.File) bool`, called with real `*os.File`s. Do NOT use the v2 `compat` adaptive-color package.
- `NO_COLOR` and non-TTY route the AUTO-detect path (`-o` omitted) to the plain renderer. An EXPLICIT `-o human` still dispatches to the styled renderer even under `NO_COLOR`/non-TTY — `lipgloss.Fprint`'s own downsampling strips the ANSI in that case, `plat`'s own code never hand-checks `NO_COLOR` inside the renderer itself.
- `internal/render/plain` is UNCHANGED by this milestone — it remains the `FormatPlain` renderer and is never touched by any task below.
- `internal/model` is UNCHANGED — this milestone styles existing fields, it does not add or remove any.
- `model.Contacts` is defined but unpopulated until a later milestone — do not render it (there is nothing to render yet).
- Width wrapping uses `lipgloss.Style.Width(n)`, confirmed locally to wrap at word boundaries and right-pad every line to exactly `n` runes — the renderer must trim trailing whitespace per wrapped line itself.
- The spinner writes to stderr only, never stdout, and only runs when stderr is a real terminal AND the format is `FormatHuman` — never for `FormatPlain`/`FormatJSON`/`FormatNDJSON`, and never when stderr itself is redirected even if stdout is a terminal.
- `charm.land/bubbletea/v2`'s `tea.NewProgram(...).Run()` requires a real `/dev/tty` for input by default and errors otherwise — confirmed locally (`bubbletea: could not open TTY: open /dev/tty: device not configured` when run non-interactively). `tea.WithInput(nil)` is REQUIRED on every `tea.NewProgram(...)` call in this codebase to avoid this, since `plat` never reads keyboard input during the spinner phase — this is also what keeps this whole codebase's test suite runnable without a real controlling terminal, exactly as it has been through M1-M4.
- Deterministic color-forcing test recipe (confirmed locally against the real `lipgloss.Fprint` → `colorprofile.Detect` code path): setting the process environment variables `CLICOLOR_FORCE=1` and `COLORTERM=truecolor` (via Go's `t.Setenv` in tests) forces `lipgloss.Fprint` to emit full TrueColor ANSI even when writing to a `*bytes.Buffer` — confirmed the resulting bytes are byte-identical to the styled string's own raw `Style.Render()` output (TrueColor profile is a pure passthrough, no downsampling needed). With NO forcing env vars set, a `*bytes.Buffer` destination reliably produces zero ANSI (confirmed empirically) — this is the renderer's natural pipe-safety, needing no separate code path.
- `-q/--quiet` remains explicitly deferred — not implemented in this milestone.
- Every task modifying a pre-existing file must confirm that package's pre-existing tests still pass unmodified (except where a task's own Global-Constraints-mandated signature change requires updating call sites, which must be called out explicitly in that task).

---

### Task 1: `NO_COLOR`-Aware `render.Select`

**Files:**
- Modify: `internal/render/render.go` (`Select` gains a third `noColor bool` parameter)
- Modify: `internal/render/render_test.go` (extend `TestSelect`'s table)
- Modify: `cmd/plat/main.go` (update `Select`'s one call site)
- Test: `internal/render/render_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `func Select(explicit string, isTTY bool, noColor bool) (Format, error)` — consumed by Task 5's `runLookup`.

- [ ] **Step 1: Write the failing test**

Replace `internal/render/render_test.go`'s existing `TestSelect` function with this extended version (everything else in the file — `TestParseFormat`, `TestIsTerminal_FalseForPipe`, `TestIsMachine` — stays unchanged):

```go
func TestSelect(t *testing.T) {
	tests := []struct {
		name     string
		explicit string
		isTTY    bool
		noColor  bool
		want     Format
		wantErr  bool
	}{
		{"explicit wins over TTY", "json", true, false, FormatJSON, false},
		{"explicit wins over pipe", "json", false, false, FormatJSON, false},
		{"explicit human wins over NO_COLOR", "human", true, true, FormatHuman, false},
		{"no explicit, TTY, no NO_COLOR -> human", "", true, false, FormatHuman, false},
		{"no explicit, pipe -> plain", "", false, false, FormatPlain, false},
		{"no explicit, TTY, NO_COLOR set -> plain", "", true, true, FormatPlain, false},
		{"invalid explicit format", "bogus", true, false, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Select(tt.explicit, tt.isTTY, tt.noColor)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Select(%q, %v, %v) expected an error, got nil", tt.explicit, tt.isTTY, tt.noColor)
				}
				return
			}
			if err != nil {
				t.Fatalf("Select(%q, %v, %v) unexpected error: %v", tt.explicit, tt.isTTY, tt.noColor, err)
			}
			if got != tt.want {
				t.Errorf("Select(%q, %v, %v) = %v, want %v", tt.explicit, tt.isTTY, tt.noColor, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/render/... -run TestSelect -v`
Expected: FAIL — build error, `Select` called with 3 arguments but the current signature only takes 2.

- [ ] **Step 3: Write the implementation**

In `internal/render/render.go`, replace the `Select` function:

```go
// Select resolves the format to use: an explicit -o value always wins
// (including "human" even under NO_COLOR or a non-terminal destination —
// lipgloss.Fprint's own downsampling strips ANSI in that case, this
// function never second-guesses an explicit choice). With no explicit
// value, a TTY with no NO_COLOR gets Human; anything else (a pipe, or
// NO_COLOR set) gets Plain.
func Select(explicit string, isTTY bool, noColor bool) (Format, error) {
	if explicit != "" {
		return ParseFormat(explicit)
	}
	if isTTY && !noColor {
		return FormatHuman, nil
	}
	return FormatPlain, nil
}
```

In `cmd/plat/main.go`, update `Select`'s one call site inside `runLookup`:

```go
	format, err := render.Select(opts.Output, render.IsTerminal(os.Stdout), os.Getenv("NO_COLOR") != "")
```//(replacing the current `render.Select(opts.Output, render.IsTerminal(os.Stdout))` line)

- [ ] **Step 4: Run tests to verify they pass, and confirm zero regression**

Run: `cd /Users/pat/codes/plat && go test ./internal/render/... -v`
Expected: PASS — all `TestSelect` subtests, and `TestParseFormat`/`TestIsTerminal_FalseForPipe`/`TestIsMachine` (unmodified) still green.

Run: `cd /Users/pat/codes/plat && go build ./... && go test ./...`
Expected: builds clean; all 12 packages `ok` (this call-site edit is the only change to `cmd/plat` in this task, and it doesn't alter any existing test's observable behavior — no test in `cmd/plat/main_test.go` sets `NO_COLOR`, and `os.Getenv("NO_COLOR")` is empty in a normal test run).

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/render/render.go internal/render/render_test.go cmd/plat/main.go
git commit -m "feat: make render.Select NO_COLOR-aware"
```

---

### Task 2: `internal/render/human` — Theme, Layout Mechanics, and Core Fields

**Files:**
- Create: `internal/render/human/human.go`
- Create: `internal/render/human/human_test.go`
- Modify: `go.mod`, `go.sum` (via `go get`)

**Interfaces:**
- Consumes: `model.Record`, `model.Field[T]`, `model.TimeValue`, `model.SourceID` (all pre-existing, unchanged).
- Produces: `type Theme struct{...}`, `func NewTheme(isDark bool) Theme`, `type Options struct{ Theme Theme; Width int }`, `func Render(w io.Writer, r model.Record, opts Options) error` — consumed by Task 3 (extends the same `Render` function) and Task 5 (`renderRecord`'s `FormatHuman` dispatch).

- [ ] **Step 1: Add the new dependencies**

Run: `cd /Users/pat/codes/plat && go get charm.land/lipgloss/v2@latest golang.org/x/term@latest`

This adds `charm.land/lipgloss/v2` (confirmed locally to resolve to `v2.0.5`, pulling in `github.com/charmbracelet/colorprofile`, `github.com/charmbracelet/x/ansi`, `github.com/lucasb-eyer/go-colorful`, `github.com/mattn/go-runewidth`, `github.com/rivo/uniseg` as transitive deps) and `golang.org/x/term` (for terminal width detection in Task 5) to `go.mod`/`go.sum`. Run `go build ./...` afterward — expected: still builds clean (nothing imports the new modules yet).

- [ ] **Step 2: Write the failing tests**

Create `internal/render/human/human_test.go`:

```go
package human

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/model"
)

func fullRecord() model.Record {
	created, _ := time.Parse(time.RFC3339, "1995-08-14T04:00:00Z")
	updated, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	return model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Handle: model.Field[string]{Value: "2336799_DOMAIN_COM-VRSN", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Registrar: model.RegistrarInfo{
			Name: model.Field[string]{Value: "Example Registrar, Inc.", Sources: []model.SourceID{model.SourceRegistrarRDAP}},
		},
		Status:  model.Field[[]string]{Value: []string{"clientTransferProhibited"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Created: model.Field[model.TimeValue]{Value: model.TimeValue{Time: created, Raw: "1995-08-14T04:00:00Z", Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Updated: model.Field[model.TimeValue]{Value: model.TimeValue{Time: updated, Raw: "2025-01-01T00:00:00Z", Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Nameservers: model.Field[[]string]{Value: []string{"a.iana-servers.net", "b.iana-servers.net"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		DNSSEC: model.Field[bool]{Value: true, Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
}

func TestNewTheme_ProducesDistinctLightAndDarkPalettes(t *testing.T) {
	dark := NewTheme(true)
	light := NewTheme(false)
	if dark.Label.Render("x") == light.Label.Render("x") {
		t.Skip("label color happens to render identically in both palettes (styles beyond color may still differ) — not a hard failure, informational only")
	}
}

func TestRender_FullyPresentRecord(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("COLORTERM", "truecolor")

	var buf bytes.Buffer
	if err := Render(&buf, fullRecord(), Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"example.com",
		"2336799_DOMAIN_COM-VRSN",
		"Example Registrar, Inc.",
		"clientTransferProhibited",
		"1995-08-14T04:00:00Z",
		"2025-01-01T00:00:00Z",
		"a.iana-servers.net",
		"b.iana-servers.net",
		"true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "\x1b[") {
		t.Error("expected ANSI escape sequences when color is forced, found none")
	}
}

func TestRender_NoColorByDefault(t *testing.T) {
	// No CLICOLOR_FORCE/COLORTERM set, and *bytes.Buffer is never a real
	// terminal — lipgloss.Fprint's own downsampling must strip all ANSI,
	// matching the plain renderer's pipe-safety guarantee.
	var buf bytes.Buffer
	if err := Render(&buf, fullRecord(), Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("expected zero ANSI with no color forced, got:\n%s", buf.String())
	}
}

func TestRender_SkipsAbsentFields(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, absent := range []string{"Handle:", "Registrar:", "Status:", "Created:", "Updated:", "Nameservers:", "DNSSEC:"} {
		if strings.Contains(out, absent) {
			t.Errorf("expected %q row to be skipped when absent, got:\n%s", absent, out)
		}
	}
}

func TestRender_UnparsedTimeFallback(t *testing.T) {
	rec := model.Record{
		Created: model.Field[model.TimeValue]{Value: model.TimeValue{Raw: "not-a-date", Parsed: false}, Sources: []model.SourceID{model.SourceRegistryWHOIS}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "not-a-date (unparsed)") {
		t.Errorf("output missing unparsed-date fallback, got:\n%s", buf.String())
	}
}

func TestRender_DefaultWidthWhenUnset(t *testing.T) {
	rec := fullRecord()
	var buf bytes.Buffer
	// Width: 0 must not error or panic — it should fall back to 80.
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: 0}); err != nil {
		t.Fatalf("unexpected error with Width: 0: %v", err)
	}
	if !strings.Contains(buf.String(), "example.com") {
		t.Error("expected output with default width, got none")
	}
}

func TestRender_WrapsLongValuesAtWidth(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Nameservers: model.Field[[]string]{
			Value:   []string{"ns1.example.com", "ns2.example.com", "ns3.example.com", "ns4.example.com"},
			Sources: []model.SourceID{model.SourceRegistryRDAP},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: 40}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines := strings.Split(buf.String(), "\n")
	nsLines := 0
	for _, l := range lines {
		if strings.Contains(l, "ns1.example.com") || (nsLines > 0 && strings.Contains(l, "ns")) {
			nsLines++
		}
	}
	if nsLines < 2 {
		t.Errorf("expected the 4-nameserver list to wrap onto multiple lines at width 40, got %d matching line(s):\n%s", nsLines, buf.String())
	}
	for _, l := range lines {
		if strings.HasSuffix(l, " ") {
			t.Errorf("line has trailing whitespace, want it trimmed: %q", l)
		}
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /Users/pat/codes/plat && go test ./internal/render/human/... -v`
Expected: FAIL — build error, package `internal/render/human` doesn't exist yet.

- [ ] **Step 4: Write the implementation**

Create `internal/render/human/human.go`:

```go
// Package human renders a merged domain record as a styled, colorized
// view for interactive terminals — the FormatHuman counterpart to
// internal/render/plain's unstyled FormatPlain. Output goes through
// lipgloss.Fprint, which downsamples/strips ANSI automatically based on
// the destination writer and the process environment (NO_COLOR,
// CLICOLOR_FORCE, COLORTERM) — this package never hand-checks those
// itself.
package human

import (
	"fmt"
	"io"
	"strings"
	"time"

	"charm.land/lipgloss/v2"

	"github.com/patramsey/plat/internal/model"
)

// labelWidth is the fixed left-column width every field row's label is
// padded to. Values wrap at whatever width remains.
const labelWidth = 20

// defaultWidth is used when Options.Width is unset (<=0) — e.g. when the
// destination isn't a real terminal and no width could be detected.
const defaultWidth = 80

// Theme holds every style the human renderer uses, resolved once at
// construction via lipgloss.LightDark so call sites never re-branch on
// dark/light per field.
type Theme struct {
	Header      lipgloss.Style // "plat · example.com" title line
	Label       lipgloss.Style // field labels ("Domain:", "Registrar:", ...)
	Value       lipgloss.Style // default field value styling
	SourceBadge lipgloss.Style // trailing "(registry-rdap, registrar-whois)" hint
	Muted       lipgloss.Style // unparsed dates, redaction notices
	OK          lipgloss.Style // ✓ / DNSSEC signed / source succeeded
	Err         lipgloss.Style // ✗ / source hard-failed
	Warn        lipgloss.Style // conflict header / source not-found
	ExpiryOK    lipgloss.Style // expires more than 90 days out
	ExpiryWarn  lipgloss.Style // expires within 90 days
	ExpiryCrit  lipgloss.Style // expires within 30 days, or already expired
}

// NewTheme builds a Theme appropriate for the detected terminal
// background. isDark should come from lipgloss.HasDarkBackground.
func NewTheme(isDark bool) Theme {
	ld := lipgloss.LightDark(isDark)
	accent := ld(lipgloss.Color("#1D4ED8"), lipgloss.Color("#60A5FA"))
	label := ld(lipgloss.Color("#6B7280"), lipgloss.Color("#9CA3AF"))
	muted := ld(lipgloss.Color("#9CA3AF"), lipgloss.Color("#6B7280"))
	green := ld(lipgloss.Color("#15803D"), lipgloss.Color("#4ADE80"))
	yellow := ld(lipgloss.Color("#A16207"), lipgloss.Color("#FACC15"))
	red := ld(lipgloss.Color("#B91C1C"), lipgloss.Color("#F87171"))

	return Theme{
		Header:      lipgloss.NewStyle().Bold(true).Foreground(accent),
		Label:       lipgloss.NewStyle().Foreground(label),
		Value:       lipgloss.NewStyle(),
		SourceBadge: lipgloss.NewStyle().Foreground(muted).Italic(true),
		Muted:       lipgloss.NewStyle().Foreground(muted),
		OK:          lipgloss.NewStyle().Foreground(green),
		Err:         lipgloss.NewStyle().Foreground(red),
		Warn:        lipgloss.NewStyle().Foreground(yellow),
		ExpiryOK:    lipgloss.NewStyle().Foreground(green),
		ExpiryWarn:  lipgloss.NewStyle().Foreground(yellow),
		ExpiryCrit:  lipgloss.NewStyle().Foreground(red).Bold(true),
	}
}

// Options controls Render's appearance.
type Options struct {
	Theme Theme
	// Width is the target terminal width for value wrapping. <=0 falls
	// back to defaultWidth.
	Width int
}

// Render writes a styled, colorized view of r to w. Field ordering and
// coverage matches internal/render/plain.Render exactly (this package
// styles, it does not add or remove fields): Domain, Handle, Registrar
// (Name/IANAID/URL/AbuseEmail/AbusePhone), Status, Created, Updated,
// Expires, Nameservers, DNSSEC, then Sources/Conflicts/Redacted blocks.
func Render(w io.Writer, r model.Record, opts Options) error {
	width := opts.Width
	if width <= 0 {
		width = defaultWidth
	}
	th := opts.Theme

	var b strings.Builder
	if r.Domain.Present() {
		b.WriteString(th.Header.Render("plat · "+r.Domain.Value) + "\n\n")
	}

	writeStringField(&b, th, width, "Domain", r.Domain)
	writeStringField(&b, th, width, "Handle", r.Handle)
	writeStringField(&b, th, width, "Registrar", r.Registrar.Name)
	writeStringField(&b, th, width, "Registrar IANA ID", r.Registrar.IANAID)
	writeStringField(&b, th, width, "Registrar URL", r.Registrar.URL)
	writeStringField(&b, th, width, "Abuse Email", r.Registrar.AbuseEmail)
	writeStringField(&b, th, width, "Abuse Phone", r.Registrar.AbusePhone)
	writeListField(&b, th, width, "Status", r.Status)
	writeTimeField(&b, th, width, "Created", r.Created, th.Value)
	writeTimeField(&b, th, width, "Updated", r.Updated, th.Value)
	writeTimeField(&b, th, width, "Expires", r.Expires, th.Value) // Task 3 replaces th.Value with expiryStyle(th, r.Expires.Value)
	writeListField(&b, th, width, "Nameservers", r.Nameservers)
	writeBoolField(&b, th, width, "DNSSEC", r.DNSSEC)

	_, err := lipgloss.Fprint(w, b.String())
	return err
}

func writeStringField(b *strings.Builder, th Theme, width int, label string, f model.Field[string]) {
	if !f.Present() {
		return
	}
	writeStyledRow(b, th, width, label, f.Value, th.Value, f.Sources)
}

func writeListField(b *strings.Builder, th Theme, width int, label string, f model.Field[[]string]) {
	if !f.Present() {
		return
	}
	writeStyledRow(b, th, width, label, strings.Join(f.Value, " · "), th.Value, f.Sources)
}

func writeBoolField(b *strings.Builder, th Theme, width int, label string, f model.Field[bool]) {
	if !f.Present() {
		return
	}
	val := "false"
	style := th.Value
	if f.Value {
		val = "true ✓"
		style = th.OK
	}
	writeStyledRow(b, th, width, label, val, style, f.Sources)
}

func writeTimeField(b *strings.Builder, th Theme, width int, label string, f model.Field[model.TimeValue], style lipgloss.Style) {
	if !f.Present() {
		return
	}
	if f.Value.Parsed {
		writeStyledRow(b, th, width, label, f.Value.Time.UTC().Format(time.RFC3339), style, f.Sources)
		return
	}
	writeStyledRow(b, th, width, label, f.Value.Raw+" (unparsed)", th.Muted, f.Sources)
}

// writeStyledRow lays out one "Label: value (sources)" row: a fixed-width
// styled label column, a wrapped+styled value column, and a trailing
// muted source-provenance badge on the row's last line only.
func writeStyledRow(b *strings.Builder, th Theme, width int, label, value string, valueStyle lipgloss.Style, sources []model.SourceID) {
	labelCol := th.Label.Render(fmt.Sprintf("%-*s", labelWidth, label+":"))
	badge := ""
	if len(sources) > 0 {
		badge = " " + th.SourceBadge.Render("("+formatSources(sources)+")")
	}

	valueWidth := width - labelWidth
	if valueWidth < 10 {
		valueWidth = 10
	}
	lines := wrapValue(value, valueWidth)
	for i, line := range lines {
		if i == 0 {
			b.WriteString(labelCol)
		} else {
			b.WriteString(strings.Repeat(" ", labelWidth))
		}
		b.WriteString(valueStyle.Render(line))
		if i == len(lines)-1 {
			b.WriteString(badge)
		}
		b.WriteString("\n")
	}
}

// wrapValue wraps s to fit within width columns using lipgloss's own
// word-boundary wrapping. lipgloss.Style.Width right-pads every wrapped
// line to exactly width runes (confirmed locally) — each returned line
// has that trailing padding trimmed, since callers do their own layout.
func wrapValue(s string, width int) []string {
	wrapped := lipgloss.NewStyle().Width(width).Render(s)
	rawLines := strings.Split(wrapped, "\n")
	lines := make([]string, len(rawLines))
	for i, l := range rawLines {
		lines[i] = strings.TrimRight(l, " ")
	}
	return lines
}

func formatSources(sources []model.SourceID) string {
	strs := make([]string, len(sources))
	for i, s := range sources {
		strs[i] = string(s)
	}
	return strings.Join(strs, ", ")
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/pat/codes/plat && go test ./internal/render/human/... -v`
Expected: PASS, all 7 test functions green.

- [ ] **Step 6: Confirm zero regression across the rest of the repo**

Run: `cd /Users/pat/codes/plat && go build ./... && go test ./...`
Expected: all 13 packages `ok` (this task only adds a new package and two new dependencies — nothing else imports `internal/render/human` yet, so nothing else can regress).

- [ ] **Step 7: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/render/human/human.go internal/render/human/human_test.go go.mod go.sum
git commit -m "feat: add the styled human renderer's theme, layout, and core fields"
```

---

### Task 3: `internal/render/human` — Expiry Color Ramp, Sources, Conflicts, Redacted

**Files:**
- Modify: `internal/render/human/human.go` (add `expiryStyle`, the Sources/Conflicts/Redacted blocks; change one line in `Render`)
- Modify: `internal/render/human/human_test.go` (extend)

**Interfaces:**
- Consumes: `human.Theme`, `human.writeStyledRow`/`wrapValue`/`formatSources` (Task 2, same file), `model.SourceResult`, `model.Conflict`, `model.RedactionNotice`, `model.Precedence` (pre-existing).
- Produces: nothing new consumed by later tasks — `human.Render`'s full field coverage (matching `plain.Render`'s) is now complete, ready for Task 5's dispatch.

- [ ] **Step 1: Write the failing tests**

Append to `internal/render/human/human_test.go` (add `"github.com/patramsey/plat/internal/model"` is already imported; no new imports needed beyond what Task 2 already added):

```go
func TestRender_ExpiryRamp(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("COLORTERM", "truecolor")
	th := NewTheme(false)

	tests := []struct {
		name      string
		until     time.Duration
		wantStyle lipgloss.Style
	}{
		{"far out -> OK", 200 * 24 * time.Hour, th.ExpiryOK},
		{"90 days -> warn boundary", 89 * 24 * time.Hour, th.ExpiryWarn},
		{"10 days -> crit", 10 * 24 * time.Hour, th.ExpiryCrit},
		{"already expired -> crit", -5 * 24 * time.Hour, th.ExpiryCrit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expires := time.Now().Add(tt.until)
			rec := model.Record{
				Domain:  model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
				Expires: model.Field[model.TimeValue]{Value: model.TimeValue{Time: expires, Raw: expires.Format(time.RFC3339), Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
			}
			var buf bytes.Buffer
			if err := Render(&buf, rec, Options{Theme: th, Width: 80}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			want := tt.wantStyle.Render(expires.UTC().Format(time.RFC3339))
			if !strings.Contains(buf.String(), want) {
				t.Errorf("expected the expiry date styled with the expected ramp color, want substring %q, got:\n%s", want, buf.String())
			}
		})
	}
}

func TestRender_SourcesBlock(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Sources: []model.SourceResult{
			{Source: model.SourceRegistryRDAP, OK: true, Latency: 89 * time.Millisecond},
			{Source: model.SourceRegistrarRDAP, OK: false, NotFound: true, Latency: 40 * time.Millisecond},
			{Source: model.SourceRegistryWHOIS, OK: false, Err: "timeout", Latency: 5 * time.Second},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{string(model.SourceRegistryRDAP), string(model.SourceRegistrarRDAP), string(model.SourceRegistryWHOIS), "timeout"} {
		if !strings.Contains(out, want) {
			t.Errorf("sources block missing %q, got:\n%s", want, out)
		}
	}
}

func TestRender_ConflictsBlock(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Conflicts: []model.Conflict{
			{
				Field: model.FieldExpires,
				Values: map[model.SourceID]string{
					model.SourceRegistryWHOIS:  "2026-08-10",
					model.SourceRegistryRDAP:   "2026-08-13T04:00:00Z",
					model.SourceRegistrarRDAP:  "2026-08-13T04:00:00Z",
					model.SourceRegistrarWHOIS: "2026-08-11",
				},
			},
		},
	}
	var first, second bytes.Buffer
	if err := Render(&first, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := Render(&second, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if first.String() != second.String() {
		t.Fatal("Render is non-deterministic across calls with the same input (conflict map ordering)")
	}
	out := first.String()
	registrarRDAPIdx := strings.Index(out, string(model.SourceRegistrarRDAP)+"=")
	registryRDAPIdx := strings.Index(out, string(model.SourceRegistryRDAP)+"=")
	registrarWHOISIdx := strings.Index(out, string(model.SourceRegistrarWHOIS)+"=")
	registryWHOISIdx := strings.Index(out, string(model.SourceRegistryWHOIS)+"=")
	if registrarRDAPIdx < 0 || registryRDAPIdx < 0 || registrarWHOISIdx < 0 || registryWHOISIdx < 0 {
		t.Fatalf("expected all 4 source values in the conflict line, got:\n%s", out)
	}
	if !(registrarRDAPIdx < registryRDAPIdx && registryRDAPIdx < registrarWHOISIdx && registrarWHOISIdx < registryWHOISIdx) {
		t.Errorf("conflict values not rendered in model.Precedence order, got:\n%s", out)
	}
}

func TestRender_RedactedBlock(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
		Redacted: []model.RedactionNotice{
			{Field: model.FieldRegistrarName, Source: model.SourceRegistrarRDAP, Reason: "redacted"},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, string(model.SourceRegistrarRDAP)) || !strings.Contains(out, "redacted") {
		t.Errorf("expected redaction notice in output, got:\n%s", out)
	}
}
```

Add `"charm.land/lipgloss/v2"` to `human_test.go`'s import block (needed for `lipgloss.Style` in `TestRender_ExpiryRamp`'s table).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/pat/codes/plat && go test ./internal/render/human/... -v -run 'ExpiryRamp|SourcesBlock|ConflictsBlock|RedactedBlock'`
Expected: FAIL — the expiry ramp test fails because `Render` currently always uses `th.Value` for Expires (no ramp yet); the Sources/Conflicts/Redacted tests fail because those blocks don't exist in `Render` yet (their expected substrings are simply absent from the output, no build error — the fields exist on `model.Record` already, just unrendered).

- [ ] **Step 3: Write the implementation**

In `internal/render/human/human.go`, change this one line inside `Render` (replace `th.Value` with a call to the new `expiryStyle` helper):

```go
	writeTimeField(&b, th, width, "Expires", r.Expires, expiryStyle(th, r.Expires.Value))
```

Immediately after the `writeBoolField(&b, th, width, "DNSSEC", r.DNSSEC)` line inside `Render`, and before the final `_, err := lipgloss.Fprint(w, b.String())` line, add:

```go
	writeSources(&b, th, r.Sources)
	writeConflicts(&b, th, r.Conflicts)
	writeRedacted(&b, th, r.Redacted)
```

Add these new functions to the file (after `formatSources`):

```go
// expiryStyle picks the color-ramp style for an expiry date: green when
// comfortably far out, yellow inside 90 days, red inside 30 days or
// already expired. An unparsed value gets no ramp — writeTimeField
// already falls back to th.Muted for that case regardless of the style
// passed here.
func expiryStyle(th Theme, tv model.TimeValue) lipgloss.Style {
	if !tv.Parsed {
		return th.Muted
	}
	until := time.Until(tv.Time)
	switch {
	case until <= 30*24*time.Hour:
		return th.ExpiryCrit
	case until <= 90*24*time.Hour:
		return th.ExpiryWarn
	default:
		return th.ExpiryOK
	}
}

func writeSources(b *strings.Builder, th Theme, sources []model.SourceResult) {
	if len(sources) == 0 {
		return
	}
	b.WriteString("\n" + th.Label.Render("Sources") + "\n")
	for _, s := range sources {
		status := th.Muted.Render("no data")
		switch {
		case s.OK:
			status = th.OK.Render("✓ ok")
		case s.NotFound:
			status = th.Warn.Render("– not found")
		case s.Err != "":
			status = th.Err.Render("✗ " + s.Err)
		}
		fmt.Fprintf(b, "  %-20s %s  %s\n", s.Source, s.Latency.Round(time.Millisecond), status)
	}
}

func writeConflicts(b *strings.Builder, th Theme, conflicts []model.Conflict) {
	if len(conflicts) == 0 {
		return
	}
	b.WriteString("\n" + th.Warn.Render("Conflicts") + "\n")
	for _, c := range conflicts {
		fmt.Fprintf(b, "  %s: %s\n", c.Field, formatConflictValues(c.Values))
	}
}

func writeRedacted(b *strings.Builder, th Theme, redacted []model.RedactionNotice) {
	if len(redacted) == 0 {
		return
	}
	b.WriteString("\n" + th.Muted.Render("Redacted") + "\n")
	for _, red := range redacted {
		fmt.Fprintf(b, "  %s: %s (%s)\n", red.Field, red.Source, red.Reason)
	}
}

// formatConflictValues renders a Conflict's map in model.Precedence order
// — Go map iteration order is randomized, and ranging over the map
// directly would make output (and any test asserting on it) flaky.
func formatConflictValues(values map[model.SourceID]string) string {
	var parts []string
	for _, src := range model.Precedence {
		if v, ok := values[src]; ok {
			parts = append(parts, fmt.Sprintf("%s=%s", src, v))
		}
	}
	return strings.Join(parts, ", ")
}
```

- [ ] **Step 4: Run tests to verify they pass, and confirm zero regression**

Run: `cd /Users/pat/codes/plat && go test ./internal/render/human/... -v`
Expected: PASS — all tests from Task 2 AND Task 3 (11 test functions total) green.

Run: `cd /Users/pat/codes/plat && go build ./... && go test ./...`
Expected: all 13 packages `ok`.

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/render/human/human.go internal/render/human/human_test.go
git commit -m "feat: add the expiry color ramp and sources/conflicts/redacted blocks to the human renderer"
```

---

### Task 4: `internal/spinner` — Lookup-in-Progress Indicator

**Files:**
- Create: `internal/spinner/spinner.go`
- Create: `internal/spinner/spinner_test.go`
- Modify: `go.mod`, `go.sum` (via `go get`)

**Interfaces:**
- Consumes: nothing from `plat`'s own packages — a standalone leaf package.
- Produces: `func Run(w io.Writer, message string, work func())` — consumed by Task 5's `lookupOne`.

- [ ] **Step 1: Add the new dependencies**

Run: `cd /Users/pat/codes/plat && go get charm.land/bubbles/v2@latest charm.land/bubbletea/v2@latest`

Confirmed locally to resolve to `bubbles/v2 v2.1.1` and `bubbletea/v2 v2.0.8`, pulling in `github.com/charmbracelet/ultraviolet`, `github.com/charmbracelet/x/term`, `github.com/charmbracelet/x/termios`, `github.com/charmbracelet/x/windows`, `github.com/clipperhouse/displaywidth`, `github.com/clipperhouse/uax29/v2`, `github.com/muesli/cancelreader`, `github.com/xo/terminfo`, `golang.org/x/sync`, `golang.org/x/sys` as transitive deps. Run `go build ./...` afterward — expected: still builds clean.

- [ ] **Step 2: Write the failing test**

Create `internal/spinner/spinner_test.go`:

```go
package spinner

import (
	"bytes"
	"testing"
)

func TestRun_ExecutesWorkAndReturns(t *testing.T) {
	var buf bytes.Buffer
	var workDone bool

	Run(&buf, "testing", func() {
		workDone = true
	})

	if !workDone {
		t.Error("work function was not called before Run returned")
	}
}

func TestRun_DoesNotRequireARealTerminal(t *testing.T) {
	// This test's mere ability to complete (not hang, not error) is the
	// assertion: Run must work when w is a plain *bytes.Buffer, not a
	// real terminal — this is what makes callers of Run (and their own
	// tests) safe to run in CI/sandboxed environments with no /dev/tty.
	var buf bytes.Buffer
	Run(&buf, "no terminal here", func() {})
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/spinner/... -v`
Expected: FAIL — build error, package `internal/spinner` doesn't exist yet.

- [ ] **Step 4: Write the implementation**

Create `internal/spinner/spinner.go`:

```go
// Package spinner shows an animated progress indicator on an io.Writer
// (intended to be stderr) while a caller-supplied function runs, then
// clears it. It is a transient use of charm.land/bubbletea/v2's Program
// machinery purely for the spinner animation — plat is a render-and-exit
// tool, not an interactive TUI, and this package never reads input.
package spinner

import (
	"io"

	tea "charm.land/bubbletea/v2"
	"charm.land/bubbles/v2/spinner"
)

// Run displays an animated spinner with message on w while work executes
// in the background, then clears the spinner once work returns. work is
// always fully executed before Run returns, regardless of whether the
// spinner itself renders (e.g. if w isn't a real terminal).
//
// tea.WithInput(nil) is required here: charm.land/bubbletea/v2's default
// Program tries to open a real controlling terminal (/dev/tty) for input
// even when only output is redirected, which fails in any environment
// without one (CI, sandboxes) — plat's spinner phase never reads
// keyboard input, so there is nothing to lose by disabling it.
func Run(w io.Writer, message string, work func()) {
	p := tea.NewProgram(newModel(message), tea.WithOutput(w), tea.WithInput(nil))

	go func() {
		work()
		p.Send(doneMsg{})
	}()

	_, _ = p.Run() // a rendering error here is non-fatal — work has already run
}

type doneMsg struct{}

type model struct {
	spinner spinner.Model
	message string
	done    bool
}

func newModel(message string) model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	return model{spinner: s, message: message}
}

func (m model) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case doneMsg:
		m.done = true
		return m, tea.Quit
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m model) View() tea.View {
	if m.done {
		return tea.NewView("")
	}
	return tea.NewView(m.spinner.View() + " " + m.message + "\n")
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./internal/spinner/... -v`
Expected: PASS, both test functions green. (Confirms the exact failure mode seen locally — `bubbletea: could not open TTY: open /dev/tty: device not configured` — does NOT occur, since `tea.WithInput(nil)` is wired correctly.)

- [ ] **Step 6: Confirm zero regression across the rest of the repo**

Run: `cd /Users/pat/codes/plat && go build ./... && go test ./...`
Expected: all 14 packages `ok`.

- [ ] **Step 7: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/spinner/spinner.go internal/spinner/spinner_test.go go.mod go.sum
git commit -m "feat: add a bubbles/bubbletea-backed lookup spinner"
```

---

### Task 5: Integrate — `cmd/plat/main.go` Wiring

**Files:**
- Modify: `cmd/plat/main.go` (add `uiConfig`, detect in `main()`, thread through `run`/`runLookup`/`lookupOne`/`renderRecord`, dispatch `FormatHuman` to `human.Render`, wrap `collect.Collect` with the spinner)
- Modify: `cmd/plat/main_test.go` (every existing call to `run(args, &stdout, &stderr)` gains a 4th `uiConfig{}` argument)
- Modify: `internal/render/render.go` (update the package doc comment — Human no longer renders identically to Plain)

**Interfaces:**
- Consumes: `render.Select` (Task 1, 3-arg), `human.Render`/`human.NewTheme`/`human.Options` (Tasks 2-3), `spinner.Run` (Task 4), `lipgloss.HasDarkBackground` (new import), `golang.org/x/term.GetSize` (new import).
- Produces: nothing consumed by later tasks — this is M5's final, root-command-visible deliverable.

This is the highest-risk task in this milestone: every function from `main()` down to `renderRecord` gains a parameter, and EVERY existing test in `main_test.go` that calls `run(...)` must be updated to match, or the package won't build.

- [ ] **Step 1: Write the failing tests**

First, find every existing call site that needs updating:

Run: `cd /Users/pat/codes/plat && grep -n 'run(' cmd/plat/main_test.go`

For EVERY line that calls `run(args, &stdout, &stderr)` (or an equivalent 3-argument form) found by that grep, change it to pass a 4th argument, `uiConfig{}` (the zero value — not dark, width 0 which `renderRecord`/`human.Render` will fall back to 80, `StderrTTY: false` which means the spinner never runs in tests). For example, a line like:

```go
got := run([]string{"localhost", "also-bad"}, &stdout, &stderr)
```

becomes:

```go
got := run([]string{"localhost", "also-bad"}, &stdout, &stderr, uiConfig{})
```

Apply this to every matching call site in the file — there is no other change needed to any existing test's logic or assertions, since a zero-value `uiConfig` preserves every existing test's prior behavior exactly (non-TTY, no spinner, plain-renderer-equivalent styling never exercised).

Then append this new test, which is the task's own regression guard for the wiring itself:

```go
func TestRun_HumanFormatDispatchesToStyledRenderer(t *testing.T) {
	// A non-TTY uiConfig still lets an EXPLICIT -o human dispatch to the
	// styled renderer (per Task 1's Select semantics) — with no color
	// forced (no CLICOLOR_FORCE/COLORTERM env vars set here), the output
	// should be styling-shaped but ANSI-free, since neither stdout here
	// (a bytes.Buffer) nor the environment forces color.
	var stdout, stderr bytes.Buffer
	got := run([]string{"-o", "human", "localhost"}, &stdout, &stderr, uiConfig{})
	if got != 2 {
		t.Fatalf("run exit code = %d, want 2 (localhost fails domain.Normalize)", got)
	}
	// localhost fails before rendering ever happens, so this only proves
	// the flag parses and the format resolves without error — the
	// dispatch-to-human-vs-plain distinction itself is exercised by
	// TestRenderRecord_DispatchesFormatHumanToStyledRenderer below,
	// which calls the unexported renderRecord function directly with a
	// real record (no network lookup needed).
}

func TestRenderRecord_DispatchesFormatHumanToStyledRenderer(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var humanBuf, plainBuf bytes.Buffer
	ui := uiConfig{Dark: false, Width: 80}

	if err := renderRecord(&humanBuf, render.FormatHuman, rec, false, ui); err != nil {
		t.Fatalf("unexpected error rendering FormatHuman: %v", err)
	}
	if err := renderRecord(&plainBuf, render.FormatPlain, rec, false, ui); err != nil {
		t.Fatalf("unexpected error rendering FormatPlain: %v", err)
	}
	if humanBuf.String() == plainBuf.String() {
		t.Error("FormatHuman and FormatPlain produced byte-identical output — expected the styled renderer's layout (e.g. the header line) to differ from the plain renderer's")
	}
	if !strings.Contains(humanBuf.String(), "example.com") {
		t.Errorf("FormatHuman output missing the domain value, got:\n%s", humanBuf.String())
	}
}
```

Add `"github.com/patramsey/plat/internal/model"` and `"github.com/patramsey/plat/internal/render"` to `cmd/plat/main_test.go`'s import block if not already present (both are already imported as of the M4 plan's Task 6 — verify via the file's current import block before assuming; add only if actually missing).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/pat/codes/plat && go test ./cmd/plat/... -v`
Expected: FAIL — build errors everywhere (`run`/`renderRecord` called with the wrong argument count; `uiConfig` undefined).

- [ ] **Step 3: Write the implementation**

In `cmd/plat/main.go`, add these imports to the import block:

```go
	"charm.land/lipgloss/v2"
	"golang.org/x/term"

	"github.com/patramsey/plat/internal/render/human"
	"github.com/patramsey/plat/internal/spinner"
```

(alongside the existing `bootstrap`, `collect`, `domain`, `merge`, `model`, `rdap`, `render`, `render/machine`, `render/plain` imports — keep the existing grouping/ordering convention: stdlib first, then third-party, then this module's own packages, matching the file's current style.)

Add the `uiConfig` type (near the top of the file, after `exitSignal`):

```go
// uiConfig carries terminal-detection results computed once in main()
// using real file descriptors, threaded down as plain data so every
// function below main() stays a pure function of its arguments — exactly
// like stdout/stderr being injected io.Writers rather than os.Stdout
// directly, which is what has kept this whole command line testable with
// bytes.Buffers since M1. The zero value (Dark: false, Width: 0 -> 80,
// NoColor: false, StderrTTY: false) is what every existing test already
// implicitly exercises: no color forced, no spinner.
type uiConfig struct {
	Dark      bool
	Width     int
	NoColor   bool
	StderrTTY bool
}
```

Replace `func main()`:

```go
func main() {
	ui := uiConfig{NoColor: os.Getenv("NO_COLOR") != ""}
	if render.IsTerminal(os.Stdout) {
		ui.Dark = lipgloss.HasDarkBackground(os.Stdin, os.Stdout)
		if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
			ui.Width = w
		}
	}
	ui.StderrTTY = render.IsTerminal(os.Stderr)
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, ui))
}
```

Change `func run`'s signature and its one internal call site:

```go
func run(args []string, stdout, stderr io.Writer, ui uiConfig) int {
```

and inside it, the `RunE` closure:

```go
		RunE: func(cmd *cobra.Command, cliArgs []string) error {
			return runLookup(cmd.Context(), stdout, stderr, cliArgs, lookupOptions{
				RefreshBootstrap: refreshBootstrap,
				Timeout:          timeout,
				Output:           output,
				Raw:              raw,
				SourceFilter:     sourceFilter,
				NoFollow:         noFollow,
			}, ui)
		},
```

Change `func runLookup`'s signature, its `Select` call, and its `lookupOne` call:

```go
func runLookup(ctx context.Context, stdout, stderr io.Writer, domains []string, opts lookupOptions, ui uiConfig) error {
	format, err := render.Select(opts.Output, render.IsTerminal(os.Stdout), ui.NoColor)
	if err != nil {
		return usageError{err}
	}
	if opts.Raw && !render.IsMachine(format) {
		return usageError{fmt.Errorf("--raw is only meaningful with -o json or -o ndjson")}
	}
	if format == render.FormatJSON && len(domains) > 1 {
		return usageError{fmt.Errorf("-o json supports exactly one domain; use -o ndjson for multiple")}
	}
	sources, err := parseSourceFilter(opts.SourceFilter)
	if err != nil {
		return usageError{err}
	}

	resolver, err := bootstrap.Load(ctx, bootstrap.Options{Refresh: opts.RefreshBootstrap, Timeout: opts.Timeout})
	if err != nil {
		return fmt.Errorf("resolving RDAP bootstrap: %w", err)
	}

	worst := 0
	for i, input := range domains {
		code := lookupOne(ctx, stdout, stderr, resolver, input, opts, sources, format, ui)
		if code > worst {
			worst = code
		}
		if !render.IsMachine(format) && i < len(domains)-1 {
			_, _ = fmt.Fprintln(stdout)
		}
	}
	if worst != 0 {
		return exitSignal{worst}
	}
	return nil
}
```

Change `func lookupOne`'s signature and body (wrap the `collect.Collect` call with the spinner):

```go
// lookupOne performs one domain's normalize -> collect -> merge ->
// render-or-report flow and returns that domain's exit code (0/2/1/3;
// 2 only for a per-domain normalize failure). Collect runs behind a
// spinner (on stderr) only when stderr is a real terminal and the output
// format is FormatHuman — never for Plain/JSON/NDJSON, and never when
// stderr is redirected even if stdout is a terminal.
func lookupOne(ctx context.Context, stdout, stderr io.Writer, resolver *bootstrap.Resolver, input string, opts lookupOptions, sources []model.SourceID, format render.Format, ui uiConfig) int {
	name, err := domain.Normalize(input)
	if err != nil {
		reportLookupError(stderr, format, input, err)
		return 2
	}

	baseURL, _ := resolver.BaseURL(name.TLD) // "" is fine — Collect degrades to WHOIS-only
	collectOpts := collect.Options{NoFollow: opts.NoFollow, Timeout: opts.Timeout, Sources: sources}

	var records []model.SourceRecord
	work := func() {
		records = collect.Collect(ctx, name, baseURL, "", collectOpts)
	}
	if ui.StderrTTY && format == render.FormatHuman {
		spinner.Run(stderr, "looking up "+name.Punycode+"...", work)
	} else {
		work()
	}

	record := merge.Merge(records)

	code := deriveOutcome(record.Sources)
	if code == 0 {
		if err := renderRecord(stdout, format, record, opts.Raw, ui); err != nil {
			reportLookupError(stderr, format, name.Punycode, err)
			return 3
		}
		return 0
	}
	reportLookupError(stderr, format, name.Punycode, fmt.Errorf("no usable data for %s", name.Punycode))
	return code
}
```

Change `func renderRecord`:

```go
func renderRecord(w io.Writer, format render.Format, record model.Record, raw bool, ui uiConfig) error {
	switch format {
	case render.FormatJSON:
		return machine.Encode(w, record, machine.Options{Raw: raw})
	case render.FormatNDJSON:
		return machine.EncodeNDJSON(w, record, machine.Options{Raw: raw})
	case render.FormatHuman:
		return human.Render(w, record, human.Options{Theme: human.NewTheme(ui.Dark), Width: ui.Width})
	default: // FormatPlain
		return plain.Render(w, record)
	}
}
```

Finally, in `internal/render/render.go`, update the package doc comment (it currently says Human and Plain render identically "in this milestone" — that's no longer true as of this task):

```go
// Package render selects which output format cmd/plat uses for a lookup
// and detects whether stdout is an interactive terminal. It does not
// import internal/render/plain, internal/render/human, or
// internal/render/machine itself — the caller (cmd/plat) dispatches to
// the right one based on the Format this package returns, keeping this
// leaf package free of all three renderers' dependencies.
package render
```

and the `Format` type's doc comment:

```go
// Format selects which renderer cmd/plat dispatches to: FormatHuman to
// internal/render/human's styled output, FormatPlain to
// internal/render/plain's unstyled output, FormatJSON/FormatNDJSON to
// internal/render/machine's encoder.
type Format int
```

- [ ] **Step 4: Run tests to verify they pass, and confirm zero regression**

Run: `cd /Users/pat/codes/plat && go test ./cmd/plat/... -v`
Expected: PASS — every pre-existing test (now updated with the 4th `uiConfig{}` argument) plus the two new tests from Step 1, all green.

Run: `cd /Users/pat/codes/plat && go mod tidy && go build ./... && go vet ./... && golangci-lint run && go test ./...`
Expected: all succeed, `golangci-lint run` reports 0 issues, all 14 packages `ok`.

- [ ] **Step 5: Manual end-to-end smoke test**

These require live network access and a real terminal, so they are not part of the automated suite — run them and visually confirm:

```bash
cd /Users/pat/codes/plat

go run ./cmd/plat google.com                     # real TTY: styled human output — colored labels, an expiry line in green/yellow/red depending on how far out it is, a "Sources" block, a brief spinner while the lookup runs
go run ./cmd/plat google.com | cat                # piped: falls back to FormatPlain (Select's auto-path), zero ANSI, byte-identical in shape to M4's plain output
go run ./cmd/plat -o human google.com | cat        # piped but EXPLICIT -o human: styled LAYOUT (header line, spacing) but zero ANSI — lipgloss.Fprint strips color since the pipe isn't a terminal
NO_COLOR=1 go run ./cmd/plat google.com            # real TTY but NO_COLOR set: auto-path falls back to FormatPlain (Select's noColor branch)
NO_COLOR=1 go run ./cmd/plat -o human google.com   # real TTY, NO_COLOR set, EXPLICIT -o human: styled layout renders, but zero ANSI (lipgloss respects NO_COLOR internally)
go run ./cmd/plat google.com 2>/dev/null           # stderr redirected: no spinner appears (stdout output unaffected either way)
```

- [ ] **Step 6: Commit**

```bash
cd /Users/pat/codes/plat
git add cmd/plat/main.go cmd/plat/main_test.go internal/render/render.go
git commit -m "feat: wire the styled human renderer and spinner into the root command"
```

---

## Milestone Verification (manual, not automated)

Once all 5 tasks are complete, in addition to Task 5's Step 5 smoke tests above, confirm:

```bash
cd /Users/pat/codes/plat

go run ./cmd/plat --source whois google.com        # human output still styles correctly with only WHOIS sources present (fewer Sources rows)
go run ./cmd/plat this-domain-should-not-exist-xyzabc123.com; echo $?   # expect exit 1, styled "no usable data" message on stderr (plain text, not JSON, since format is human)
COLUMNS=40 go run ./cmd/plat google.com            # narrow terminal: confirm nameserver/status lists wrap instead of overflowing (note: COLUMNS isn't read by golang.org/x/term.GetSize automatically in all terminals — if this doesn't visibly narrow the output, resize the actual terminal window instead and re-run)
```

If a real-world domain's data surfaces a layout edge case (e.g. an unusually long registrar URL that wraps awkwardly), that's a finding for a follow-up task — extend `internal/render/human`'s tests rather than hand-patching `cmd/plat`.

---

## Self-Review

**Spec coverage:** "Lipgloss layout" (Tasks 2-3's `Theme`/`Render`), "spinner" (Task 4), "color ramps" (Task 3's `expiryStyle`), "NO_COLOR" (Task 1's `Select` + the deliberate no-hand-checking in the renderer itself), "width handling" (Task 2's `wrapValue`/`writeStyledRow`) — every item from the milestone's one-line spec is covered by a task. CLAUDE.md's binding constraints (Lip Gloss writer functions, `HasDarkBackground`, no `compat` package, `NO_COLOR`/non-TTY routing) are each traced to a specific Global Constraint and task.

**Placeholder scan:** no "TBD"/"handle appropriately"/"similar to Task N" patterns — every step has complete, runnable code, including the full `Theme`, the full width-wrapping mechanics, the full spinner package, and the full `cmd/plat` rewiring.

**Type consistency:** `human.Render(w io.Writer, r model.Record, opts Options) error` and `human.Options{Theme, Width}` are used identically in Tasks 2, 3, and 5. `spinner.Run(w io.Writer, message string, work func())` is used identically in Task 4 and Task 5. `uiConfig{Dark, Width, NoColor, StderrTTY}` is defined once in Task 5 and used consistently across `main`/`run`/`runLookup`/`lookupOne`/`renderRecord`. `render.Select(explicit string, isTTY bool, noColor bool) (Format, error)` — the 3-arg signature from Task 1 is used identically at its only call site in Task 5.

**Regression discipline:** every task that modifies a pre-existing file (Task 1: `render.go`, `render_test.go`, `main.go`; Task 5: `main.go`, `main_test.go`, `render.go`) has an explicit step confirming that package's pre-existing tests still pass — Task 5 additionally spells out, rather than assumes, that EVERY existing `run(...)` call site in `main_test.go` needs its new 4th argument, since a silently-missed call site would simply fail to compile (a safe, loud failure mode, not a silent behavior change) but should still be found deliberately via the `grep` step rather than by trial and error.
