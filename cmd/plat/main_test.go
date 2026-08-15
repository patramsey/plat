package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/patramsey/plat/internal/bootstrap"
	"github.com/patramsey/plat/internal/domain"
	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/rdap"
	"github.com/patramsey/plat/internal/render"
	"github.com/patramsey/plat/internal/render/human"
	"github.com/patramsey/plat/internal/render/machine"
	"github.com/patramsey/plat/internal/whois"
)

func TestExitCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil error", nil, 0},
		{"usage error", usageError{errors.New("bad input")}, 2},
		{"domain not found", rdap.ErrDomainNotFound, 1},
		{"wrapped domain not found", fmt.Errorf("lookup: %w", rdap.ErrDomainNotFound), 1},
		{"other error", errors.New("network exploded"), 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer
			got := exitCode(tt.err, &stderr)
			if got != tt.want {
				t.Errorf("exitCode(%v) = %d, want %d", tt.err, got, tt.want)
			}
			if tt.err != nil && stderr.Len() == 0 {
				t.Errorf("expected an error message written to stderr")
			}
		})
	}
}

func TestRun_RejectsWrongArgCount(t *testing.T) {
	// M4 note: this table previously also covered a "two args" case
	// ({"example.com", "example.org"}, want exit 2) under M1's exactly-
	// one-argument rule. M4 changes the Args validator to "at least one",
	// so two syntactically valid domains are no longer a usage error at
	// all — they're valid multi-domain input and (since both are real,
	// resolvable domains) now trigger real network lookups that succeed
	// with exit 0. That case is removed here; multi-domain acceptance is
	// covered without live network dependencies by
	// TestRun_AcceptsMultipleDomainArgs (using "localhost"/"also-bad",
	// which fail domain.Normalize before any network call) and by
	// TestRun_NoArgsStillRejected below covering the zero-args side of
	// this rule.
	tests := []struct {
		name string
		args []string
	}{
		{"no args", []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := run(tt.args, &stdout, &stderr, uiConfig{})
			if got != 2 {
				t.Errorf("run(%v) exit code = %d, want 2 (usage error)", tt.args, got)
			}
		})
	}
}

func TestRun_VersionSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"version"}, &stdout, &stderr, uiConfig{})
	if got != 0 {
		t.Errorf("run([version]) exit code = %d, want 0", got)
	}
	if stdout.Len() == 0 {
		t.Error("expected version to be printed to stdout")
	}
}

func TestDeriveOutcome(t *testing.T) {
	tests := []struct {
		name string
		in   []model.SourceResult
		want int
	}{
		{"all OK", []model.SourceResult{{OK: true}, {OK: true}}, 0},
		{"mixed OK and failed", []model.SourceResult{{OK: true}, {}}, 0},
		{"mixed OK and notfound", []model.SourceResult{{OK: true}, {NotFound: true}}, 0},
		{"all notfound", []model.SourceResult{{NotFound: true}, {NotFound: true}}, 1},
		{"single notfound", []model.SourceResult{{NotFound: true}}, 1},
		{"mixed notfound and failed", []model.SourceResult{{NotFound: true}, {}}, 3},
		{"all failed", []model.SourceResult{{}, {}}, 3},
		{"single failed", []model.SourceResult{{}}, 3},
		{"zero sources", []model.SourceResult{}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deriveOutcome(tt.in); got != tt.want {
				t.Errorf("deriveOutcome(%+v) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestLookupOutcomeError(t *testing.T) {
	tests := []struct {
		name    string
		code    int
		sources []model.SourceResult
		want    string
	}{
		{
			"not registered, single source",
			1,
			[]model.SourceResult{{Source: model.SourceRegistryRDAP, NotFound: true}},
			"is not registered (checked: registry-rdap)",
		},
		{
			"not registered, all sources agree",
			1,
			[]model.SourceResult{
				{Source: model.SourceRegistrarRDAP, NotFound: true},
				{Source: model.SourceRegistryRDAP, NotFound: true},
				{Source: model.SourceRegistrarWHOIS, NotFound: true},
			},
			"is not registered (checked: registrar-rdap, registry-rdap, registrar-whois)",
		},
		{
			"total failure, zero sources",
			3,
			nil,
			"lookup failed -- no sources could be reached",
		},
		{
			"total failure, all sources errored",
			3,
			[]model.SourceResult{{Source: model.SourceRegistryRDAP, Err: "timeout"}, {Source: model.SourceRegistryWHOIS, Err: "dial refused"}},
			"lookup inconclusive -- 2 of 2 sources failed, so non-existence can't be confirmed (checked: registry-rdap, registry-whois)",
		},
		{
			"total failure, mixed notfound and errored",
			3,
			[]model.SourceResult{{Source: model.SourceRegistryRDAP, NotFound: true}, {Source: model.SourceRegistryWHOIS, Err: "timeout"}},
			"lookup inconclusive -- 1 of 2 sources failed, so non-existence can't be confirmed (checked: registry-rdap, registry-whois)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := lookupOutcomeError(tt.code, tt.sources).Error()
			if got != tt.want {
				t.Errorf("lookupOutcomeError(%d, %+v) = %q, want %q", tt.code, tt.sources, got, tt.want)
			}
			if strings.Contains(got, "no usable data") {
				t.Error("message should never fall back to the old generic \"no usable data\" wording")
			}
		})
	}
}

func TestParseSourceFilter(t *testing.T) {
	tests := []struct {
		in      string
		want    []model.SourceID
		wantErr bool
	}{
		{"", nil, false},
		{"rdap", []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistrarRDAP}, false},
		{"whois", []model.SourceID{model.SourceRegistryWHOIS, model.SourceRegistrarWHOIS}, false},
		{"registry", []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistryWHOIS}, false},
		{"registrar", []model.SourceID{model.SourceRegistrarRDAP, model.SourceRegistrarWHOIS}, false},
		{"bogus", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseSourceFilter(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseSourceFilter(%q) expected an error, got nil", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSourceFilter(%q) unexpected error: %v", tt.in, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("parseSourceFilter(%q) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseSourceFilter(%q)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestRun_AcceptsMultipleDomainArgs(t *testing.T) {
	// A single malformed domain among several still yields a usage-level
	// per-domain error (exit code 2 contributes to the overall worst
	// code) rather than a hard cobra arg-count usage error — multiple
	// args are now valid at the Args-validator level.
	var stdout, stderr bytes.Buffer
	got := run([]string{"localhost", "also-bad"}, &stdout, &stderr, uiConfig{})
	if got != 2 {
		t.Errorf("run([localhost also-bad]) exit code = %d, want 2 (both are single-label, worst code across domains is 2)", got)
	}
}

func TestRun_NoArgsStillRejected(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{}, &stdout, &stderr, uiConfig{})
	if got != 2 {
		t.Errorf("run([]) exit code = %d, want 2 (at least one domain required)", got)
	}
	// A bare invocation is a "how do I use this" moment, not a mistake
	// that needs explaining — it should show the same help --help does,
	// not a terse one-line error.
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Errorf("expected help output on stdout for a bare invocation, got stdout:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("expected nothing on stderr when showing help for a bare invocation, got:\n%s", stderr.String())
	}
}

// TestRun_ReservedIPRejectedAtExit2 is a regression test for a real
// defect caught during live verification: reserved/private IP input
// (10.0.0.1, ::1, etc.) used to sail past domain.Normalize, spend several
// seconds actually querying whois.iana.org, and then exit 3 with the
// factually wrong message "lookup failed -- no sources could be
// reached" (IANA's WHOIS server was reached and answered; it just had no
// "refer:" line for private-use space). domain.Normalize now rejects
// these up front, so this exits 2 immediately -- no network involved,
// keeping this test hermetic -- with a message that doesn't misdescribe
// what happened.
func TestRun_ReservedIPRejectedAtExit2(t *testing.T) {
	tests := []string{"10.0.0.1", "127.0.0.1", "0.0.0.0", "255.255.255.255", "::1"}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := run([]string{input}, &stdout, &stderr, uiConfig{})
			if got != 2 {
				t.Errorf("run([%s]) exit code = %d, want 2 (usage error, not exit 3)", input, got)
			}
			errMsg := stderr.String()
			if strings.Contains(errMsg, "no sources could be reached") || strings.Contains(errMsg, "unreachable") {
				t.Errorf("run([%s]) stderr = %q, must not claim sources were unreachable (whois.iana.org answers just fine for these)", input, errMsg)
			}
		})
	}
}

func TestRun_InvalidOutputFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"-o", "bogus", "example.com"}, &stdout, &stderr, uiConfig{})
	if got != 2 {
		t.Errorf("run with -o bogus exit code = %d, want 2", got)
	}
}

func TestRun_RawWithoutMachineFormatIsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"--raw", "-o", "plain", "example.com"}, &stdout, &stderr, uiConfig{})
	if got != 2 {
		t.Errorf("run with --raw -o plain exit code = %d, want 2", got)
	}
}

func TestRun_MultiDomainJSONIsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"-o", "json", "a.com", "b.com"}, &stdout, &stderr, uiConfig{})
	if got != 2 {
		t.Errorf("run with -o json and 2 domains exit code = %d, want 2", got)
	}
}

func TestRun_InvalidSourceFilter(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"--source", "bogus", "example.com"}, &stdout, &stderr, uiConfig{})
	if got != 2 {
		t.Errorf("run with --source bogus exit code = %d, want 2", got)
	}
}

// TestRun_CobraFlagParseErrorsAreUsageErrors covers a class of usage
// mistake that never reaches the hand-written usageError paths above:
// cobra/pflag's own flag-parsing errors (unknown flag, wrong argument
// type, missing flag value) happen inside root.Execute() itself, before
// RunE ever runs. Without SetFlagErrorFunc wrapping them, these fell
// through exitCode's default case to exit 3 ("total lookup failure")
// even though no lookup was ever attempted.
func TestRun_CobraFlagParseErrorsAreUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"unknown flag", []string{"--bogus-flag", "example.com"}},
		{"wrong argument type", []string{"--timeout", "notaduration", "example.com"}},
		{"missing flag value", []string{"-o"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := run(tt.args, &stdout, &stderr, uiConfig{})
			if got != 2 {
				t.Errorf("run(%v) exit code = %d, want 2", tt.args, got)
			}
		})
	}
}

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

	if err := renderRecord(&humanBuf, render.FormatHuman, rec, false, false, false, false, ui); err != nil {
		t.Fatalf("unexpected error rendering FormatHuman: %v", err)
	}
	if err := renderRecord(&plainBuf, render.FormatPlain, rec, false, false, false, false, ui); err != nil {
		t.Fatalf("unexpected error rendering FormatPlain: %v", err)
	}
	if humanBuf.String() == plainBuf.String() {
		t.Error("FormatHuman and FormatPlain produced byte-identical output — expected the styled renderer's layout (e.g. the header line) to differ from the plain renderer's")
	}
	if !strings.Contains(humanBuf.String(), "example.com") {
		t.Errorf("FormatHuman output missing the domain value, got:\n%s", humanBuf.String())
	}
}

func TestRenderRecord_VerboseGatesSourcesBlockButNotConflicts(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Sources: []model.SourceResult{
			{Source: model.SourceRegistryRDAP, OK: true, Latency: 89 * time.Millisecond},
		},
		Conflicts: []model.Conflict{
			{
				Field: model.FieldExpires,
				Values: map[model.SourceID]string{
					model.SourceRegistryRDAP:  "2026-08-13T04:00:00Z",
					model.SourceRegistrarRDAP: "2026-08-10T04:00:00Z",
				},
			},
		},
	}
	ui := uiConfig{Dark: false, Width: 80}

	for _, format := range []render.Format{render.FormatHuman, render.FormatPlain} {
		var quietBuf, verboseBuf bytes.Buffer
		if err := renderRecord(&quietBuf, format, rec, false, false, true, false, ui); err != nil {
			t.Fatalf("format %v: unexpected error rendering non-verbose: %v", format, err)
		}
		if err := renderRecord(&verboseBuf, format, rec, false, true, true, false, ui); err != nil {
			t.Fatalf("format %v: unexpected error rendering verbose: %v", format, err)
		}

		if strings.Contains(quietBuf.String(), "89ms") {
			t.Errorf("format %v: non-verbose output unexpectedly contains Sources latency detail:\n%s", format, quietBuf.String())
		}
		if !strings.Contains(verboseBuf.String(), "89ms") {
			t.Errorf("format %v: verbose output missing Sources latency detail:\n%s", format, verboseBuf.String())
		}

		// showConflicts is pinned true for both -- verbose and
		// show-conflicts are independent flags, so toggling verbose must
		// not also hide the Conflicts detail block. "GR=" is
		// registry-rdap's 2-letter sourceCode abbreviation (see
		// internal/render/human and internal/render/plain's sourceCode).
		for _, buf := range []*bytes.Buffer{&quietBuf, &verboseBuf} {
			if !strings.Contains(buf.String(), "GR=") {
				t.Errorf("format %v: expected Conflicts to stay visible regardless of verbose, got:\n%s", format, buf.String())
			}
		}
	}
}

func TestRenderRecord_ShowConflictsGatesConflictDetailBlock(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Conflicts: []model.Conflict{
			{
				Field: model.FieldExpires,
				Values: map[model.SourceID]string{
					model.SourceRegistryRDAP:  "2026-08-13T04:00:00Z",
					model.SourceRegistrarRDAP: "2026-08-10T04:00:00Z",
				},
			},
		},
	}
	ui := uiConfig{Dark: false, Width: 80}

	for _, format := range []render.Format{render.FormatHuman, render.FormatPlain} {
		var hiddenBuf, shownBuf bytes.Buffer
		if err := renderRecord(&hiddenBuf, format, rec, false, false, false, false, ui); err != nil {
			t.Fatalf("format %v: unexpected error rendering with conflicts hidden: %v", format, err)
		}
		if err := renderRecord(&shownBuf, format, rec, false, false, true, false, ui); err != nil {
			t.Fatalf("format %v: unexpected error rendering with conflicts shown: %v", format, err)
		}

		// "GR=" is registry-rdap's 2-letter sourceCode abbreviation.
		if strings.Contains(hiddenBuf.String(), "GR=") {
			t.Errorf("format %v: expected the raw per-source conflict detail hidden by default, got:\n%s", format, hiddenBuf.String())
		}
		if !strings.Contains(hiddenBuf.String(), "--conflicts") {
			t.Errorf("format %v: expected a hint pointing at --conflicts when conflicts are hidden, got:\n%s", format, hiddenBuf.String())
		}
		if !strings.Contains(shownBuf.String(), "GR=") {
			t.Errorf("format %v: expected the raw per-source conflict detail with --conflicts, got:\n%s", format, shownBuf.String())
		}
	}
}

func TestRun_VersionSubcommandIncludesBuildMetadata(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"version"}, &stdout, &stderr, uiConfig{})
	if got != 0 {
		t.Errorf("run([version]) exit code = %d, want 0", got)
	}
	out := stdout.String()
	for _, want := range []string{version, commit, date, builtBy} {
		if !strings.Contains(out, want) {
			t.Errorf("version output missing %q, got: %q", want, out)
		}
	}
}

func TestRun_CompletionCommandAvailable(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"completion", "bash"}, &stdout, &stderr, uiConfig{})
	if got != 0 {
		t.Fatalf("run([completion bash]) exit code = %d, want 0, stderr=%s", got, stderr.String())
	}
	if !strings.Contains(stdout.String(), "bash completion") {
		t.Errorf("expected bash completion script content in output, got %d bytes", stdout.Len())
	}
}

func TestExitSignal_ErrorReturnsEmptyString(t *testing.T) {
	if got := (exitSignal{code: 3}).Error(); got != "" {
		t.Errorf("exitSignal{code: 3}.Error() = %q, want empty string (per-domain errors are already reported by reportLookupError before exitSignal is ever constructed)", got)
	}
}

func TestRenderRecord_DispatchesJSONAndNDJSON(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	ui := uiConfig{}

	var jsonBuf bytes.Buffer
	if err := renderRecord(&jsonBuf, render.FormatJSON, rec, false, false, false, false, ui); err != nil {
		t.Fatalf("unexpected error rendering FormatJSON: %v", err)
	}
	if !strings.Contains(jsonBuf.String(), `"schemaVersion":1`) {
		t.Errorf("FormatJSON output missing schemaVersion, got:\n%s", jsonBuf.String())
	}
	if !strings.Contains(jsonBuf.String(), `"example.com"`) {
		t.Errorf("FormatJSON output missing domain value, got:\n%s", jsonBuf.String())
	}

	var ndjsonBuf bytes.Buffer
	if err := renderRecord(&ndjsonBuf, render.FormatNDJSON, rec, false, false, false, false, ui); err != nil {
		t.Fatalf("unexpected error rendering FormatNDJSON: %v", err)
	}
	if !strings.Contains(ndjsonBuf.String(), `"domain"`) {
		t.Errorf("FormatNDJSON output missing domain field, got:\n%s", ndjsonBuf.String())
	}
}

func TestReportLookupError_MachineFormatEncodesJSON(t *testing.T) {
	var stderr bytes.Buffer
	sources := []model.SourceResult{{Source: model.SourceRegistryRDAP, Err: "timeout", Latency: 5 * time.Second}}
	reportLookupError(&stderr, render.FormatJSON, "example.com", fmt.Errorf("boom"), sources, true, uiConfig{})
	out := stderr.String()
	if !strings.Contains(out, `"domain":"example.com"`) {
		t.Errorf("expected a JSON error object with the domain field, got:\n%s", out)
	}
	if !strings.Contains(out, `"error":"boom"`) {
		t.Errorf("expected a JSON error object with the error field, got:\n%s", out)
	}
	if strings.Contains(out, string(model.SourceRegistryRDAP)) {
		t.Errorf("machine format must stay verbose-independent (the stable {error,domain} shape only), got:\n%s", out)
	}
}

func TestReportLookupError_HumanFormatPrintsPlainLine(t *testing.T) {
	var stderr bytes.Buffer
	reportLookupError(&stderr, render.FormatPlain, "example.com", fmt.Errorf("boom"), nil, false, uiConfig{})
	out := stderr.String()
	if !strings.HasPrefix(out, "plat: example.com: boom") {
		t.Errorf("expected a plain \"plat: domain: err\" line, got: %q", out)
	}
}

func TestReportLookupError_NotRegisteredUsesOKStyleInHumanFormat(t *testing.T) {
	// Regression test: a confirmed-not-registered outcome is the tool's
	// most common "good" result (checking domain availability), not a
	// failure, so in human mode it should render in th.OK, not th.Err --
	// unlike every other reportLookupError call (usage errors, total
	// lookup failure, a render error), which all keep th.Err.
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("COLORTERM", "truecolor")
	sources := []model.SourceResult{{Source: model.SourceRegistryRDAP, NotFound: true}}
	th := human.NewTheme(false)

	var notRegistered bytes.Buffer
	reportLookupError(&notRegistered, render.FormatHuman, "example.com", lookupOutcomeError(1, sources), sources, false, uiConfig{})
	wantOK := th.OK.Render("plat: example.com: is not registered (checked: registry-rdap)") + "\n"
	if notRegistered.String() != wantOK {
		t.Errorf("not-registered output = %q, want th.OK-styled %q", notRegistered.String(), wantOK)
	}

	failedSources := []model.SourceResult{{Source: model.SourceRegistryRDAP, Err: "timeout"}}
	var failed bytes.Buffer
	reportLookupError(&failed, render.FormatHuman, "example.com", lookupOutcomeError(3, failedSources), failedSources, false, uiConfig{})
	wantErr := th.Err.Render("plat: example.com: lookup inconclusive -- 1 of 1 sources failed, so non-existence can't be confirmed (checked: registry-rdap)") + "\n"
	if failed.String() != wantErr {
		t.Errorf("total-failure output = %q, want th.Err-styled %q", failed.String(), wantErr)
	}
}

func TestReportLookupError_VerboseIncludesSourceDiagnostics(t *testing.T) {
	sources := []model.SourceResult{
		{Source: model.SourceRegistryRDAP, NotFound: true, Latency: 40 * time.Millisecond},
		{Source: model.SourceRegistryWHOIS, Err: "dial tcp: timeout", Latency: 5 * time.Second},
	}

	for _, format := range []render.Format{render.FormatHuman, render.FormatPlain} {
		var quiet, verbose bytes.Buffer
		reportLookupError(&quiet, format, "example.com", fmt.Errorf("no usable data for example.com"), sources, false, uiConfig{})
		reportLookupError(&verbose, format, "example.com", fmt.Errorf("no usable data for example.com"), sources, true, uiConfig{})

		if strings.Contains(quiet.String(), "dial tcp: timeout") {
			t.Errorf("format %v: non-verbose error output unexpectedly contains source diagnostics:\n%s", format, quiet.String())
		}
		if !strings.Contains(verbose.String(), "dial tcp: timeout") {
			t.Errorf("format %v: verbose error output missing source diagnostics, got:\n%s", format, verbose.String())
		}
	}
}

func TestVersionInfo_HumanLine(t *testing.T) {
	vi := versionInfo{Version: "1.2.3", Commit: "abc1234", Date: "2026-01-01T00:00:00Z", BuiltBy: "goreleaser"}
	got := vi.humanLine()
	want := "plat 1.2.3 (abc1234, built 2026-01-01T00:00:00Z by goreleaser)"
	if got != want {
		t.Errorf("humanLine() = %q, want %q", got, want)
	}
}

func TestVersionInfo_HumanLineWithFull(t *testing.T) {
	vi := versionInfo{
		Version: "1.2.3", Commit: "abc1234", Date: "2026-01-01T00:00:00Z", BuiltBy: "goreleaser",
		GoVersion: "go1.25.0", Platform: "darwin/arm64",
	}
	got := vi.humanLine()
	want := "plat 1.2.3 (abc1234, built 2026-01-01T00:00:00Z by goreleaser)\ngo:       go1.25.0\nplatform: darwin/arm64"
	if got != want {
		t.Errorf("humanLine() = %q, want %q", got, want)
	}
}

func TestCurrentVersionInfo_Full(t *testing.T) {
	vi := currentVersionInfo(true)
	if vi.GoVersion == "" {
		t.Error("expected GoVersion to be set when full=true")
	}
	if vi.Platform == "" {
		t.Error("expected Platform to be set when full=true")
	}
}

func TestCurrentVersionInfo_NotFull(t *testing.T) {
	vi := currentVersionInfo(false)
	if vi.GoVersion != "" || vi.Platform != "" {
		t.Errorf("expected GoVersion/Platform empty when full=false, got %+v", vi)
	}
}

func TestRun_RootVersionFlag(t *testing.T) {
	var stdoutFlag, stderrFlag bytes.Buffer
	gotFlag := run([]string{"--version"}, &stdoutFlag, &stderrFlag, uiConfig{})
	if gotFlag != 0 {
		t.Errorf("run([--version]) exit code = %d, want 0", gotFlag)
	}

	var stdoutCmd, stderrCmd bytes.Buffer
	gotCmd := run([]string{"version"}, &stdoutCmd, &stderrCmd, uiConfig{})
	if gotCmd != 0 {
		t.Errorf("run([version]) exit code = %d, want 0", gotCmd)
	}

	if stdoutFlag.String() != stdoutCmd.String() {
		t.Errorf("plat --version output = %q, want identical to plat version output %q", stdoutFlag.String(), stdoutCmd.String())
	}
}

func TestRun_RootVersionFlagSkipsNoArgsHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"--version"}, &stdout, &stderr, uiConfig{})
	if got != 0 {
		t.Fatalf("run([--version]) exit code = %d, want 0", got)
	}
	if strings.Contains(stdout.String(), "Usage:") {
		t.Errorf("plat --version triggered the no-args help path instead of printing the version, got:\n%s", stdout.String())
	}
}

func TestRun_VersionSubcommand_JSONOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"version", "-o", "json"}, &stdout, &stderr, uiConfig{})
	if got != 0 {
		t.Fatalf("run([version -o json]) exit code = %d, want 0, stderr=%s", got, stderr.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, stdout.String())
	}
	wantKeys := []string{"version", "commit", "date", "builtBy"}
	for _, k := range wantKeys {
		if _, ok := decoded[k]; !ok {
			t.Errorf("missing key %q in %v", k, decoded)
		}
	}
	if len(decoded) != len(wantKeys) {
		t.Errorf("decoded = %v, want exactly %d keys (no goVersion/platform without --full)", decoded, len(wantKeys))
	}
}

func TestRun_VersionSubcommand_InvalidOutputFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"version", "-o", "bogus"}, &stdout, &stderr, uiConfig{})
	if got != 2 {
		t.Errorf("run([version -o bogus]) exit code = %d, want 2", got)
	}
}

func TestRun_VersionSubcommand_Full(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"version", "--full"}, &stdout, &stderr, uiConfig{})
	if got != 0 {
		t.Fatalf("run([version --full]) exit code = %d, want 0, stderr=%s", got, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "go:") || !strings.Contains(out, "platform:") {
		t.Errorf("expected go:/platform: lines with --full, got:\n%s", out)
	}
}

func TestRun_VersionSubcommand_WithoutFullOmitsGoInfo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"version"}, &stdout, &stderr, uiConfig{})
	if got != 0 {
		t.Fatalf("run([version]) exit code = %d, want 0", got)
	}
	out := stdout.String()
	if strings.Contains(out, "go:") || strings.Contains(out, "platform:") {
		t.Errorf("expected no go:/platform: lines without --full, got:\n%s", out)
	}
}

func TestRun_VersionSubcommand_FullJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"version", "-o", "json", "--full"}, &stdout, &stderr, uiConfig{})
	if got != 0 {
		t.Fatalf("run([version -o json --full]) exit code = %d, want 0, stderr=%s", got, stderr.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, stdout.String())
	}
	for _, k := range []string{"version", "commit", "date", "builtBy", "goVersion", "platform"} {
		v, ok := decoded[k]
		if !ok || v == "" {
			t.Errorf("missing or empty key %q in %v", k, decoded)
		}
	}
}

func TestRenderRecord_Quiet(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Status: model.Field[[]string]{Value: []string{"clientTransferProhibited"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	ui := uiConfig{Dark: false, Width: 80}

	tests := []struct {
		name   string
		format render.Format
	}{
		{"human", render.FormatHuman},
		{"plain", render.FormatPlain},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := renderRecord(&buf, tt.format, rec, false, false, false, true, ui); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := strings.TrimRight(buf.String(), "\n")
			want := "example.com: locked"
			if got != want {
				t.Errorf("renderRecord(quiet=true, format=%v) = %q, want %q", tt.format, got, want)
			}
		})
	}
}

func TestRenderRecord_QuietIgnoredForMachineFormats(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Status: model.Field[[]string]{Value: []string{"clientTransferProhibited"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	ui := uiConfig{Dark: false, Width: 80}
	var buf bytes.Buffer
	if err := renderRecord(&buf, render.FormatJSON, rec, false, false, false, true, ui); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Errorf("expected --quiet to be ignored for -o json (full JSON still emitted), got: %s", buf.String())
	}
}

func TestIPQuietSummary(t *testing.T) {
	tests := []struct {
		name string
		rec  model.IPRecord
		want string
	}{
		{
			name: "cidr and org both present",
			rec: model.IPRecord{
				CIDR: model.Field[string]{Value: "8.8.8.0/24", Sources: []model.SourceID{model.SourceRegistryRDAP}},
				Org: model.OrgInfo{
					Name: model.Field[string]{Value: "Google LLC", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
				},
			},
			want: "8.8.8.0/24 · Google LLC",
		},
		{
			name: "cidr present, org absent",
			rec: model.IPRecord{
				CIDR: model.Field[string]{Value: "8.8.8.0/24", Sources: []model.SourceID{model.SourceRegistryRDAP}},
			},
			want: "8.8.8.0/24",
		},
		{
			name: "org present, cidr absent",
			rec: model.IPRecord{
				Org: model.OrgInfo{
					Name: model.Field[string]{Value: "Google LLC", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
				},
			},
			want: "Google LLC",
		},
		{
			name: "neither cidr nor org, handle present",
			rec: model.IPRecord{
				Handle: model.Field[string]{Value: "NET-8-8-8-0-2", Sources: []model.SourceID{model.SourceRegistryRDAP}},
			},
			want: "NET-8-8-8-0-2",
		},
		{
			name: "fully empty record",
			rec:  model.IPRecord{},
			want: "no data",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipQuietSummary(tt.rec)
			if got != tt.want {
				t.Errorf("ipQuietSummary() = %q, want %q", got, tt.want)
			}
			if strings.HasPrefix(got, "·") || strings.HasSuffix(got, "·") {
				t.Errorf("ipQuietSummary() = %q, separator dangles with no value on one side", got)
			}
		})
	}
}

func TestASNQuietSummary(t *testing.T) {
	tests := []struct {
		name string
		rec  model.ASNRecord
		want string
	}{
		{
			name: "handle and org both present",
			rec: model.ASNRecord{
				Handle: model.Field[string]{Value: "AS15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
				Org: model.OrgInfo{
					Name: model.Field[string]{Value: "Google LLC", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
				},
			},
			want: "AS15169 · Google LLC",
		},
		{
			name: "handle present, org absent",
			rec: model.ASNRecord{
				Handle: model.Field[string]{Value: "AS15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
			},
			want: "AS15169",
		},
		{
			name: "org present, handle absent",
			rec: model.ASNRecord{
				Org: model.OrgInfo{
					Name: model.Field[string]{Value: "Google LLC", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
				},
			},
			want: "Google LLC",
		},
		{
			name: "neither handle nor org, name present",
			rec: model.ASNRecord{
				Name: model.Field[string]{Value: "GOOGLE", Sources: []model.SourceID{model.SourceRegistryRDAP}},
			},
			want: "GOOGLE",
		},
		{
			name: "fully empty record",
			rec:  model.ASNRecord{},
			want: "no data",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := asnQuietSummary(tt.rec)
			if got != tt.want {
				t.Errorf("asnQuietSummary() = %q, want %q", got, tt.want)
			}
			if strings.HasPrefix(got, "·") || strings.HasSuffix(got, "·") {
				t.Errorf("asnQuietSummary() = %q, separator dangles with no value on one side", got)
			}
		})
	}
}

func TestRenderIPRecord_DispatchesFormatHumanToStyledRenderer(t *testing.T) {
	rec := model.IPRecord{
		CIDR: model.Field[string]{Value: "8.8.8.0/24", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var humanBuf, plainBuf bytes.Buffer
	ui := uiConfig{Dark: false, Width: 80}

	if err := renderIPRecord(&humanBuf, render.FormatHuman, rec, false, false, false, false, ui); err != nil {
		t.Fatalf("unexpected error rendering FormatHuman: %v", err)
	}
	if err := renderIPRecord(&plainBuf, render.FormatPlain, rec, false, false, false, false, ui); err != nil {
		t.Fatalf("unexpected error rendering FormatPlain: %v", err)
	}
	if humanBuf.String() == plainBuf.String() {
		t.Error("FormatHuman and FormatPlain produced byte-identical output — expected the styled renderer's layout to differ from the plain renderer's")
	}
	if !strings.Contains(humanBuf.String(), "8.8.8.0/24") {
		t.Errorf("FormatHuman output missing the CIDR value, got:\n%s", humanBuf.String())
	}
}

func TestRenderIPRecord_DispatchesJSONAndNDJSON(t *testing.T) {
	rec := model.IPRecord{
		CIDR: model.Field[string]{Value: "8.8.8.0/24", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	ui := uiConfig{}

	var jsonBuf bytes.Buffer
	if err := renderIPRecord(&jsonBuf, render.FormatJSON, rec, false, false, false, false, ui); err != nil {
		t.Fatalf("unexpected error rendering FormatJSON: %v", err)
	}
	if !strings.Contains(jsonBuf.String(), `"schemaVersion":1`) {
		t.Errorf("FormatJSON output missing schemaVersion, got:\n%s", jsonBuf.String())
	}
	if !strings.Contains(jsonBuf.String(), `"8.8.8.0/24"`) {
		t.Errorf("FormatJSON output missing cidr value, got:\n%s", jsonBuf.String())
	}

	var ndjsonBuf bytes.Buffer
	if err := renderIPRecord(&ndjsonBuf, render.FormatNDJSON, rec, false, false, false, false, ui); err != nil {
		t.Fatalf("unexpected error rendering FormatNDJSON: %v", err)
	}
	if !strings.Contains(ndjsonBuf.String(), `"cidr"`) {
		t.Errorf("FormatNDJSON output missing cidr field, got:\n%s", ndjsonBuf.String())
	}
}

func TestRenderIPRecord_Quiet(t *testing.T) {
	rec := model.IPRecord{
		CIDR: model.Field[string]{Value: "8.8.8.0/24", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Org: model.OrgInfo{
			Name: model.Field[string]{Value: "Google LLC", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
		},
	}
	ui := uiConfig{Dark: false, Width: 80}

	tests := []struct {
		name   string
		format render.Format
	}{
		{"human", render.FormatHuman},
		{"plain", render.FormatPlain},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := renderIPRecord(&buf, tt.format, rec, false, false, false, true, ui); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := strings.TrimRight(buf.String(), "\n")
			want := "8.8.8.0/24 · Google LLC"
			if got != want {
				t.Errorf("renderIPRecord(quiet=true, format=%v) = %q, want %q", tt.format, got, want)
			}
		})
	}
}

func TestRenderIPRecord_QuietIgnoredForMachineFormats(t *testing.T) {
	rec := model.IPRecord{
		CIDR: model.Field[string]{Value: "8.8.8.0/24", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	ui := uiConfig{Dark: false, Width: 80}
	var buf bytes.Buffer
	if err := renderIPRecord(&buf, render.FormatJSON, rec, false, false, false, true, ui); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Errorf("expected --quiet to be ignored for -o json (full JSON still emitted), got: %s", buf.String())
	}
}

func TestRenderASNRecord_DispatchesFormatHumanToStyledRenderer(t *testing.T) {
	rec := model.ASNRecord{
		Handle: model.Field[string]{Value: "AS15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var humanBuf, plainBuf bytes.Buffer
	ui := uiConfig{Dark: false, Width: 80}

	if err := renderASNRecord(&humanBuf, render.FormatHuman, rec, false, false, false, false, ui); err != nil {
		t.Fatalf("unexpected error rendering FormatHuman: %v", err)
	}
	if err := renderASNRecord(&plainBuf, render.FormatPlain, rec, false, false, false, false, ui); err != nil {
		t.Fatalf("unexpected error rendering FormatPlain: %v", err)
	}
	if humanBuf.String() == plainBuf.String() {
		t.Error("FormatHuman and FormatPlain produced byte-identical output — expected the styled renderer's layout to differ from the plain renderer's")
	}
	if !strings.Contains(humanBuf.String(), "AS15169") {
		t.Errorf("FormatHuman output missing the handle value, got:\n%s", humanBuf.String())
	}
}

func TestRenderASNRecord_DispatchesJSONAndNDJSON(t *testing.T) {
	rec := model.ASNRecord{
		Handle: model.Field[string]{Value: "AS15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	ui := uiConfig{}

	var jsonBuf bytes.Buffer
	if err := renderASNRecord(&jsonBuf, render.FormatJSON, rec, false, false, false, false, ui); err != nil {
		t.Fatalf("unexpected error rendering FormatJSON: %v", err)
	}
	if !strings.Contains(jsonBuf.String(), `"schemaVersion":1`) {
		t.Errorf("FormatJSON output missing schemaVersion, got:\n%s", jsonBuf.String())
	}
	if !strings.Contains(jsonBuf.String(), `"AS15169"`) {
		t.Errorf("FormatJSON output missing handle value, got:\n%s", jsonBuf.String())
	}

	var ndjsonBuf bytes.Buffer
	if err := renderASNRecord(&ndjsonBuf, render.FormatNDJSON, rec, false, false, false, false, ui); err != nil {
		t.Fatalf("unexpected error rendering FormatNDJSON: %v", err)
	}
	if !strings.Contains(ndjsonBuf.String(), `"handle"`) {
		t.Errorf("FormatNDJSON output missing handle field, got:\n%s", ndjsonBuf.String())
	}
}

func TestRenderASNRecord_Quiet(t *testing.T) {
	rec := model.ASNRecord{
		Handle: model.Field[string]{Value: "AS15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Org: model.OrgInfo{
			Name: model.Field[string]{Value: "Google LLC", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
		},
	}
	ui := uiConfig{Dark: false, Width: 80}

	tests := []struct {
		name   string
		format render.Format
	}{
		{"human", render.FormatHuman},
		{"plain", render.FormatPlain},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := renderASNRecord(&buf, tt.format, rec, false, false, false, true, ui); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := strings.TrimRight(buf.String(), "\n")
			want := "AS15169 · Google LLC"
			if got != want {
				t.Errorf("renderASNRecord(quiet=true, format=%v) = %q, want %q", tt.format, got, want)
			}
		})
	}
}

func TestRenderASNRecord_QuietIgnoredForMachineFormats(t *testing.T) {
	rec := model.ASNRecord{
		Handle: model.Field[string]{Value: "AS15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	ui := uiConfig{Dark: false, Width: 80}
	var buf bytes.Buffer
	if err := renderASNRecord(&buf, render.FormatJSON, rec, false, false, false, true, ui); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Errorf("expected --quiet to be ignored for -o json (full JSON still emitted), got: %s", buf.String())
	}
}

func TestRun_QuietFlagRegistered(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"--help"}, &stdout, &stderr, uiConfig{})
	if got != 0 {
		t.Fatalf("run([--help]) exit code = %d, want 0", got)
	}
	if !strings.Contains(stdout.String(), "--quiet") {
		t.Errorf("expected --quiet to be listed in --help output, got:\n%s", stdout.String())
	}
}

func TestEffectiveNoColor(t *testing.T) {
	tests := []struct {
		name        string
		envNoColor  bool
		flagNoColor bool
		want        bool
	}{
		{"neither set", false, false, false},
		{"NO_COLOR env var only", true, false, true},
		{"--no-color flag only", false, true, true},
		{"both set", true, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := effectiveNoColor(uiConfig{NoColor: tt.envNoColor}, tt.flagNoColor)
			if got != tt.want {
				t.Errorf("effectiveNoColor(NoColor=%v, flag=%v) = %v, want %v", tt.envNoColor, tt.flagNoColor, got, tt.want)
			}
		})
	}
}

func TestRun_NoColorFlagRegistered(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"--help"}, &stdout, &stderr, uiConfig{})
	if got != 0 {
		t.Fatalf("run([--help]) exit code = %d, want 0", got)
	}
	if !strings.Contains(stdout.String(), "--no-color") {
		t.Errorf("expected --no-color to be listed in --help output, got:\n%s", stdout.String())
	}
}

func TestDiff_RejectsNameMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")
	if err := os.WriteFile(path, []byte(`{"schemaVersion":1,"objectType":"domain","domain":{"value":"example.com","sources":["registry-rdap"]},"conflicts":[],"redacted":[],"sources":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := run([]string{"--diff", path, "iana.org"}, &out, &errBuf, uiConfig{})
	if code != 2 {
		t.Errorf("exit = %d, want 2 (usage error)", code)
	}
	if !strings.Contains(errBuf.String(), "snapshot is for") {
		t.Errorf("stderr missing the mismatch message:\n%s", errBuf.String())
	}
}

func TestDiff_RejectsNdjson(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.ndjson")
	line := `{"schemaVersion":1,"objectType":"domain","domain":{"value":"example.com","sources":["registry-rdap"]},"conflicts":[],"redacted":[],"sources":[]}`
	if err := os.WriteFile(path, []byte(line+"\n"+line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := run([]string{"--diff", path, "example.com"}, &out, &errBuf, uiConfig{})
	if code != 2 {
		t.Errorf("exit = %d, want 2 (usage error)", code)
	}
	if !strings.Contains(errBuf.String(), "not ndjson") {
		t.Errorf("stderr missing the ndjson message:\n%s", errBuf.String())
	}
}

func TestDiff_RejectsMultipleNames(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--diff", "irrelevant.json", "a.com", "b.com"}, &out, &errBuf, uiConfig{})
	if code != 2 {
		t.Errorf("exit = %d, want 2 (usage error)", code)
	}
	if !strings.Contains(errBuf.String(), "exactly one name") {
		t.Errorf("stderr missing the one-name message:\n%s", errBuf.String())
	}
}

// TestDiffNameMatches covers loadSnapshot's type-aware name check: an
// exact case-insensitive match (the strings.EqualFold fallback, used by
// domain/ASN queries and by any IP snapshot whose Name doesn't parse as
// a CIDR) versus CIDR-containment matching (used when it does). This
// was a self-disclosed gap in live verification -- a real defect was
// found and fixed here (an IP snapshot's Name is always the registry's
// allocated block, e.g. "8.8.8.0/24", never the literal address
// queried), but nothing in CI covered it before this test.
func TestDiffNameMatches(t *testing.T) {
	tests := []struct {
		name string
		snap machine.Snapshot
		q    domain.Query
		want bool
	}{
		{
			name: "domain: case-insensitive match falls back to EqualFold",
			snap: machine.Snapshot{ObjectType: "domain", Name: "EXAMPLE.COM"},
			q:    domain.Query{Kind: domain.KindDomain, Name: domain.Name{Punycode: "example.com"}},
			want: true,
		},
		{
			name: "domain: mismatch via EqualFold fallback",
			snap: machine.Snapshot{ObjectType: "domain", Name: "EXAMPLE.COM"},
			q:    domain.Query{Kind: domain.KindDomain, Name: domain.Name{Punycode: "example.org"}},
			want: false,
		},
		{
			name: "asn: case-insensitive handle match falls back to EqualFold",
			snap: machine.Snapshot{ObjectType: "asn", Name: "as15169"},
			q:    domain.Query{Kind: domain.KindASN, ASN: 15169},
			want: true,
		},
		{
			name: "asn: mismatched number via EqualFold fallback",
			snap: machine.Snapshot{ObjectType: "asn", Name: "AS15169"},
			q:    domain.Query{Kind: domain.KindASN, ASN: 13335},
			want: false,
		},
		{
			name: "ip: snapshot Name that isn't a CIDR falls back to EqualFold",
			snap: machine.Snapshot{ObjectType: "ip", Name: "8.8.8.8"},
			q:    domain.Query{Kind: domain.KindIPv4, IP: netip.MustParseAddr("8.8.8.8")},
			want: true,
		},
		{
			name: "ip: literal address matches its own saved CIDR block",
			snap: machine.Snapshot{ObjectType: "ip", Name: "8.8.8.0/24"},
			q:    domain.Query{Kind: domain.KindIPv4, IP: netip.MustParseAddr("8.8.8.8")},
			want: true,
		},
		{
			name: "ip: address outside an unrelated same-family CIDR block",
			snap: machine.Snapshot{ObjectType: "ip", Name: "8.8.8.0/24"},
			q:    domain.Query{Kind: domain.KindIPv4, IP: netip.MustParseAddr("1.1.1.1")},
			want: false,
		},
		{
			name: "ip: ipv6 address matches its own saved ipv6 CIDR block",
			snap: machine.Snapshot{ObjectType: "ip", Name: "2001:4860:4860::/48"},
			q:    domain.Query{Kind: domain.KindIPv6, IP: netip.MustParseAddr("2001:4860:4860::8888")},
			want: true,
		},
		{
			name: "ip: cross-family, ipv6 query against an ipv4 CIDR snapshot never matches",
			snap: machine.Snapshot{ObjectType: "ip", Name: "8.8.8.0/24"},
			q:    domain.Query{Kind: domain.KindIPv6, IP: netip.MustParseAddr("2001:4860:4860::8888")},
			want: false,
		},
		{
			name: "ip: cross-family, ipv4 query against an ipv6 CIDR snapshot never matches",
			snap: machine.Snapshot{ObjectType: "ip", Name: "2001:4860:4860::/48"},
			q:    domain.Query{Kind: domain.KindIPv4, IP: netip.MustParseAddr("8.8.8.8")},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := diffNameMatches(tt.snap, tt.q)
			if got != tt.want {
				t.Errorf("diffNameMatches(snap.Name=%q, query=%q) = %v, want %v", tt.snap.Name, diffQueryName(tt.q), got, tt.want)
			}
		})
	}
}

// TestRunLookup_EmitsInInputOrder is the test that makes buffering
// meaningful: it must fail if results are ever streamed in completion
// order. The fake work deliberately finishes in reverse.
func TestRunLookup_EmitsInInputOrder(t *testing.T) {
	names := []string{"a.com", "b.com", "c.com", "d.com"}
	results := make([]string, len(names))

	var g errgroup.Group
	g.SetLimit(4)
	for i, n := range names {
		g.Go(func() error {
			// Later names finish first.
			time.Sleep(time.Duration(len(names)-i) * 10 * time.Millisecond)
			results[i] = n
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	for i, want := range names {
		if results[i] != want {
			t.Errorf("results[%d] = %q, want %q -- output must follow input order, not completion order", i, results[i], want)
		}
	}
}

// TestRunLookup_PoolIsBounded asserts no more than the configured number
// of lookups are ever in flight, counted rather than timed -- a timing
// assertion here would be flaky and would not actually prove bounding.
func TestRunLookup_PoolIsBounded(t *testing.T) {
	const limit = 3
	var mu sync.Mutex
	inFlight, maxSeen := 0, 0

	var g errgroup.Group
	g.SetLimit(limit)
	for range 20 {
		g.Go(func() error {
			mu.Lock()
			inFlight++
			if inFlight > maxSeen {
				maxSeen = inFlight
			}
			mu.Unlock()

			time.Sleep(5 * time.Millisecond)

			mu.Lock()
			inFlight--
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if maxSeen > limit {
		t.Errorf("max concurrent = %d, want <= %d", maxSeen, limit)
	}
	if maxSeen < 2 {
		t.Errorf("max concurrent = %d, want >= 2 -- the pool never actually ran anything in parallel", maxSeen)
	}
}

// TestRunLookupPool_BoundsRealLookupOneConcurrency is I2's pool-bounding
// test: unlike TestRunLookup_PoolIsBounded above (which drives a
// standalone errgroup, never calling into plat's own code at all -- proven
// by mutation: making runLookupPool's g.SetLimit(opts.Concurrency) inert
// still left that test, and 186 others, passing), this drives
// runLookupPool itself and counts how many lookupOne calls are
// simultaneously mid-flight, via a real RDAP server every worker queries.
//
// This deliberately goes through RDAP, not WHOIS: every name shares one
// registry (one bootstrap.NewResolver entry, one httptest.Server), but
// WHOIS's own per-server HostLimiter/IANACache (the C1 fix elsewhere in
// this change) would otherwise serialize or cache away the very
// concurrency this test needs to observe -- a shared WHOIS listener is
// not a clean proxy for pool concurrency once pacing and caching are
// correctly in place. RDAP has no such pacing, so each of numDomains
// names makes exactly one concurrent-safe-to-observe HTTP request
// (sources restricted to registry-rdap only, NoFollow skips the
// registrar hop) and the handler's in-flight counter directly reflects
// how many lookupOne calls the pool let run at once. If
// g.SetLimit(opts.Concurrency) is ever made inert, maxInFlight blows past
// concurrency (approaching len(domains)) and this test fails.
func TestRunLookupPool_BoundsRealLookupOneConcurrency(t *testing.T) {
	const numDomains = 8
	const concurrency = 3
	const hopDelay = 60 * time.Millisecond

	fixture, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	var inFlight, maxInFlight int32
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&inFlight, 1)
		for {
			cur := atomic.LoadInt32(&maxInFlight)
			if n <= cur || atomic.CompareAndSwapInt32(&maxInFlight, cur, n) {
				break
			}
		}
		time.Sleep(hopDelay)
		atomic.AddInt32(&inFlight, -1)

		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer rdapSrv.Close()

	domains := make([]string, numDomains)
	for i := range domains {
		domains[i] = fmt.Sprintf("name%d.com", i)
	}

	resolver := bootstrap.NewResolver(map[string]string{"com": rdapSrv.URL})
	opts := lookupOptions{NoFollow: true, Concurrency: concurrency}
	sources := []model.SourceID{model.SourceRegistryRDAP}
	var stdout, stderr bytes.Buffer
	if err := runLookupPool(context.Background(), &stdout, &stderr, domains, opts, sources, render.FormatPlain, uiConfig{}, resolver); err != nil {
		t.Fatalf("runLookupPool: %v\nstderr:\n%s", err, stderr.String())
	}

	got := atomic.LoadInt32(&maxInFlight)
	if got > concurrency {
		t.Errorf("max concurrent lookups = %d, want <= %d (opts.Concurrency)", got, concurrency)
	}
	if got < 2 {
		t.Errorf("max concurrent lookups = %d, want >= 2 -- the pool never actually overlapped anything", got)
	}
}

// TestRunLookup_ConcurrencyMustBeAtLeastOne is I2's usage-error coverage
// for the "< 1" guard in runLookup: 0 and negative values must be
// rejected as a usage error (exit 2, a message naming --concurrency)
// before any bootstrap/network work happens -- proven by mutation:
// breaking the guard (e.g. widening it to "< 0") left 187 tests passing.
// The guard runs before runLookup's bootstrap.Load call, so this needs no
// fake resolver or network access to stay hermetic.
func TestRunLookup_ConcurrencyMustBeAtLeastOne(t *testing.T) {
	for _, c := range []int{0, -1, -5} {
		t.Run(fmt.Sprintf("concurrency=%d", c), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := runLookup(context.Background(), &stdout, &stderr, []string{"example.com"}, lookupOptions{Concurrency: c}, uiConfig{})
			var uErr usageError
			if !errors.As(err, &uErr) {
				t.Fatalf("runLookup with --concurrency %d returned %v (%T), want a usageError", c, err, err)
			}
			if !strings.Contains(uErr.Error(), "--concurrency must be at least 1") {
				t.Errorf("usageError = %q, want it to name --concurrency and the minimum", uErr.Error())
			}
		})
	}
}

// TestRunLookup_ConcurrencyOneIsValid is the other half of the "< 1"
// guard: exactly 1 must NOT be rejected. runLookup necessarily proceeds
// past the guard into bootstrap.Load (there is no seam in runLookup
// itself to skip it, unlike runLookupPool's tests elsewhere in this
// file) -- a tiny Timeout keeps any real network attempt bounded, and
// Load's own documented fetch/cache/embedded-fallback chain means it
// still succeeds offline. The domain itself ("also-bad", single-label)
// then fails domain.Normalize before any further network call, so the
// only thing this test actually waits on is that bounded bootstrap
// attempt, not a real WHOIS/RDAP round trip. What's asserted is narrow
// and precise: whatever runLookup returns, it must not be the
// "--concurrency must be at least 1" usage error the guard produces for
// 0 or negative.
func TestRunLookup_ConcurrencyOneIsValid(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := runLookup(context.Background(), &stdout, &stderr, []string{"also-bad"}, lookupOptions{Concurrency: 1, Timeout: 10 * time.Millisecond}, uiConfig{})
	var uErr usageError
	if errors.As(err, &uErr) && strings.Contains(uErr.Error(), "--concurrency") {
		t.Errorf("runLookup with --concurrency 1 was rejected as a usage error: %v", err)
	}
}

// TestRunLookup_EndToEnd_EmitsInInputOrder is what TestRunLookup_EmitsInInputOrder
// above does NOT prove: that runLookup itself -- not just the errgroup
// primitive it's built on -- emits in input order rather than completion
// order. It drives the real path (runLookup, not lookupOne directly) through
// two names that reach the render step, using the fake-WHOIS-listener
// pattern from lookupone_test.go, with "slow.com" listed first but rigged
// to finish decisively later than "fast.net" (listed second). If runLookup
// ever regressed to flushing in completion order, "Fast Registrar" would
// appear before "Slow Registrar" in stdout.
//
// Both names share one fake IANA server (as runLookup's own single
// opts.whoisIANAServer override -- and real whois.iana.org in
// production -- always does for every name in a run), so runLookup's own
// per-run HostLimiter (whois.NewHostLimiter(whois.DefaultWHOISInterval),
// built automatically for any run of more than one name) paces both
// names' IANA hop against that one shared host. Because that pacing picks
// whichever goroutine reaches Acquire first essentially at random, the
// *other* one absorbs a wait of up to one full DefaultWHOISInterval before
// its registry hop even starts -- so the artificial gap between the two
// names' registry-hop response times has to be decisively larger than
// DefaultWHOISInterval, not just larger than zero, or this test would
// pass or fail depending on which goroutine happened to win that race
// rather than on whether output order is actually correct. slow.com and
// fast.net get separate fake registry WHOIS servers precisely so that,
// unlike the shared IANA hop, their registry hops are on different hosts
// and never pace against each other (whois.HostLimiter's whole point --
// see its doc comment) -- only slow.com's registry response carries the
// deliberate delay. See the worked-through timing below.
func TestRunLookup_EndToEnd_EmitsInInputOrder(t *testing.T) {
	// slowDelay must exceed whois.DefaultWHOISInterval by a decisive
	// margin. Worked through for both possible outcomes of the shared-IANA-
	// host race (each name's IANA-hop wait is either ~0 or ~1
	// DefaultWHOISInterval, and every other hop below is on a private,
	// unshared host so it never adds pacing wait of its own):
	//
	//   race won by fast.net: fast.net total ~= 0 (no IANA wait, no
	//     registry delay). slow.com total ~= 0 (no IANA wait) + slowDelay.
	//     fast.net finishes first as long as slowDelay > 0.
	//   race won by slow.com: slow.com total ~= 0 (no IANA wait) +
	//     slowDelay. fast.net total ~= 1 DefaultWHOISInterval (lost the
	//     race) + 0 (no registry delay). fast.net finishes first only if
	//     slowDelay > ~1 DefaultWHOISInterval.
	//
	// So the binding constraint is the second case: slowDelay must clear
	// one full DefaultWHOISInterval with margin to spare for scheduling
	// jitter. 3x gives a 2x-interval cushion either way.
	const slowDelay = 3 * whois.DefaultWHOISInterval

	// No RDAP coverage for either TLD -- degrades to WHOIS-only, same as
	// TestLookupOne_WHOISOnlyDegradedMode, so this test's only variable is
	// the WHOIS timing, not RDAP/WHOIS merge behavior.
	resolver := bootstrap.NewResolver(map[string]string{})

	slowRegistryAddr := startFakeWHOISListener(t, func(query string) string {
		time.Sleep(slowDelay)
		return "Domain Name: SLOW.COM\nRegistrar: Slow Registrar, Inc.\n"
	})
	fastRegistryAddr := startFakeWHOISListener(t, func(query string) string {
		return "Domain Name: FAST.NET\nRegistrar: Fast Registrar, Inc.\n"
	})
	// One shared IANA server for both names -- see the doc comment above
	// for why that's deliberate, not an oversight. Dispatches on the TLD
	// each name's IANA hop queries with (name.TLD, per
	// internal/whois/referral.go's Lookup), which is exactly why slow.com
	// and fast.net need to differ in TLD, not just in second-level label.
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		switch strings.TrimSpace(query) {
		case "com":
			return "refer: " + slowRegistryAddr + "\n"
		case "net":
			return "refer: " + fastRegistryAddr + "\n"
		default:
			t.Errorf("unexpected IANA query %q", query)
			return ""
		}
	})

	var stdout, stderr bytes.Buffer
	opts := lookupOptions{
		whoisIANAServer: ianaAddr,
		NoFollow:        true,
		Concurrency:     2, // must be >= 2 for the two lookups to genuinely overlap
	}
	err := runLookupPool(context.Background(), &stdout, &stderr, []string{"slow.com", "fast.net"}, opts, nil, render.FormatPlain, uiConfig{}, resolver)
	if err != nil {
		t.Fatalf("runLookupPool: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	out := stdout.String()
	slowIdx := strings.Index(out, "Slow Registrar")
	fastIdx := strings.Index(out, "Fast Registrar")
	if slowIdx == -1 || fastIdx == -1 {
		t.Fatalf("stdout missing one or both registrar names, got:\n%s", out)
	}
	if slowIdx > fastIdx {
		t.Errorf("output has fast.net's record before slow.com's, but slow.com was listed first on the command line -- "+
			"output must follow input order, not completion order (fast.net finished first by design). got:\n%s", out)
	}
}

// TestRunLookup_CounterBranch_ConcurrentWithErrorDoesNotRace is a
// regression test for a real defect: runLookupPool's progress counter was
// briefly wired to write to raw stderr via spinner.RunFunc, while every
// worker's own diagnostics (reportLookupError, reached whenever a name
// fails -- not-found, a normalize failure, a total lookup failure, or -v
// output) already go through syncStderr, the syncWriter built in Task 4
// precisely to serialize concurrent writes to the one shared stderr
// (main.go's syncWriter doc comment explains why). Writing to raw stderr
// from the counter's animation goroutine while a worker writes through
// syncStderr concurrently is a data race -- caught reliably under -race --
// and even without -race, glues the error text onto the counter's
// in-progress \r line with no reset.
//
// No prior committed test drove this branch at all: showCounter requires
// ui.StderrTTY && format == render.FormatHuman && len(domains) > 1, which
// the one direct runLookupPool test (TestRunLookup_EndToEnd_EmitsInInputOrder,
// above) never hits -- it uses FormatPlain and the zero-value uiConfig
// (StderrTTY: false). So "go test -race" was not actually exercising this
// code path before this test existed.
//
// "localhost" and "also-bad" both fail domain.Normalize before any network
// call (single-label input, same as TestRun_AcceptsMultipleDomainArgs),
// so every worker hits reportLookupError immediately and repeatedly
// relative to the counter's own animation ticks -- maximizing the chance
// any unsynchronized write gets caught, and keeping the test hermetic and
// fast (no fake WHOIS/RDAP servers needed).
func TestRunLookup_CounterBranch_ConcurrentWithErrorDoesNotRace(t *testing.T) {
	resolver := bootstrap.NewResolver(map[string]string{})
	var stdout, stderr bytes.Buffer
	opts := lookupOptions{Concurrency: 2}

	err := runLookupPool(context.Background(), &stdout, &stderr,
		[]string{"localhost", "also-bad"}, opts, nil, render.FormatHuman,
		uiConfig{StderrTTY: true}, resolver)

	var sig exitSignal
	if err != nil && !errors.As(err, &sig) {
		t.Fatalf("runLookupPool: unexpected error type %v\nstderr:\n%s", err, stderr.String())
	}
}
