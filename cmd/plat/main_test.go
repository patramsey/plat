package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/rdap"
	"github.com/patramsey/plat/internal/render"
	"github.com/patramsey/plat/internal/render/human"
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

func TestRun_WhoisSubcommandRegistered(t *testing.T) {
	var stdout, stderr bytes.Buffer
	_ = run([]string{"whois", "--help"}, &stdout, &stderr, uiConfig{})
	if !strings.Contains(stdout.String(), "Look up domain ownership via WHOIS") {
		t.Errorf("expected whois subcommand help text in output, got:\n%s", stdout.String())
	}
}

func TestRun_WhoisRejectsWrongArgCount(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no args", []string{"whois"}},
		{"two args", []string{"whois", "example.com", "example.org"}},
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

func TestRun_WhoisHiddenFromHelp(t *testing.T) {
	// M4 note: a bare strings.Contains(out, "whois") check (M2's original
	// assertion) now false-positives against the new --source flag's own
	// help text ("restrict to one source: rdap, whois, registry,
	// registrar"), which legitimately mentions "whois" as a filter value
	// and has nothing to do with the whois subcommand's visibility. The
	// assertion is narrowed to what this test actually means to verify:
	// that the hidden `whois` subcommand doesn't appear in the top-level
	// command listing (its Use/Short text, unlike the flag description,
	// is unique to the subcommand entry).
	var stdout, stderr bytes.Buffer
	_ = run([]string{"--help"}, &stdout, &stderr, uiConfig{})
	out := stdout.String()
	if strings.Contains(out, "whois <domain>") || strings.Contains(out, "WHOIS (debug/demo") {
		t.Errorf("expected 'whois' subcommand to be hidden from --help output, got:\n%s", out)
	}
}

func TestRun_MergeSubcommandRegistered(t *testing.T) {
	var stdout, stderr bytes.Buffer
	_ = run([]string{"merge", "--help"}, &stdout, &stderr, uiConfig{})
	if !strings.Contains(stdout.String(), "merged RDAP+WHOIS") {
		t.Errorf("expected merge subcommand help text in output, got:\n%s", stdout.String())
	}
}

func TestRun_MergeRejectsWrongArgCount(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no args", []string{"merge"}},
		{"two args", []string{"merge", "example.com", "example.org"}},
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

func TestRun_MergeHiddenFromHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	_ = run([]string{"--help"}, &stdout, &stderr, uiConfig{})
	if strings.Contains(stdout.String(), "merge") {
		t.Errorf("expected 'merge' subcommand to be hidden from --help output, got:\n%s", stdout.String())
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

func TestRun_IPAddressInputRejected(t *testing.T) {
	// Guards the wiring, not the parsing: internal/domain already unit-
	// tests that Normalize rejects these, but the bug this fixes was that
	// an IP produced exit 0 and a schema-clean record built from a WHOIS
	// response about the "TLD" 8. Asserting the exit code here is what
	// actually pins that shut -- a lookup path that swallowed the error
	// would still pass every internal/domain test.
	tests := []struct {
		name  string
		input string
	}{
		{"bare IPv4", "8.8.8.8"},
		{"bare IPv6", "2001:4860:4860::8888"},
		{"CIDR prefix", "8.8.8.0/24"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := run([]string{tt.input}, &stdout, &stderr, uiConfig{})
			if got != 2 {
				t.Errorf("run([%s]) exit code = %d, want 2 (usage error)", tt.input, got)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty -- a rejected input must not emit a record", stdout.String())
			}
			if !strings.Contains(stderr.String(), "IP address lookups are not supported") {
				t.Errorf("stderr = %q, want the IP-address rejection message", stderr.String())
			}
		})
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
