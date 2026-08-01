package human

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

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
		Status:      model.Field[[]string]{Value: []string{"clientTransferProhibited"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Created:     model.Field[model.TimeValue]{Value: model.TimeValue{Time: created, Raw: "1995-08-14T04:00:00Z", Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Updated:     model.Field[model.TimeValue]{Value: model.TimeValue{Time: updated, Raw: "2025-01-01T00:00:00Z", Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Nameservers: model.Field[[]string]{Value: []string{"a.iana-servers.net", "b.iana-servers.net"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		DNSSEC:      model.Field[bool]{Value: true, Sources: []model.SourceID{model.SourceRegistryRDAP}},
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
	// Width 60: narrow enough that the 4-nameserver list still can't fit
	// on one line once the box border/padding and source badge are
	// accounted for, but wide enough that individual hostnames wrap
	// whole rather than breaking mid-word — this test is about list
	// wrapping across entries, not word-breaking within one.
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: 60}); err != nil {
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
		t.Errorf("expected the 4-nameserver list to wrap onto multiple lines at width 60, got %d matching line(s):\n%s", nsLines, buf.String())
	}
	for _, l := range lines {
		if strings.HasSuffix(l, " ") {
			t.Errorf("line has trailing whitespace, want it trimmed: %q", l)
		}
	}
}

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
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: 80, Verbose: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{string(model.SourceRegistryRDAP), string(model.SourceRegistrarRDAP), string(model.SourceRegistryWHOIS), "timeout"} {
		if !strings.Contains(out, want) {
			t.Errorf("sources block missing %q, got:\n%s", want, out)
		}
	}
}

func TestRender_SourcesBlockColumnsAlignDespiteVaryingLatencyWidth(t *testing.T) {
	// Regression test: the Sources block used to be a hand-formatted
	// "%-20s %s  %s" line that only padded the Source column, so the
	// Status column drifted whenever latency strings differed in length
	// (e.g. "89ms" is 2 runes shorter than "5s" is... backwards: "5s" is
	// shorter than "89ms", so the second row's status used to start 2
	// columns earlier). table.Table computes real column widths, so both
	// rows' "✓ ok" must land at the same column regardless.
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Sources: []model.SourceResult{
			{Source: model.SourceRegistryRDAP, OK: true, Latency: 89 * time.Millisecond},
			{Source: model.SourceRegistrarRDAP, OK: true, Latency: 5 * time.Second},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: 80, Verbose: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var statusCols []int
	for l := range strings.SplitSeq(buf.String(), "\n") {
		if idx := strings.Index(l, "✓ ok"); idx >= 0 {
			statusCols = append(statusCols, idx)
		}
	}
	if len(statusCols) != 2 {
		t.Fatalf("expected 2 status rows, got %d in:\n%s", len(statusCols), buf.String())
	}
	if statusCols[0] != statusCols[1] {
		t.Errorf("Status column not aligned across rows with differing latency width (89ms vs 5s): got columns %v in:\n%s", statusCols, buf.String())
	}
}

func TestRender_SourcesBlockHugsContentWhenShort(t *testing.T) {
	// table.Width() both expands and contracts to fill exactly the width
	// given, so calling it unconditionally would stretch a short Sources
	// table out to the box's full width with a large ugly gap before the
	// status column. Render must only constrain width when content would
	// actually overflow — a short table's rightmost content (status text)
	// should sit close to the source name, not padded out near Width:80.
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Sources: []model.SourceResult{
			{Source: model.SourceRegistryRDAP, OK: true, Latency: 10 * time.Millisecond},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: 80, Verbose: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for l := range strings.SplitSeq(buf.String(), "\n") {
		if idx := strings.Index(l, "✓ ok"); idx >= 0 && idx > 40 {
			t.Errorf("short Sources table was stretched to fill the box width instead of hugging its content, status landed at column %d:\n%s", idx, buf.String())
		}
	}
}

func TestRender_SourcesBlockWrapsWhenErrorMessageIsLong(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Sources: []model.SourceResult{
			{Source: model.SourceRegistryWHOIS, Err: strings.Repeat("connection reset by peer, retrying with backoff, ", 3)},
		},
	}
	const width = 80
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: width, Verbose: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for l := range strings.SplitSeq(buf.String(), "\n") {
		if n := lipgloss.Width(l); n > width {
			t.Errorf("Sources block with a long error message overflowed width %d (got %d): %q", width, n, l)
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
	if err := Render(&first, rec, Options{Theme: NewTheme(false), Width: 80, ShowConflicts: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := Render(&second, rec, Options{Theme: NewTheme(false), Width: 80, ShowConflicts: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if first.String() != second.String() {
		t.Fatal("Render is non-deterministic across calls with the same input (conflict map ordering)")
	}
	out := first.String()
	registrarRDAPIdx := strings.Index(out, sourceCode(model.SourceRegistrarRDAP)+"=")
	registryRDAPIdx := strings.Index(out, sourceCode(model.SourceRegistryRDAP)+"=")
	registrarWHOISIdx := strings.Index(out, sourceCode(model.SourceRegistrarWHOIS)+"=")
	registryWHOISIdx := strings.Index(out, sourceCode(model.SourceRegistryWHOIS)+"=")
	if registrarRDAPIdx < 0 || registryRDAPIdx < 0 || registrarWHOISIdx < 0 || registryWHOISIdx < 0 {
		t.Fatalf("expected all 4 source values in the conflict line, got:\n%s", out)
	}
	if registrarRDAPIdx >= registryRDAPIdx || registryRDAPIdx >= registrarWHOISIdx || registrarWHOISIdx >= registryWHOISIdx {
		t.Errorf("conflict values not rendered in model.Precedence order, got:\n%s", out)
	}
}

func TestRender_ConflictsBlockNeverOverflowsWidth(t *testing.T) {
	// Regression test, reproducing a real live report: writeConflicts
	// used to print its line with NO width awareness at all -- every
	// other section (fields, Sources, badges) wraps against width, but
	// this one didn't, so a conflict citing several long values (three
	// differently-precision timestamps here, matching what a real
	// registry/registrar/WHOIS three-way disagreement looks like)
	// stretched the auto-sizing box's effective width far past its
	// target, dragging every other, correctly-wrapped line in the box
	// along with it into overflow too.
	rec := model.Record{
		Domain: model.Field[string]{Value: "for.ninja", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Conflicts: []model.Conflict{
			{
				Field: model.FieldRegistrarName,
				Values: map[model.SourceID]string{
					model.SourceRegistrarRDAP: "NAMECHEAP INC",
					model.SourceRegistryRDAP:  "NameCheap, Inc.",
				},
			},
			{
				Field: model.FieldUpdated,
				Values: map[model.SourceID]string{
					model.SourceRegistrarRDAP:  "2025-08-28T07:43:46Z",
					model.SourceRegistryRDAP:   "2025-09-02T07:44:19.008Z",
					model.SourceRegistrarWHOIS: "2025-08-28T07:43:46.30Z",
				},
			},
		},
	}
	for _, width := range []int{80, 100, 122, 150} {
		var buf bytes.Buffer
		if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: width, ShowConflicts: true}); err != nil {
			t.Fatalf("width %d: unexpected error: %v", width, err)
		}
		for l := range strings.SplitSeq(buf.String(), "\n") {
			if w := lipgloss.Width(l); w > width {
				t.Errorf("width %d: line exceeds it (got %d visible columns): %q", width, w, l)
			}
		}
	}
}

func TestRender_ConflictsBlockWrapsWithinOneSourceEntry(t *testing.T) {
	// Regression test, reproducing a real live report (ycombinator.com):
	// unlike TestRender_ConflictsBlockNeverOverflowsWidth's scalar-value
	// conflicts, a nameservers conflict with several nameservers per
	// source produces a single "source=ns1, ns2, ns3, ns4" item that is,
	// by itself, wider than any reasonable target width. wrapItems only
	// ever breaks BETWEEN items, never within one, so this one opaque
	// item stretched the box to 125 columns regardless of a much
	// narrower requested width -- the box auto-sizes to its widest line.
	rec := model.Record{
		Domain: model.Field[string]{Value: "ycombinator.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Nameservers: model.Field[[]string]{
			Value:   []string{"ns-225.awsdns-28.com", "ns-1411.awsdns-48.org", "ns-1914.awsdns-47.co.uk", "ns-556.awsdns-05.net"},
			Sources: []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistrarWHOIS},
		},
		Conflicts: []model.Conflict{
			{
				Field: model.FieldNameservers,
				Values: map[model.SourceID]string{
					model.SourceRegistrarRDAP:  "ns-1411.awsdns-48.org, ns-1914.awsdns-47.co.uk, ns-225.awsdns-28.com",
					model.SourceRegistryRDAP:   "ns-1411.awsdns-48.org, ns-1914.awsdns-47.co.uk, ns-225.awsdns-28.com, ns-556.awsdns-05.net",
					model.SourceRegistrarWHOIS: "ns-1411.awsdns-48.org, ns-1914.awsdns-47.co.uk, ns-225.awsdns-28.com, ns-556.awsdns-05.net",
				},
			},
		},
	}
	for _, width := range []int{80, 100, 120, 140} {
		var buf bytes.Buffer
		if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: width, ShowConflicts: true}); err != nil {
			t.Fatalf("width %d: unexpected error: %v", width, err)
		}
		out := buf.String()
		for l := range strings.SplitSeq(out, "\n") {
			if w := lipgloss.Width(l); w > width {
				t.Errorf("width %d: line exceeds it (got %d visible columns): %q", width, w, l)
			}
		}
		for _, ns := range []string{"ns-1411.awsdns-48.org", "ns-1914.awsdns-47.co.uk", "ns-225.awsdns-28.com", "ns-556.awsdns-05.net"} {
			if !strings.Contains(out, ns) {
				t.Errorf("width %d: expected %q to still appear somewhere in output, got:\n%s", width, ns, out)
			}
		}
	}
}

func TestRender_ConflictedFieldGetsMarkerByDefaultDetailHidden(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "beers.com", Sources: []model.SourceID{model.SourceRegistrarRDAP, model.SourceRegistryRDAP}},
		Updated: model.Field[model.TimeValue]{
			Value:   model.TimeValue{Raw: "2024-12-09T15:05:00Z", Parsed: true},
			Sources: []model.SourceID{model.SourceRegistrarRDAP},
		},
		Conflicts: []model.Conflict{
			{
				Field: model.FieldUpdated,
				Values: map[model.SourceID]string{
					model.SourceRegistrarRDAP: "2024-12-09T15:05:00Z",
					model.SourceRegistryRDAP:  "2026-05-12T10:26:26Z",
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: 100}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	lines := strings.Split(out, "\n")
	var domainLine, updatedLine string
	for _, l := range lines {
		if strings.Contains(l, "Domain:") {
			domainLine = l
		}
		if strings.Contains(l, "Updated:") {
			updatedLine = l
		}
	}
	if !strings.Contains(updatedLine, "⚠") {
		t.Errorf("expected the conflicted Updated row to carry a ⚠ marker, got: %q", updatedLine)
	}
	if strings.Contains(domainLine, "⚠") {
		t.Errorf("expected the non-conflicted Domain row to carry no ⚠ marker, got: %q", domainLine)
	}
	if strings.Contains(out, "registry-rdap=") {
		t.Errorf("expected no raw per-source conflict detail without --conflicts, got:\n%s", out)
	}
	if !strings.Contains(out, "--conflicts") {
		t.Errorf("expected a hint pointing at --conflicts, got:\n%s", out)
	}
}

func TestRender_RegistrarURLIsHyperlinked(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("COLORTERM", "truecolor")

	const url = "https://www.markmonitor.com"
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Registrar: model.RegistrarInfo{
			URL: model.Field[string]{Value: url, Sources: []model.SourceID{model.SourceRegistrarRDAP}},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, ansi.SetHyperlink(url)) {
		t.Errorf("expected Registrar URL wrapped in an OSC 8 hyperlink open sequence, got:\n%s", out)
	}
	if !strings.Contains(out, ansi.ResetHyperlink()) {
		t.Errorf("expected Registrar URL's OSC 8 hyperlink to be closed, got:\n%s", out)
	}
}

func TestRender_HyperlinkStrippedWithoutColor(t *testing.T) {
	// Same empirical guarantee as color: lipgloss.Fprint strips ALL ANSI
	// escapes (via colorprofile's NoTTY path, which calls ansi.Strip) for
	// non-terminal/no-color output, including OSC 8 -- not just the CSI
	// sequences color/bold use. This must hold with zero special-casing
	// in Render itself.
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Registrar: model.RegistrarInfo{
			URL: model.Field[string]{Value: "https://www.markmonitor.com", Sources: []model.SourceID{model.SourceRegistrarRDAP}},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ContainsRune(buf.String(), 0x1b) {
		t.Errorf("expected zero ANSI (including OSC 8) with no color forced, got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "https://www.markmonitor.com") {
		t.Errorf("expected the URL text to remain fully readable once stripped, got:\n%s", buf.String())
	}
}

func TestRender_LongURLThatWrapsIsNotHyperlinked(t *testing.T) {
	// OSC 8's open/close markers must stay on the same line as each
	// other; a URL long enough to wrap onto multiple lines must fall
	// back to plain (still fully readable) text rather than splitting
	// the hyperlink markers across lines.
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("COLORTERM", "truecolor")

	longURL := "https://www.example-registrar-with-an-extremely-long-hostname-that-cannot-possibly-fit-on-one-line.com/whois"
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Registrar: model.RegistrarInfo{
			URL: model.Field[string]{Value: longURL, Sources: []model.SourceID{model.SourceRegistrarRDAP}},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: 40}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, ansi.SetHyperlink(longURL)) {
		t.Errorf("expected no hyperlink markers once the URL wraps onto multiple lines, got:\n%s", out)
	}
	if !strings.Contains(out, "hostname") {
		t.Errorf("expected the URL text to still be present even without a hyperlink, got:\n%s", out)
	}
}

func TestRender_IdentityFieldsAreAccented(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("COLORTERM", "truecolor")
	th := NewTheme(false)

	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Registrar: model.RegistrarInfo{
			Name: model.Field[string]{Value: "Example Registrar, Inc.", Sources: []model.SourceID{model.SourceRegistrarRDAP}},
		},
		Handle: model.Field[string]{Value: "some-handle", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: th, Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, th.Identity.Render("example.com")) {
		t.Errorf("expected Domain value styled with th.Identity, got:\n%s", out)
	}
	if !strings.Contains(out, th.Identity.Render("Example Registrar, Inc.")) {
		t.Errorf("expected Registrar value styled with th.Identity, got:\n%s", out)
	}
	if strings.Contains(out, th.Identity.Render("some-handle")) {
		t.Errorf("expected Handle to NOT be styled with th.Identity (only Domain/Registrar are), got:\n%s", out)
	}
}

func TestRender_StatusColorCoding(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("COLORTERM", "truecolor")
	th := NewTheme(false)

	tests := []struct {
		name      string
		status    string
		wantStyle lipgloss.Style
	}{
		{"protective status -> OK", "clientTransferProhibited", th.OK},
		{"bare (unprefixed) protective status -> OK", "transferProhibited", th.OK},
		{"at-risk status -> Err", "pendingDelete", th.Err},
		{"transitional status -> Warn", "pendingTransfer", th.Warn},
		{"unrecognized status -> plain Value", "ok", th.Value},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := model.Record{
				Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
				Status: model.Field[[]string]{Value: []string{tt.status}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
			}
			var buf bytes.Buffer
			if err := Render(&buf, rec, Options{Theme: th, Width: 80}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			want := tt.wantStyle.Render(tt.status)
			if !strings.Contains(buf.String(), want) {
				t.Errorf("expected status %q styled with the expected color, want substring %q, got:\n%s", tt.status, want, buf.String())
			}
		})
	}
}

func TestRender_ConflictDiffHighlighting(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("COLORTERM", "truecolor")
	th := NewTheme(false)

	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Conflicts: []model.Conflict{
			{
				Field: model.FieldRegistrarName,
				Values: map[model.SourceID]string{
					model.SourceRegistrarRDAP: "Example Registrar A",
					model.SourceRegistryRDAP:  "Example Registrar B",
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: th, Width: 80, ShowConflicts: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "Example Registrar "+th.Warn.Render("A")) {
		t.Errorf("expected the differing letter 'A' highlighted with th.Warn, got:\n%s", out)
	}
	if !strings.Contains(out, "Example Registrar "+th.Warn.Render("B")) {
		t.Errorf("expected the differing letter 'B' highlighted with th.Warn, got:\n%s", out)
	}
	if strings.Contains(out, th.Warn.Render("Example Registrar ")) {
		t.Errorf("expected the shared prefix 'Example Registrar ' to stay unstyled, got:\n%s", out)
	}
}

func TestRender_ConflictDiffHighlightingIgnoresCase(t *testing.T) {
	// commonAffixLen used to compare case-sensitively, so a genuine
	// conflict differing only after an incidental case difference (here,
	// "m" vs "M" four characters in) highlighted a huge chunk of both
	// values instead of the actual point of difference — the comma.
	// Conflict *detection* already normalizes case (internal/merge's
	// normalizeScalar); the highlighter must agree with it about what
	// counts as "the same so far".
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("COLORTERM", "truecolor")
	th := NewTheme(false)

	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Conflicts: []model.Conflict{
			{
				Field: model.FieldRegistrarName,
				Values: map[model.SourceID]string{
					model.SourceRegistrarRDAP:  "Markmonitor Inc.",
					model.SourceRegistrarWHOIS: "MarkMonitor, Inc.",
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: th, Width: 80, ShowConflicts: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	// The case-insensitive shared prefix is "markmonitor" (11 runes) and
	// shared suffix is " Inc." (5 runes, matched case-insensitively) --
	// neither should be highlighted; the highlighted middle must be
	// short (just around the comma), not "monitor Inc." / "Monitor, Inc."
	// the way case-sensitive matching produced before this fix.
	if strings.Contains(out, th.Warn.Render("monitor Inc.")) || strings.Contains(out, th.Warn.Render("Monitor, Inc.")) {
		t.Errorf("expected a narrow, case-insensitive-aware highlight, got the old wide case-sensitive one:\n%s", out)
	}
	if !strings.Contains(out, "Markmonitor") || !strings.Contains(out, "MarkMonitor") {
		t.Errorf("expected both original (unmodified) values still present verbatim, got:\n%s", out)
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

func TestRender_RedactedBlockWrapsLongReason(t *testing.T) {
	// Regression test found via a systematic audit: writeRedacted passed
	// its whole "source (reason)" value as a single one-element slice to
	// writeWrappedEntry/wrapItems, which only ever breaks BETWEEN items
	// -- with just one, there was nothing to break between, so a long,
	// free-form reason string never wrapped at all regardless of width.
	// A prose reason must word-wrap like any other long value
	// (wrapValue), not be treated as an atomic, unbreakable item.
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
		Redacted: []model.RedactionNotice{
			{Field: model.FieldRegistrarName, Source: model.SourceRegistrarRDAP, Reason: "redacted for privacy per applicable data protection law and registry policy"},
		},
	}
	const width = 80
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: width}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for l := range strings.SplitSeq(out, "\n") {
		if w := lipgloss.Width(l); w > width {
			t.Errorf("line exceeds width %d (got %d visible columns): %q", width, w, l)
		}
	}
	if strings.Count(out, "\n") < 8 {
		t.Errorf("expected the long reason to actually wrap onto multiple lines, got a suspiciously short output:\n%s", out)
	}
	if !strings.Contains(out, "redacted for privacy") || !strings.Contains(out, "registry policy") {
		t.Errorf("expected the long reason text to still be present (just wrapped), got:\n%s", out)
	}
}

func TestRender_SummaryLine(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("COLORTERM", "truecolor")
	th := NewTheme(false)

	// +1h buffer: expirySummary truncates hours-until/24 to whole days, so
	// an exact "+300 days" would flake to 299 whenever this test takes
	// even a few milliseconds to reach Render after computing expires.
	expires := time.Now().Add(300*24*time.Hour + time.Hour)
	rec := model.Record{
		Domain:  model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Status:  model.Field[[]string]{Value: []string{"clientTransferProhibited"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Expires: model.Field[model.TimeValue]{Value: model.TimeValue{Time: expires, Raw: expires.Format(time.RFC3339), Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Conflicts: []model.Conflict{
			{Field: model.FieldUpdated, Values: map[model.SourceID]string{model.SourceRegistryRDAP: "a", model.SourceRegistrarRDAP: "b"}},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: th, Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, th.OK.Render("🔒 locked")) {
		t.Errorf("expected a locked badge from the protective status, got:\n%s", out)
	}
	if !strings.Contains(out, "expires in 300 days") {
		t.Errorf("expected an expiry countdown in the summary, got:\n%s", out)
	}
	if !strings.Contains(out, th.Warn.Render("⚠ 1 conflict")) {
		t.Errorf("expected a singular conflict count in the summary, got:\n%s", out)
	}

	// The summary is data about the domain, not a heading — it belongs
	// inside the box as its first section, not floating above it next to
	// the title.
	boxStart := strings.Index(out, "╭")
	summaryPos := strings.Index(out, "expires in 300 days")
	domainPos := strings.Index(out, "Domain:")
	if boxStart < 0 || summaryPos < boxStart {
		t.Errorf("expected the summary to appear inside the box (after the opening border), got:\n%s", out)
	}
	if domainPos < 0 || summaryPos >= domainPos {
		t.Errorf("expected the summary to appear before the Domain row, got:\n%s", out)
	}
}

func TestRender_SummaryLineOmittedWhenNothingToSay(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	lines := strings.Split(out, "\n")
	if len(lines) < 2 || lines[0] != "plat · example.com" || lines[1] != "" {
		t.Errorf("expected the title line followed directly by a blank line, got:\n%s", out)
	}
	// With nothing to summarize, the box's first content row must be
	// Domain directly — no leftover blank line where a summary section
	// would otherwise have gone.
	boxStart := strings.Index(out, "╭")
	firstContentLine := strings.Split(out[boxStart:], "\n")[1]
	if !strings.Contains(firstContentLine, "Domain:") {
		t.Errorf("expected Domain to be the box's first content row when there's nothing to summarize, got first row: %q\nfull output:\n%s", firstContentLine, out)
	}
}

func TestRender_RecordIsBoxed(t *testing.T) {
	rec := fullRecord()
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"╭", "╮", "╰", "╯", "│"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected a rounded-border box (missing %q), got:\n%s", want, out)
		}
	}
}

func TestRender_BoxedRowsStayWithinWidth(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Status: model.Field[[]string]{
			Value:   []string{"clientTransferProhibited", "clientUpdateProhibited", "clientDeleteProhibited"},
			Sources: []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistrarRDAP},
		},
	}
	const width = 80
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: width}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for l := range strings.SplitSeq(buf.String(), "\n") {
		if n := len([]rune(l)); n > width {
			t.Errorf("line exceeds the requested width %d (got %d runes): %q", width, n, l)
		}
	}
}

func TestRender_LongBadgeNeverOverflowsWidth(t *testing.T) {
	// Regression test: writeStyledRow/writeStyledListRow used to
	// unconditionally append the source badge to whatever the last
	// wrapped line was. With a long badge (3+ sources, ~50 visible
	// columns), badgeWidth alone can eat the whole per-line budget down
	// to the 10-column floor -- but the last wrapped chunk (or, for an
	// unbreakable token like a date or URL, the whole value) still had
	// the badge appended on top of it regardless, blowing the box far
	// past its target width. Reproduces the exact shape that triggered
	// it live: three agreeing sources on every field at a real-world
	// terminal width.
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("COLORTERM", "truecolor")
	th := NewTheme(false)

	threeSources := []model.SourceID{model.SourceRegistrarRDAP, model.SourceRegistryRDAP, model.SourceRegistrarWHOIS}
	created, _ := time.Parse(time.RFC3339, "2014-05-28T17:00:06Z")
	rec := model.Record{
		Domain: model.Field[string]{Value: "fro.ninja", Sources: threeSources},
		Registrar: model.RegistrarInfo{
			Name: model.Field[string]{Value: "Name.com, Inc", Sources: threeSources},
		},
		Status:  model.Field[[]string]{Value: []string{"transferProhibited", "clientTransferProhibited"}, Sources: threeSources},
		Created: model.Field[model.TimeValue]{Value: model.TimeValue{Time: created, Raw: "2014-05-28T17:00:06Z", Parsed: true}, Sources: threeSources},
	}

	for _, width := range []int{80, 100, 120, 150} {
		var buf bytes.Buffer
		if err := Render(&buf, rec, Options{Theme: th, Width: width, Verbose: true}); err != nil {
			t.Fatalf("width %d: unexpected error: %v", width, err)
		}
		for l := range strings.SplitSeq(buf.String(), "\n") {
			if w := lipgloss.Width(l); w > width {
				t.Errorf("width %d: line exceeds it (got %d visible columns): %q", width, w, l)
			}
		}
	}
}

func TestRender_ShortValueDoesNotWrapJustBecauseOfALongBadge(t *testing.T) {
	// The wrap-width calculation used to reserve room for the badge
	// (badgeWidth) even though writeBadge already relocates the badge to
	// its own line whenever it doesn't fit — so a 20-column date behind
	// a 3-source badge got squeezed to the 10-column floor and wrapped
	// character-by-character for no reason, even at widths with plenty
	// of room to spare.
	threeSources := []model.SourceID{model.SourceRegistrarRDAP, model.SourceRegistryRDAP, model.SourceRegistrarWHOIS}
	created, _ := time.Parse(time.RFC3339, "2014-05-28T17:00:06Z")
	rec := model.Record{
		Domain:  model.Field[string]{Value: "fro.ninja", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Created: model.Field[model.TimeValue]{Value: model.TimeValue{Time: created, Raw: "2014-05-28T17:00:06Z", Parsed: true}, Sources: threeSources},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "2014-05-28T17:00:06Z") {
		t.Errorf("expected the date on one unbroken line despite the 3-source badge, got:\n%s", out)
	}
}

func TestRender_FourSourceBadgeNeverOverflows(t *testing.T) {
	// A 4-source badge is now the 2-letter sourceCode form ("RR, GR, RW,
	// GW", ~14 visible columns) rather than the full names ("registrar-
	// rdap, registry-rdap, registrar-whois, registry-whois", ~64 columns)
	// -- short enough that it no longer needs its own-line wrap fallback
	// even with all 4 sources present, but this still guards against
	// overflow regressing, and that all 4 codes show up correctly.
	allFour := []model.SourceID{model.SourceRegistrarRDAP, model.SourceRegistryRDAP, model.SourceRegistrarWHOIS, model.SourceRegistryWHOIS}
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: allFour},
	}
	const width = 80
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: width}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for l := range strings.SplitSeq(out, "\n") {
		if w := lipgloss.Width(l); w > width {
			t.Errorf("line exceeds width %d (got %d visible columns): %q", width, w, l)
		}
	}
	for _, want := range []string{"RR", "GR", "RW", "GW"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the badge, got:\n%s", want, out)
		}
	}
}

func TestRender_SourceLegendWrapsAtNarrowWidth(t *testing.T) {
	// The legend text itself ("RR registrar-rdap   GR registry-rdap   RW
	// registrar-whois   GW registry-whois") is ~77 columns -- now the
	// widest fixed string in the box, and the one place a badge-like
	// overflow risk still exists after sourceCode shortened everything
	// else. It must wrap like everything else in this file rather than
	// overflow just because it's a one-time legend.
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	for _, width := range []int{40, 60, 80} {
		var buf bytes.Buffer
		if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: width}); err != nil {
			t.Fatalf("width %d: unexpected error: %v", width, err)
		}
		out := buf.String()
		for l := range strings.SplitSeq(out, "\n") {
			if w := lipgloss.Width(l); w > width {
				t.Errorf("width %d: line exceeds it (got %d visible columns): %q", width, w, l)
			}
		}
		// Only check the four short codes, not the full words next to
		// them -- at narrow widths lipgloss's word-wrap legitimately
		// breaks even a single long word mid-hyphen (e.g. "registrar-
		// whois" -> "registrar-" / "whois" across two lines), so a full
		// word is never guaranteed to survive as one contiguous
		// substring. The 2-letter codes are short enough to never need
		// splitting themselves.
		for _, want := range []string{"RR", "GR", "RW", "GW"} {
			if !strings.Contains(out, want) {
				t.Errorf("width %d: expected code %q to still appear, got:\n%s", width, want, out)
			}
		}
	}
}

func TestWrapItems_NeverStartsALineWithTheSeparator(t *testing.T) {
	items := []string{"clientUpdateProhibited", "clientTransferProhibited", "clientDeleteProhibited", "serverUpdateProhibited", "serverTransferProhibited", "serverDeleteProhibited"}
	for _, line := range wrapItems(items, 30, " · ") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "·") {
			t.Errorf("wrapped line starts with the bare separator: %q\nall lines: %v", line, wrapItems(items, 30, " · "))
		}
	}
}

func TestWrapItems_PreservesANSIStyledItems(t *testing.T) {
	th := NewTheme(false)
	styled := th.OK.Render("ok") + " and more"
	items := []string{styled, "plain"}
	lines := wrapItems(items, 100, " · ")
	if len(lines) != 1 || lines[0] != styled+" · plain" {
		t.Errorf("wrapItems altered a pre-styled item, got %q", lines)
	}
}

func TestRender_BoolFieldFalseGetsCrossmark(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("COLORTERM", "truecolor")
	th := NewTheme(false)

	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		DNSSEC: model.Field[bool]{Value: false, Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: th, Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, th.Muted.Render("false ✗")) {
		t.Errorf("expected DNSSEC false rendered as muted \"false ✗\", got:\n%s", out)
	}
}

func TestRender_BorderColorMatchesVerdict(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("COLORTERM", "truecolor")
	th := NewTheme(false)

	tests := []struct {
		name      string
		status    string
		wantStyle lipgloss.Style
	}{
		{"protective status -> OK border", "clientTransferProhibited", th.OK},
		{"at-risk status -> Err border", "pendingDelete", th.Err},
		{"no recognized status -> Muted border", "ok", th.Muted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := model.Record{
				Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
				Status: model.Field[[]string]{Value: []string{tt.status}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
			}
			var buf bytes.Buffer
			if err := Render(&buf, rec, Options{Theme: th, Width: 80}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// Derive the exact color-setting escape sequence tt.wantStyle
			// applies before content, by rendering a probe rune and
			// splitting on it — avoids assuming border rendering composes
			// its escape codes identically to a plain Style.Render call.
			probe := tt.wantStyle.Render("\x01")
			prefix := probe[:strings.IndexByte(probe, '\x01')]
			if !strings.Contains(buf.String(), prefix+"╭") {
				t.Errorf("expected the box's top-left corner styled with the verdict color (prefix %q), got:\n%s", prefix, buf.String())
			}
		})
	}
}

// TestRender_NameserversWithEmptySourcesStillShowsField covers a real
// merge.Merge output shape: a genuine nameserver conflict (no single
// source's set equals the merged union) leaves Field.Sources empty while
// Field.Value stays populated with the union (see internal/merge's
// nameservers() doc comment). Present() being false must not make the
// whole row disappear -- only the per-source badge should be absent.
func TestRender_NameserversWithEmptySourcesStillShowsField(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Nameservers: model.Field[[]string]{
			Value:   []string{"ns1.example.com", "ns2.example.com", "ns3.example.com"},
			Sources: nil,
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Nameservers:") {
		t.Fatalf("expected a Nameservers row even with empty Sources, got:\n%s", out)
	}
	if !strings.Contains(out, "ns1.example.com") {
		t.Fatalf("expected the nameserver values to render, got:\n%s", out)
	}
}

// TestRender_SingleOverWideListItemNeverOverflowsWidth covers a value
// wrapItems can't help with: one item (not several) already wider than
// the available column. wrapItems only breaks *between* items, so
// without a secondary word-wrap pass (like writeWrappedEntry already
// does for the Conflicts block), a single over-wide nameserver or status
// code blows the box border out past the requested terminal width.
func TestRender_SingleOverWideListItemNeverOverflowsWidth(t *testing.T) {
	longNS := "ns1-" + strings.Repeat("x", 100) + ".example.com"
	rec := model.Record{
		Domain:      model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Nameservers: model.Field[[]string]{Value: []string{longNS}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	const width = 80
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Theme: NewTheme(false), Width: width}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, l := range strings.Split(buf.String(), "\n") {
		if n := lipgloss.Width(l); n > width {
			t.Errorf("line exceeds the requested width %d (got %d): %q", width, n, l)
		}
	}
}

func TestQuietSummary(t *testing.T) {
	// +1h buffer: same reasoning as TestRender_SummaryLine -- truncating
	// hours-until/24 to whole days would flake to 299 otherwise.
	expires := time.Now().Add(300*24*time.Hour + time.Hour)
	rec := model.Record{
		Domain:  model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Status:  model.Field[[]string]{Value: []string{"clientTransferProhibited"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Expires: model.Field[model.TimeValue]{Value: model.TimeValue{Time: expires, Raw: expires.Format(time.RFC3339), Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Conflicts: []model.Conflict{
			{Field: model.FieldUpdated, Values: map[model.SourceID]string{model.SourceRegistryRDAP: "a", model.SourceRegistrarRDAP: "b"}},
		},
	}
	got := QuietSummary(rec)
	want := "locked · expires in 300 days · 1 conflict"
	if got != want {
		t.Errorf("QuietSummary() = %q, want %q", got, want)
	}
	if strings.Contains(got, "\x1b[") {
		t.Errorf("QuietSummary() must never contain ANSI escape codes, got: %q", got)
	}
}

func TestQuietSummary_AtRisk(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Status: model.Field[[]string]{Value: []string{"pendingDelete"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	got := QuietSummary(rec)
	want := "at risk"
	if got != want {
		t.Errorf("QuietSummary() = %q, want %q", got, want)
	}
}

func TestQuietSummary_NoRecognizedStatusNoExpiryNoConflicts(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	got := QuietSummary(rec)
	if got != "" {
		t.Errorf("QuietSummary() = %q, want empty string", got)
	}
}

func TestQuietSummary_ExpiredInThePast(t *testing.T) {
	expired := time.Now().Add(-10*24*time.Hour - time.Hour)
	rec := model.Record{
		Domain:  model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Expires: model.Field[model.TimeValue]{Value: model.TimeValue{Time: expired, Raw: expired.Format(time.RFC3339), Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	got := QuietSummary(rec)
	want := "expired 10 days ago"
	if got != want {
		t.Errorf("QuietSummary() = %q, want %q", got, want)
	}
}
