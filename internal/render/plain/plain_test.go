package plain

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/patramsey/plat/model"
)

func TestRender_FullyPresentRecord(t *testing.T) {
	created, _ := time.Parse(time.RFC3339, "1995-08-14T04:00:00Z")
	expires, _ := time.Parse(time.RFC3339, "2026-08-13T04:00:00Z")

	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Handle: model.Field[string]{Value: "2336799_DOMAIN_COM-VRSN", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Registrar: model.RegistrarInfo{
			Name: model.Field[string]{Value: "Example Registrar, Inc.", Sources: []model.SourceID{model.SourceRegistrarRDAP}},
		},
		Status:      model.Field[[]string]{Value: []string{"clientTransferProhibited"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Created:     model.Field[model.TimeValue]{Value: model.TimeValue{Time: created, Raw: "1995-08-14T04:00:00Z", Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Expires:     model.Field[model.TimeValue]{Value: model.TimeValue{Time: expires, Raw: "2026-08-13T04:00:00Z", Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Nameservers: model.Field[[]string]{Value: []string{"a.iana-servers.net", "b.iana-servers.net"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Sources: []model.SourceResult{
			{Source: model.SourceRegistryRDAP, OK: true, Latency: 89 * time.Millisecond},
			{Source: model.SourceRegistrarRDAP, OK: true, Latency: 145 * time.Millisecond},
			{Source: model.SourceRegistryWHOIS, OK: false, Err: "timeout"},
		},
	}

	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Verbose: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"Domain:", "example.com",
		"Handle:", "2336799_DOMAIN_COM-VRSN",
		"Example Registrar, Inc.",
		"clientTransferProhibited",
		"1995-08-14T04:00:00Z",
		"2026-08-13T04:00:00Z",
		"a.iana-servers.net",
		string(model.SourceRegistryRDAP),
		"89ms",
		"timeout",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, out)
		}
	}

	for _, b := range []byte(out) {
		if b == 0x1b {
			t.Fatalf("output contains ANSI escape byte, want zero ANSI:\n%s", out)
		}
	}
}

func TestRender_UnparsedTimeFallback(t *testing.T) {
	rec := model.Record{
		Domain:  model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
		Expires: model.Field[model.TimeValue]{Value: model.TimeValue{Raw: "not-a-date", Parsed: false}, Sources: []model.SourceID{model.SourceRegistryWHOIS}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "not-a-date (unparsed)") {
		t.Errorf("output missing unparsed-date fallback, got:\n%s", out)
	}
}

func TestRender_SkipsAbsentFields(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, absent := range []string{"Handle:", "Registrar:", "Status:", "Created:", "Expires:", "Nameservers:", "DNSSEC:"} {
		if strings.Contains(out, absent) {
			t.Errorf("expected %q row to be skipped when absent, got:\n%s", absent, out)
		}
	}
}

func TestRender_DNSSECBothValues(t *testing.T) {
	tests := []struct {
		name  string
		value bool
		want  string
	}{
		{"signed", true, "true"},
		{"unsigned", false, "false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := model.Record{
				Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
				DNSSEC: model.Field[bool]{Value: tt.value, Sources: []model.SourceID{model.SourceRegistryRDAP}},
			}
			var buf bytes.Buffer
			if err := Render(&buf, rec, Options{}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			out := buf.String()
			if !strings.Contains(out, "DNSSEC:") || !strings.Contains(out, tt.want) {
				t.Errorf("output missing DNSSEC row with value %q, got:\n%s", tt.want, out)
			}
		})
	}
}

func TestRender_ConflictOrderingIsDeterministic(t *testing.T) {
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
	if err := Render(&first, rec, Options{ShowConflicts: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := Render(&second, rec, Options{ShowConflicts: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if first.String() != second.String() {
		t.Fatalf("Render is non-deterministic across calls with the same input:\nfirst:\n%s\nsecond:\n%s", first.String(), second.String())
	}

	out := first.String()
	// model.Precedence order is registrar-rdap, registry-rdap,
	// registrar-whois, registry-whois — the conflict line must list
	// values in that order regardless of map iteration order.
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
	if err := Render(&buf, rec, Options{}); err != nil {
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
	if !strings.Contains(updatedLine, "[conflict]") {
		t.Errorf("expected the conflicted Updated row to carry a [conflict] marker, got: %q", updatedLine)
	}
	if strings.Contains(domainLine, "[conflict]") {
		t.Errorf("expected the non-conflicted Domain row to carry no marker, got: %q", domainLine)
	}
	if strings.Contains(out, "registry-rdap=") {
		t.Errorf("expected no raw per-source conflict detail without --conflicts, got:\n%s", out)
	}
	if !strings.Contains(out, "--conflicts") {
		t.Errorf("expected a hint pointing at --conflicts, got:\n%s", out)
	}
}

func TestRender_RedactedSection(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
		Redacted: []model.RedactionNotice{
			{Field: model.FieldRegistrarName, Source: model.SourceRegistrarRDAP, Reason: "redacted"},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, string(model.SourceRegistrarRDAP)) || !strings.Contains(out, "redacted") {
		t.Errorf("expected redaction notice in output, got:\n%s", out)
	}
}

// TestRender_NameserversWithEmptySourcesStillShowsField mirrors the human
// renderer's test: a genuine nameserver conflict leaves Field.Sources
// empty while Field.Value stays populated with the union (see
// internal/merge's nameservers() doc comment). The row must still print.
func TestRender_NameserversWithEmptySourcesStillShowsField(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Nameservers: model.Field[[]string]{
			Value:   []string{"ns1.example.com", "ns2.example.com"},
			Sources: nil,
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Nameservers:") || !strings.Contains(out, "ns1.example.com") {
		t.Errorf("expected a Nameservers row even with empty Sources, got:\n%s", out)
	}
}

func TestRender_LifecycleSection(t *testing.T) {
	updated, _ := time.Parse(time.RFC3339, "2026-08-01T00:00:00Z")
	endsBy := updated.Add(30 * 24 * time.Hour)
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Lifecycle: &model.LifecycleInfo{
			Stage:           model.LifecycleRedemptionGrace,
			Label:           "Redemption Grace Period",
			Description:     "This domain has expired and is no longer eligible for normal renewal.",
			EstimatedEndsBy: &endsBy,
			EstimateBasis:   "Estimate based on ICANN's fixed 30-day Redemption Grace Period policy for gTLDs.",
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Lifecycle (Redemption Grace Period):",
		"no longer eligible for normal renewal",
		"2026-08-31T00:00:00Z",
		"30-day Redemption Grace Period",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, out)
		}
	}
}

func TestRender_LifecycleAbsentWhenNil(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "Lifecycle") {
		t.Errorf("output contains Lifecycle section, want none when Record.Lifecycle is nil:\n%s", buf.String())
	}
}

// TestRender_LifecycleSectionOmitsEstimateWhenAbsent covers the real
// pendingRestore case (see internal/merge's pendingRestoreInfo): the
// label/description line should still render, but with no
// EstimatedEndsBy, the "Lifecycle estimate:" row must be omitted
// entirely.
func TestRender_LifecycleSectionOmitsEstimateWhenAbsent(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Lifecycle: &model.LifecycleInfo{
			Stage:       model.LifecyclePendingRestore,
			Label:       "Pending Restore",
			Description: "A restore request is being processed by the registry; this is normally resolved within a few days.",
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Lifecycle (Pending Restore):") {
		t.Errorf("output missing lifecycle label row, got:\n%s", out)
	}
	if !strings.Contains(out, "restore request is being processed") {
		t.Errorf("output missing lifecycle description, got:\n%s", out)
	}
	for _, absent := range []string{"Lifecycle estimate", "Estimated", "estimate"} {
		if strings.Contains(out, absent) {
			t.Errorf("output contains %q, want no estimate row when EstimatedEndsBy is nil:\n%s", absent, out)
		}
	}
}

// TestRender_DomainLegendKeepsRegistrarSources guards the opposite
// direction from its IP and ASN siblings in this package: unlike an IP
// allocation or ASN, a domain genuinely can be sourced from all four --
// registrar RDAP/WHOIS are reachable in the chain, not merely defined in
// the type. When a record's fields actually carry all four, the legend
// must show all four; it's the data doing the gating now; this fixture
// gives every code a field to attach to, not a type-based assumption.
func TestRender_DomainLegendKeepsRegistrarSources(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistrarRDAP}},
		Handle: model.Field[string]{Value: "H1", Sources: []model.SourceID{model.SourceRegistryWHOIS, model.SourceRegistrarWHOIS}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"RR registrar-rdap", "GR registry-rdap",
		"RW registrar-whois", "GW registry-whois",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("domain legend is missing %q -- all four sources are reachable for a domain:\n%s", want, out)
		}
	}
}

func TestLegendListsOnlyPresentCodes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		record model.Record
		want   string
	}{
		{
			name: "single source",
			record: model.Record{
				Domain: model.Field[string]{Value: "denic.de", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
			},
			want: "GW registry-whois",
		},
		{
			name: "all four",
			record: model.Record{
				Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistrarRDAP}},
				Handle: model.Field[string]{Value: "H1", Sources: []model.SourceID{model.SourceRegistryWHOIS, model.SourceRegistrarWHOIS}},
			},
			want: "RR registrar-rdap   GR registry-rdap   RW registrar-whois   GW registry-whois",
		},
		{
			name: "code reachable only through a conflict",
			record: model.Record{
				Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
				Conflicts: []model.Conflict{{
					Field:  "updated",
					Values: map[model.SourceID]string{model.SourceRegistrarWHOIS: "a", model.SourceRegistryRDAP: "b"},
				}},
			},
			want: "GR registry-rdap   RW registrar-whois",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := Render(&buf, tc.record, Options{}); err != nil {
				t.Fatalf("Render: %v", err)
			}
			if !strings.Contains(buf.String(), tc.want) {
				t.Errorf("legend line missing %q; got:\n%s", tc.want, buf.String())
			}
			// The whole point: codes that never appear as a badge must not
			// be explained.
			for _, absent := range absentCodes(tc.want) {
				if strings.Contains(buf.String(), absent) {
					t.Errorf("legend explains %q, which appears on no field; got:\n%s", absent, buf.String())
				}
			}
		})
	}
}

// absentCodes returns the "XX source-id" legend entries NOT in want.
func absentCodes(want string) []string {
	var out []string
	for _, s := range model.Precedence {
		entry := sourceCode(s) + " " + string(s)
		if !strings.Contains(want, entry) {
			out = append(out, entry)
		}
	}
	return out
}

func TestNoLegendWhenRecordHasNoProvenance(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, model.Record{}, Options{}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, s := range model.Precedence {
		if strings.Contains(buf.String(), string(s)) {
			t.Errorf("empty record produced a legend mentioning %q; got:\n%s", s, buf.String())
		}
	}
}

// TestWidthZeroIsByteIdenticalToUnwrapped pins the exact bytes Render
// produces for a representative record at the default Width of 0. Width 0
// is what term.GetSize reports for a non-terminal stdout, and plain is also
// the renderer pipes and NO_COLOR get -- so this must stay byte-identical
// to what the renderer has always produced. Scripts grep these lines; do
// not weaken this assertion.
func TestWidthZeroIsByteIdenticalToUnwrapped(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, representativeRecord(), Options{Verbose: true, ShowConflicts: true}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := buf.String()
	if got != wantRepresentativeOutput {
		t.Errorf("output changed.\n--- got ---\n%s\n--- want ---\n%s", got, wantRepresentativeOutput)
	}
}

// representativeRecord exercises every row shape the renderer has: a
// scalar, a list long enough to dominate the value column, a timestamp, a
// bool, a conflict, and a redaction.
func representativeRecord() model.Record {
	return model.Record{
		Domain:      model.Field[string]{Value: "EXAMPLE.COM", Sources: []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistrarWHOIS, model.SourceRegistryWHOIS}},
		Registrar:   model.RegistrarInfo{Name: model.Field[string]{Value: "RESERVED-Internet Assigned Numbers Authority", Sources: []model.SourceID{model.SourceRegistryRDAP}}},
		Status:      model.Field[[]string]{Value: []string{"clientDeleteProhibited", "clientTransferProhibited", "clientUpdateProhibited"}, Sources: []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistryWHOIS}},
		Created:     model.Field[model.TimeValue]{Value: model.TimeValue{Parsed: true, Time: time.Date(1995, 8, 14, 4, 0, 0, 0, time.UTC)}, Sources: []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistryWHOIS}},
		Nameservers: model.Field[[]string]{Value: []string{"a.iana-servers.net", "b.iana-servers.net"}, Sources: []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistryWHOIS}},
		DNSSEC:      model.Field[bool]{Value: true, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Sources:     []model.SourceResult{{Source: model.SourceRegistryRDAP, OK: true, Latency: 121 * time.Millisecond}},
		Conflicts:   []model.Conflict{{Field: "created", Values: map[model.SourceID]string{model.SourceRegistryRDAP: "1995-08-14T04:00:00Z", model.SourceRegistryWHOIS: "1995-08-13T04:00:00Z"}}},
		Redacted:    []model.RedactionNotice{{Field: "registrantName", Source: model.SourceRegistryRDAP, Reason: "gdpr"}},
	}
}

const wantRepresentativeOutput = `Domain:       EXAMPLE.COM                                                                 GR, RW, GW
Registrar:    RESERVED-Internet Assigned Numbers Authority                                GR
Status:       clientDeleteProhibited · clientTransferProhibited · clientUpdateProhibited  GR, GW
Created:      1995-08-14T04:00:00Z                                                        GR, GW [conflict]
Nameservers:  a.iana-servers.net · b.iana-servers.net                                     GR, GW
DNSSEC:       true                                                                        GR
GR registry-rdap   RW registrar-whois   GW registry-whois
---
registry-rdap:  121ms  ok
---
Conflict (created):  GR=1995-08-14T04:00:00Z, GW=1995-08-13T04:00:00Z
---
Redacted (registrantName):  registry-rdap (gdpr)
`

// TestWidthCapsFieldRows checks only the field-row budget emitRowsWithin
// actually enforces -- it does not (and cannot) promise every line in the
// output stays under width: an unbreakable scalar (a long URL, a status
// code with no space to wrap on) still overflows by design, and this
// record has neither Verbose nor ShowConflicts set, so the -v source
// block, "Conflict (...)" lines, Redacted, and Lifecycle sit outside its
// reach entirely.
func TestWidthCapsFieldRows(t *testing.T) {
	for _, width := range []int{60, 80, 100} {
		t.Run(fmt.Sprintf("width%d", width), func(t *testing.T) {
			var buf bytes.Buffer
			if err := Render(&buf, representativeRecord(), Options{Width: width}); err != nil {
				t.Fatalf("Render: %v", err)
			}
			for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
				if n := utf8.RuneCountInString(line); n > width {
					t.Errorf("line is %d columns, over the %d budget: %q", n, width, line)
				}
			}
		})
	}
}

// Wrapping breaks between whole items, never inside a hostname -- a
// truncated nameserver is worse than a wrapped one, because it looks like
// a real (wrong) name.
func TestWrappingNeverSplitsAnItem(t *testing.T) {
	rec := model.Record{
		Nameservers: model.Field[[]string]{
			Value:   []string{"ns1.verylongnameserverexample.com", "ns2.verylongnameserverexample.com", "ns3.verylongnameserverexample.com"},
			Sources: []model.SourceID{model.SourceRegistryRDAP},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Width: 60}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	for _, ns := range rec.Nameservers.Value {
		if !strings.Contains(out, ns) {
			t.Errorf("nameserver %q was split across lines; got:\n%s", ns, out)
		}
	}
}

// A terminal narrower than the columns themselves must degrade, not panic
// or loop.
func TestVeryNarrowWidthDegradesGracefully(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, representativeRecord(), Options{Width: 20}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("narrow render produced no output")
	}
}

// Multibyte content must not throw the source column out of alignment --
// the list separator alone is a 2-byte rune.
func TestPaddingCountsRunesNotBytes(t *testing.T) {
	rec := model.Record{
		Domain:      model.Field[string]{Value: "bücher.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Nameservers: model.Field[[]string]{Value: []string{"ns1.bücher.com", "ns2.bücher.com"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Width: 60}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var cols []int
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		// i > 0, not >= 0: Render always appends a source legend line
		// ("GR registry-rdap"), which itself starts with "GR" at offset
		// 0 -- a genuine data row's source column can never start at 0,
		// since the label and padding always precede it. Excluding that
		// leaves only the rows this test is actually about.
		if i := strings.Index(line, "GR"); i > 0 {
			cols = append(cols, utf8.RuneCountInString(line[:i]))
		}
	}
	if len(cols) < 2 {
		t.Fatalf("expected at least two source-tagged rows, got %d", len(cols))
	}
	for _, c := range cols[1:] {
		if c != cols[0] {
			t.Errorf("source column starts at differing rune offsets %v -- padding counted bytes", cols)
		}
	}
}

func TestVerboseReportsNotQueriedSources(t *testing.T) {
	rec := model.Record{
		Domain:  model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Sources: []model.SourceResult{{Source: model.SourceRegistryRDAP, OK: true, Latency: 100 * time.Millisecond}},
	}
	opts := Options{
		Verbose:          true,
		NotQueried:       []model.SourceID{model.SourceRegistryWHOIS, model.SourceRegistrarWHOIS},
		NotQueriedReason: "--source rdap",
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, opts); err != nil {
		t.Fatalf("Render: %v", err)
	}
	want := "(registry-whois, registrar-whois not queried: --source rdap)"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("verbose output missing %q; got:\n%s", want, buf.String())
	}
}

func TestNotQueriedLineIsVerboseOnly(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	opts := Options{
		Verbose:          false,
		NotQueried:       []model.SourceID{model.SourceRegistryWHOIS},
		NotQueriedReason: "--source rdap",
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, opts); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(buf.String(), "not queried") {
		t.Errorf("default (non-verbose) output gained a not-queried line; got:\n%s", buf.String())
	}
}

// TestNotQueriedLineWrapsToWidth is a regression test for the same defect
// the human package's writeSources had: writeNotQueried used to emit one
// unwrapped line regardless of Width, so a long reason string ("--source
// rdap, --no-follow" plus several source names) could sit outside every
// field row's budget even on a narrow terminal.
func TestNotQueriedLineWrapsToWidth(t *testing.T) {
	rec := model.Record{
		Domain:  model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Sources: []model.SourceResult{{Source: model.SourceRegistryRDAP, OK: true, Latency: 100 * time.Millisecond}},
	}
	opts := Options{
		Verbose:          true,
		Width:            60,
		NotQueried:       []model.SourceID{model.SourceRegistrarRDAP, model.SourceRegistrarWHOIS, model.SourceRegistryWHOIS},
		NotQueriedReason: "--source rdap, --no-follow",
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, opts); err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if n := utf8.RuneCountInString(line); n > opts.Width {
			t.Errorf("line is %d columns, over the %d budget: %q", n, opts.Width, line)
		}
	}
	// The wrapped text must still be present, just split across lines --
	// "not" and "queried:" may land on either side of a wrap point.
	if !strings.Contains(buf.String(), "queried:") {
		t.Errorf("wrapped output lost the not-queried line entirely; got:\n%s", buf.String())
	}
}

func TestNoNotQueriedLineWhenNothingFiltered(t *testing.T) {
	rec := model.Record{
		Domain:  model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Sources: []model.SourceResult{{Source: model.SourceRegistryRDAP, OK: true}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec, Options{Verbose: true}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(buf.String(), "not queried") {
		t.Errorf("unfiltered verbose run gained a not-queried line; got:\n%s", buf.String())
	}
}
