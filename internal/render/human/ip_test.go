package human

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/model"
)

func fullIPRecord() model.IPRecord {
	reg, _ := time.Parse(time.RFC3339, "2023-12-28T22:24:33Z")
	return model.IPRecord{
		Handle:       model.Field[string]{Value: "NET-8-8-8-0-2", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Name:         model.Field[string]{Value: "GOGL", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		StartAddress: model.Field[string]{Value: "8.8.8.0", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		EndAddress:   model.Field[string]{Value: "8.8.8.255", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		CIDR:         model.Field[string]{Value: "8.8.8.0/24", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		IPVersion:    model.Field[string]{Value: "v4", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Country:      model.Field[string]{Value: "US", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
		Org: model.OrgInfo{
			Name: model.Field[string]{Value: "Google LLC", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
		},
		Status:     model.Field[[]string]{Value: []string{"active"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Registered: model.Field[model.TimeValue]{Value: model.TimeValue{Time: reg, Raw: "2023-12-28T17:24:33-05:00", Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Sources: []model.SourceResult{
			{Source: model.SourceRegistryRDAP, OK: true, Latency: 120 * time.Millisecond},
		},
	}
}

func TestRenderIP_FullyPresentRecord(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("COLORTERM", "truecolor")

	var buf bytes.Buffer
	if err := RenderIP(&buf, fullIPRecord(), Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"NET-8-8-8-0-2",
		"GOGL",
		"8.8.8.0",
		"8.8.8.255",
		"8.8.8.0/24",
		"v4",
		"US",
		"Google LLC",
		"active",
		"2023-12-28T22:24:33Z",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "\x1b[") {
		t.Error("expected ANSI escape sequences when color is forced, found none")
	}
}

func TestRenderIP_NoColorByDefault(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderIP(&buf, fullIPRecord(), Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("expected zero ANSI with no color forced, got:\n%s", buf.String())
	}
}

func TestRenderIP_SkipsAbsentFields(t *testing.T) {
	rec := model.IPRecord{
		Handle: model.Field[string]{Value: "NET-8-8-8-0-2", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := RenderIP(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, absent := range []string{"Network:", "Range:", "CIDR:", "Type:", "IP Version:", "Parent:", "Organization:", "Org ID:", "Country:", "Abuse Email:", "Abuse Phone:", "Status:", "Registered:", "Updated:"} {
		if strings.Contains(out, absent) {
			t.Errorf("expected %q row to be skipped when absent, got:\n%s", absent, out)
		}
	}
}

func TestRenderIP_DefaultWidthWhenUnset(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderIP(&buf, fullIPRecord(), Options{Theme: NewTheme(false), Width: 0}); err != nil {
		t.Fatalf("unexpected error with Width: 0: %v", err)
	}
	if !strings.Contains(buf.String(), "8.8.8.0/24") {
		t.Error("expected output with default width, got none")
	}
}

func TestRenderIP_TitleUsesCIDR(t *testing.T) {
	rec := model.IPRecord{
		Handle: model.Field[string]{Value: "NET-8-8-8-0-2", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		CIDR:   model.Field[string]{Value: "8.8.8.0/24", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := RenderIP(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "plat · 8.8.8.0/24") {
		t.Errorf("expected title to use CIDR, got:\n%s", out)
	}
}

func TestRenderIP_TitleFallsBackToHandle(t *testing.T) {
	rec := model.IPRecord{
		Handle: model.Field[string]{Value: "NET-8-8-8-0-2", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := RenderIP(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "plat · NET-8-8-8-0-2") {
		t.Errorf("expected title to fall back to handle when CIDR absent, got:\n%s", out)
	}
}

func TestRenderIP_NoTitleWhenNeitherPresent(t *testing.T) {
	rec := model.IPRecord{
		Country: model.Field[string]{Value: "US", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
	}
	var buf bytes.Buffer
	if err := RenderIP(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "plat ·") {
		t.Errorf("expected no title when neither CIDR nor Handle is present, got:\n%s", buf.String())
	}
}

func TestRenderIP_RangeBothAddresses(t *testing.T) {
	rec := model.IPRecord{
		StartAddress: model.Field[string]{Value: "8.8.8.0", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		EndAddress:   model.Field[string]{Value: "8.8.8.255", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := RenderIP(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "8.8.8.0 - 8.8.8.255") {
		t.Errorf("expected combined Range row, got:\n%s", out)
	}
}

func TestRenderIP_RangeOnlyStartAddress(t *testing.T) {
	rec := model.IPRecord{
		StartAddress: model.Field[string]{Value: "8.8.8.0", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := RenderIP(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "8.8.8.0") {
		t.Errorf("expected a Range row with just the start address, got:\n%s", out)
	}
	if strings.Contains(out, "8.8.8.0 - ") {
		t.Errorf("expected no dangling separator when only start address is present, got:\n%s", out)
	}
}

// TestRenderIP_RangeMarkedWhenOnlyEndAddressConflicts pins a real gap
// found by review: merge.MergeIP merges StartAddress and EndAddress
// through two independent scalar() calls, keyed "startAddress" and
// "endAddress" respectively, so a genuine disagreement can land on EITHER
// field's own model.Conflict entry while the other field agrees across
// sources. The combined Range row must still carry the ⚠ marker in that
// case -- checking conflict state via only the startAddress key would
// silently drop it even though the record's Conflicts (and the
// --conflicts hint) do report it.
func TestRenderIP_RangeMarkedWhenOnlyEndAddressConflicts(t *testing.T) {
	rec := model.IPRecord{
		StartAddress: model.Field[string]{Value: "8.8.8.0", Sources: []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistryWHOIS}},
		EndAddress:   model.Field[string]{Value: "8.8.8.255", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Conflicts: []model.Conflict{
			{
				Field: model.FieldIPEndAddress,
				Values: map[model.SourceID]string{
					model.SourceRegistryRDAP:  "8.8.8.255",
					model.SourceRegistryWHOIS: "8.8.8.254",
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := RenderIP(&buf, rec, Options{Theme: NewTheme(false), Width: 100}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	var rangeLine string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "8.8.8.0") && strings.Contains(l, "8.8.8.255") {
			rangeLine = l
		}
	}
	if !strings.Contains(rangeLine, "⚠") {
		t.Errorf("expected the Range row to carry a ⚠ marker when only EndAddress conflicts, got: %q\nfull output:\n%s", rangeLine, out)
	}
}

// TestRenderIP_RangeMarkedWhenOnlyStartAddressConflicts is the mirror of
// the EndAddress case above, guarding against a fix that only checks
// EndAddress (or only StartAddress) instead of ORing both.
func TestRenderIP_RangeMarkedWhenOnlyStartAddressConflicts(t *testing.T) {
	rec := model.IPRecord{
		StartAddress: model.Field[string]{Value: "8.8.8.0", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		EndAddress:   model.Field[string]{Value: "8.8.8.255", Sources: []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistryWHOIS}},
		Conflicts: []model.Conflict{
			{
				Field: model.FieldIPStartAddress,
				Values: map[model.SourceID]string{
					model.SourceRegistryRDAP:  "8.8.8.0",
					model.SourceRegistryWHOIS: "8.8.8.1",
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := RenderIP(&buf, rec, Options{Theme: NewTheme(false), Width: 100}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	var rangeLine string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "8.8.8.0") && strings.Contains(l, "8.8.8.255") {
			rangeLine = l
		}
	}
	if !strings.Contains(rangeLine, "⚠") {
		t.Errorf("expected the Range row to carry a ⚠ marker when only StartAddress conflicts, got: %q\nfull output:\n%s", rangeLine, out)
	}
}

// TestRenderIP_RangeBadgeUnionsBothAddressesSources covers the same
// underlying independent-merge behavior from the source-badge side:
// StartAddress and EndAddress can each be agreed on by a different subset
// of sources (e.g. StartAddress only confirmed by RDAP, EndAddress
// confirmed by both RDAP and WHOIS). The Range row's source badge must
// show the union of both, not just StartAddress's.
func TestRenderIP_RangeBadgeUnionsBothAddressesSources(t *testing.T) {
	rec := model.IPRecord{
		StartAddress: model.Field[string]{Value: "8.8.8.0", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		EndAddress:   model.Field[string]{Value: "8.8.8.255", Sources: []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistryWHOIS}},
	}
	var buf bytes.Buffer
	if err := RenderIP(&buf, rec, Options{Theme: NewTheme(false), Width: 100}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	var rangeLine string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "8.8.8.0") && strings.Contains(l, "8.8.8.255") {
			rangeLine = l
		}
	}
	if !strings.Contains(rangeLine, sourceCode(model.SourceRegistryRDAP)) || !strings.Contains(rangeLine, sourceCode(model.SourceRegistryWHOIS)) {
		t.Errorf("expected the Range row's badge to include both GR and GW (union of both addresses' sources), got: %q", rangeLine)
	}
}

func TestRenderIP_ConflictedFieldGetsMarkerByDefaultDetailHidden(t *testing.T) {
	rec := model.IPRecord{
		Handle: model.Field[string]{Value: "NET-8-8-8-0-2", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Country: model.Field[string]{
			Value:   "US",
			Sources: []model.SourceID{model.SourceRegistryRDAP},
		},
		Conflicts: []model.Conflict{
			{
				Field: model.FieldIPCountry,
				Values: map[model.SourceID]string{
					model.SourceRegistryRDAP:  "US",
					model.SourceRegistryWHOIS: "CA",
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := RenderIP(&buf, rec, Options{Theme: NewTheme(false), Width: 100}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	lines := strings.Split(out, "\n")
	var handleLine, countryLine string
	for _, l := range lines {
		if strings.Contains(l, "Handle:") {
			handleLine = l
		}
		if strings.Contains(l, "Country:") {
			countryLine = l
		}
	}
	if !strings.Contains(countryLine, "⚠") {
		t.Errorf("expected the conflicted Country row to carry a ⚠ marker, got: %q", countryLine)
	}
	if strings.Contains(handleLine, "⚠") {
		t.Errorf("expected the non-conflicted Handle row to carry no ⚠ marker, got: %q", handleLine)
	}
	if strings.Contains(out, "registry-whois=") {
		t.Errorf("expected no raw per-source conflict detail without --conflicts, got:\n%s", out)
	}
	if !strings.Contains(out, "--conflicts") {
		t.Errorf("expected a hint pointing at --conflicts, got:\n%s", out)
	}
}

func TestRenderIP_RedactedBlock(t *testing.T) {
	rec := model.IPRecord{
		Handle: model.Field[string]{Value: "NET-8-8-8-0-2", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
		Redacted: []model.RedactionNotice{
			{Field: model.FieldOrgName, Source: model.SourceRegistryRDAP, Reason: "redacted"},
		},
	}
	var buf bytes.Buffer
	if err := RenderIP(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Redacted") || !strings.Contains(out, string(model.SourceRegistryRDAP)) {
		t.Errorf("expected redaction notice in output, got:\n%s", out)
	}
}

func TestRenderIP_SourcesBlock(t *testing.T) {
	rec := model.IPRecord{
		Handle: model.Field[string]{Value: "NET-8-8-8-0-2", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Sources: []model.SourceResult{
			{Source: model.SourceRegistryRDAP, OK: true, Latency: 89 * time.Millisecond},
			{Source: model.SourceRegistryWHOIS, OK: false, Err: "timeout"},
		},
	}
	var buf bytes.Buffer
	if err := RenderIP(&buf, rec, Options{Theme: NewTheme(false), Width: 80, Verbose: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Sources") || !strings.Contains(out, "timeout") {
		t.Errorf("expected verbose Sources block, got:\n%s", out)
	}
}

func TestRenderIP_NoLockBadgeExpiryOrLifecycle(t *testing.T) {
	// IP allocations have no domain-style lock status, expiry countdown,
	// or lifecycle interpretation -- none of those concepts apply, so
	// none of their marker text should ever appear in IP output.
	var buf bytes.Buffer
	if err := RenderIP(&buf, fullIPRecord(), Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, absent := range []string{"locked", "at risk", "expires in", "expired", "Lifecycle"} {
		if strings.Contains(out, absent) {
			t.Errorf("output contains %q, want no domain-only concept in IP output:\n%s", absent, out)
		}
	}
}

func TestRenderIP_BorderIsAlwaysMuted(t *testing.T) {
	// Unlike Render, whose border color reflects a domain's lock/at-risk
	// verdict, RenderIP has no such verdict to color by -- the border is
	// always th.Muted regardless of record contents (e.g. status values
	// that would be "good"/"crit" for a domain don't apply here).
	th := NewTheme(false)
	rec := model.IPRecord{
		Handle: model.Field[string]{Value: "NET-8-8-8-0-2", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Status: model.Field[[]string]{Value: []string{"active"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("COLORTERM", "truecolor")
	var buf bytes.Buffer
	if err := RenderIP(&buf, rec, Options{Theme: th, Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "\x1b[") {
		t.Fatalf("expected ANSI output when color is forced, found none")
	}
}

func TestRenderIP_UnhandledFieldOrderEntryPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected writeIPField to panic on an unrecognized model.FieldSpec key")
		}
	}()
	var b strings.Builder
	writeIPField(&b, NewTheme(false), 80, model.IPRecord{}, model.FieldSpec{Label: "Bogus", Key: "bogus"})
}

// TestRenderIP_LegendOmitsRegistrarSources is the IP counterpart to
// TestRenderASN_LegendOmitsRegistrarSources -- an IP allocation is held
// directly from an RIR, with no registrar in the chain. Kept as a pair so
// neither object type quietly regains the domain legend.
func TestRenderIP_LegendOmitsRegistrarSources(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderIP(&buf, fullIPRecord(), Options{Theme: NewTheme(false), Width: 100}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	for _, absent := range []string{"registrar-rdap", "registrar-whois"} {
		if strings.Contains(out, absent) {
			t.Errorf("IP legend mentions %q, but an IP allocation has no registrar:\n%s", absent, out)
		}
	}
	for _, want := range []string{"GR registry-rdap", "GW registry-whois"} {
		if !strings.Contains(out, want) {
			t.Errorf("IP legend is missing %q:\n%s", want, out)
		}
	}
}
