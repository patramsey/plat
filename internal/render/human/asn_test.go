package human

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/model"
)

func fullASNRecord() model.ASNRecord {
	reg, _ := time.Parse(time.RFC3339, "2000-03-30T00:00:00Z")
	return model.ASNRecord{
		Handle:      model.Field[string]{Value: "AS15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Name:        model.Field[string]{Value: "GOOGLE", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Type:        model.Field[string]{Value: "DIRECT ALLOCATION", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		StartAutnum: model.Field[string]{Value: "15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		EndAutnum:   model.Field[string]{Value: "15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Country:     model.Field[string]{Value: "US", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
		Org: model.OrgInfo{
			Name: model.Field[string]{Value: "Google LLC", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
		},
		Status:     model.Field[[]string]{Value: []string{"active"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Registered: model.Field[model.TimeValue]{Value: model.TimeValue{Time: reg, Raw: "2000-03-30T00:00:00Z", Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Sources: []model.SourceResult{
			{Source: model.SourceRegistryRDAP, OK: true, Latency: 120 * time.Millisecond},
		},
	}
}

func TestRenderASN_FullyPresentRecord(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("COLORTERM", "truecolor")

	var buf bytes.Buffer
	if err := RenderASN(&buf, fullASNRecord(), Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"AS15169",
		"GOOGLE",
		"15169",
		"DIRECT ALLOCATION",
		"US",
		"Google LLC",
		"active",
		"2000-03-30T00:00:00Z",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "\x1b[") {
		t.Error("expected ANSI escape sequences when color is forced, found none")
	}
}

func TestRenderASN_NoColorByDefault(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderASN(&buf, fullASNRecord(), Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("expected zero ANSI with no color forced, got:\n%s", buf.String())
	}
}

func TestRenderASN_SkipsAbsentFields(t *testing.T) {
	rec := model.ASNRecord{
		Handle: model.Field[string]{Value: "AS15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := RenderASN(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, absent := range []string{"AS Name:", "Range:", "Type:", "Organization:", "Org ID:", "Country:", "Abuse Email:", "Abuse Phone:", "Status:", "Registered:", "Updated:"} {
		if strings.Contains(out, absent) {
			t.Errorf("expected %q row to be skipped when absent, got:\n%s", absent, out)
		}
	}
}

func TestRenderASN_DefaultWidthWhenUnset(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderASN(&buf, fullASNRecord(), Options{Theme: NewTheme(false), Width: 0}); err != nil {
		t.Fatalf("unexpected error with Width: 0: %v", err)
	}
	if !strings.Contains(buf.String(), "15169") {
		t.Error("expected output with default width, got none")
	}
}

func TestRenderASN_TitleUsesHandle(t *testing.T) {
	rec := model.ASNRecord{
		Handle: model.Field[string]{Value: "AS15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Name:   model.Field[string]{Value: "GOOGLE", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := RenderASN(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "plat · AS15169") {
		t.Errorf("expected title to use Handle, got:\n%s", out)
	}
}

func TestRenderASN_TitleFallsBackToName(t *testing.T) {
	rec := model.ASNRecord{
		Name: model.Field[string]{Value: "GOOGLE", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := RenderASN(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "plat · GOOGLE") {
		t.Errorf("expected title to fall back to Name when Handle absent, got:\n%s", out)
	}
}

func TestRenderASN_NoTitleWhenNeitherPresent(t *testing.T) {
	rec := model.ASNRecord{
		Country: model.Field[string]{Value: "US", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
	}
	var buf bytes.Buffer
	if err := RenderASN(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "plat ·") {
		t.Errorf("expected no title when neither Handle nor Name is present, got:\n%s", buf.String())
	}
}

func TestRenderASN_RangeBothAutnums(t *testing.T) {
	rec := model.ASNRecord{
		StartAutnum: model.Field[string]{Value: "15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		EndAutnum:   model.Field[string]{Value: "15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := RenderASN(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "15169 - 15169") {
		t.Errorf("expected combined Range row, got:\n%s", out)
	}
}

func TestRenderASN_RangeOnlyStartAutnum(t *testing.T) {
	rec := model.ASNRecord{
		StartAutnum: model.Field[string]{Value: "15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := RenderASN(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "15169") {
		t.Errorf("expected a Range row with just the start autnum, got:\n%s", out)
	}
	if strings.Contains(out, "15169 - ") {
		t.Errorf("expected no dangling separator when only start autnum is present, got:\n%s", out)
	}
}

// TestRenderASN_RangeMarkedWhenOnlyEndAutnumConflicts pins the same real
// gap the IP feature review found: merge.MergeASN merges StartAutnum and
// EndAutnum through two independent scalar() calls, keyed "startAutnum"
// and "endAutnum" respectively, so a genuine disagreement can land on
// EITHER field's own model.Conflict entry while the other field agrees
// across sources. The combined Range row must still carry the ⚠ marker in
// that case.
func TestRenderASN_RangeMarkedWhenOnlyEndAutnumConflicts(t *testing.T) {
	rec := model.ASNRecord{
		StartAutnum: model.Field[string]{Value: "15169", Sources: []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistryWHOIS}},
		EndAutnum:   model.Field[string]{Value: "15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Conflicts: []model.Conflict{
			{
				Field: model.FieldASNEndAutnum,
				Values: map[model.SourceID]string{
					model.SourceRegistryRDAP:  "15169",
					model.SourceRegistryWHOIS: "15170",
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := RenderASN(&buf, rec, Options{Theme: NewTheme(false), Width: 100}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	var rangeLine string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "15169") {
			rangeLine = l
		}
	}
	if !strings.Contains(rangeLine, "⚠") {
		t.Errorf("expected the Range row to carry a ⚠ marker when only EndAutnum conflicts, got: %q\nfull output:\n%s", rangeLine, out)
	}
}

// TestRenderASN_RangeMarkedWhenOnlyStartAutnumConflicts is the mirror of
// the EndAutnum case above, guarding against a fix that only checks
// EndAutnum (or only StartAutnum) instead of ORing both.
func TestRenderASN_RangeMarkedWhenOnlyStartAutnumConflicts(t *testing.T) {
	rec := model.ASNRecord{
		StartAutnum: model.Field[string]{Value: "15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		EndAutnum:   model.Field[string]{Value: "15169", Sources: []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistryWHOIS}},
		Conflicts: []model.Conflict{
			{
				Field: model.FieldASNStartAutnum,
				Values: map[model.SourceID]string{
					model.SourceRegistryRDAP:  "15169",
					model.SourceRegistryWHOIS: "15168",
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := RenderASN(&buf, rec, Options{Theme: NewTheme(false), Width: 100}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	var rangeLine string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "15169") {
			rangeLine = l
		}
	}
	if !strings.Contains(rangeLine, "⚠") {
		t.Errorf("expected the Range row to carry a ⚠ marker when only StartAutnum conflicts, got: %q\nfull output:\n%s", rangeLine, out)
	}
}

// TestRenderASN_RangeBadgeUnionsBothAutnumsSources covers the same
// underlying independent-merge behavior from the source-badge side.
func TestRenderASN_RangeBadgeUnionsBothAutnumsSources(t *testing.T) {
	rec := model.ASNRecord{
		StartAutnum: model.Field[string]{Value: "15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		EndAutnum:   model.Field[string]{Value: "15169", Sources: []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistryWHOIS}},
	}
	var buf bytes.Buffer
	if err := RenderASN(&buf, rec, Options{Theme: NewTheme(false), Width: 100}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	var rangeLine string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "15169") {
			rangeLine = l
		}
	}
	if !strings.Contains(rangeLine, sourceCode(model.SourceRegistryRDAP)) || !strings.Contains(rangeLine, sourceCode(model.SourceRegistryWHOIS)) {
		t.Errorf("expected the Range row's badge to include both GR and GW (union of both autnums' sources), got: %q", rangeLine)
	}
}

func TestRenderASN_ConflictedFieldGetsMarkerByDefaultDetailHidden(t *testing.T) {
	rec := model.ASNRecord{
		Handle: model.Field[string]{Value: "AS15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Country: model.Field[string]{
			Value:   "US",
			Sources: []model.SourceID{model.SourceRegistryRDAP},
		},
		Conflicts: []model.Conflict{
			{
				Field: model.FieldASNCountry,
				Values: map[model.SourceID]string{
					model.SourceRegistryRDAP:  "US",
					model.SourceRegistryWHOIS: "CA",
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := RenderASN(&buf, rec, Options{Theme: NewTheme(false), Width: 100}); err != nil {
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

func TestRenderASN_RedactedBlock(t *testing.T) {
	rec := model.ASNRecord{
		Handle: model.Field[string]{Value: "AS15169", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
		Redacted: []model.RedactionNotice{
			{Field: model.FieldOrgName, Source: model.SourceRegistryRDAP, Reason: "redacted"},
		},
	}
	var buf bytes.Buffer
	if err := RenderASN(&buf, rec, Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Redacted") || !strings.Contains(out, string(model.SourceRegistryRDAP)) {
		t.Errorf("expected redaction notice in output, got:\n%s", out)
	}
}

func TestRenderASN_SourcesBlock(t *testing.T) {
	rec := model.ASNRecord{
		Handle: model.Field[string]{Value: "AS15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Sources: []model.SourceResult{
			{Source: model.SourceRegistryRDAP, OK: true, Latency: 89 * time.Millisecond},
			{Source: model.SourceRegistryWHOIS, OK: false, Err: "timeout"},
		},
	}
	var buf bytes.Buffer
	if err := RenderASN(&buf, rec, Options{Theme: NewTheme(false), Width: 80, Verbose: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Sources") || !strings.Contains(out, "timeout") {
		t.Errorf("expected verbose Sources block, got:\n%s", out)
	}
}

func TestRenderASN_NoLockBadgeExpiryOrLifecycle(t *testing.T) {
	// ASNs have no domain-style lock status, expiry countdown, or
	// lifecycle interpretation -- none of those concepts apply, so none of
	// their marker text should ever appear in ASN output.
	var buf bytes.Buffer
	if err := RenderASN(&buf, fullASNRecord(), Options{Theme: NewTheme(false), Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, absent := range []string{"locked", "at risk", "expires in", "expired", "Lifecycle"} {
		if strings.Contains(out, absent) {
			t.Errorf("output contains %q, want no domain-only concept in ASN output:\n%s", absent, out)
		}
	}
}

func TestRenderASN_BorderIsAlwaysMuted(t *testing.T) {
	// Unlike Render, whose border color reflects a domain's lock/at-risk
	// verdict, RenderASN has no such verdict to color by -- the border is
	// always th.Muted regardless of record contents (e.g. status values
	// that would be "good"/"crit" for a domain don't apply here).
	th := NewTheme(false)
	rec := model.ASNRecord{
		Handle: model.Field[string]{Value: "AS15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Status: model.Field[[]string]{Value: []string{"active"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("COLORTERM", "truecolor")
	var buf bytes.Buffer
	if err := RenderASN(&buf, rec, Options{Theme: th, Width: 80}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "\x1b[") {
		t.Fatalf("expected ANSI output when color is forced, found none")
	}
}

func TestRenderASN_UnhandledFieldOrderEntryPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected writeASNField to panic on an unrecognized model.FieldSpec key")
		}
	}()
	var b strings.Builder
	writeASNField(&b, NewTheme(false), 80, model.ASNRecord{}, model.FieldSpec{Label: "Bogus", Key: "bogus"})
}

// TestRenderASN_LegendOmitsRegistrarSources pins the object-type-aware
// legend. An autonomous system is registered directly with an RIR and has
// no registrar, so registrar-rdap/registrar-whois can never supply a field
// here -- listing their codes explains badges that cannot appear, which
// reads as "plat failed to reach the registrar" rather than "no such
// source exists". The registry codes must still be explained, since those
// badges do appear in the default view.
func TestRenderASN_LegendOmitsRegistrarSources(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderASN(&buf, fullASNRecord(), Options{Theme: NewTheme(false), Width: 100}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	for _, absent := range []string{"registrar-rdap", "registrar-whois"} {
		if strings.Contains(out, absent) {
			t.Errorf("ASN legend mentions %q, but an ASN has no registrar:\n%s", absent, out)
		}
	}
	for _, want := range []string{"GR registry-rdap", "GW registry-whois"} {
		if !strings.Contains(out, want) {
			t.Errorf("ASN legend is missing %q:\n%s", want, out)
		}
	}
}
