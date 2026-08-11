package plain

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
	var buf bytes.Buffer
	if err := RenderASN(&buf, fullASNRecord(), Options{Verbose: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"Handle:", "AS15169",
		"AS Name:", "GOOGLE",
		"Range:", "15169 - 15169",
		"Type:", "DIRECT ALLOCATION",
		"Country:", "US",
		"Organization:", "Google LLC",
		"active",
		"2000-03-30T00:00:00Z",
		string(model.SourceRegistryRDAP),
		"120ms",
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

func TestRenderASN_SkipsAbsentFields(t *testing.T) {
	rec := model.ASNRecord{
		Handle: model.Field[string]{Value: "AS15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := RenderASN(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, absent := range []string{"AS Name:", "Range:", "Type:", "Organization:", "Org ID:", "Country:", "Abuse Email:", "Abuse Phone:", "Status:", "Registered:", "Updated:"} {
		if strings.Contains(out, absent) {
			t.Errorf("expected %q row to be skipped when absent, got:\n%s", absent, out)
		}
	}
}

func TestRenderASN_RangeBothAutnums(t *testing.T) {
	rec := model.ASNRecord{
		StartAutnum: model.Field[string]{Value: "15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		EndAutnum:   model.Field[string]{Value: "15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := RenderASN(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Range:") || !strings.Contains(out, "15169 - 15169") {
		t.Errorf("expected combined Range row, got:\n%s", out)
	}
}

func TestRenderASN_RangeOnlyStartAutnum(t *testing.T) {
	rec := model.ASNRecord{
		StartAutnum: model.Field[string]{Value: "15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := RenderASN(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Range:") || !strings.Contains(out, "15169") {
		t.Errorf("expected a Range row with just the start autnum, got:\n%s", out)
	}
	if strings.Contains(out, "15169 - ") {
		t.Errorf("expected no dangling separator when only start autnum is present, got:\n%s", out)
	}
}

func TestRenderASN_RangeOnlyEndAutnum(t *testing.T) {
	rec := model.ASNRecord{
		EndAutnum: model.Field[string]{Value: "15170", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := RenderASN(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Range:") || !strings.Contains(out, "15170") {
		t.Errorf("expected a Range row with just the end autnum, got:\n%s", out)
	}
	if strings.Contains(out, " - 15170") {
		t.Errorf("expected no dangling separator when only end autnum is present, got:\n%s", out)
	}
}

func TestRenderASN_RangeAbsentWhenNeitherAutnumPresent(t *testing.T) {
	rec := model.ASNRecord{
		Handle: model.Field[string]{Value: "AS15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := RenderASN(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "Range:") {
		t.Errorf("expected no Range row when neither autnum is present, got:\n%s", buf.String())
	}
}

// TestRenderASN_RangeMarkedWhenOnlyEndAutnumConflicts pins the same real
// gap the IP feature review found (see TestRenderIP_RangeMarkedWhenOnlyEndAddressConflicts):
// merge.MergeASN merges StartAutnum and EndAutnum through two independent
// scalar() calls, keyed "startAutnum" and "endAutnum" respectively, so a
// genuine disagreement can land on EITHER field's own model.Conflict entry
// while the other field agrees across sources. The combined Range row must
// still carry the [conflict] marker in that case.
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
	if err := RenderASN(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	var rangeLine string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "Range:") {
			rangeLine = l
		}
	}
	if !strings.Contains(rangeLine, "[conflict]") {
		t.Errorf("expected the Range row to carry a [conflict] marker when only EndAutnum conflicts, got: %q\nfull output:\n%s", rangeLine, out)
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
	if err := RenderASN(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	var rangeLine string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "Range:") {
			rangeLine = l
		}
	}
	if !strings.Contains(rangeLine, "[conflict]") {
		t.Errorf("expected the Range row to carry a [conflict] marker when only StartAutnum conflicts, got: %q\nfull output:\n%s", rangeLine, out)
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
	if err := RenderASN(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	var rangeLine string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "Range:") {
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
	if err := RenderASN(&buf, rec, Options{}); err != nil {
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
	if !strings.Contains(countryLine, "[conflict]") {
		t.Errorf("expected the conflicted Country row to carry a [conflict] marker, got: %q", countryLine)
	}
	if strings.Contains(handleLine, "[conflict]") {
		t.Errorf("expected the non-conflicted Handle row to carry no marker, got: %q", handleLine)
	}
	if !strings.Contains(out, "--conflicts") {
		t.Errorf("expected a hint pointing at --conflicts, got:\n%s", out)
	}
}

func TestRenderASN_RedactedSection(t *testing.T) {
	rec := model.ASNRecord{
		Handle: model.Field[string]{Value: "AS15169", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
		Redacted: []model.RedactionNotice{
			{Field: model.FieldOrgName, Source: model.SourceRegistryRDAP, Reason: "redacted"},
		},
	}
	var buf bytes.Buffer
	if err := RenderASN(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, string(model.SourceRegistryRDAP)) || !strings.Contains(out, "redacted") {
		t.Errorf("expected redaction notice in output, got:\n%s", out)
	}
}

func TestRenderASN_NoLifecycleSection(t *testing.T) {
	// ASN records have no lifecycle concept -- unlike domains, there's no
	// "Lifecycle" word that could ever appear in ASN output.
	var buf bytes.Buffer
	if err := RenderASN(&buf, fullASNRecord(), Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "Lifecycle") {
		t.Errorf("expected no Lifecycle section in ASN output, got:\n%s", buf.String())
	}
}

func TestRenderASN_UnhandledFieldOrderEntryPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected writeASNField to panic on an unrecognized model.FieldSpec key")
		}
	}()
	writeASNField(nil, model.ASNRecord{}, model.FieldSpec{Label: "Bogus", Key: "bogus"})
}
