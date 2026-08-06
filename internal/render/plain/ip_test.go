package plain

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
	var buf bytes.Buffer
	if err := RenderIP(&buf, fullIPRecord(), Options{Verbose: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"Handle:", "NET-8-8-8-0-2",
		"Network:", "GOGL",
		"Range:", "8.8.8.0 - 8.8.8.255",
		"CIDR:", "8.8.8.0/24",
		"IP Version:", "v4",
		"Country:", "US",
		"Organization:", "Google LLC",
		"active",
		"2023-12-28T22:24:33Z",
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

func TestRenderIP_SkipsAbsentFields(t *testing.T) {
	rec := model.IPRecord{
		Handle: model.Field[string]{Value: "NET-8-8-8-0-2", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := RenderIP(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, absent := range []string{"Network:", "Range:", "CIDR:", "Type:", "IP Version:", "Parent:", "Organization:", "Org ID:", "Country:", "Abuse Email:", "Abuse Phone:", "Status:", "Registered:", "Updated:"} {
		if strings.Contains(out, absent) {
			t.Errorf("expected %q row to be skipped when absent, got:\n%s", absent, out)
		}
	}
}

func TestRenderIP_RangeBothAddresses(t *testing.T) {
	rec := model.IPRecord{
		StartAddress: model.Field[string]{Value: "8.8.8.0", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		EndAddress:   model.Field[string]{Value: "8.8.8.255", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := RenderIP(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Range:") || !strings.Contains(out, "8.8.8.0 - 8.8.8.255") {
		t.Errorf("expected combined Range row, got:\n%s", out)
	}
}

func TestRenderIP_RangeOnlyStartAddress(t *testing.T) {
	rec := model.IPRecord{
		StartAddress: model.Field[string]{Value: "8.8.8.0", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := RenderIP(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Range:") || !strings.Contains(out, "8.8.8.0") {
		t.Errorf("expected a Range row with just the start address, got:\n%s", out)
	}
	if strings.Contains(out, "8.8.8.0 - ") {
		t.Errorf("expected no dangling separator when only start address is present, got:\n%s", out)
	}
}

func TestRenderIP_RangeOnlyEndAddress(t *testing.T) {
	rec := model.IPRecord{
		EndAddress: model.Field[string]{Value: "8.8.8.255", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := RenderIP(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Range:") || !strings.Contains(out, "8.8.8.255") {
		t.Errorf("expected a Range row with just the end address, got:\n%s", out)
	}
	if strings.Contains(out, " - 8.8.8.255") {
		t.Errorf("expected no dangling separator when only end address is present, got:\n%s", out)
	}
}

func TestRenderIP_RangeAbsentWhenNeitherAddressPresent(t *testing.T) {
	rec := model.IPRecord{
		Handle: model.Field[string]{Value: "NET-8-8-8-0-2", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := RenderIP(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "Range:") {
		t.Errorf("expected no Range row when neither address is present, got:\n%s", buf.String())
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
	if err := RenderIP(&buf, rec, Options{}); err != nil {
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

func TestRenderIP_RedactedSection(t *testing.T) {
	rec := model.IPRecord{
		Handle: model.Field[string]{Value: "NET-8-8-8-0-2", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
		Redacted: []model.RedactionNotice{
			{Field: model.FieldOrgName, Source: model.SourceRegistryRDAP, Reason: "redacted"},
		},
	}
	var buf bytes.Buffer
	if err := RenderIP(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, string(model.SourceRegistryRDAP)) || !strings.Contains(out, "redacted") {
		t.Errorf("expected redaction notice in output, got:\n%s", out)
	}
}

func TestRenderIP_NoLifecycleSection(t *testing.T) {
	// IP records have no lifecycle concept -- unlike domains, there's no
	// "Lifecycle" word that could ever appear in IP output.
	var buf bytes.Buffer
	if err := RenderIP(&buf, fullIPRecord(), Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "Lifecycle") {
		t.Errorf("expected no Lifecycle section in IP output, got:\n%s", buf.String())
	}
}

func TestRenderIP_UnhandledFieldOrderEntryPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected writeIPField to panic on an unrecognized model.FieldSpec key")
		}
	}()
	writeIPField(nil, model.IPRecord{}, model.FieldSpec{Label: "Bogus", Key: "bogus"})
}
