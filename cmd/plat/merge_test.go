package main

import (
	"bytes"
	"strings"
	"testing"
	"text/tabwriter"
	"time"

	"github.com/patramsey/plat/internal/model"
)

func TestPrintRecord_FullyPresentRecord(t *testing.T) {
	created, _ := time.Parse(time.RFC3339, "1995-08-14T04:00:00Z")
	expires, _ := time.Parse(time.RFC3339, "2026-08-13T04:00:00Z")
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Handle: model.Field[string]{Value: "2336799_DOMAIN_COM-VRSN", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Registrar: model.RegistrarInfo{
			Name:       model.Field[string]{Value: "Example Registrar, Inc.", Sources: []model.SourceID{model.SourceRegistrarRDAP}},
			IANAID:     model.Field[string]{Value: "9999", Sources: []model.SourceID{model.SourceRegistrarRDAP}},
			AbuseEmail: model.Field[string]{Value: "abuse@example.test", Sources: []model.SourceID{model.SourceRegistrarRDAP}},
			AbusePhone: model.Field[string]{Value: "+1.5555550100", Sources: []model.SourceID{model.SourceRegistrarRDAP}},
		},
		Status:      model.Field[[]string]{Value: []string{"clientTransferProhibited"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Created:     model.Field[model.TimeValue]{Value: model.TimeValue{Time: created, Raw: "1995-08-14T04:00:00Z", Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Expires:     model.Field[model.TimeValue]{Value: model.TimeValue{Time: expires, Raw: "2026-08-13T04:00:00Z", Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Nameservers: model.Field[[]string]{Value: []string{"a.iana-servers.net", "b.iana-servers.net"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Sources: []model.SourceResult{
			{Source: model.SourceRegistryRDAP, OK: true, Latency: 89 * time.Millisecond},
			{Source: model.SourceRegistrarRDAP, OK: false, Err: "timeout", Latency: 5 * time.Second},
		},
		Conflicts: []model.Conflict{
			{Field: model.FieldExpires, Values: map[model.SourceID]string{model.SourceRegistryRDAP: "2026-08-13T04:00:00Z", model.SourceRegistryWHOIS: "2026-08-10"}},
		},
		Redacted: []model.RedactionNotice{
			{Field: model.FieldRegistrarName, Source: model.SourceRegistrarWHOIS, Reason: "redacted"},
		},
	}

	var buf bytes.Buffer
	if err := printRecord(&buf, rec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"Domain:", "example.com",
		"Handle:", "2336799_DOMAIN_COM-VRSN",
		"Registrar:", "Example Registrar, Inc.",
		"Registrar IANA ID:", "9999",
		"Abuse Email:", "abuse@example.test",
		"Abuse Phone:", "+1.5555550100",
		"Status:", "clientTransferProhibited",
		"Created:", "1995-08-14T04:00:00Z",
		"Expires:", "2026-08-13T04:00:00Z",
		"Nameservers:", "a.iana-servers.net",
		"Source registry-rdap:", "89ms", "ok",
		"Source registrar-rdap:", "timeout",
		"Conflict expires:",
		"Redacted registrar.name:", "redacted",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, out)
		}
	}
}

func TestPrintRecord_SkipsAbsentFields(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := printRecord(&buf, rec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, absent := range []string{"Handle:", "Registrar:", "Status:", "Created:", "Expires:", "Nameservers:"} {
		if strings.Contains(out, absent) {
			t.Errorf("expected %q row to be skipped when absent, got:\n%s", absent, out)
		}
	}
}

func TestPrintTimeField_UnparsedFallback(t *testing.T) {
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	printTimeField(tw, "Expires", model.Field[model.TimeValue]{
		Value:   model.TimeValue{Raw: "not-a-date", Parsed: false},
		Sources: []model.SourceID{model.SourceRegistryWHOIS},
	})
	_ = tw.Flush()
	if !strings.Contains(buf.String(), "not-a-date (unparsed)") {
		t.Errorf("output missing unparsed-date fallback, got:\n%s", buf.String())
	}
}
