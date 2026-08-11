package machine

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/model"
)

// fullASNRecord populates every ASNRecord field, including Type,
// Conflicts, Redacted, and all four Org sub-fields -- the IP feature's
// fullIPRecord() review finding was that its own fixture omitted several
// fields, leaving buildIPView's mappings for them never executed by any
// test. This fixture must not repeat that gap.
func fullASNRecord() model.ASNRecord {
	reg, _ := time.Parse(time.RFC3339, "2000-03-30T00:00:00Z")
	upd, _ := time.Parse(time.RFC3339, "2024-03-15T18:02:11Z")
	return model.ASNRecord{
		Handle:      model.Field[string]{Value: "AS15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Name:        model.Field[string]{Value: "GOOGLE", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Type:        model.Field[string]{Value: "DIRECT ALLOCATION", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		StartAutnum: model.Field[string]{Value: "15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		EndAutnum:   model.Field[string]{Value: "15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Country:     model.Field[string]{Value: "US", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
		Org: model.OrgInfo{
			Name:       model.Field[string]{Value: "Google LLC", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
			ID:         model.Field[string]{Value: "GOGL", Sources: []model.SourceID{model.SourceRegistryRDAP}},
			AbuseEmail: model.Field[string]{Value: "network-abuse@google.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
			AbusePhone: model.Field[string]{Value: "+1-650-253-0000", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		},
		Status:     model.Field[[]string]{Value: []string{"active"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Registered: model.Field[model.TimeValue]{Value: model.TimeValue{Time: reg, Raw: "2000-03-30T00:00:00Z", Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Updated:    model.Field[model.TimeValue]{Value: model.TimeValue{Time: upd, Raw: "2024-03-15T18:02:11Z", Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Conflicts: []model.Conflict{
			{
				Field: model.FieldOrgAbuseEmail,
				Values: map[model.SourceID]string{
					model.SourceRegistryRDAP:  "network-abuse@google.com",
					model.SourceRegistryWHOIS: "abuse@google.com",
				},
			},
		},
		Redacted: []model.RedactionNotice{
			{Field: model.FieldASNCountry, Source: model.SourceRegistryRDAP, Reason: "redacted"},
		},
		Sources: []model.SourceResult{
			{Source: model.SourceRegistryRDAP, OK: true, Latency: 120 * time.Millisecond},
			{Source: model.SourceRegistryWHOIS, OK: true, Latency: 45 * time.Millisecond},
		},
	}
}

func TestEncodeASN_FullRecord(t *testing.T) {
	var buf bytes.Buffer
	if err := EncodeASN(&buf, fullASNRecord(), Options{}); err != nil {
		t.Fatalf("EncodeASN: %v", err)
	}
	checkGolden(t, "asn-record.json", buf.Bytes())

	var decoded map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output did not unmarshal: %v", err)
	}
	if decoded["objectType"] != "asn" {
		t.Errorf("objectType = %v, want \"asn\"", decoded["objectType"])
	}
	if decoded["schemaVersion"].(float64) != 1 {
		t.Errorf("schemaVersion = %v, want 1 (additive change, no bump)", decoded["schemaVersion"])
	}
	if _, ok := decoded["registrar"]; ok {
		t.Error("registrar key present on an ASN record, want absent")
	}
	if _, ok := decoded["nameservers"]; ok {
		t.Error("nameservers key present on an ASN record, want absent")
	}
	if _, ok := decoded["cidr"]; ok {
		t.Error("cidr key present on an ASN record, want absent")
	}
	for _, want := range []string{"handle", "name", "type", "startAutnum", "endAutnum", "country", "org", "status", "registered", "updated"} {
		if _, ok := decoded[want]; !ok {
			t.Errorf("%q missing from a fully-populated record", want)
		}
	}
	org, ok := decoded["org"].(map[string]interface{})
	if !ok {
		t.Fatalf("org field missing or wrong shape: %v", decoded["org"])
	}
	for _, want := range []string{"name", "id", "abuseEmail", "abusePhone"} {
		if _, ok := org[want]; !ok {
			t.Errorf("org.%s missing from a fully-populated record", want)
		}
	}
	conflicts, ok := decoded["conflicts"].([]interface{})
	if !ok || len(conflicts) != 1 {
		t.Errorf("conflicts = %v, want exactly 1 entry", decoded["conflicts"])
	}
	redacted, ok := decoded["redacted"].([]interface{})
	if !ok || len(redacted) != 1 {
		t.Errorf("redacted = %v, want exactly 1 entry", decoded["redacted"])
	}
}

// TestEncodeASN_RawEmbedding covers buildASNView's --raw source-embedding
// branch (RDAP JSON embedded as-is, WHOIS text embedded as a JSON string,
// plus the invalid-JSON fallback path) -- the ASN-record counterpart to
// TestEncodeIP_RawEmbedding, since EncodeASN has its own copy of this
// logic rather than sharing Encode's.
func TestEncodeASN_RawEmbedding(t *testing.T) {
	rec := model.ASNRecord{
		Handle: model.Field[string]{Value: "AS15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Sources: []model.SourceResult{
			{Source: model.SourceRegistryRDAP, OK: true, Latency: 89 * time.Millisecond, Raw: []byte(`{"objectClassName":"autnum","handle":"AS15169"}`)},
			{Source: model.SourceRegistryWHOIS, OK: true, Latency: 30 * time.Millisecond, Raw: []byte("ASNumber: 15169\nASName: GOOGLE\n")},
		},
	}

	var withRaw bytes.Buffer
	if err := EncodeASN(&withRaw, rec, Options{Raw: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded map[string]interface{}
	_ = json.Unmarshal(withRaw.Bytes(), &decoded)
	sources := decoded["sources"].([]interface{})
	rdapSource := sources[0].(map[string]interface{})
	rawField, ok := rdapSource["raw"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected sources[0].raw to be a JSON object (embedded as-is), got %T: %v", rdapSource["raw"], rdapSource["raw"])
	}
	if rawField["handle"] != "AS15169" {
		t.Errorf("sources[0].raw.handle = %v, want AS15169 (RDAP raw JSON should be embedded, not double-encoded as a string)", rawField["handle"])
	}
	whoisSource := sources[1].(map[string]interface{})
	whoisRaw, ok := whoisSource["raw"].(string)
	if !ok {
		t.Fatalf("expected sources[1].raw to be a JSON string (WHOIS text), got %T", whoisSource["raw"])
	}
	if whoisRaw != "ASNumber: 15169\nASName: GOOGLE\n" {
		t.Errorf("sources[1].raw = %q, want the WHOIS text verbatim", whoisRaw)
	}

	var withoutRaw bytes.Buffer
	if err := EncodeASN(&withoutRaw, rec, Options{Raw: false}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded2 map[string]interface{}
	_ = json.Unmarshal(withoutRaw.Bytes(), &decoded2)
	sources2 := decoded2["sources"].([]interface{})
	if _, exists := sources2[0].(map[string]interface{})["raw"]; exists {
		t.Error("expected sources[].raw to be omitted entirely when Options.Raw is false")
	}
}

func TestEncodeASNNDJSON_MultipleRecords(t *testing.T) {
	var buf bytes.Buffer
	rec1 := model.ASNRecord{Handle: model.Field[string]{Value: "AS15169", Sources: []model.SourceID{model.SourceRegistryRDAP}}}
	rec2 := model.ASNRecord{Handle: model.Field[string]{Value: "AS13335", Sources: []model.SourceID{model.SourceRegistryRDAP}}}
	if err := EncodeASNNDJSON(&buf, rec1, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := EncodeASNNDJSON(&buf, rec2, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	for i, line := range lines {
		if !json.Valid(line) {
			t.Errorf("line %d is not valid JSON: %s", i, line)
		}
		var decoded map[string]interface{}
		if err := json.Unmarshal(line, &decoded); err != nil {
			t.Fatalf("line %d: unmarshal: %v", i, err)
		}
		if decoded["objectType"] != "asn" {
			t.Errorf("line %d: objectType = %v, want \"asn\"", i, decoded["objectType"])
		}
	}
	handle0 := mustDecodeASNHandle(t, lines[0])
	handle1 := mustDecodeASNHandle(t, lines[1])
	if handle0 != "AS15169" || handle1 != "AS13335" {
		t.Errorf("handle values = %q, %q, want %q, %q (records must not bleed into each other)", handle0, handle1, "AS15169", "AS13335")
	}
	if !bytes.HasSuffix(buf.Bytes(), []byte("\n")) {
		t.Error("expected output to be newline-terminated")
	}
}

func mustDecodeASNHandle(t *testing.T, line []byte) string {
	t.Helper()
	var decoded map[string]interface{}
	if err := json.Unmarshal(line, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	handle, ok := decoded["handle"].(map[string]interface{})
	if !ok {
		t.Fatalf("handle field missing or wrong shape: %v", decoded["handle"])
	}
	v, _ := handle["value"].(string)
	return v
}

func TestEncodeASN_AbsentFieldsOmitted(t *testing.T) {
	var buf bytes.Buffer
	if err := EncodeASN(&buf, model.ASNRecord{}, Options{}); err != nil {
		t.Fatalf("EncodeASN: %v", err)
	}
	var decoded map[string]interface{}
	_ = json.Unmarshal(buf.Bytes(), &decoded)
	for _, k := range []string{"handle", "name", "type", "startAutnum", "endAutnum", "country", "org", "status", "registered", "updated"} {
		if _, ok := decoded[k]; ok {
			t.Errorf("%q present on an empty record, want omitted", k)
		}
	}
}
