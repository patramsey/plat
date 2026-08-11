package machine

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/model"
)

func fullIPRecord() model.IPRecord {
	reg, _ := time.Parse(time.RFC3339, "2023-12-28T22:24:33Z")
	upd, _ := time.Parse(time.RFC3339, "2024-03-15T18:02:11Z")
	return model.IPRecord{
		Handle:       model.Field[string]{Value: "NET-8-8-8-0-2", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Name:         model.Field[string]{Value: "GOGL", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Type:         model.Field[string]{Value: "DIRECT ALLOCATION", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		StartAddress: model.Field[string]{Value: "8.8.8.0", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		EndAddress:   model.Field[string]{Value: "8.8.8.255", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		CIDR:         model.Field[string]{Value: "8.8.8.0/24", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		IPVersion:    model.Field[string]{Value: "v4", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		ParentHandle: model.Field[string]{Value: "NET-8-0-0-0-0", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Country:      model.Field[string]{Value: "US", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
		Org: model.OrgInfo{
			Name:       model.Field[string]{Value: "Google LLC", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
			ID:         model.Field[string]{Value: "GOGL", Sources: []model.SourceID{model.SourceRegistryRDAP}},
			AbuseEmail: model.Field[string]{Value: "network-abuse@google.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
			AbusePhone: model.Field[string]{Value: "+1-650-253-0000", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		},
		Status:     model.Field[[]string]{Value: []string{"active"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Registered: model.Field[model.TimeValue]{Value: model.TimeValue{Time: reg, Raw: "2023-12-28T17:24:33-05:00", Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
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
			{Field: model.FieldIPCountry, Source: model.SourceRegistryRDAP, Reason: "redacted"},
		},
		Sources: []model.SourceResult{
			{Source: model.SourceRegistryRDAP, OK: true, Latency: 120 * time.Millisecond},
			{Source: model.SourceRegistryWHOIS, OK: true, Latency: 45 * time.Millisecond},
		},
	}
}

func TestEncodeIP_FullRecord(t *testing.T) {
	var buf bytes.Buffer
	if err := EncodeIP(&buf, fullIPRecord(), Options{}); err != nil {
		t.Fatalf("EncodeIP: %v", err)
	}
	checkGolden(t, "ip-record.json", buf.Bytes())

	var decoded map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output did not unmarshal: %v", err)
	}
	if decoded["objectType"] != "ip" {
		t.Errorf("objectType = %v, want \"ip\"", decoded["objectType"])
	}
	if decoded["schemaVersion"].(float64) != 1 {
		t.Errorf("schemaVersion = %v, want 1 (additive change, no bump)", decoded["schemaVersion"])
	}
	if _, ok := decoded["registrar"]; ok {
		t.Error("registrar key present on an IP record, want absent")
	}
	if _, ok := decoded["nameservers"]; ok {
		t.Error("nameservers key present on an IP record, want absent")
	}
}

// TestEncodeIP_RawEmbedding covers buildIPView's --raw source-embedding
// branch (RDAP JSON embedded as-is, WHOIS text embedded as a JSON string,
// plus the invalid-JSON fallback path) -- the IP-record counterpart to
// TestEncode_RawEmbedding, since EncodeIP has its own copy of this logic
// rather than sharing Encode's.
func TestEncodeIP_RawEmbedding(t *testing.T) {
	rec := model.IPRecord{
		CIDR: model.Field[string]{Value: "8.8.8.0/24", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Sources: []model.SourceResult{
			{Source: model.SourceRegistryRDAP, OK: true, Latency: 89 * time.Millisecond, Raw: []byte(`{"objectClassName":"ip network","handle":"NET-8-8-8-0-2"}`)},
			{Source: model.SourceRegistryWHOIS, OK: true, Latency: 30 * time.Millisecond, Raw: []byte("NetRange: 8.8.8.0 - 8.8.8.255\nOrgName: Google LLC\n")},
		},
	}

	var withRaw bytes.Buffer
	if err := EncodeIP(&withRaw, rec, Options{Raw: true}); err != nil {
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
	if rawField["handle"] != "NET-8-8-8-0-2" {
		t.Errorf("sources[0].raw.handle = %v, want NET-8-8-8-0-2 (RDAP raw JSON should be embedded, not double-encoded as a string)", rawField["handle"])
	}
	whoisSource := sources[1].(map[string]interface{})
	whoisRaw, ok := whoisSource["raw"].(string)
	if !ok {
		t.Fatalf("expected sources[1].raw to be a JSON string (WHOIS text), got %T", whoisSource["raw"])
	}
	if whoisRaw != "NetRange: 8.8.8.0 - 8.8.8.255\nOrgName: Google LLC\n" {
		t.Errorf("sources[1].raw = %q, want the WHOIS text verbatim", whoisRaw)
	}

	var withoutRaw bytes.Buffer
	if err := EncodeIP(&withoutRaw, rec, Options{Raw: false}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded2 map[string]interface{}
	_ = json.Unmarshal(withoutRaw.Bytes(), &decoded2)
	sources2 := decoded2["sources"].([]interface{})
	if _, exists := sources2[0].(map[string]interface{})["raw"]; exists {
		t.Error("expected sources[].raw to be omitted entirely when Options.Raw is false")
	}
}

func TestEncodeIPNDJSON_MultipleRecords(t *testing.T) {
	var buf bytes.Buffer
	rec1 := model.IPRecord{CIDR: model.Field[string]{Value: "8.8.8.0/24", Sources: []model.SourceID{model.SourceRegistryRDAP}}}
	rec2 := model.IPRecord{CIDR: model.Field[string]{Value: "1.1.1.0/24", Sources: []model.SourceID{model.SourceRegistryRDAP}}}
	if err := EncodeIPNDJSON(&buf, rec1, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := EncodeIPNDJSON(&buf, rec2, Options{}); err != nil {
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
		if decoded["objectType"] != "ip" {
			t.Errorf("line %d: objectType = %v, want \"ip\"", i, decoded["objectType"])
		}
	}
	cidr0 := mustDecodeIPCIDR(t, lines[0])
	cidr1 := mustDecodeIPCIDR(t, lines[1])
	if cidr0 != "8.8.8.0/24" || cidr1 != "1.1.1.0/24" {
		t.Errorf("cidr values = %q, %q, want %q, %q (records must not bleed into each other)", cidr0, cidr1, "8.8.8.0/24", "1.1.1.0/24")
	}
	if !bytes.HasSuffix(buf.Bytes(), []byte("\n")) {
		t.Error("expected output to be newline-terminated")
	}
}

func mustDecodeIPCIDR(t *testing.T, line []byte) string {
	t.Helper()
	var decoded map[string]interface{}
	if err := json.Unmarshal(line, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cidr, ok := decoded["cidr"].(map[string]interface{})
	if !ok {
		t.Fatalf("cidr field missing or wrong shape: %v", decoded["cidr"])
	}
	v, _ := cidr["value"].(string)
	return v
}

func TestEncodeIP_AbsentFieldsOmitted(t *testing.T) {
	var buf bytes.Buffer
	if err := EncodeIP(&buf, model.IPRecord{}, Options{}); err != nil {
		t.Fatalf("EncodeIP: %v", err)
	}
	var decoded map[string]interface{}
	_ = json.Unmarshal(buf.Bytes(), &decoded)
	for _, k := range []string{"handle", "name", "cidr", "org", "status", "registered"} {
		if _, ok := decoded[k]; ok {
			t.Errorf("%q present on an empty record, want omitted", k)
		}
	}
}
