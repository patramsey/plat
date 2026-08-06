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
	return model.IPRecord{
		Handle:       model.Field[string]{Value: "NET-8-8-8-0-2", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Name:         model.Field[string]{Value: "GOGL", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Type:         model.Field[string]{Value: "DIRECT ALLOCATION", Sources: []model.SourceID{model.SourceRegistryRDAP}},
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
