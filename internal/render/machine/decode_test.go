package machine

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/model"
)

// decodeFixtureRecord is a domain record with one field of each kind:
// scalar, list, time, and bool.
func decodeFixtureRecord() model.Record {
	exp, _ := time.Parse(time.RFC3339, "2027-08-03T04:00:00Z")
	src := []model.SourceID{model.SourceRegistryRDAP}
	tr := true
	return model.Record{
		Domain:      model.Field[string]{Value: "example.com", Sources: src},
		Status:      model.Field[[]string]{Value: []string{"clientTransferProhibited"}, Sources: src},
		Expires:     model.Field[model.TimeValue]{Value: model.TimeValue{Time: exp, Raw: "2027-08-03T04:00:00Z", Parsed: true}, Sources: src},
		Nameservers: model.Field[[]string]{Value: []string{"a.iana-servers.net", "b.iana-servers.net"}, Sources: src},
		DNSSEC:      model.Field[bool]{Value: tr, Sources: src},
	}
}

// TestDecode_RoundTripPreservesFields is the test that catches Decode and
// Fields silently disagreeing with the encoder. Encoding a record and
// decoding it back must yield the same flattened fields the encoder's own
// view produces -- if a JSON key is misspelled in the decode path, the
// value arrives empty and this fails.
func TestDecode_RoundTripPreservesFields(t *testing.T) {
	var buf bytes.Buffer
	if err := Encode(&buf, decodeFixtureRecord(), Options{}); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	snap, err := Decode(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if snap.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", snap.SchemaVersion, SchemaVersion)
	}
	if snap.ObjectType != "domain" {
		t.Errorf("ObjectType = %q, want domain", snap.ObjectType)
	}
	if snap.Name != "example.com" {
		t.Errorf("Name = %q, want example.com", snap.Name)
	}

	got := map[string]Field{}
	for _, f := range snap.Fields() {
		got[f.Key] = f
	}

	if f := got[model.FieldExpires]; f.Value != "2027-08-03T04:00:00Z" {
		t.Errorf("Expires = %q, want 2027-08-03T04:00:00Z", f.Value)
	}
	if f := got[model.FieldNameservers]; len(f.List) != 2 {
		t.Errorf("Nameservers list = %q, want 2 entries", f.List)
	}
	if f := got[model.FieldStatus]; len(f.List) != 1 || f.List[0] != "clientTransferProhibited" {
		t.Errorf("Status list = %q, want [clientTransferProhibited]", f.List)
	}
	if f := got[model.FieldDNSSEC]; f.Value != "true" {
		t.Errorf("DNSSEC = %q, want true", f.Value)
	}
	if f := got[model.FieldExpires]; f.Label != "Expires" {
		t.Errorf("Expires label = %q, want Expires (must come from model.FieldOrder)", f.Label)
	}
}

func TestDecode_Rejections(t *testing.T) {
	for _, tt := range []struct {
		name string
		body string
		want error
	}{
		{"unsupported schema", `{"schemaVersion":99,"objectType":"domain"}`, ErrUnsupportedSchema},
		{"unknown object type", `{"schemaVersion":1,"objectType":"nameserver"}`, ErrUnknownObjectType},
		{"ndjson", "{\"schemaVersion\":1,\"objectType\":\"domain\"}\n{\"schemaVersion\":1,\"objectType\":\"domain\"}\n", ErrMultipleRecords},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(tt.body))
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
	if _, err := Decode(strings.NewReader("not json")); err == nil {
		t.Error("expected an error for malformed JSON")
	}
}
