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

// TestDecode_IPRoundTrip guards the objectType fix in Decode's switch:
// buildIPView writes objectType "ip" (see ip.go), not RDAP's "ip network"
// objectClassName. fullIPRecord (defined in ip_test.go) populates every
// IPRecord field, so len(Fields()) pins the IPFieldOrder count too.
func TestDecode_IPRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := EncodeIP(&buf, fullIPRecord(), Options{}); err != nil {
		t.Fatalf("EncodeIP: %v", err)
	}

	snap, err := Decode(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if snap.ObjectType != "ip" {
		t.Errorf("ObjectType = %q, want ip", snap.ObjectType)
	}
	if snap.Name != "8.8.8.0/24" {
		t.Errorf("Name = %q, want 8.8.8.0/24", snap.Name)
	}

	fields := snap.Fields()
	if len(fields) != len(model.IPFieldOrder) {
		t.Fatalf("len(Fields()) = %d, want %d (every IPFieldOrder entry populated)", len(fields), len(model.IPFieldOrder))
	}

	got := map[string]Field{}
	for _, f := range fields {
		got[f.Key] = f
	}
	if f := got[model.FieldIPHandle]; f.Value != "NET-8-8-8-0-2" {
		t.Errorf("Handle = %q, want NET-8-8-8-0-2", f.Value)
	}
	if f := got[model.FieldIPStartAddress]; f.Value != "8.8.8.0 - 8.8.8.255" {
		t.Errorf("Range = %q, want combined start - end", f.Value)
	}
	if f := got[model.FieldOrgName]; f.Value != "Google LLC" {
		t.Errorf("Org name = %q, want Google LLC", f.Value)
	}
	if f := got[model.FieldIPStatus]; len(f.List) != 1 || f.List[0] != "active" {
		t.Errorf("Status list = %q, want [active]", f.List)
	}
	if f := got[model.FieldIPUpdated]; f.Value != "2024-03-15T18:02:11Z" {
		t.Errorf("Updated = %q, want 2024-03-15T18:02:11Z", f.Value)
	}
	if f := got[model.FieldIPStartAddress]; f.Label != "Range" {
		t.Errorf("Range label = %q, want Range (must come from model.IPFieldOrder)", f.Label)
	}
}

// TestDecode_ASNRoundTrip is the ASN counterpart to TestDecode_IPRoundTrip,
// guarding the same objectType fix ("asn", not RDAP's "autnum"
// objectClassName). fullASNRecord (defined in asn_test.go) populates every
// ASNRecord field.
func TestDecode_ASNRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := EncodeASN(&buf, fullASNRecord(), Options{}); err != nil {
		t.Fatalf("EncodeASN: %v", err)
	}

	snap, err := Decode(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if snap.ObjectType != "asn" {
		t.Errorf("ObjectType = %q, want asn", snap.ObjectType)
	}
	if snap.Name != "AS15169" {
		t.Errorf("Name = %q, want AS15169", snap.Name)
	}

	fields := snap.Fields()
	if len(fields) != len(model.ASNFieldOrder) {
		t.Fatalf("len(Fields()) = %d, want %d (every ASNFieldOrder entry populated)", len(fields), len(model.ASNFieldOrder))
	}

	got := map[string]Field{}
	for _, f := range fields {
		got[f.Key] = f
	}
	if f := got[model.FieldASNHandle]; f.Value != "AS15169" {
		t.Errorf("Handle = %q, want AS15169", f.Value)
	}
	if f := got[model.FieldASNStartAutnum]; f.Value != "15169 - 15169" {
		t.Errorf("Range = %q, want combined start - end", f.Value)
	}
	if f := got[model.FieldASNStartAutnum]; f.Label != "Range" {
		t.Errorf("Range label = %q, want Range (must come from model.ASNFieldOrder)", f.Label)
	}
	if f := got[model.FieldOrgName]; f.Value != "Google LLC" {
		t.Errorf("Org name = %q, want Google LLC", f.Value)
	}
	if f := got[model.FieldASNStatus]; len(f.List) != 1 || f.List[0] != "active" {
		t.Errorf("Status list = %q, want [active]", f.List)
	}
}

// decodeFixtureUnparsedExpires is a domain record whose Expires field was
// attempted but never parsed -- Value.Parsed is false, Value.Time is the
// zero value, and only Raw carries information. This is a real shape:
// timeFieldView (machine.go) only sets timeFieldValue.Value when Parsed is
// true, leaving it nil on the wire otherwise.
func decodeFixtureUnparsedExpires() model.Record {
	src := []model.SourceID{model.SourceRegistryWHOIS}
	return model.Record{
		Domain: model.Field[string]{Value: "example.net", Sources: src},
		Expires: model.Field[model.TimeValue]{
			Value:   model.TimeValue{Raw: "circa 2030", Parsed: false},
			Sources: src,
		},
	}
}

// TestDecode_UnparsedTimestamp guards tstamp's nil-check: timeFieldValue's
// wire "value" key is nil (an untyped nil, not a zero string) whenever the
// source's raw timestamp failed to parse, and tstamp must not dereference
// it unconditionally. The field is still present -- Fields() should
// surface the raw string, not omit the field or panic.
func TestDecode_UnparsedTimestamp(t *testing.T) {
	var buf bytes.Buffer
	if err := Encode(&buf, decodeFixtureUnparsedExpires(), Options{}); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	snap, err := Decode(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	got := map[string]Field{}
	for _, f := range snap.Fields() {
		got[f.Key] = f
	}
	f, ok := got[model.FieldExpires]
	if !ok {
		t.Fatal("Expires field missing from Fields(), want present with raw fallback")
	}
	if f.Value != "circa 2030" {
		t.Errorf("Expires = %q, want raw fallback %q", f.Value, "circa 2030")
	}
}

// TestDecode_FieldsOmitsAbsentFields pins the exact number of fields
// decodeFixtureRecord's flattener produces. decodeFixtureRecord populates
// 5 of model.FieldOrder's 13 entries (Domain, Status, Expires,
// Nameservers, DNSSEC); the other 8 (Handle, the five registrar fields,
// Created, Updated) are absent Field[T] zero values with no Sources. A
// regression that starts emitting empty placeholders for absent fields
// instead of omitting them would grow this count silently -- a map
// lookup on only the populated keys (as the round-trip test above does)
// cannot catch that, since it never looks at what else came back.
func TestDecode_FieldsOmitsAbsentFields(t *testing.T) {
	var buf bytes.Buffer
	if err := Encode(&buf, decodeFixtureRecord(), Options{}); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	snap, err := Decode(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	fields := snap.Fields()
	if len(fields) != 5 {
		t.Fatalf("len(Fields()) = %d, want 5 (only Domain, Status, Expires, Nameservers, DNSSEC populated)", len(fields))
	}
	for _, key := range []string{model.FieldHandle, model.FieldRegistrarName, model.FieldCreated, model.FieldUpdated} {
		for _, f := range fields {
			if f.Key == key {
				t.Errorf("Fields() contains absent field %q, want omitted", key)
			}
		}
	}
}
