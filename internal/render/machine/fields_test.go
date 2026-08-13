package machine

import (
	"bytes"
	"testing"

	"github.com/patramsey/plat/internal/model"
)

// TestDecode_IPFields_EmptyRecord decodes a wholly empty IPRecord and
// checks Fields() comes back empty. fullIPRecord (ip_test.go) already
// exercises every ipFields case's "value present" branch; nothing
// exercised the "value absent -> continue" branch each case also has,
// including orgScalar's o==nil guard (buildOrgView returns nil when all
// four Org sub-fields are absent, which is exactly this record's shape).
func TestDecode_IPFields_EmptyRecord(t *testing.T) {
	var buf bytes.Buffer
	if err := EncodeIP(&buf, model.IPRecord{}, Options{}); err != nil {
		t.Fatalf("EncodeIP: %v", err)
	}
	snap, err := Decode(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	fields := snap.Fields()
	if len(fields) != 0 {
		t.Errorf("Fields() = %+v, want empty (every field absent)", fields)
	}
}

// TestDecode_IPFields_PartialRecord covers ipFields' branches that
// fullIPRecord's every-field-populated fixture can't reach: the Range
// field's "no EndAddress" fallback (start alone, no " - end" suffix),
// and orgScalar's non-nil-Org-but-one-field-absent path (Org present via
// Name, but ID/AbuseEmail/AbusePhone are each individually absent).
func TestDecode_IPFields_PartialRecord(t *testing.T) {
	rec := model.IPRecord{
		StartAddress: model.Field[string]{Value: "8.8.8.0", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Org: model.OrgInfo{
			Name: model.Field[string]{Value: "Google LLC", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
		},
		Sources: []model.SourceResult{{Source: model.SourceRegistryRDAP, OK: true}},
	}
	var buf bytes.Buffer
	if err := EncodeIP(&buf, rec, Options{}); err != nil {
		t.Fatalf("EncodeIP: %v", err)
	}
	snap, err := Decode(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	got := map[string]Field{}
	for _, f := range snap.Fields() {
		got[f.Key] = f
	}

	if f, ok := got[model.FieldIPStartAddress]; !ok || f.Value != "8.8.8.0" {
		t.Errorf("Range = %+v, want value 8.8.8.0 with no end-address suffix", f)
	}
	if f, ok := got[model.FieldOrgName]; !ok || f.Value != "Google LLC" {
		t.Errorf("Org name = %+v, want Google LLC", f)
	}
	for _, key := range []string{model.FieldOrgID, model.FieldOrgAbuseEmail, model.FieldOrgAbusePhone} {
		if _, ok := got[key]; ok {
			t.Errorf("Fields() contains %q, want absent (Org present but that sub-field is not)", key)
		}
	}
	for _, key := range []string{model.FieldIPHandle, model.FieldIPName, model.FieldIPType, model.FieldIPCIDR, model.FieldIPVersion, model.FieldIPParent, model.FieldIPCountry, model.FieldIPStatus, model.FieldIPRegistered, model.FieldIPUpdated} {
		if _, ok := got[key]; ok {
			t.Errorf("Fields() contains %q, want absent", key)
		}
	}
}

// TestDecode_ASNFields_EmptyRecord is TestDecode_IPFields_EmptyRecord's
// ASN counterpart.
func TestDecode_ASNFields_EmptyRecord(t *testing.T) {
	var buf bytes.Buffer
	if err := EncodeASN(&buf, model.ASNRecord{}, Options{}); err != nil {
		t.Fatalf("EncodeASN: %v", err)
	}
	snap, err := Decode(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	fields := snap.Fields()
	if len(fields) != 0 {
		t.Errorf("Fields() = %+v, want empty (every field absent)", fields)
	}
}

// TestDecode_ASNFields_PartialRecord is TestDecode_IPFields_PartialRecord's
// ASN counterpart: the Range field's "no EndAutnum" fallback, and
// orgScalar's non-nil-Org-but-one-field-absent path.
func TestDecode_ASNFields_PartialRecord(t *testing.T) {
	rec := model.ASNRecord{
		StartAutnum: model.Field[string]{Value: "15169", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Org: model.OrgInfo{
			Name: model.Field[string]{Value: "Google LLC", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
		},
		Sources: []model.SourceResult{{Source: model.SourceRegistryRDAP, OK: true}},
	}
	var buf bytes.Buffer
	if err := EncodeASN(&buf, rec, Options{}); err != nil {
		t.Fatalf("EncodeASN: %v", err)
	}
	snap, err := Decode(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	got := map[string]Field{}
	for _, f := range snap.Fields() {
		got[f.Key] = f
	}

	if f, ok := got[model.FieldASNStartAutnum]; !ok || f.Value != "15169" {
		t.Errorf("Range = %+v, want value 15169 with no end-autnum suffix", f)
	}
	if f, ok := got[model.FieldOrgName]; !ok || f.Value != "Google LLC" {
		t.Errorf("Org name = %+v, want Google LLC", f)
	}
	for _, key := range []string{model.FieldOrgID, model.FieldOrgAbuseEmail, model.FieldOrgAbusePhone} {
		if _, ok := got[key]; ok {
			t.Errorf("Fields() contains %q, want absent (Org present but that sub-field is not)", key)
		}
	}
	for _, key := range []string{model.FieldASNHandle, model.FieldASNName, model.FieldASNType, model.FieldASNCountry, model.FieldASNStatus, model.FieldASNRegistered, model.FieldASNUpdated} {
		if _, ok := got[key]; ok {
			t.Errorf("Fields() contains %q, want absent", key)
		}
	}
}
