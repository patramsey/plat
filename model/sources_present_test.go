package model

import (
	"reflect"
	"testing"
	"time"
)

func TestPresentSourcesUnionsFieldsAndConflicts(t *testing.T) {
	r := Record{
		Domain:      Field[string]{Value: "example.com", Sources: []SourceID{SourceRegistryRDAP}},
		Nameservers: Field[[]string]{Value: []string{"a.iana-servers.net"}, Sources: []SourceID{SourceRegistryWHOIS}},
		Conflicts: []Conflict{{
			Field:  "updated",
			Values: map[SourceID]string{SourceRegistrarRDAP: "a", SourceRegistryWHOIS: "b"},
		}},
	}
	got := PresentSources(r)
	want := []SourceID{SourceRegistrarRDAP, SourceRegistryRDAP, SourceRegistryWHOIS}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PresentSources = %v, want %v (Precedence order, deduplicated)", got, want)
	}
}

func TestPresentSourcesEmptyRecord(t *testing.T) {
	if got := PresentSources(Record{}); len(got) != 0 {
		t.Errorf("PresentSources(empty) = %v, want empty", got)
	}
}

func TestPresentSourcesIPAndASN(t *testing.T) {
	ip := IPRecord{
		CIDR: Field[string]{Value: "8.8.8.0/24", Sources: []SourceID{SourceRegistryWHOIS}},
		Org:  OrgInfo{Name: Field[string]{Value: "Google LLC", Sources: []SourceID{SourceRegistryRDAP}}},
	}
	if got, want := PresentSourcesIP(ip), []SourceID{SourceRegistryRDAP, SourceRegistryWHOIS}; !reflect.DeepEqual(got, want) {
		t.Errorf("PresentSourcesIP = %v, want %v", got, want)
	}

	asn := ASNRecord{
		Handle: Field[string]{Value: "AS15169", Sources: []SourceID{SourceRegistryRDAP}},
	}
	if got, want := PresentSourcesASN(asn), []SourceID{SourceRegistryRDAP}; !reflect.DeepEqual(got, want) {
		t.Errorf("PresentSourcesASN = %v, want %v", got, want)
	}
}

// TestPresentSourcesCoversEveryField is the guard that makes the explicit
// unions above safe to maintain. It walks each record type for every
// Field[T] it contains (recursing into embedded structs like
// RegistrarInfo and OrgInfo), sets that one field's Sources to a marker,
// and asserts the marker comes back. A field added to the struct and to
// FieldOrder but forgotten in PresentSources* fails here rather than
// silently rendering a badge the legend cannot decode.
func TestPresentSourcesCoversEveryField(t *testing.T) {
	const marker = SourceID("marker-source")

	for _, tc := range []struct {
		name string
		zero any
		call func(any) []SourceID
	}{
		{"Record", Record{}, func(v any) []SourceID { return PresentSources(v.(Record)) }},
		{"IPRecord", IPRecord{}, func(v any) []SourceID { return PresentSourcesIP(v.(IPRecord)) }},
		{"ASNRecord", ASNRecord{}, func(v any) []SourceID { return PresentSourcesASN(v.(ASNRecord)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths := sourcesFieldPaths(reflect.TypeOf(tc.zero), nil)
			if len(paths) == 0 {
				t.Fatalf("found no Field[T] paths in %s -- the walker is broken, not the code under test", tc.name)
			}
			for _, path := range paths {
				rec := reflect.New(reflect.TypeOf(tc.zero)).Elem()
				target := rec
				for _, i := range path {
					target = target.Field(i)
				}
				target.Set(reflect.ValueOf([]SourceID{marker}))

				found := false
				for _, s := range tc.call(rec.Interface()) {
					if s == marker {
						found = true
					}
				}
				if !found {
					t.Errorf("%s: field path %v is rendered but not covered by PresentSources*; its badge would have no legend entry",
						tc.name, fieldPathName(reflect.TypeOf(tc.zero), path))
				}
			}
		})
	}
}

// sourcesFieldPaths returns the index path to every `Sources []SourceID`
// slice reachable from t through exported struct fields, recursing one
// level into nested structs (RegistrarInfo, OrgInfo) but not into slices,
// maps, or pointers -- Conflicts and Redacted carry their own handling in
// PresentSources* and are covered by the union test above.
func sourcesFieldPaths(t reflect.Type, prefix []int) [][]int {
	var out [][]int
	sourceSliceType := reflect.TypeOf([]SourceID(nil))
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		path := append(append([]int{}, prefix...), i)
		switch {
		case f.Type == sourceSliceType && f.Name == "Sources":
			out = append(out, path)
		case f.Type.Kind() == reflect.Struct && f.Type != reflect.TypeOf(time.Time{}):
			out = append(out, sourcesFieldPaths(f.Type, path)...)
		}
	}
	return out
}

func fieldPathName(t reflect.Type, path []int) string {
	name := ""
	cur := t
	for _, i := range path {
		f := cur.Field(i)
		if name != "" {
			name += "."
		}
		name += f.Name
		cur = f.Type
	}
	return name
}
