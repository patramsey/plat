package merge

import (
	"slices"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/model"
)

func asnsr(source model.SourceID, present bool) model.ASNSourceRecord {
	return model.ASNSourceRecord{
		Meta:           model.SourceResult{Source: source, OK: present},
		Present:        present,
		RedactedFields: map[string]bool{},
	}
}

func TestMergeASN_CombinesRDAPAndWHOIS(t *testing.T) {
	registered, _ := time.Parse(time.RFC3339, "2000-03-30T00:00:00Z")

	rdapSrc := asnsr(model.SourceRegistryRDAP, true)
	rdapSrc.Handle = "AS15169"
	rdapSrc.Name = "GOOGLE"
	rdapSrc.StartAutnum = "15169"
	rdapSrc.EndAutnum = "15169"
	rdapSrc.Registered = model.TimeValue{Time: registered, Raw: "2000-03-30T00:00:00Z", Parsed: true}

	whoisSrc := asnsr(model.SourceRegistryWHOIS, true)
	whoisSrc.Handle = "AS15169"
	whoisSrc.OrgName = "Google LLC" // richer than RDAP's "GOOGLE"
	whoisSrc.Country = "US"

	rec := MergeASN([]model.ASNSourceRecord{rdapSrc, whoisSrc})

	if rec.Handle.Value != "AS15169" {
		t.Errorf("Handle = %q, want AS15169", rec.Handle.Value)
	}
	if len(rec.Handle.Sources) != 2 {
		t.Errorf("Handle.Sources = %v, want both sources agreeing", rec.Handle.Sources)
	}
	if rec.Org.Name.Value != "Google LLC" {
		t.Errorf("Org.Name = %q, want the WHOIS-only value", rec.Org.Name.Value)
	}
	if rec.StartAutnum.Value != "15169" {
		t.Errorf("StartAutnum = %q, want the RDAP-only value", rec.StartAutnum.Value)
	}
	if !rec.Registered.Present() || !rec.Registered.Value.Parsed {
		t.Error("Registered not present/parsed, want the RDAP timestamp")
	}
}

func TestMergeASN_RDAPWinsOnConflict(t *testing.T) {
	a := asnsr(model.SourceRegistryRDAP, true)
	a.Name = "GOOGLE"
	b := asnsr(model.SourceRegistryWHOIS, true)
	b.Name = "SOMETHING-ELSE"

	rec := MergeASN([]model.ASNSourceRecord{b, a}) // deliberately out of order

	if rec.Name.Value != "GOOGLE" {
		t.Errorf("Name = %q, want the registry-rdap value (higher precedence)", rec.Name.Value)
	}
	found := false
	for _, c := range rec.Conflicts {
		if c.Field == model.FieldASNName {
			found = true
		}
	}
	if !found {
		t.Error("no Conflict recorded for the disagreeing name")
	}
}

// TestMergeASN_StatusIsSortedRegardlessOfInputOrder covers issue #49's
// deterministic-ordering fix for statusUnion's union, which shares the
// identical append-union shape as domain nameservers/status.
func TestMergeASN_StatusIsSortedRegardlessOfInputOrder(t *testing.T) {
	want := []string{"active", "allocated", "reassigned"}

	orderings := [][]string{
		{"reassigned", "active", "allocated"},
		{"allocated", "reassigned", "active"},
		{"active", "allocated", "reassigned"},
	}

	for i, st := range orderings {
		a := asnsr(model.SourceRegistryRDAP, true)
		a.Status = st
		b := asnsr(model.SourceRegistryWHOIS, true)
		b.Status = st

		rec := MergeASN([]model.ASNSourceRecord{a, b})

		if !slices.Equal(rec.Status.Value, want) {
			t.Errorf("ordering %d: Status.Value = %v, want sorted %v", i, rec.Status.Value, want)
		}
	}
}

func TestMergeASN_ZeroSources(t *testing.T) {
	rec := MergeASN(nil)
	if rec.Handle.Present() || rec.Name.Present() {
		t.Errorf("expected an empty ASNRecord from zero sources, got %+v", rec)
	}
}
