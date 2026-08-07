package merge

import (
	"testing"
	"time"

	"github.com/patramsey/plat/internal/model"
)

func ipsr(source model.SourceID, present bool) model.IPSourceRecord {
	return model.IPSourceRecord{
		Meta:           model.SourceResult{Source: source, OK: present},
		Present:        present,
		RedactedFields: map[string]bool{},
	}
}

func TestMergeIP_CombinesRDAPAndWHOIS(t *testing.T) {
	registered, _ := time.Parse(time.RFC3339, "2023-12-28T22:24:33Z")

	rdapSrc := ipsr(model.SourceRegistryRDAP, true)
	rdapSrc.Handle = "NET-8-8-8-0-2"
	rdapSrc.Name = "GOGL"
	rdapSrc.CIDR = "8.8.8.0/24"
	rdapSrc.Registered = model.TimeValue{Time: registered, Raw: "2023-12-28T17:24:33-05:00", Parsed: true}

	whoisSrc := ipsr(model.SourceRegistryWHOIS, true)
	whoisSrc.Handle = "NET-8-8-8-0-2"
	whoisSrc.OrgName = "Google LLC" // richer than RDAP's "GOGL"
	whoisSrc.Country = "US"

	rec := MergeIP([]model.IPSourceRecord{rdapSrc, whoisSrc})

	if rec.Handle.Value != "NET-8-8-8-0-2" {
		t.Errorf("Handle = %q, want NET-8-8-8-0-2", rec.Handle.Value)
	}
	if len(rec.Handle.Sources) != 2 {
		t.Errorf("Handle.Sources = %v, want both sources agreeing", rec.Handle.Sources)
	}
	if rec.Org.Name.Value != "Google LLC" {
		t.Errorf("Org.Name = %q, want the WHOIS-only value", rec.Org.Name.Value)
	}
	if rec.CIDR.Value != "8.8.8.0/24" {
		t.Errorf("CIDR = %q, want the RDAP-only value", rec.CIDR.Value)
	}
	if !rec.Registered.Present() || !rec.Registered.Value.Parsed {
		t.Error("Registered not present/parsed, want the RDAP timestamp")
	}
}

func TestMergeIP_RDAPWinsOnConflict(t *testing.T) {
	a := ipsr(model.SourceRegistryRDAP, true)
	a.Name = "GOGL"
	b := ipsr(model.SourceRegistryWHOIS, true)
	b.Name = "SOMETHING-ELSE"

	rec := MergeIP([]model.IPSourceRecord{b, a}) // deliberately out of order

	if rec.Name.Value != "GOGL" {
		t.Errorf("Name = %q, want the registry-rdap value (higher precedence)", rec.Name.Value)
	}
	found := false
	for _, c := range rec.Conflicts {
		if c.Field == model.FieldIPName {
			found = true
		}
	}
	if !found {
		t.Error("no Conflict recorded for the disagreeing name")
	}
}

func TestMergeIP_ZeroSources(t *testing.T) {
	rec := MergeIP(nil)
	if rec.Handle.Present() || rec.Name.Present() {
		t.Errorf("expected an empty IPRecord from zero sources, got %+v", rec)
	}
}
