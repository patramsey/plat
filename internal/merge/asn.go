package merge

import (
	"sort"

	"github.com/patramsey/plat/internal/model"
)

// MergeASN combines per-source ASN records into one unified,
// provenance-annotated ASNRecord. Like MergeIP, it is a pure function,
// never errors, and treats a source contributing nothing as normal.
// Precedence collapses to registry-rdap -> registry-whois: an ASN has no
// registrar, so the two registrar SourceIDs never occur.
func MergeASN(sources []model.ASNSourceRecord) model.ASNRecord {
	var rec model.ASNRecord
	for _, s := range sources {
		rec.Sources = append(rec.Sources, s.Meta)
	}

	present := presentSorted(sources)
	st := &mergeState{}

	str := func(field string, get func(model.ASNSourceRecord) string) model.Field[string] {
		cands := make([]scalarCandidate, len(present))
		for i, s := range present {
			cands[i] = scalarCandidate{Source: s.Meta.Source, Value: get(s), Redacted: s.RedactedFields[field]}
		}
		return st.scalar(field, cands)
	}

	rec.Handle = str(model.FieldASNHandle, func(s model.ASNSourceRecord) string { return s.Handle })
	rec.Name = str(model.FieldASNName, func(s model.ASNSourceRecord) string { return s.Name })
	rec.Type = str(model.FieldASNType, func(s model.ASNSourceRecord) string { return s.Type })
	rec.StartAutnum = str(model.FieldASNStartAutnum, func(s model.ASNSourceRecord) string { return s.StartAutnum })
	rec.EndAutnum = str(model.FieldASNEndAutnum, func(s model.ASNSourceRecord) string { return s.EndAutnum })
	rec.Country = str(model.FieldASNCountry, func(s model.ASNSourceRecord) string { return s.Country })
	rec.Org.Name = str(model.FieldOrgName, func(s model.ASNSourceRecord) string { return s.OrgName })
	rec.Org.ID = str(model.FieldOrgID, func(s model.ASNSourceRecord) string { return s.OrgID })
	rec.Org.AbuseEmail = str(model.FieldOrgAbuseEmail, func(s model.ASNSourceRecord) string { return s.AbuseEmail })
	rec.Org.AbusePhone = str(model.FieldOrgAbusePhone, func(s model.ASNSourceRecord) string { return s.AbusePhone })

	regCands := make([]timeCandidate, len(present))
	updCands := make([]timeCandidate, len(present))
	for i, s := range present {
		regCands[i] = timeCandidate{Source: s.Meta.Source, TimeValue: s.Registered}
		updCands[i] = timeCandidate{Source: s.Meta.Source, TimeValue: s.Updated}
	}
	rec.Registered = st.timestamp(model.FieldASNRegistered, regCands)
	rec.Updated = st.timestamp(model.FieldASNUpdated, updCands)

	rec.Status = asnStatus(present)

	for _, s := range present {
		st.redactions = append(st.redactions, s.Redactions...)
	}
	rec.Conflicts = st.conflicts
	rec.Redacted = st.redactions
	return rec
}

// asnStatus unions status values across sources, mirroring the domain
// status() helper's union-not-conflict policy (and ipStatus's identical
// reasoning for IP networks).
func asnStatus(present []model.ASNSourceRecord) model.Field[[]string] {
	seen := map[string]bool{}
	var order []string
	var contributors []model.SourceID
	for _, s := range present {
		if len(s.Status) == 0 {
			continue
		}
		contributors = append(contributors, s.Meta.Source)
		for _, st := range s.Status {
			if st == "" || seen[st] {
				continue
			}
			seen[st] = true
			order = append(order, st)
		}
	}
	if len(contributors) == 0 {
		return model.Field[[]string]{}
	}
	// Sorted last for the same reason as domain status() in merge.go:
	// deterministic output regardless of upstream ordering.
	sort.Strings(order)
	return model.Field[[]string]{Value: order, Sources: contributors}
}
