package merge

import (
	"github.com/patramsey/plat/internal/source"
	"github.com/patramsey/plat/model"
)

// MergeASN combines per-source ASN records into one unified,
// provenance-annotated ASNRecord. Like MergeIP, it is a pure function,
// never errors, and treats a source contributing nothing as normal.
// Precedence collapses to registry-rdap -> registry-whois: an ASN has no
// registrar, so the two registrar SourceIDs never occur.
func MergeASN(sources []source.ASNSourceRecord) model.ASNRecord {
	var rec model.ASNRecord
	for _, s := range sources {
		rec.Sources = append(rec.Sources, s.Meta)
	}

	present := presentSorted(sources)
	st := &mergeState{}

	str := func(field string, get func(source.ASNSourceRecord) string) model.Field[string] {
		cands := make([]scalarCandidate, len(present))
		for i, s := range present {
			cands[i] = scalarCandidate{Source: s.Meta.Source, Value: get(s), Redacted: s.RedactedFields[field]}
		}
		return st.scalar(field, cands)
	}

	rec.Handle = str(model.FieldASNHandle, func(s source.ASNSourceRecord) string { return s.Handle })
	rec.Name = str(model.FieldASNName, func(s source.ASNSourceRecord) string { return s.Name })
	rec.Type = str(model.FieldASNType, func(s source.ASNSourceRecord) string { return s.Type })
	rec.StartAutnum = str(model.FieldASNStartAutnum, func(s source.ASNSourceRecord) string { return s.StartAutnum })
	rec.EndAutnum = str(model.FieldASNEndAutnum, func(s source.ASNSourceRecord) string { return s.EndAutnum })
	rec.Country = str(model.FieldASNCountry, func(s source.ASNSourceRecord) string { return s.Country })
	rec.Org.Name = str(model.FieldOrgName, func(s source.ASNSourceRecord) string { return s.OrgName })
	rec.Org.ID = str(model.FieldOrgID, func(s source.ASNSourceRecord) string { return s.OrgID })
	rec.Org.AbuseEmail = str(model.FieldOrgAbuseEmail, func(s source.ASNSourceRecord) string { return s.AbuseEmail })
	rec.Org.AbusePhone = str(model.FieldOrgAbusePhone, func(s source.ASNSourceRecord) string { return s.AbusePhone })

	regCands := make([]timeCandidate, len(present))
	updCands := make([]timeCandidate, len(present))
	for i, s := range present {
		regCands[i] = timeCandidate{Source: s.Meta.Source, TimeValue: s.Registered}
		updCands[i] = timeCandidate{Source: s.Meta.Source, TimeValue: s.Updated}
	}
	rec.Registered = st.timestamp(model.FieldASNRegistered, regCands)
	rec.Updated = st.timestamp(model.FieldASNUpdated, updCands)

	rec.Status = statusUnion(present)

	for _, s := range present {
		st.redactions = append(st.redactions, s.Redactions...)
	}
	rec.Conflicts = st.conflicts
	rec.Redacted = st.redactions
	return rec
}
