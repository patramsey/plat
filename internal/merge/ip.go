package merge

import (
	"github.com/patramsey/plat/internal/model"
)

// MergeIP combines per-source IP records into one unified,
// provenance-annotated IPRecord. Like Merge, it is a pure function, never
// errors, and treats a source contributing nothing as normal. Precedence
// collapses to registry-rdap -> registry-whois: an IP allocation has no
// registrar, so the two registrar SourceIDs never occur.
func MergeIP(sources []model.IPSourceRecord) model.IPRecord {
	var rec model.IPRecord
	for _, s := range sources {
		rec.Sources = append(rec.Sources, s.Meta)
	}

	present := presentSorted(sources)
	st := &mergeState{}

	str := func(field string, get func(model.IPSourceRecord) string) model.Field[string] {
		cands := make([]scalarCandidate, len(present))
		for i, s := range present {
			cands[i] = scalarCandidate{Source: s.Meta.Source, Value: get(s), Redacted: s.RedactedFields[field]}
		}
		return st.scalar(field, cands)
	}

	rec.Handle = str(model.FieldIPHandle, func(s model.IPSourceRecord) string { return s.Handle })
	rec.Name = str(model.FieldIPName, func(s model.IPSourceRecord) string { return s.Name })
	rec.Type = str(model.FieldIPType, func(s model.IPSourceRecord) string { return s.Type })
	rec.StartAddress = str(model.FieldIPStartAddress, func(s model.IPSourceRecord) string { return s.StartAddress })
	rec.EndAddress = str(model.FieldIPEndAddress, func(s model.IPSourceRecord) string { return s.EndAddress })
	rec.CIDR = str(model.FieldIPCIDR, func(s model.IPSourceRecord) string { return s.CIDR })
	rec.IPVersion = str(model.FieldIPVersion, func(s model.IPSourceRecord) string { return s.IPVersion })
	rec.ParentHandle = str(model.FieldIPParent, func(s model.IPSourceRecord) string { return s.ParentHandle })
	rec.Country = str(model.FieldIPCountry, func(s model.IPSourceRecord) string { return s.Country })
	rec.Org.Name = str(model.FieldOrgName, func(s model.IPSourceRecord) string { return s.OrgName })
	rec.Org.ID = str(model.FieldOrgID, func(s model.IPSourceRecord) string { return s.OrgID })
	rec.Org.AbuseEmail = str(model.FieldOrgAbuseEmail, func(s model.IPSourceRecord) string { return s.AbuseEmail })
	rec.Org.AbusePhone = str(model.FieldOrgAbusePhone, func(s model.IPSourceRecord) string { return s.AbusePhone })

	regCands := make([]timeCandidate, len(present))
	updCands := make([]timeCandidate, len(present))
	for i, s := range present {
		regCands[i] = timeCandidate{Source: s.Meta.Source, TimeValue: s.Registered}
		updCands[i] = timeCandidate{Source: s.Meta.Source, TimeValue: s.Updated}
	}
	rec.Registered = st.timestamp(model.FieldIPRegistered, regCands)
	rec.Updated = st.timestamp(model.FieldIPUpdated, updCands)

	rec.Status = statusUnion(present)

	for _, s := range present {
		st.redactions = append(st.redactions, s.Redactions...)
	}
	rec.Conflicts = st.conflicts
	rec.Redacted = st.redactions
	return rec
}
