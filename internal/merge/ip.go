package merge

import "github.com/patramsey/plat/internal/model"

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

	present := presentSortedIP(sources)
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

	rec.Status = ipStatus(present)

	for _, s := range present {
		st.redactions = append(st.redactions, s.Redactions...)
	}
	rec.Conflicts = st.conflicts
	rec.Redacted = st.redactions
	return rec
}

func presentSortedIP(sources []model.IPSourceRecord) []model.IPSourceRecord {
	out := make([]model.IPSourceRecord, 0, len(sources))
	for _, s := range sources {
		if s.Present {
			out = append(out, s)
		}
	}
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && model.Rank(out[j-1].Meta.Source) > model.Rank(out[j].Meta.Source) {
			out[j-1], out[j] = out[j], out[j-1]
			j--
		}
	}
	return out
}

// ipStatus unions status values across sources, mirroring the domain
// status() helper's union-not-conflict policy.
func ipStatus(present []model.IPSourceRecord) model.Field[[]string] {
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
	return model.Field[[]string]{Value: order, Sources: contributors}
}
