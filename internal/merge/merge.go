package merge

import (
	"sort"
	"strings"
	"time"

	"github.com/patramsey/plat/internal/model"
)

const clockSkew = 24 * time.Hour

// Merge combines per-source records into one unified, provenance-
// annotated Record. It is a pure function — no I/O — and never errors: a
// source with no usable data simply doesn't contribute to any field.
func Merge(sources []model.SourceRecord) model.Record {
	rec := model.Record{Contacts: map[model.Role]model.Contact{}}
	for _, s := range sources {
		rec.Sources = append(rec.Sources, s.Meta)
	}

	present := presentSorted(sources)
	st := &mergeState{}

	rec.Domain = st.scalar(model.FieldDomain, scalarCandidates(present, model.FieldDomain, func(s model.SourceRecord) string { return s.Domain }))
	rec.Handle = st.scalar(model.FieldHandle, scalarCandidates(present, model.FieldHandle, func(s model.SourceRecord) string { return s.Handle }))
	rec.Registrar.Name = st.scalar(model.FieldRegistrarName, scalarCandidates(present, model.FieldRegistrarName, func(s model.SourceRecord) string { return s.Registrar.Name }))
	rec.Registrar.IANAID = st.scalar(model.FieldRegistrarIANAID, scalarCandidates(present, model.FieldRegistrarIANAID, func(s model.SourceRecord) string { return s.Registrar.IANAID }))
	rec.Registrar.URL = st.scalar(model.FieldRegistrarURL, scalarCandidates(present, model.FieldRegistrarURL, func(s model.SourceRecord) string { return s.Registrar.URL }))
	rec.Registrar.AbuseEmail = st.scalar(model.FieldRegistrarAbuseEmail, scalarCandidates(present, model.FieldRegistrarAbuseEmail, func(s model.SourceRecord) string { return s.Registrar.AbuseEmail }))
	rec.Registrar.AbusePhone = st.scalar(model.FieldRegistrarAbusePhone, scalarCandidates(present, model.FieldRegistrarAbusePhone, func(s model.SourceRecord) string { return s.Registrar.AbusePhone }))

	rec.Created = st.timestamp(model.FieldCreated, timeCandidates(present, func(s model.SourceRecord) model.TimeValue { return s.Created }))
	rec.Updated = st.timestamp(model.FieldUpdated, timeCandidates(present, func(s model.SourceRecord) model.TimeValue { return s.Updated }))
	rec.Expires = st.timestamp(model.FieldExpires, timeCandidates(present, func(s model.SourceRecord) model.TimeValue { return s.Expires }))

	rec.Nameservers = st.nameservers(present)
	rec.Status = st.status(present)
	rec.DNSSEC = st.dnssec(present)

	for _, s := range present {
		st.redactions = append(st.redactions, s.Redactions...)
	}

	rec.Conflicts = st.conflicts
	rec.Redacted = st.redactions
	return rec
}

type mergeState struct {
	conflicts  []model.Conflict
	redactions []model.RedactionNotice
}

func presentSorted(sources []model.SourceRecord) []model.SourceRecord {
	out := make([]model.SourceRecord, 0, len(sources))
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

type scalarCandidate struct {
	Source   model.SourceID
	Value    string
	Redacted bool
}

func scalarCandidates(present []model.SourceRecord, field string, get func(model.SourceRecord) string) []scalarCandidate {
	out := make([]scalarCandidate, len(present))
	for i, s := range present {
		out[i] = scalarCandidate{Source: s.Meta.Source, Value: get(s), Redacted: s.RedactedFields[field]}
	}
	return out
}

// normalizeScalar reduces s to a comparison-only canonical form (lowercase,
// trimmed, no trailing period, commas treated as whitespace) so formatting
// differences across sources — different casing, incidental leading/
// trailing whitespace, a registrar name reported as "Inc" by one source
// and "Inc." by another, a domain or URL with a trailing root-zone dot,
// "Example Corp, Inc." vs "EXAMPLE CORP INC" (the same real-world pattern
// shows up under multiple registrars: MarkMonitor and Name.com both
// report their own name with and without the comma depending on source)
// — don't get reported as a Conflict. Commas are treated as whitespace
// rather than simply deleted so "Foo,Inc" (no space) and "Foo, Inc" (with
// one) normalize identically, and treated separately from the trailing-
// period rule rather than stripping periods everywhere, since an
// internal period can be semantically meaningful (e.g. "Name.com" is a
// real registrar's brand name, not punctuation noise). This never
// affects the VALUE stored on the merged Field: the winning candidate's
// original string (whatever casing/whitespace/punctuation it had) is
// what callers see; normalization only decides whether two candidates
// agree or disagree.
func normalizeScalar(s string) string {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	s = strings.ReplaceAll(s, ",", " ")
	s = strings.Join(strings.Fields(s), " ")
	return strings.ToLower(s)
}

// scalar picks the first present, non-empty, non-redacted candidate (in
// precedence order — cands is already sorted) as the winner. A skipped
// higher-precedence redacted candidate generates a RedactionNotice. Every
// present non-redacted candidate whose value matches the winner (after
// normalizeScalar) joins Field.Sources; a genuinely differing one becomes
// part of a Conflict.
func (m *mergeState) scalar(field string, cands []scalarCandidate) model.Field[string] {
	var winner *scalarCandidate
	for i := range cands {
		c := &cands[i]
		if c.Value == "" {
			continue
		}
		if c.Redacted {
			if winner == nil {
				m.redactions = append(m.redactions, model.RedactionNotice{Field: field, Source: c.Source, Reason: "redacted"})
			}
			continue
		}
		if winner == nil {
			winner = c
		}
	}
	if winner == nil {
		return model.Field[string]{}
	}

	f := model.Field[string]{Value: winner.Value}
	conflictValues := map[model.SourceID]string{}
	hasConflict := false
	for _, c := range cands {
		if c.Value == "" || c.Redacted {
			continue
		}
		if normalizeScalar(c.Value) == normalizeScalar(winner.Value) {
			f.Sources = append(f.Sources, c.Source)
		} else {
			hasConflict = true
			conflictValues[c.Source] = c.Value
		}
	}
	if hasConflict {
		conflictValues[winner.Source] = winner.Value
		m.conflicts = append(m.conflicts, model.Conflict{Field: field, Values: conflictValues})
	}
	return f
}

type timeCandidate struct {
	Source model.SourceID
	model.TimeValue
}

func timeCandidates(present []model.SourceRecord, get func(model.SourceRecord) model.TimeValue) []timeCandidate {
	out := make([]timeCandidate, len(present))
	for i, s := range present {
		out[i] = timeCandidate{Source: s.Meta.Source, TimeValue: get(s)}
	}
	return out
}

// timestamp picks the first present (non-empty Raw) candidate as the
// winner (in precedence order), regardless of whether it parsed. If any
// pair of present+Parsed candidates differ by more than clockSkew, records
// one Conflict listing every present candidate's Raw value.
//
// Expires is a deliberate exception: on a genuine conflict, the winner
// becomes the earliest *parsed* candidate instead of the precedence
// winner. Showing more runway than actually exists is the riskier failure
// mode for an expiration date -- a surprise lapse -- so when sources
// disagree, expires conservatively assumes the sooner date. Every other
// field keeps the precedence winner even when it conflicts, since there's
// no equivalent "safer" direction for e.g. a registrar name or a creation
// date; an earlier Created or Updated isn't more trustworthy, just older.
//
// Sources only includes candidates within clockSkew of the (possibly
// overridden) winner -- matching scalar()'s convention that Sources means
// "agrees with the displayed value", not merely "reported something". A
// candidate whose parsed time genuinely disagrees is excluded and only
// surfaces via the Conflict entry; an unparsed candidate can't be proven
// to disagree, so it stays included.
func (m *mergeState) timestamp(field string, cands []timeCandidate) model.Field[model.TimeValue] {
	var winner *timeCandidate
	for i := range cands {
		if cands[i].Raw == "" {
			continue
		}
		winner = &cands[i]
		break
	}
	if winner == nil {
		return model.Field[model.TimeValue]{}
	}

	var parsed []timeCandidate
	for _, c := range cands {
		if c.Raw != "" && c.Parsed {
			parsed = append(parsed, c)
		}
	}
	conflictFound := false
	for i := 0; i < len(parsed); i++ {
		for j := i + 1; j < len(parsed); j++ {
			d := parsed[i].Time.Sub(parsed[j].Time)
			if d < 0 {
				d = -d
			}
			if d > clockSkew {
				conflictFound = true
			}
		}
	}
	if conflictFound {
		values := map[model.SourceID]string{}
		for _, c := range cands {
			if c.Raw != "" {
				values[c.Source] = c.Raw
			}
		}
		m.conflicts = append(m.conflicts, model.Conflict{Field: field, Values: values})

		if field == model.FieldExpires {
			earliest := parsed[0]
			for _, c := range parsed[1:] {
				if c.Time.Before(earliest.Time) {
					earliest = c
				}
			}
			winner = &earliest
		}
	}

	f := model.Field[model.TimeValue]{Value: winner.TimeValue}
	for _, c := range cands {
		if c.Raw == "" {
			continue
		}
		if winner.Parsed && c.Parsed {
			d := c.Time.Sub(winner.Time)
			if d < 0 {
				d = -d
			}
			if d > clockSkew {
				continue
			}
		}
		f.Sources = append(f.Sources, c.Source)
	}
	return f
}

func normalizeNS(ns string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(ns), "."))
}

// nameservers computes the union of normalized nameserver names across all
// present sources. A Conflict is recorded if two present sources' sets
// (after normalization) are unequal — the merged value stays the union
// either way, since a nameserver a lower-precedence source didn't mention
// isn't necessarily wrong, just possibly stale or incomplete there.
//
// Sources lists only the sources whose own (normalized) set exactly equals
// the merged union — matching scalar()'s convention that a field's Sources
// badge means "sources that agree with the displayed value", not merely
// "sources that contributed something". A source reporting a strict subset
// (e.g. a registry lagging behind a recent NS change) disagrees with the
// union and is surfaced only via the Conflict entry, never counted as
// agreeing. If no single source's set equals the full union (a genuine
// three-way fork with no complete picture anywhere), Sources is left empty
// rather than falsely crediting every contributor with full agreement --
// the renderers key showing the row on len(Value) rather than Present(),
// specifically to keep this case from making the row (not just its badge)
// disappear.
func (m *mergeState) nameservers(present []model.SourceRecord) model.Field[[]string] {
	unionSeen := map[string]bool{}
	var order []string
	var sourceOrder []model.SourceID
	sourceSets := map[model.SourceID]map[string]bool{}

	for _, s := range present {
		if len(s.Nameservers) == 0 {
			continue
		}
		sourceOrder = append(sourceOrder, s.Meta.Source)
		set := map[string]bool{}
		for _, ns := range s.Nameservers {
			n := normalizeNS(ns)
			set[n] = true
			if !unionSeen[n] {
				unionSeen[n] = true
				order = append(order, n)
			}
		}
		sourceSets[s.Meta.Source] = set
	}

	if len(sourceOrder) == 0 {
		return model.Field[[]string]{}
	}

	conflictFound := false
	for i := 0; i < len(sourceOrder); i++ {
		for j := i + 1; j < len(sourceOrder); j++ {
			if !setsEqual(sourceSets[sourceOrder[i]], sourceSets[sourceOrder[j]]) {
				conflictFound = true
			}
		}
	}
	if conflictFound {
		values := map[model.SourceID]string{}
		for src, set := range sourceSets {
			values[src] = strings.Join(sortedKeys(set), ", ")
		}
		m.conflicts = append(m.conflicts, model.Conflict{Field: model.FieldNameservers, Values: values})
	}

	var agreeing []model.SourceID
	for _, src := range sourceOrder {
		if setsEqual(sourceSets[src], unionSeen) {
			agreeing = append(agreeing, src)
		}
	}

	return model.Field[[]string]{Value: order, Sources: agreeing}
}

func setsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// status unions the (already EPP-normalized by the adapter) status codes
// across all present sources. Differing status sets are NOT treated as a
// Conflict — thick vs. thin registries legitimately report different
// status vocabularies for the same domain, so a set difference here isn't
// evidence of disagreement the way a differing nameserver or expiry is.
func (m *mergeState) status(present []model.SourceRecord) model.Field[[]string] {
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

// dnssec picks the first present source that expressed an opinion
// (DNSSEC != nil), by precedence. Present-and-differing sources are
// treated as a Conflict, same as any other scalar.
func (m *mergeState) dnssec(present []model.SourceRecord) model.Field[bool] {
	var winner *model.SourceRecord
	for i := range present {
		if present[i].DNSSEC != nil {
			winner = &present[i]
			break
		}
	}
	if winner == nil {
		return model.Field[bool]{}
	}
	f := model.Field[bool]{Value: *winner.DNSSEC}
	conflictValues := map[model.SourceID]string{}
	hasConflict := false
	for _, s := range present {
		if s.DNSSEC == nil {
			continue
		}
		if *s.DNSSEC == *winner.DNSSEC {
			f.Sources = append(f.Sources, s.Meta.Source)
		} else {
			hasConflict = true
			conflictValues[s.Meta.Source] = boolStr(*s.DNSSEC)
		}
	}
	if hasConflict {
		conflictValues[winner.Meta.Source] = boolStr(*winner.DNSSEC)
		m.conflicts = append(m.conflicts, model.Conflict{Field: model.FieldDNSSEC, Values: conflictValues})
	}
	return f
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
