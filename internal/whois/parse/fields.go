package parse

// CommonFields holds the WHOIS fields every registry object type carries
// regardless of whether it names a netblock or an autonomous system: who
// holds it, how to reach them, when it changed. Embedded by IPFields and
// ASNFields so the vocabulary mapping to these fields is defined exactly
// once -- three shipped bugs came from maintaining it twice (a `status`
// entry present in one lookup table and absent from its twin, and
// LACNIC's owner/ownerid/changed keys fixed in asn.go but not ip.go).
type CommonFields struct {
	Handle     string
	OrgName    string
	OrgID      string
	Country    string
	Registered string
	Updated    string
	AbuseEmail string
	AbusePhone string
	Statuses   []string

	// descr holds RPSL's free-text `descr:` line, kept separate from
	// OrgName rather than folded into it. In RPSL responses a block's
	// `descr:` (a description of the resource) can precede the
	// organisation block's `org-name:` (the actual org identity), so
	// first-occurrence-wins would let descr permanently shadow org-name.
	// Both parsers fall back to descr for OrgName only when no explicit
	// name key ever appeared, after the scan completes.
	descr string
}

// fieldRef pairs a field's setter with its getter so first-occurrence-wins
// can be enforced without reflection. One entry per key: the previous
// design used two parallel maps that had to be edited in lockstep, and
// they drifted -- "status" ended up in one and not the other, truncating
// legitimate statuses while letting foreign ones leak in.
type fieldRef[T any] struct {
	set func(*T, string)
	get func(*T) string
}

// commonFields is the WHOIS vocabulary shared by every registry object
// type. Declared once and lifted into each concrete parser's table (via
// liftCommon/buildFields below), so a shared key cannot be defined for one
// object type and forgotten for the other -- exactly the failure that left
// LACNIC's owner/ownerid/changed keys mapped in asn.go but not ip.go,
// silently single-sourcing every LACNIC IP lookup through v0.3.0.
var commonFields = map[string]fieldRef[CommonFields]{
	"orgname": {set: func(f *CommonFields, v string) { f.OrgName = v }, get: func(f *CommonFields) string { return f.OrgName }},
	// "org-name" is AFRINIC's own vocabulary: its inetnum/aut-num's bare
	// "org:" line points at a separate "organisation:" object, which
	// carries "org-name:" for the actual identity string.
	"org-name": {set: func(f *CommonFields, v string) { f.OrgName = v }, get: func(f *CommonFields) string { return f.OrgName }},
	// "owner" is LACNIC's RPSL vocabulary for the object holder's name --
	// LACNIC does not use "orgname"/"org-name"/"descr" for this at all, so
	// without this entry LACNIC WHOIS contributed no org identity
	// whatsoever (confirmed live against 200.3.12.1 and AS28573). Ranked
	// alongside orgname/org-name (a direct, first-occurrence-wins
	// assignment to OrgName) rather than routed through the descr fallback
	// below: descr is only ever consulted after the full scan, when
	// OrgName is still empty, so owner inherently outranks it exactly as
	// orgname/org-name already do.
	"owner": {set: func(f *CommonFields, v string) { f.OrgName = v }, get: func(f *CommonFields) string { return f.OrgName }},
	"descr": {set: func(f *CommonFields, v string) { f.descr = v }, get: func(f *CommonFields) string { return f.descr }},
	"orgid": {set: func(f *CommonFields, v string) { f.OrgID = v }, get: func(f *CommonFields) string { return f.OrgID }},
	"org":   {set: func(f *CommonFields, v string) { f.OrgID = v }, get: func(f *CommonFields) string { return f.OrgID }},
	// "ownerid" is LACNIC's RPSL vocabulary for the registry-assigned
	// holder ID (e.g. "UY-LACN-LACNIC") -- distinct from "orgid"/"org",
	// which LACNIC's inetnum/aut-num response never emits.
	"ownerid":       {set: func(f *CommonFields, v string) { f.OrgID = v }, get: func(f *CommonFields) string { return f.OrgID }},
	"country":       {set: func(f *CommonFields, v string) { f.Country = v }, get: func(f *CommonFields) string { return f.Country }},
	"regdate":       {set: func(f *CommonFields, v string) { f.Registered = v }, get: func(f *CommonFields) string { return f.Registered }},
	"created":       {set: func(f *CommonFields, v string) { f.Registered = v }, get: func(f *CommonFields) string { return f.Registered }},
	"updated":       {set: func(f *CommonFields, v string) { f.Updated = v }, get: func(f *CommonFields) string { return f.Updated }},
	"last-modified": {set: func(f *CommonFields, v string) { f.Updated = v }, get: func(f *CommonFields) string { return f.Updated }},
	// "changed" is LACNIC's RPSL vocabulary for last-modified -- distinct
	// from "updated"/"last-modified", which LACNIC's inetnum/aut-num
	// response never emits (confirmed live against 200.3.12.1 and
	// AS28573).
	"changed":       {set: func(f *CommonFields, v string) { f.Updated = v }, get: func(f *CommonFields) string { return f.Updated }},
	"orgabuseemail": {set: func(f *CommonFields, v string) { f.AbuseEmail = v }, get: func(f *CommonFields) string { return f.AbuseEmail }},
	"abuse-mailbox": {set: func(f *CommonFields, v string) { f.AbuseEmail = v }, get: func(f *CommonFields) string { return f.AbuseEmail }},
	"orgabusephone": {set: func(f *CommonFields, v string) { f.AbusePhone = v }, get: func(f *CommonFields) string { return f.AbusePhone }},
}

// liftCommon promotes a fieldRef[CommonFields] to a fieldRef[T], given an
// accessor from *T to its embedded *CommonFields. This is what lets
// commonFields' entries populate either concrete parser's table without
// the vocabulary itself ever being redeclared per type.
func liftCommon[T any](ref fieldRef[CommonFields], common func(*T) *CommonFields) fieldRef[T] {
	lifted := fieldRef[T]{
		set: func(f *T, v string) { ref.set(common(f), v) },
	}
	// A nil ref.get must stay nil once lifted, not become a non-nil
	// wrapper that panics when called: every commonFields entry has a
	// getter today, but a future getter-less shared key (append-valued,
	// like ipFields' own "status") would otherwise panic on first use in
	// both ParseIP's and ParseASN's lookup, since both treat a non-nil get
	// as "safe to call".
	if ref.get != nil {
		lifted.get = func(f *T) string { return ref.get(common(f)) }
	}
	return lifted
}

// buildFields merges commonFields, lifted via common, into a type's own
// specific vocabulary map (mutated and returned), so each parser's table
// is the shared 16 keys plus whatever is genuinely type-specific.
func buildFields[T any](specific map[string]fieldRef[T], common func(*T) *CommonFields) map[string]fieldRef[T] {
	for k, ref := range commonFields {
		specific[k] = liftCommon(ref, common)
	}
	return specific
}
