package parse

import "strings"

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

// IPFields is the IP-network counterpart to Fields. The two are kept
// separate rather than merged because they share almost no keys: an IP
// allocation has no registrar, nameservers, expiry, or DNSSEC, and a
// domain has no netblock range or originating org.
type IPFields struct {
	CommonFields

	NetRange string
	CIDR     string
	NetName  string
	Parent   string
	NetType  string
}

// ipFields maps the lowercased WHOIS key to the setter/getter pair for the
// IPFields member it populates. Both major vocabularies are covered in one
// table: ARIN's CamelCase keys (NetRange, OrgName) and the RPSL-style keys
// RIPE, APNIC, LACNIC and AFRINIC share (inetnum, netname, descr), plus
// LACNIC's own RPSL variants (owner, ownerid, changed) that the other RPSL
// registries don't use. A key already set is never overwritten, so the
// first occurrence wins -- this matters for ARIN, whose responses repeat
// RegDate/Updated for both the network and the org, and whose network
// block comes first. Entries with no get are append-valued (status), so
// there is no single "current value" to test for first-occurrence-wins.
var ipFields = map[string]fieldRef[IPFields]{
	"netrange":  {set: func(f *IPFields, v string) { f.NetRange = v }, get: func(f *IPFields) string { return f.NetRange }},
	"inetnum":   {set: func(f *IPFields, v string) { f.NetRange = v }, get: func(f *IPFields) string { return f.NetRange }},
	"inet6num":  {set: func(f *IPFields, v string) { f.NetRange = v }, get: func(f *IPFields) string { return f.NetRange }},
	"cidr":      {set: func(f *IPFields, v string) { f.CIDR = v }, get: func(f *IPFields) string { return f.CIDR }},
	"netname":   {set: func(f *IPFields, v string) { f.NetName = v }, get: func(f *IPFields) string { return f.NetName }},
	"nethandle": {set: func(f *IPFields, v string) { f.Handle = v }, get: func(f *IPFields) string { return f.Handle }},
	"parent":    {set: func(f *IPFields, v string) { f.Parent = v }, get: func(f *IPFields) string { return f.Parent }},
	"nettype":   {set: func(f *IPFields, v string) { f.NetType = v }, get: func(f *IPFields) string { return f.NetType }},
	"orgname":   {set: func(f *IPFields, v string) { f.OrgName = v }, get: func(f *IPFields) string { return f.OrgName }},
	"org-name":  {set: func(f *IPFields, v string) { f.OrgName = v }, get: func(f *IPFields) string { return f.OrgName }},
	// "owner" is LACNIC's RPSL vocabulary for the inetnum holder's name --
	// LACNIC does not use "orgname"/"org-name"/"descr" for this at all, so
	// without this entry LACNIC WHOIS contributed no org identity
	// whatsoever (confirmed live against 200.3.12.1). Ranked alongside
	// orgname/org-name (a direct, first-occurrence-wins assignment to
	// OrgName) rather than routed through the descr fallback below: descr
	// is only ever consulted after the full scan, when OrgName is still
	// empty, so owner inherently outranks it exactly as orgname/org-name
	// already do. In practice LACNIC's inetnum responses have "owner:" but
	// no "descr:", while RIPE/APNIC have "descr:" but no "owner:", so the
	// two rarely collide -- but were they to, owner winning is consistent
	// with how ASNFields already treats this identical LACNIC key.
	"owner": {set: func(f *IPFields, v string) { f.OrgName = v }, get: func(f *IPFields) string { return f.OrgName }},
	"descr": {set: func(f *IPFields, v string) { f.descr = v }, get: func(f *IPFields) string { return f.descr }},
	"orgid": {set: func(f *IPFields, v string) { f.OrgID = v }, get: func(f *IPFields) string { return f.OrgID }},
	"org":   {set: func(f *IPFields, v string) { f.OrgID = v }, get: func(f *IPFields) string { return f.OrgID }},
	// "ownerid" is LACNIC's RPSL vocabulary for the registry-assigned
	// holder ID (e.g. "UY-LACN-LACNIC") -- distinct from "orgid"/"org",
	// which LACNIC's inetnum response never emits.
	"ownerid":       {set: func(f *IPFields, v string) { f.OrgID = v }, get: func(f *IPFields) string { return f.OrgID }},
	"country":       {set: func(f *IPFields, v string) { f.Country = v }, get: func(f *IPFields) string { return f.Country }},
	"regdate":       {set: func(f *IPFields, v string) { f.Registered = v }, get: func(f *IPFields) string { return f.Registered }},
	"created":       {set: func(f *IPFields, v string) { f.Registered = v }, get: func(f *IPFields) string { return f.Registered }},
	"updated":       {set: func(f *IPFields, v string) { f.Updated = v }, get: func(f *IPFields) string { return f.Updated }},
	"last-modified": {set: func(f *IPFields, v string) { f.Updated = v }, get: func(f *IPFields) string { return f.Updated }},
	// "changed" is LACNIC's RPSL vocabulary for last-modified -- distinct
	// from "updated"/"last-modified", which LACNIC's inetnum response
	// never emits (confirmed live against 200.3.12.1).
	"changed":       {set: func(f *IPFields, v string) { f.Updated = v }, get: func(f *IPFields) string { return f.Updated }},
	"orgabuseemail": {set: func(f *IPFields, v string) { f.AbuseEmail = v }, get: func(f *IPFields) string { return f.AbuseEmail }},
	"abuse-mailbox": {set: func(f *IPFields, v string) { f.AbuseEmail = v }, get: func(f *IPFields) string { return f.AbuseEmail }},
	"orgabusephone": {set: func(f *IPFields, v string) { f.AbusePhone = v }, get: func(f *IPFields) string { return f.AbusePhone }},
	"status":        {set: func(f *IPFields, v string) { f.Statuses = append(f.Statuses, v) }},
}

// ParseIP extracts IP-network fields from a raw RIR WHOIS response,
// handling both ARIN's and the RPSL-style vocabularies in one pass. When
// no authoritative org identity (org-name/OrgName) was found anywhere in
// the response, it falls back to RPSL's descr line -- see the descr field
// doc comment on CommonFields for why that can't just be folded into the
// first-occurrence-wins scan itself.
func ParseIP(raw string) IPFields {
	var f IPFields
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "%") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		ref, known := ipFields[key]
		if !known {
			continue
		}
		if ref.get != nil && ref.get(&f) != "" {
			continue // first occurrence wins
		}
		ref.set(&f, val)
	}
	if f.OrgName == "" {
		f.OrgName = f.descr
	}
	return f
}
