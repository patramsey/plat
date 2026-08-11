package parse

import "strings"

// IPFields is the IP-network counterpart to Fields. The two are kept
// separate rather than merged because they share almost no keys: an IP
// allocation has no registrar, nameservers, expiry, or DNSSEC, and a
// domain has no netblock range or originating org.
type IPFields struct {
	NetRange   string
	CIDR       string
	NetName    string
	Handle     string
	Parent     string
	NetType    string
	OrgName    string
	OrgID      string
	Country    string
	Registered string
	Updated    string
	AbuseEmail string
	AbusePhone string
	Statuses   []string

	// descr holds RPSL's free-text `descr:` line, kept separate from
	// OrgName rather than folded into it. In every live RPSL response the
	// inetnum/inet6num block's `descr:` (a description of the netblock,
	// e.g. "RIPE Network Coordination Centre") precedes the organisation
	// block's `org-name:` (the actual org identity, e.g. "Reseaux IP
	// Europeens Network Coordination Centre (RIPE NCC)") -- so
	// first-occurrence-wins would let descr permanently shadow org-name.
	// ParseIP falls back to descr for OrgName only when no org-name (or
	// ARIN's OrgName) ever appeared, after the scan completes.
	descr string
}

// ipSynonyms maps the lowercased WHOIS key to the IPFields member it
// populates. Both major vocabularies are covered in one table: ARIN's
// CamelCase keys (NetRange, OrgName) and the RPSL-style keys RIPE, APNIC,
// LACNIC and AFRINIC share (inetnum, netname, descr), plus LACNIC's own
// RPSL variants (owner, ownerid, changed) that the other RPSL registries
// don't use. A key already set is never overwritten, so the first
// occurrence wins -- this matters for ARIN, whose responses repeat
// RegDate/Updated for both the network and the org, and whose network
// block comes first.
var ipSynonyms = map[string]func(*IPFields, string){
	"netrange":  func(f *IPFields, v string) { f.NetRange = v },
	"inetnum":   func(f *IPFields, v string) { f.NetRange = v },
	"inet6num":  func(f *IPFields, v string) { f.NetRange = v },
	"cidr":      func(f *IPFields, v string) { f.CIDR = v },
	"netname":   func(f *IPFields, v string) { f.NetName = v },
	"nethandle": func(f *IPFields, v string) { f.Handle = v },
	"parent":    func(f *IPFields, v string) { f.Parent = v },
	"nettype":   func(f *IPFields, v string) { f.NetType = v },
	"orgname":   func(f *IPFields, v string) { f.OrgName = v },
	"org-name":  func(f *IPFields, v string) { f.OrgName = v },
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
	"owner": func(f *IPFields, v string) { f.OrgName = v },
	"descr": func(f *IPFields, v string) { f.descr = v },
	"orgid": func(f *IPFields, v string) { f.OrgID = v },
	"org":   func(f *IPFields, v string) { f.OrgID = v },
	// "ownerid" is LACNIC's RPSL vocabulary for the registry-assigned
	// holder ID (e.g. "UY-LACN-LACNIC") -- distinct from "orgid"/"org",
	// which LACNIC's inetnum response never emits.
	"ownerid":       func(f *IPFields, v string) { f.OrgID = v },
	"country":       func(f *IPFields, v string) { f.Country = v },
	"regdate":       func(f *IPFields, v string) { f.Registered = v },
	"created":       func(f *IPFields, v string) { f.Registered = v },
	"updated":       func(f *IPFields, v string) { f.Updated = v },
	"last-modified": func(f *IPFields, v string) { f.Updated = v },
	// "changed" is LACNIC's RPSL vocabulary for last-modified -- distinct
	// from "updated"/"last-modified", which LACNIC's inetnum response
	// never emits (confirmed live against 200.3.12.1).
	"changed":       func(f *IPFields, v string) { f.Updated = v },
	"orgabuseemail": func(f *IPFields, v string) { f.AbuseEmail = v },
	"abuse-mailbox": func(f *IPFields, v string) { f.AbuseEmail = v },
	"orgabusephone": func(f *IPFields, v string) { f.AbusePhone = v },
	"status":        func(f *IPFields, v string) { f.Statuses = append(f.Statuses, v) },
}

// ipFieldGet reports whether the member a key maps to is already
// populated, so first-occurrence-wins can be enforced without reflection.
var ipFieldGet = map[string]func(*IPFields) string{
	"netrange":      func(f *IPFields) string { return f.NetRange },
	"inetnum":       func(f *IPFields) string { return f.NetRange },
	"inet6num":      func(f *IPFields) string { return f.NetRange },
	"cidr":          func(f *IPFields) string { return f.CIDR },
	"netname":       func(f *IPFields) string { return f.NetName },
	"nethandle":     func(f *IPFields) string { return f.Handle },
	"parent":        func(f *IPFields) string { return f.Parent },
	"nettype":       func(f *IPFields) string { return f.NetType },
	"orgname":       func(f *IPFields) string { return f.OrgName },
	"org-name":      func(f *IPFields) string { return f.OrgName },
	"owner":         func(f *IPFields) string { return f.OrgName },
	"descr":         func(f *IPFields) string { return f.descr },
	"orgid":         func(f *IPFields) string { return f.OrgID },
	"org":           func(f *IPFields) string { return f.OrgID },
	"ownerid":       func(f *IPFields) string { return f.OrgID },
	"country":       func(f *IPFields) string { return f.Country },
	"regdate":       func(f *IPFields) string { return f.Registered },
	"created":       func(f *IPFields) string { return f.Registered },
	"updated":       func(f *IPFields) string { return f.Updated },
	"last-modified": func(f *IPFields) string { return f.Updated },
	"changed":       func(f *IPFields) string { return f.Updated },
	"orgabuseemail": func(f *IPFields) string { return f.AbuseEmail },
	"abuse-mailbox": func(f *IPFields) string { return f.AbuseEmail },
	"orgabusephone": func(f *IPFields) string { return f.AbusePhone },
}

// ParseIP extracts IP-network fields from a raw RIR WHOIS response,
// handling both ARIN's and the RPSL-style vocabularies in one pass. When
// no authoritative org identity (org-name/OrgName) was found anywhere in
// the response, it falls back to RPSL's descr line -- see the descr field
// doc comment on IPFields for why that can't just be folded into the
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
		set, known := ipSynonyms[key]
		if !known {
			continue
		}
		if get, ok := ipFieldGet[key]; ok && get(&f) != "" {
			continue // first occurrence wins
		}
		set(&f, val)
	}
	if f.OrgName == "" {
		f.OrgName = f.descr
	}
	return f
}
