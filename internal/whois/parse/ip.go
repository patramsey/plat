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
}

// ipSynonyms maps the lowercased WHOIS key to the IPFields member it
// populates. Both major vocabularies are covered in one table: ARIN's
// CamelCase keys (NetRange, OrgName) and the RPSL-style keys RIPE, APNIC,
// LACNIC and AFRINIC share (inetnum, netname, descr). A key already set
// is never overwritten, so the first occurrence wins -- this matters for
// ARIN, whose responses repeat RegDate/Updated for both the network and
// the org, and whose network block comes first.
var ipSynonyms = map[string]func(*IPFields, string){
	"netrange":      func(f *IPFields, v string) { f.NetRange = v },
	"inetnum":       func(f *IPFields, v string) { f.NetRange = v },
	"inet6num":      func(f *IPFields, v string) { f.NetRange = v },
	"cidr":          func(f *IPFields, v string) { f.CIDR = v },
	"netname":       func(f *IPFields, v string) { f.NetName = v },
	"nethandle":     func(f *IPFields, v string) { f.Handle = v },
	"parent":        func(f *IPFields, v string) { f.Parent = v },
	"nettype":       func(f *IPFields, v string) { f.NetType = v },
	"orgname":       func(f *IPFields, v string) { f.OrgName = v },
	"org-name":      func(f *IPFields, v string) { f.OrgName = v },
	"descr":         func(f *IPFields, v string) { f.OrgName = v },
	"orgid":         func(f *IPFields, v string) { f.OrgID = v },
	"org":           func(f *IPFields, v string) { f.OrgID = v },
	"country":       func(f *IPFields, v string) { f.Country = v },
	"regdate":       func(f *IPFields, v string) { f.Registered = v },
	"created":       func(f *IPFields, v string) { f.Registered = v },
	"updated":       func(f *IPFields, v string) { f.Updated = v },
	"last-modified": func(f *IPFields, v string) { f.Updated = v },
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
	"descr":         func(f *IPFields) string { return f.OrgName },
	"orgid":         func(f *IPFields) string { return f.OrgID },
	"org":           func(f *IPFields) string { return f.OrgID },
	"country":       func(f *IPFields) string { return f.Country },
	"regdate":       func(f *IPFields) string { return f.Registered },
	"created":       func(f *IPFields) string { return f.Registered },
	"updated":       func(f *IPFields) string { return f.Updated },
	"last-modified": func(f *IPFields) string { return f.Updated },
	"orgabuseemail": func(f *IPFields) string { return f.AbuseEmail },
	"abuse-mailbox": func(f *IPFields) string { return f.AbuseEmail },
	"orgabusephone": func(f *IPFields) string { return f.AbusePhone },
}

// ParseIP extracts IP-network fields from a raw RIR WHOIS response,
// handling both ARIN's and the RPSL-style vocabularies in one pass.
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
	return f
}
