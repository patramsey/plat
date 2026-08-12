package parse

import "strings"

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
// IPFields member it populates. It's built from two parts: the type-specific
// keys declared directly below (ARIN's CamelCase NetRange/CIDR/NetName and
// the RPSL-style inetnum/inet6num/netname vocabulary, none of which any
// other object type has), plus the 16 keys shared with ASNFields --
// orgname/owner/descr, org identity, country, dates, abuse contacts -- which
// commonFields declares once and buildFields lifts in here so they can never
// drift out of sync with asn.go's table again. A key already set is never
// overwritten, so the first occurrence wins -- this matters for ARIN, whose
// responses repeat RegDate/Updated for both the network and the org, and
// whose network block comes first. The "status" entry has no get: it's
// append-valued, so there is no single "current value" to test for
// first-occurrence-wins.
var ipFields = buildFields(map[string]fieldRef[IPFields]{
	"netrange":  {set: func(f *IPFields, v string) { f.NetRange = v }, get: func(f *IPFields) string { return f.NetRange }},
	"inetnum":   {set: func(f *IPFields, v string) { f.NetRange = v }, get: func(f *IPFields) string { return f.NetRange }},
	"inet6num":  {set: func(f *IPFields, v string) { f.NetRange = v }, get: func(f *IPFields) string { return f.NetRange }},
	"cidr":      {set: func(f *IPFields, v string) { f.CIDR = v }, get: func(f *IPFields) string { return f.CIDR }},
	"netname":   {set: func(f *IPFields, v string) { f.NetName = v }, get: func(f *IPFields) string { return f.NetName }},
	"nethandle": {set: func(f *IPFields, v string) { f.Handle = v }, get: func(f *IPFields) string { return f.Handle }},
	"parent":    {set: func(f *IPFields, v string) { f.Parent = v }, get: func(f *IPFields) string { return f.Parent }},
	"nettype":   {set: func(f *IPFields, v string) { f.NetType = v }, get: func(f *IPFields) string { return f.NetType }},
	"status":    {set: func(f *IPFields, v string) { f.Statuses = append(f.Statuses, v) }},
}, func(f *IPFields) *CommonFields { return &f.CommonFields })

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
