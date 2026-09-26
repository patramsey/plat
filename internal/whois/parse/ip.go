package parse

import (
	"net/netip"
	"strings"
)

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
	// ARIN names the holder of a network reassigned to a customer with
	// CustName rather than OrgName; RDAP reports it as the registrant.
	"custname": {set: func(f *IPFields, v string) { f.OrgName = v }, get: func(f *IPFields) string { return f.OrgName }},
}, func(f *IPFields) *CommonFields { return &f.CommonFields })

// ParseIP extracts IP-network fields from a raw RIR WHOIS response,
// handling both ARIN's and the RPSL-style vocabularies in one pass. When
// no authoritative org identity (org-name/OrgName) was found anywhere in
// the response, it falls back to RPSL's descr line -- see the descr field
// doc comment on CommonFields for why that can't just be folded into the
// first-occurrence-wins scan itself.
func ParseIP(raw string) IPFields {
	raw = mostSpecificNetwork(raw)
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

// mostSpecificNetwork narrows an ARIN response that lists several
// networks to the section describing the narrowest one. ARIN's "n + "
// answer for an address inside nested networks gives each matching
// network's full record, least specific first -- for 12.0.0.1, AT&T's /8
// and then the /22 reassigned to a customer. RDAP answers with the most
// specific network, so WHOIS must too, or the sources conflict on every
// field. Each section runs from one "NetRange:" line to the next. Every
// listed network contains the queried address, so they nest, and the
// narrowest is the one contained in all the others. A response with at
// most one NetRange -- every RPSL-style RIR's, and ARIN's single-match
// answers -- is returned unchanged.
func mostSpecificNetwork(raw string) string {
	lines := strings.Split(raw, "\n")
	var starts []int
	for i, l := range lines {
		if k, _, ok := strings.Cut(strings.TrimSpace(l), ":"); ok && strings.EqualFold(strings.TrimSpace(k), "netrange") {
			starts = append(starts, i)
		}
	}
	if len(starts) < 2 {
		return raw
	}
	best := -1
	var bestLo, bestHi netip.Addr
	for n, i := range starts {
		_, v, _ := strings.Cut(lines[i], ":")
		lo, hi, ok := parseNetRange(v)
		if !ok {
			continue
		}
		if best < 0 || (bestLo.Compare(lo) <= 0 && hi.Compare(bestHi) <= 0) {
			best, bestLo, bestHi = n, lo, hi
		}
	}
	if best < 0 {
		return raw
	}
	end := len(lines)
	if best+1 < len(starts) {
		end = starts[best+1]
	}
	return strings.Join(lines[starts[best]:end], "\n")
}

// parseNetRange parses ARIN's "<start> - <end>" NetRange value.
func parseNetRange(v string) (lo, hi netip.Addr, ok bool) {
	a, b, found := strings.Cut(v, "-")
	if !found {
		return netip.Addr{}, netip.Addr{}, false
	}
	lo, err1 := netip.ParseAddr(strings.TrimSpace(a))
	hi, err2 := netip.ParseAddr(strings.TrimSpace(b))
	if err1 != nil || err2 != nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	return lo, hi, true
}
