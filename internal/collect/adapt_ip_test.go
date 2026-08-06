package collect

import (
	"encoding/json"
	"testing"

	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/rdap"
	"github.com/patramsey/plat/internal/whois"
	"github.com/patramsey/plat/internal/whois/parse"
)

// rdapTime builds an rdap.RDAPTime by round-tripping through the type's own
// UnmarshalJSON, exactly as encoding/json would when decoding a real RDAP
// response -- avoids hand-constructing the unexported layout-parsing logic
// a second time in test code.
func rdapTime(t *testing.T, s string) rdap.RDAPTime {
	t.Helper()
	var rt rdap.RDAPTime
	if err := json.Unmarshal([]byte(`"`+s+`"`), &rt); err != nil {
		t.Fatalf("unmarshaling RDAPTime %q: %v", s, err)
	}
	return rt
}

// arinLikeIPNetwork returns an *rdap.IPNetworkResponse shaped like ARIN's
// real response for 8.8.8.8, per the coordinator's requested fixture.
func arinLikeIPNetwork(t *testing.T) *rdap.IPNetworkResponse {
	t.Helper()
	return &rdap.IPNetworkResponse{
		ObjectClassName: "ip network",
		Handle:          "NET-8-8-8-0-2",
		StartAddress:    "8.8.8.0",
		EndAddress:      "8.8.8.255",
		IPVersion:       "v4",
		Name:            "GOGL",
		Type:            "DIRECT ALLOCATION",
		ParentHandle:    "NET-8-0-0-0-0",
		Status:          rdap.StatusList{"active"},
		CIDR0CIDRs:      []rdap.CIDR0{{V4Prefix: "8.8.8.0", Length: 24}},
		Events: []rdap.Event{
			{Action: "registration", Date: rdapTime(t, "2023-12-28T17:24:33-05:00")},
			{Action: "last changed", Date: rdapTime(t, "2023-12-29T09:10:00-05:00")},
		},
		Entities: rdap.EntityList{
			{Roles: []string{"registrant"}, VCardArray: rdap.VCardArray{FullName: "Google LLC"}},
			{Roles: []string{"abuse"}, VCardArray: rdap.VCardArray{Email: "network-abuse@google.com", Tel: "+1-650-253-0000"}},
		},
	}
}

func TestFromIPRDAP_ARINFixture(t *testing.T) {
	resp := arinLikeIPNetwork(t)
	meta := model.SourceResult{Source: model.SourceRegistryRDAP, OK: true}

	sr := fromIPRDAP(meta, resp)

	if !sr.Present {
		t.Fatal("Present = false, want true")
	}
	if sr.Meta.Source != model.SourceRegistryRDAP {
		t.Errorf("Meta.Source = %q, want %q", sr.Meta.Source, model.SourceRegistryRDAP)
	}
	if sr.Handle != "NET-8-8-8-0-2" {
		t.Errorf("Handle = %q, want NET-8-8-8-0-2", sr.Handle)
	}
	if sr.Name != "GOGL" {
		t.Errorf("Name = %q, want GOGL", sr.Name)
	}
	if sr.Type != "DIRECT ALLOCATION" {
		t.Errorf("Type = %q, want DIRECT ALLOCATION", sr.Type)
	}
	if sr.StartAddress != "8.8.8.0" || sr.EndAddress != "8.8.8.255" {
		t.Errorf("StartAddress/EndAddress = %q/%q, want 8.8.8.0/8.8.8.255", sr.StartAddress, sr.EndAddress)
	}
	if sr.IPVersion != "v4" {
		t.Errorf("IPVersion = %q, want v4", sr.IPVersion)
	}
	if sr.ParentHandle != "NET-8-0-0-0-0" {
		t.Errorf("ParentHandle = %q, want NET-8-0-0-0-0", sr.ParentHandle)
	}

	// CIDR must be derived via CIDR0.Prefix(), not hand-assembled.
	wantCIDR := resp.CIDR0CIDRs[0].Prefix()
	if wantCIDR != "8.8.8.0/24" {
		t.Fatalf("test fixture sanity check failed: CIDR0.Prefix() = %q, want 8.8.8.0/24", wantCIDR)
	}
	if sr.CIDR != wantCIDR {
		t.Errorf("CIDR = %q, want %q (from CIDR0.Prefix())", sr.CIDR, wantCIDR)
	}

	if len(sr.Status) != 1 || sr.Status[0] != "active" {
		t.Errorf("Status = %v, want [active]", sr.Status)
	}

	// Registration event -> Registered field.
	if !sr.Registered.Parsed {
		t.Errorf("Registered.Parsed = false, want true: %+v", sr.Registered)
	}
	if sr.Registered.Raw != "2023-12-28T17:24:33-05:00" {
		t.Errorf("Registered.Raw = %q, want 2023-12-28T17:24:33-05:00", sr.Registered.Raw)
	}
	// Last-changed event -> Updated field, and the two must land in
	// distinct fields rather than one clobbering the other.
	if !sr.Updated.Parsed {
		t.Errorf("Updated.Parsed = false, want true: %+v", sr.Updated)
	}
	if sr.Updated.Raw != "2023-12-29T09:10:00-05:00" {
		t.Errorf("Updated.Raw = %q, want 2023-12-29T09:10:00-05:00", sr.Updated.Raw)
	}
	if sr.Registered.Raw == sr.Updated.Raw {
		t.Error("Registered and Updated carry the same Raw value, want the two distinct events kept separate")
	}

	// OrgName from the registrant entity's vCard FullName.
	if sr.OrgName != "Google LLC" {
		t.Errorf("OrgName = %q, want Google LLC (from the registrant entity)", sr.OrgName)
	}
	if sr.AbuseEmail != "network-abuse@google.com" {
		t.Errorf("AbuseEmail = %q, want network-abuse@google.com", sr.AbuseEmail)
	}
	if sr.AbusePhone != "+1-650-253-0000" {
		t.Errorf("AbusePhone = %q, want +1-650-253-0000", sr.AbusePhone)
	}
}

func TestFromIPRDAP_FetchError(t *testing.T) {
	// Task 7's future caller resolves a fetch error into meta (OK=false,
	// Err set) before calling fromIPRDAP with a nil response -- mirroring
	// how FromRDAP(src, nil, latency, fetchErr) behaves for domains, but
	// pre-resolved since fromIPRDAP's brief-mandated signature carries no
	// fetchErr parameter of its own.
	meta := model.SourceResult{Source: model.SourceRegistryRDAP, OK: false, Err: "connection refused"}

	sr := fromIPRDAP(meta, nil)

	if sr.Present {
		t.Error("Present = true, want false on a fetch error")
	}
	if sr.Meta.OK {
		t.Error("Meta.OK = true, want false")
	}
	if sr.Meta.Err != "connection refused" {
		t.Errorf("Meta.Err = %q, want connection refused (preserved from the caller)", sr.Meta.Err)
	}
}

func TestFromIPRDAP_NotFound(t *testing.T) {
	// Mirrors FromRDAP's rdap.ErrDomainNotFound handling (reused verbatim
	// for IP lookups -- ipAt returns the same sentinel on a 404). The
	// future Task 7 caller sets NotFound via errors.Is(fetchErr,
	// rdap.ErrDomainNotFound) before calling fromIPRDAP; this pins that
	// fromIPRDAP doesn't clobber it.
	meta := model.SourceResult{Source: model.SourceRegistryRDAP, OK: false, NotFound: true, Err: "rdap: ip not found"}

	sr := fromIPRDAP(meta, nil)

	if sr.Present {
		t.Error("Present = true, want false for a not-found response")
	}
	if !sr.Meta.NotFound {
		t.Error("Meta.NotFound = false, want true (preserved from the caller)")
	}
}

func TestFromIPRDAP_EmptyResponse(t *testing.T) {
	// A non-nil but entirely empty IPNetworkResponse (e.g. a malformed
	// document that still decoded to a zero value) must not be reported
	// present either.
	sr := fromIPRDAP(model.SourceResult{Source: model.SourceRegistryRDAP, OK: true}, &rdap.IPNetworkResponse{})

	if sr.Present {
		t.Error("Present = true, want false for an entirely empty IPNetworkResponse")
	}
}

func TestFromIPRDAP_RedactedOrgName(t *testing.T) {
	resp := &rdap.IPNetworkResponse{
		Handle: "NET-1-2-3-0-1",
		Entities: rdap.EntityList{
			{Roles: []string{"registrant"}, VCardArray: rdap.VCardArray{FullName: "REDACTED FOR PRIVACY"}},
		},
	}

	sr := fromIPRDAP(model.SourceResult{Source: model.SourceRegistryRDAP, OK: true}, resp)

	if sr.OrgName != "" {
		t.Errorf("OrgName = %q, want empty (redacted placeholder must not surface as a real value)", sr.OrgName)
	}
	if !sr.RedactedFields[model.FieldOrgName] {
		t.Error("RedactedFields[org.name] = false, want true")
	}
	// Still present overall: the handle is real data even though the org
	// name is redacted, matching adapt_rdap.go's treatment of a redacted
	// registrar name alongside other real fields.
	if !sr.Present {
		t.Error("Present = false, want true (Handle is populated even though OrgName is redacted)")
	}
}

func TestFromIPHop_PopulatedFields(t *testing.T) {
	hop := whois.Hop{
		IPFields: &parse.IPFields{
			NetRange:   "8.8.8.0 - 8.8.8.255",
			CIDR:       "8.8.8.0/24",
			NetName:    "GOGL",
			Handle:     "NET-8-8-8-0-2",
			Parent:     "NET-8-0-0-0-0",
			NetType:    "Direct Allocation",
			OrgName:    "Google LLC",
			OrgID:      "GOGL",
			Country:    "US",
			Registered: "2023-12-28",
			Updated:    "2023-12-29",
			AbuseEmail: "network-abuse@google.com",
			AbusePhone: "+1-650-253-0000",
			Statuses:   []string{"active"},
		},
	}

	sr := fromIPHop(model.SourceResult{Source: model.SourceRegistryWHOIS, OK: true}, hop)

	if !sr.Present {
		t.Fatal("Present = false, want true")
	}
	if sr.StartAddress != "8.8.8.0" {
		t.Errorf("StartAddress = %q, want 8.8.8.0 (split from NetRange, not the combined string)", sr.StartAddress)
	}
	if sr.EndAddress != "8.8.8.255" {
		t.Errorf("EndAddress = %q, want 8.8.8.255 (split from NetRange)", sr.EndAddress)
	}
	if sr.CIDR != "8.8.8.0/24" {
		t.Errorf("CIDR = %q, want 8.8.8.0/24", sr.CIDR)
	}
	if sr.Name != "GOGL" {
		t.Errorf("Name = %q, want GOGL (from NetName)", sr.Name)
	}
	if sr.Handle != "NET-8-8-8-0-2" {
		t.Errorf("Handle = %q, want NET-8-8-8-0-2", sr.Handle)
	}
	if sr.ParentHandle != "NET-8-0-0-0-0" {
		t.Errorf("ParentHandle = %q, want NET-8-0-0-0-0 (from Parent)", sr.ParentHandle)
	}
	if sr.Type != "Direct Allocation" {
		t.Errorf("Type = %q, want Direct Allocation (from NetType)", sr.Type)
	}
	if sr.OrgName != "Google LLC" {
		t.Errorf("OrgName = %q, want Google LLC", sr.OrgName)
	}
	if sr.OrgID != "GOGL" {
		t.Errorf("OrgID = %q, want GOGL", sr.OrgID)
	}
	if sr.Country != "US" {
		t.Errorf("Country = %q, want US", sr.Country)
	}
	if sr.AbuseEmail != "network-abuse@google.com" {
		t.Errorf("AbuseEmail = %q, want network-abuse@google.com", sr.AbuseEmail)
	}
	if sr.AbusePhone != "+1-650-253-0000" {
		t.Errorf("AbusePhone = %q, want +1-650-253-0000", sr.AbusePhone)
	}
	if len(sr.Status) != 1 || sr.Status[0] != "active" {
		t.Errorf("Status = %v, want [active]", sr.Status)
	}

	// Dates parsed via parse.ParseDate -- the same tolerant multi-format
	// parser the domain WHOIS adapter uses -- must land Parsed=true.
	if !sr.Registered.Parsed {
		t.Errorf("Registered.Parsed = false, want true: %+v", sr.Registered)
	}
	if sr.Registered.Raw != "2023-12-28" {
		t.Errorf("Registered.Raw = %q, want 2023-12-28", sr.Registered.Raw)
	}
	if !sr.Updated.Parsed {
		t.Errorf("Updated.Parsed = false, want true: %+v", sr.Updated)
	}
	if sr.Updated.Raw != "2023-12-29" {
		t.Errorf("Updated.Raw = %q, want 2023-12-29", sr.Updated.Raw)
	}
}

func TestFromIPHop_NilIPFields(t *testing.T) {
	// A domain hop (or a hop where IP parsing never ran) carries a nil
	// IPFields pointer -- this must degrade to Present:false, not panic.
	hop := whois.Hop{Raw: "some raw text that was never IP-parsed"}

	sr := fromIPHop(model.SourceResult{Source: model.SourceRegistryWHOIS, OK: true}, hop)

	if sr.Present {
		t.Error("Present = true, want false when hop.IPFields is nil")
	}
	if sr.Meta.OK {
		t.Error("Meta.OK = true, want false when hop.IPFields is nil")
	}
}

func TestFromIPHop_HopError(t *testing.T) {
	hop := whois.Hop{Err: errDeadline}

	sr := fromIPHop(model.SourceResult{Source: model.SourceRegistryWHOIS, OK: true}, hop)

	if sr.Present {
		t.Error("Present = true, want false when hop.Err is set")
	}
	if sr.Meta.OK {
		t.Error("Meta.OK = true, want false when hop.Err is set")
	}
}

func TestFromIPHop_RedactedOrgName(t *testing.T) {
	hop := whois.Hop{
		IPFields: &parse.IPFields{
			Handle:  "NET-1-2-3-0-1",
			OrgName: "REDACTED FOR PRIVACY",
		},
	}

	sr := fromIPHop(model.SourceResult{Source: model.SourceRegistryWHOIS, OK: true}, hop)

	if sr.OrgName != "" {
		t.Errorf("OrgName = %q, want empty (redacted placeholder), matching adapt_whois.go's fromHop treatment of a redacted registrar name", sr.OrgName)
	}
	if !sr.RedactedFields[model.FieldOrgName] {
		t.Error("RedactedFields[org.name] = false, want true")
	}
	if !sr.Present {
		t.Error("Present = false, want true (Handle is populated even though OrgName is redacted)")
	}
}

func TestFromIPHop_ARINParentNotationNormalized(t *testing.T) {
	// ARIN's Parent line prefixes the handle with the parent network's
	// name ("NET8 (NET-8-0-0-0-0)"), unlike RDAP's bare parentHandle. This
	// pins that fromIPHop extracts the bare handle so it compares equal
	// to RDAP's value in merge.MergeIP rather than producing a false
	// conflict.
	hop := whois.Hop{
		IPFields: &parse.IPFields{
			Handle: "NET-8-8-8-0-2",
			Parent: "NET8 (NET-8-0-0-0-0)",
		},
	}

	sr := fromIPHop(model.SourceResult{Source: model.SourceRegistryWHOIS, OK: true}, hop)

	if sr.ParentHandle != "NET-8-0-0-0-0" {
		t.Errorf("ParentHandle = %q, want NET-8-0-0-0-0 (extracted from ARIN's \"name (handle)\" notation)", sr.ParentHandle)
	}
}

func TestSplitNetRange(t *testing.T) {
	tests := []struct {
		name               string
		raw                string
		wantStart, wantEnd string
	}{
		{"ARIN-style with spaces", "8.8.8.0 - 8.8.8.255", "8.8.8.0", "8.8.8.255"},
		{"RIPE-style inetnum, no spaces", "8.8.8.0-8.8.8.255", "8.8.8.0", "8.8.8.255"},
		{"extra whitespace", "  8.8.8.0   -   8.8.8.255  ", "8.8.8.0", "8.8.8.255"},
		{"IPv6 range", "2001:4860:: - 2001:4860:ffff:ffff:ffff:ffff:ffff:ffff", "2001:4860::", "2001:4860:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"empty", "", "", ""},
		{"no separator", "not a range at all", "", ""},
		{"trailing hyphen, empty end", "8.8.8.0 - ", "", ""},
		{"leading hyphen, empty start", " - 8.8.8.255", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStart, gotEnd := splitNetRange(tt.raw)
			if gotStart != tt.wantStart || gotEnd != tt.wantEnd {
				t.Errorf("splitNetRange(%q) = (%q, %q), want (%q, %q)", tt.raw, gotStart, gotEnd, tt.wantStart, tt.wantEnd)
			}
		})
	}
}

// TestRangeAndCIDRFromNetRange covers CIDR-form NetRange input -- LACNIC
// reports IPv4 netblocks this way ("inetnum: 200.3.12.0/22"), and RIPE,
// APNIC, and AFRINIC report *all* IPv6 netblocks this way
// ("inet6num: 2001:67c:2e8::/48"). Before this fix, splitNetRange alone
// degraded these to ("", "") and nothing else populated CIDR from
// NetRange -- silently dropping the netblock, the most identifying field
// on the record, from the WHOIS source.
func TestRangeAndCIDRFromNetRange(t *testing.T) {
	tests := []struct {
		name                         string
		netRange, cidrIn             string
		wantStart, wantEnd, wantCIDR string
	}{
		{
			name:      "hyphenated form still works, ARIN CIDR line kept",
			netRange:  "8.8.8.0 - 8.8.8.255",
			cidrIn:    "8.8.8.0/24",
			wantStart: "8.8.8.0", wantEnd: "8.8.8.255", wantCIDR: "8.8.8.0/24",
		},
		{
			name:      "LACNIC-style IPv4 CIDR inetnum",
			netRange:  "200.3.12.0/22",
			wantStart: "200.3.12.0", wantEnd: "200.3.15.255", wantCIDR: "200.3.12.0/22",
		},
		{
			name:      "RIPE/APNIC/AFRINIC-style IPv6 CIDR inet6num",
			netRange:  "2001:67c:2e8::/48",
			wantStart: "2001:67c:2e8::", wantEnd: "2001:67c:2e8:ffff:ffff:ffff:ffff:ffff", wantCIDR: "2001:67c:2e8::/48",
		},
		{
			name:      "CIDR-form with an unaligned host part still masks down",
			netRange:  "10.0.0.5/24",
			wantStart: "10.0.0.0", wantEnd: "10.0.0.255", wantCIDR: "10.0.0.0/24",
		},
		{
			name:      "malformed input degrades safely, doesn't fabricate a range",
			netRange:  "not a range at all",
			wantStart: "", wantEnd: "", wantCIDR: "",
		},
		{
			name:      "empty input degrades safely",
			netRange:  "",
			wantStart: "", wantEnd: "", wantCIDR: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStart, gotEnd, gotCIDR := rangeAndCIDRFromNetRange(tt.netRange, tt.cidrIn)
			if gotStart != tt.wantStart || gotEnd != tt.wantEnd || gotCIDR != tt.wantCIDR {
				t.Errorf("rangeAndCIDRFromNetRange(%q, %q) = (%q, %q, %q), want (%q, %q, %q)",
					tt.netRange, tt.cidrIn, gotStart, gotEnd, gotCIDR, tt.wantStart, tt.wantEnd, tt.wantCIDR)
			}
		})
	}
}

func TestParentHandleFromWHOIS(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"ARIN name-prefixed handle", "NET8 (NET-8-0-0-0-0)", "NET-8-0-0-0-0"},
		{"bare handle, no parens", "NET-8-0-0-0-0", "NET-8-0-0-0-0"},
		{"empty", "", ""},
		{"empty parens", "NET8 ()", "NET8 ()"},
		{"parens with only whitespace", "NET8 (   )", "NET8 (   )"},
		{"handle alone in parens, no name", "(NET-1-0-0-0)", "NET-1-0-0-0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parentHandleFromWHOIS(tt.raw)
			if got != tt.want {
				t.Errorf("parentHandleFromWHOIS(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}
