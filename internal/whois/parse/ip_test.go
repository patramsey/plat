package parse

import (
	"os"
	"reflect"
	"testing"
)

func TestParseIP_ARIN(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/whois/arin-8.8.8.8.txt")
	if err != nil {
		t.Fatalf("reading golden: %v", err)
	}
	f := ParseIP(string(raw))

	for _, tt := range []struct{ name, got, want string }{
		{"NetRange", f.NetRange, "8.8.8.0 - 8.8.8.255"},
		{"CIDR", f.CIDR, "8.8.8.0/24"},
		{"NetName", f.NetName, "GOGL"},
		{"NetHandle", f.Handle, "NET-8-8-8-0-2"},
		{"NetType", f.NetType, "Direct Allocation"},
		{"OrgName", f.OrgName, "Google LLC"},
		{"OrgID", f.OrgID, "GOGL"},
		{"Country", f.Country, "US"},
	} {
		if tt.got != tt.want {
			t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.want)
		}
	}
	if f.AbuseEmail == "" {
		t.Error("AbuseEmail is empty, want ARIN's OrgAbuseEmail value")
	}
}

func TestParseIP_RIPE(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/whois/ripe-193.0.6.139.txt")
	if err != nil {
		t.Fatalf("reading golden: %v", err)
	}
	f := ParseIP(string(raw))

	if f.NetRange != "193.0.0.0 - 193.0.7.255" {
		t.Errorf("NetRange = %q, want RIPE's inetnum value", f.NetRange)
	}
	if f.NetName != "RIPE-NCC" {
		t.Errorf("NetName = %q, want RIPE's netname value", f.NetName)
	}
	if f.Country != "NL" {
		t.Errorf("Country = %q, want NL", f.Country)
	}
	// Regression for a false-conflict bug: the inetnum block's descr
	// ("RIPE Network Coordination Centre") precedes the organisation
	// block's org-name ("Reseaux IP Europeens Network Coordination Centre
	// (RIPE NCC)") in every live RPSL response. org-name is the value
	// that matches RDAP's registrant name, so it must win regardless of
	// which line appears first.
	const wantOrgName = "Reseaux IP Europeens Network Coordination Centre (RIPE NCC)"
	if f.OrgName != wantOrgName {
		t.Errorf("OrgName = %q, want %q (org-name must win over the earlier descr line)", f.OrgName, wantOrgName)
	}
}

// TestParseIP_DescrFallsBackWhenNoOrgName covers the inet6num case noted
// during live verification: 2001:67c:2e8::1's inet6num block has no
// descr line at all, so org-name wins outright with no ambiguity. This
// pins the opposite case -- a response with descr but no org-name/OrgName
// anywhere -- falls back to descr rather than leaving OrgName empty.
func TestParseIP_DescrFallsBackWhenNoOrgName(t *testing.T) {
	raw := "inetnum:  10.0.0.0 - 10.0.0.255\ndescr:    Some Netblock Description\ncountry:  NL\n"
	f := ParseIP(raw)
	if f.OrgName != "Some Netblock Description" {
		t.Errorf("OrgName = %q, want the descr fallback value", f.OrgName)
	}
}

// TestParseIP_OrgNameBeforeDescrStillWins pins first-occurrence-wins
// among org-name lines themselves once the fallback is in play: a
// response with org-name appearing before descr must not let the later
// descr overwrite it.
func TestParseIP_OrgNameBeforeDescrStillWins(t *testing.T) {
	raw := "inetnum:  10.0.0.0 - 10.0.0.255\norg-name: Real Org\ndescr:    Netblock Description\n"
	f := ParseIP(raw)
	if f.OrgName != "Real Org" {
		t.Errorf("OrgName = %q, want %q (org-name must win even though it appeared first here too)", f.OrgName, "Real Org")
	}
}

func TestParseIP_EmptyInput(t *testing.T) {
	// IPFields embeds a []string (Statuses), so it isn't comparable with
	// != (the brief's literal test snippet fails to compile for exactly
	// this reason); reflect.DeepEqual preserves the same zero-value intent.
	if got := ParseIP(""); !reflect.DeepEqual(got, IPFields{}) {
		t.Errorf("ParseIP(\"\") = %+v, want the zero value", got)
	}
}
