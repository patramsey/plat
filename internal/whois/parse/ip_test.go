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

// TestParseIP_LACNIC is a regression test for a live-probed gap: LACNIC's
// RPSL vocabulary uses "owner" (not "orgname"/"org-name"/"descr") for the
// inetnum holder's name, "ownerid" (not "orgid"/"org") for the holder's
// registry ID, and "changed" (not "updated"/"last-modified") for
// last-modified, reporting both created/changed as compact unpunctuated
// "20080902"-style dates. None of those three were recognized before this
// fix (the identical gap was already fixed in ParseASN), so LACNIC's
// registry-whois source for IP lookups contributed nothing but the
// netblock range and country -- e.g. plat 200.3.12.1 showed Organization
// and Updated as RDAP-only despite WHOIS actually carrying both.
func TestParseIP_LACNIC(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/whois/lacnic-200.3.12.1.txt")
	if err != nil {
		t.Fatalf("reading golden: %v", err)
	}
	f := ParseIP(string(raw))

	if f.OrgName != "LACNIC - Latin American and Caribbean IP address" {
		t.Errorf("OrgName = %q, want LACNIC - Latin American and Caribbean IP address (from LACNIC's \"owner:\" line)", f.OrgName)
	}
	if f.OrgID != "UY-LACN-LACNIC" {
		t.Errorf("OrgID = %q, want UY-LACN-LACNIC (from LACNIC's \"ownerid:\" line)", f.OrgID)
	}
	if f.Country != "UY" {
		t.Errorf("Country = %q, want UY", f.Country)
	}
	if !ParseDate(f.Registered).Parsed {
		t.Errorf("Registered = %q did not parse", f.Registered)
	}
	if ParseDate(f.Registered).Time.Format("2006-01-02") != "2008-09-02" {
		t.Errorf("Registered = %q, want to parse to 2008-09-02", f.Registered)
	}
	if !ParseDate(f.Updated).Parsed {
		t.Errorf("Updated = %q did not parse", f.Updated)
	}
	// The golden's second person (nic-hdl) object also carries a "changed:"
	// line (2026-01-20, that contact record's own edit date) after the
	// inetnum object's blank-line terminator. ParseIP has no per-object
	// tracking (unlike ParseASN's as-block/aut-num handling) -- it relies
	// on the inetnum object's "changed:" appearing first in the file, so
	// plain first-occurrence-wins picks the netblock's own date rather
	// than the trailing contact object's.
	if ParseDate(f.Updated).Time.Format("2006-01-02") != "2008-09-02" {
		t.Errorf("Updated = %q, want to parse to 2008-09-02 (inetnum object's own changed, not the trailing contact object's)", f.Updated)
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
