package parse

import (
	"fmt"
	"os"
	"reflect"
	"strings"
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

// commonFieldKeys is a hardcoded snapshot of commonFields' key set,
// deliberately independent of the live map. Ranging directly over
// commonFields (the brief's original sketch) cannot actually catch a key
// disappearing from the table: `for key := range commonFields` just
// produces one fewer subtest when a key is removed, and a test with no
// case for the missing key trivially "passes" -- confirmed by hand while
// sanity-checking this test (see TestCommonVocabularyReachesBothParsers'
// doc comment). Keying off an independent list means a key vanishing from
// commonFields still gets asked about below, and fails loudly instead of
// silently going untested.
var commonFieldKeys = []string{
	"orgname", "org-name", "owner", "descr", "orgid", "org", "ownerid",
	"country", "regdate", "created", "updated", "last-modified", "changed",
	"orgabuseemail", "abuse-mailbox", "orgabusephone",
}

// TestCommonVocabularyReachesBothParsers is the regression test for the
// class of bug this consolidation exists to prevent: a shared WHOIS key
// mapped for one object type and forgotten for the other. LACNIC's
// owner/ownerid/changed keys were fixed in the ASN parser and shipped
// unmapped in the IP parser, silently single-sourcing every LACNIC IP
// lookup. If someone adds a shared key to only one table, this fails.
//
// The per-key assertion compares fmt.Sprintf("%+v", ...) of the whole
// returned struct against a sentinel value, deliberately including a
// subtest for commonFields' "descr" key even though CommonFields.descr is
// unexported: fmt's struct formatting reads unexported field values
// directly via reflection (verified by hand -- %+v on a struct value
// prints unexported fields' contents, not just their names, including
// through struct embedding), so the sentinel shows up in the raw %+v
// output for descr exactly as it does for every exported field. This
// matters beyond descr's own subtest: descr is the one key with a
// same-package fallback (both parsers copy descr into the exported
// OrgName when OrgName is otherwise empty) that would mask a broken %+v
// assumption by surfacing the sentinel through OrgName regardless: every
// other key here has no such fallback, so %+v actually reaching
// unexported fields -- not just descr's fallback path -- is what makes
// this test meaningful across the full table, not only for descr.
//
// The leading non-subtest check guards the other direction: if
// commonFields gains or loses a key without commonFieldKeys being kept in
// sync, that's reported too (non-fatally, so the per-key subtests below
// still run and still name any specific key that stopped resolving).
//
// Scope: this proves reachability, not targeting. Because the assertion
// is "the sentinel appears SOMEWHERE in %+v", a setter wired to the wrong
// field (e.g. "orgid" accidentally writing OrgName) would still pass --
// the sentinel shows up in the struct dump either way. That's the right
// scope for the bug class that actually shipped here (a key missing from
// one table entirely, not a key pointed at the wrong field); the golden
// tests (TestParseIP_*, TestParseASN_*) are what pin each key to its
// correct field.
func TestCommonVocabularyReachesBothParsers(t *testing.T) {
	if len(commonFieldKeys) != len(commonFields) {
		t.Errorf("commonFieldKeys has %d entries, commonFields has %d -- keep commonFieldKeys in sync with commonFields", len(commonFieldKeys), len(commonFields))
	}
	for _, key := range commonFieldKeys {
		t.Run(key, func(t *testing.T) {
			raw := key + ": sentinel-value\n"
			ip := ParseIP(raw)
			asn := ParseASN(raw)
			if !strings.Contains(fmt.Sprintf("%+v", ip), "sentinel-value") {
				t.Errorf("ParseIP dropped shared key %q", key)
			}
			if !strings.Contains(fmt.Sprintf("%+v", asn), "sentinel-value") {
				t.Errorf("ParseASN dropped shared key %q", key)
			}
		})
	}
}

// TestIPDoesNotApplyObjectBoundaryTracking pins a deliberate asymmetry
// with ParseASN, which skips as-block objects and gives aut-num
// two-level precedence (see ParseASN's doc comment). ParseIP has neither:
// in every real IP response the primary object leads (ARIN "NetRange:",
// RIPE and LACNIC "inetnum:"), so plain first-occurrence-wins already
// keeps a trailing object (here, a contact "role:" block) from shadowing
// it -- adding ASN-style object-boundary machinery would ship a path no
// real response exercises. If a RIR ever leads with an interposing
// object, revisit this; don't delete it in passing because it looks
// inconsistent with asn.go.
func TestIPDoesNotApplyObjectBoundaryTracking(t *testing.T) {
	raw := "inetnum: 10.0.0.0/8\ncountry: AA\n\nrole: Some Contact\ncountry: ZZ\n"
	f := ParseIP(raw)
	if f.Country != "AA" {
		t.Errorf("Country = %q, want AA (first occurrence wins, no object gating)", f.Country)
	}
}

// TestIPStatusAccumulatesUnconditionally pins a deliberate asymmetry with
// ParseASN (see TestASNStatusSuppressedOutsideAutNum in asn_test.go):
// ParseIP has no object-boundary tracking at all (see
// TestIPDoesNotApplyObjectBoundaryTracking above), so it has no notion of
// "inside" vs. "outside" a primary object to gate status on in the first
// place -- every "status:" line in the response accumulates into
// f.Statuses unconditionally, regardless of which RPSL object it belongs
// to. This matches every real IP response observed live, where the
// netblock object leads and no other object in practice carries its own
// status line. Don't add ASN-style object gating here without a real
// response that needs it.
func TestIPStatusAccumulatesUnconditionally(t *testing.T) {
	raw := "inetnum: 10.0.0.0/8\nstatus: ALLOCATED\n\nrole: Some Contact\nstatus: ANOTHER\n"
	f := ParseIP(raw)
	want := []string{"ALLOCATED", "ANOTHER"}
	if !reflect.DeepEqual(f.Statuses, want) {
		t.Errorf("Statuses = %v, want %v (every status line accumulates, no object gating)", f.Statuses, want)
	}
}
