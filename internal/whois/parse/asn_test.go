package parse

import (
	"os"
	"reflect"
	"testing"
)

func TestParseASN_ARIN(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/whois/arin-as15169.txt")
	if err != nil {
		t.Fatalf("reading golden: %v", err)
	}
	f := ParseASN(string(raw))

	for _, tt := range []struct{ name, got, want string }{
		{"Number", f.Number, "15169"},
		{"Name", f.Name, "GOOGLE"},
		{"Handle", f.Handle, "AS15169"},
		{"OrgName", f.OrgName, "Google LLC"},
		{"OrgID", f.OrgID, "GOGL"},
		{"Registered", f.Registered, "2000-03-30"},
	} {
		if tt.got != tt.want {
			t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.want)
		}
	}
}

// TestParseASN_RIPE_SkipsASBlock is the load-bearing test of this task.
// RIPE answers an ASN query with an as-block object BEFORE the aut-num
// object. Naive first-occurrence-wins would take descr/created from the
// block ("RIPE NCC ASN block") rather than the ASN itself.
func TestParseASN_RIPE_SkipsASBlock(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/whois/ripe-as3333.txt")
	if err != nil {
		t.Fatalf("reading golden: %v", err)
	}
	f := ParseASN(string(raw))

	if f.Handle != "AS3333" {
		t.Errorf("Handle = %q, want AS3333 (from aut-num, not as-block)", f.Handle)
	}
	if f.Name != "RIPE-NCC-AS" {
		t.Errorf("Name = %q, want RIPE-NCC-AS (as-name)", f.Name)
	}
	if f.OrgName == "RIPE NCC ASN block" {
		t.Fatal("OrgName came from the as-block's descr; want the aut-num's own descr")
	}
	if f.OrgName == "" {
		t.Error("OrgName is empty, want the aut-num's descr/org value")
	}
	if f.OrgName != "Reseaux IP Europeens Network Coordination Centre (RIPE NCC)" {
		t.Errorf("OrgName = %q, want the aut-num's own descr line", f.OrgName)
	}
}

// TestParseASN_APNIC_RoleObjectDoesNotShadowAutNum is a regression test
// for a real defect caught during live verification against AS4808:
// APNIC places a "role" object (its own Hostmaster contact, with its own
// "country" and "last-modified" describing that contact, not the ASN)
// between the as-block and the aut-num object. Skipping only as-block
// wasn't enough -- the role object's country ("AU", APNIC's own
// Brisbane address) and last-modified (2013, the contact record's own
// edit date) were shadowing the aut-num object's real "country" (CN)
// and "last-modified" (2025, the ASN's own record) under plain
// first-occurrence-wins. See ParseASN's doc comment for the fix: the
// aut-num object's own values always win, regardless of what a
// preceding object already set.
func TestParseASN_APNIC_RoleObjectDoesNotShadowAutNum(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/whois/apnic-as4808.txt")
	if err != nil {
		t.Fatalf("reading golden: %v", err)
	}
	f := ParseASN(string(raw))

	if f.Country != "CN" {
		t.Errorf("Country = %q, want CN (aut-num's own country, not the preceding role object's AU)", f.Country)
	}
	if f.Updated != "2025-01-22T13:06:13Z" {
		t.Errorf("Updated = %q, want 2025-01-22T13:06:13Z (aut-num's own last-modified, not the preceding role object's 2013 value)", f.Updated)
	}
	// abuse-mailbox has no equivalent key inside the aut-num object itself
	// -- it must still be picked up from the irt object that follows
	// aut-num, confirming the fix didn't also break ordinary
	// first-occurrence-wins fallback for fields aut-num never carries.
	if f.AbuseEmail != "hqs-ipabuse@chinaunicom.cn" {
		t.Errorf("AbuseEmail = %q, want hqs-ipabuse@chinaunicom.cn (from the irt object after aut-num)", f.AbuseEmail)
	}
	if f.Name != "CHINA169-BJ" {
		t.Errorf("Name = %q, want CHINA169-BJ", f.Name)
	}
}

// TestParseASN_APNIC_FirstDescrWithinAutNumWins is a regression test for
// a real defect introduced by the fix above and caught during live
// verification against AS4608: the aut-num-always-wins rule was
// implemented as an unconditional overwrite, which meant the LAST
// occurrence of a repeated key within the aut-num object itself won, not
// the first. APNIC's aut-num object for AS4608 carries seven "descr:"
// lines -- the first is the real org name ("Asia Pacific Network
// Information Centre"), the remaining six are a multi-line postal
// address ending in "Australia". Unconditional overwrite reported
// "Australia" as OrgName. ParseASN must still apply first-occurrence-wins
// *within* the aut-num object; only a value belonging to some earlier,
// different object should ever be overwritten by aut-num's own data. See
// ParseASN's doc comment for the fromAutNum mechanism.
func TestParseASN_APNIC_FirstDescrWithinAutNumWins(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/whois/apnic-as4608.txt")
	if err != nil {
		t.Fatalf("reading golden: %v", err)
	}
	f := ParseASN(string(raw))

	if f.OrgName == "Australia" {
		t.Fatal("OrgName came from the aut-num object's last descr line (the postal address's country); want the first")
	}
	if f.OrgName != "Asia Pacific Network Information Centre" {
		t.Errorf("OrgName = %q, want Asia Pacific Network Information Centre (the aut-num object's first descr line)", f.OrgName)
	}
	// Country ("AU") is a genuinely separate key from the address's
	// trailing "descr: Australia" line, and must still come through
	// correctly -- confirming the fix didn't overcorrect into ignoring
	// aut-num's own country key entirely.
	if f.Country != "AU" {
		t.Errorf("Country = %q, want AU", f.Country)
	}
	if f.Name != "APNIC-SERVICES" {
		t.Errorf("Name = %q, want APNIC-SERVICES", f.Name)
	}
	if f.Handle != "AS4608" {
		t.Errorf("Handle = %q, want AS4608", f.Handle)
	}
}

func TestParseASN_EmptyInput(t *testing.T) {
	if got := ParseASN(""); !reflect.DeepEqual(got, ASNFields{}) {
		t.Errorf("ParseASN(\"\") = %+v, want the zero value", got)
	}
}

// TestParseASN_MultipleStatusLinesWithinAutNumAllAccumulate is a
// regression test for the Task-6 fromAutNum fix inverting status
// precedence: the fromAutNum[key] first-occurrence-wins short-circuit was
// applied uniformly to every synonym key, including "status", even
// though status is append-valued. A real aut-num object with two
// "status:" lines was silently truncated to just the first.
func TestParseASN_MultipleStatusLinesWithinAutNumAllAccumulate(t *testing.T) {
	raw := `aut-num:     AS64512
status:      ASSIGNED
status:      ROUTED
source:      TEST
`
	f := ParseASN(raw)
	if want := []string{"ASSIGNED", "ROUTED"}; !reflect.DeepEqual(f.Statuses, want) {
		t.Errorf("Statuses = %v, want %v (both status lines within aut-num must accumulate)", f.Statuses, want)
	}
}

// TestParseASN_StatusFromNonAutNumObjectIsSuppressed is the inverse
// regression: a "status:" line belonging to some other RPSL object (a
// role/person/organisation contact object) must never leak into
// f.Statuses, whether that object precedes or follows the aut-num
// object. Before the fix, "status" had no asnFieldGet entry, so it
// bypassed the aut-num-always-wins gate entirely and any object's status
// line was appended unconditionally.
func TestParseASN_StatusFromNonAutNumObjectIsSuppressed(t *testing.T) {
	raw := `role:        Some Contact
status:      BOGUS
source:      TEST

aut-num:     AS64512
status:      ASSIGNED
source:      TEST

role:        Another Contact
status:      ALSO-BOGUS
source:      TEST
`
	f := ParseASN(raw)
	if want := []string{"ASSIGNED"}; !reflect.DeepEqual(f.Statuses, want) {
		t.Errorf("Statuses = %v, want %v (only the aut-num object's own status, none of the surrounding role objects')", f.Statuses, want)
	}
}
