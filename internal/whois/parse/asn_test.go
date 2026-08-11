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

func TestParseASN_EmptyInput(t *testing.T) {
	if got := ParseASN(""); !reflect.DeepEqual(got, ASNFields{}) {
		t.Errorf("ParseASN(\"\") = %+v, want the zero value", got)
	}
}
