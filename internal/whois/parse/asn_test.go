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

func TestParseASN_EmptyInput(t *testing.T) {
	if got := ParseASN(""); !reflect.DeepEqual(got, ASNFields{}) {
		t.Errorf("ParseASN(\"\") = %+v, want the zero value", got)
	}
}
