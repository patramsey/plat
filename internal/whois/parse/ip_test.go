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
	if f.OrgName == "" {
		t.Error("OrgName is empty, want RIPE's descr/org value")
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
