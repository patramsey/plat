package domain

import (
	"slices"
	"testing"
)

func TestKnownTLD(t *testing.T) {
	for _, tc := range []struct {
		tld  string
		want bool
	}{
		{"com", true},
		{"uk", true},
		{"xn--p1ai", true}, // .рф
		{"ck", true},       // known only through the wildcard rule *.ck
		{"gr", true},       // real, though IANA lists no server for it
		{"comm", false},
		{"notarealtld", false},
	} {
		if got := KnownTLD(tc.tld); got != tc.want {
			t.Errorf("KnownTLD(%q) = %v, want %v", tc.tld, got, tc.want)
		}
	}
}

func TestSuggestTLDs(t *testing.T) {
	for _, tc := range []struct {
		tld  string
		want []string
	}{
		{"comm", []string{"com"}},            // insertion
		{"cmo", []string{"com", "co", "mo"}}, // swap first, common TLDs first
		{"ogr", []string{"org", "gr"}},
		{"nett", []string{"net", "ntt", "next"}},
		{"notarealtld", nil},
	} {
		if got := SuggestTLDs(tc.tld); !slices.Equal(got, tc.want) {
			t.Errorf("SuggestTLDs(%q) = %v, want %v", tc.tld, got, tc.want)
		}
	}
}
