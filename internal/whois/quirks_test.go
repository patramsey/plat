package whois

import "testing"

func TestBuildQuery(t *testing.T) {
	tests := []struct {
		name   string
		server string
		domain string
		want   string
	}{
		{"verisign prefix", "whois.verisign-grs.com", "example.com", "domain example.com"},
		{"verisign prefix with port", "whois.verisign-grs.com:43", "example.com", "domain example.com"},
		{"jprs suffix", "whois.jprs.jp", "example.jp", "example.jp/e"},
		{"denic prefix", "whois.denic.de", "example.de", "-T dn,ace example.de"},
		{"unknown server default", "whois.example-registry.example", "example.tld", "example.tld"},
		{"local test address default", "127.0.0.1:54321", "example.com", "example.com"},
		{
			// A host that merely ends with the same characters as a known
			// registry host, but isn't actually a subdomain of it, must
			// not get that registry's quirk applied -- strings.HasSuffix
			// alone can't tell "evildenic.de" apart from a genuine
			// "*.denic.de" host.
			"host merely ending in a quirk suffix is not a label match",
			"whois.evildenic.de", "example.de", "example.de",
		},
		{
			"genuine subdomain of a quirk host still matches",
			"backup.denic.de", "example.de", "-T dn,ace example.de",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildQuery(tt.server, tt.domain)
			if got != tt.want {
				t.Errorf("BuildQuery(%q, %q) = %q, want %q", tt.server, tt.domain, got, tt.want)
			}
		})
	}
}

// A bare ARIN query for an address inside nested networks returns only a
// one-line-per-network summary with no key/value record, which parsed to
// an empty "ok" source. "n + " asks for the full record of every match.
// It is for IP queries only: "n" means network, so an ASN or domain
// query must stay bare.
func TestBuildIPQuery(t *testing.T) {
	for _, tt := range []struct{ server, want string }{
		{"whois.arin.net", "n + 12.0.0.1"},
		{"whois.arin.net:43", "n + 12.0.0.1"},
		{"whois.ripe.net", "12.0.0.1"},
		{"127.0.0.1:54321", "12.0.0.1"},
	} {
		if got := BuildIPQuery(tt.server, "12.0.0.1"); got != tt.want {
			t.Errorf("BuildIPQuery(%q) = %q, want %q", tt.server, got, tt.want)
		}
	}
	if got := BuildQuery("whois.arin.net", "AS15169"); got != "AS15169" {
		t.Errorf("BuildQuery(arin, AS15169) = %q, want the bare ASN", got)
	}
}
