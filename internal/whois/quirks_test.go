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
