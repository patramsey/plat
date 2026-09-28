package parse

import (
	"slices"
	"testing"
)

// WHOIS-only ccTLDs whose registered answers parsed to an empty record:
// no domain, registrar or nameservers, so a lookup showed nothing. Each
// fixture is the registry's real answer. See #112.
func TestParse_CCTLDFormats(t *testing.T) {
	for _, tt := range []struct {
		fixture, tld, domain, registrar string
		nameservers                     []string
		created, expires                string
	}{
		{fixture: "cidr-gg-recorded.txt", tld: "gg", domain: "nic.gg",
			registrar:   "Alderney Domains (http://www.channelisles.net)",
			nameservers: []string{"ns1.livedns.co.uk", "ns2.livedns.co.uk"}},
		{fixture: "cidr-je-recorded.txt", tld: "je", domain: "nic.je"},
		{fixture: "nicbo-bo-registered-recorded.txt", tld: "bo", domain: "nic.bo",
			created: "2004-11-19", expires: "2030-12-31"},
		{fixture: "dnslu-lu-registered-recorded.txt", tld: "lu", domain: "nic.lu",
			registrar: "Fondation Restena", nameservers: []string{"ns1.restena.lu", "ns2.restena.lu"}},
		{fixture: "isoc-il-recorded.txt", tld: "il", domain: "isoc.org.il",
			registrar: "Israel Internet Association ISOC-IL"},
		{fixture: "nicit-it-google-recorded.txt", tld: "it", domain: "google.it",
			registrar: "MarkMonitor International Limited"},
	} {
		t.Run(tt.tld, func(t *testing.T) {
			f := Parse(loadFixture(t, tt.fixture), tt.tld)
			if f.Domain != tt.domain {
				t.Errorf("Domain = %q, want %q", f.Domain, tt.domain)
			}
			if tt.registrar != "" && f.Registrar != tt.registrar {
				t.Errorf("Registrar = %q, want %q", f.Registrar, tt.registrar)
			}
			if tt.nameservers != nil && !slices.Equal(f.Nameservers, tt.nameservers) {
				t.Errorf("Nameservers = %v, want %v", f.Nameservers, tt.nameservers)
			}
			if tt.nameservers == nil && len(f.Nameservers) == 0 && tt.tld != "bo" {
				t.Error("Nameservers empty")
			}
			if tt.created != "" && (f.Created.Raw != tt.created || !f.Created.Parsed) {
				t.Errorf("Created = %+v, want Parsed %q", f.Created, tt.created)
			}
			if tt.expires != "" && (f.Expires.Raw != tt.expires || !f.Expires.Parsed) {
				t.Errorf("Expires = %+v, want Parsed %q", f.Expires, tt.expires)
			}
			if f.NotFound || f.Unsupported {
				t.Errorf("NotFound=%v Unsupported=%v for a registered answer", f.NotFound, f.Unsupported)
			}
		})
	}
}

// ISOC-IL answers a name with no record with its terms of use and
// nothing else, so a free .il name read as registered (exit 0).
func TestParse_ILCommentOnlyAnswerIsNotFound(t *testing.T) {
	if f := Parse(loadFixture(t, "isoc-il-notfound-recorded.txt"), "il"); !f.NotFound {
		t.Error("NotFound = false for ISOC-IL's comment-only answer")
	}
}

// .lu rate-limits with "%% Maximum query rate reached", which matched no
// marker, so a rate-limited lookup showed as an empty success.
func TestParse_LURateLimit(t *testing.T) {
	if f := Parse(loadFixture(t, "dnslu-lu-ratelimited-recorded.txt"), "lu"); !f.RateLimited {
		t.Error("RateLimited = false for .lu's \"Maximum query rate reached\"")
	}
}
