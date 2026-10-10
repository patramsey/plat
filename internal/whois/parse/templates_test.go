package parse

import (
	"slices"
	"strings"
	"testing"
)

// templateManifest is the single source of truth this milestone
// establishes for "every registered ccTLD template must have a fixture
// that parses to expected canonical fields." Adding a template without
// adding a row here (or adding a row without registering the template)
// fails this test — that's the intended regression guard: a missing
// fixture can't silently pass.
var templateManifest = []struct {
	tld         string
	fixture     string
	wantDomain  string
	wantNSCount int
}{
	{tld: "de", fixture: "denic-de-recorded.txt", wantDomain: "denic.de", wantNSCount: 4},
	{tld: "jp", fixture: "jprs-jp-google-recorded.txt", wantDomain: "GOOGLE.JP", wantNSCount: 4},
	{tld: "uk", fixture: "nominet-uk-recorded.txt", wantDomain: "bbc.co.uk", wantNSCount: 8},
	{tld: "eu", fixture: "eurid-eu-recorded.txt", wantDomain: "europa.eu", wantNSCount: 12},
	{tld: "fr", fixture: "afnic-fr-recorded.txt", wantDomain: "nic.fr", wantNSCount: 4},
	{tld: "nl", fixture: "sidn-nl-google-recorded.txt", wantDomain: "google.nl", wantNSCount: 4},
	{tld: "cz", fixture: "cznic-cz-seznam-recorded.txt", wantDomain: "seznam.cz", wantNSCount: 2},
	{tld: "br", fixture: "registrobr-br-google-recorded.txt", wantDomain: "google.com.br", wantNSCount: 4},
	{tld: "mx", fixture: "nicmx-mx-recorded.txt", wantDomain: "nic.mx", wantNSCount: 3},
	{tld: "be", fixture: "dnsbe-be-recorded.txt", wantDomain: "dns.be", wantNSCount: 4},
	{tld: "it", fixture: "nicit-it-google-recorded.txt", wantDomain: "google.it", wantNSCount: 4},
	{tld: "at", fixture: "nicat-at-recorded.txt", wantDomain: "nic.at", wantNSCount: 5},
	{tld: "gg", fixture: "cidr-gg-recorded.txt", wantDomain: "nic.gg", wantNSCount: 2},
	{tld: "je", fixture: "cidr-je-recorded.txt", wantDomain: "nic.je", wantNSCount: 2},
	{tld: "bo", fixture: "nicbo-bo-registered-recorded.txt", wantDomain: "nic.bo", wantNSCount: 0},
	{tld: "lu", fixture: "dnslu-lu-registered-recorded.txt", wantDomain: "nic.lu", wantNSCount: 2},
	{tld: "il", fixture: "isoc-il-recorded.txt", wantDomain: "isoc.org.il", wantNSCount: 1},
	{tld: "pl", fixture: "nask-pl-google-recorded.txt", wantDomain: "google.pl", wantNSCount: 4},
	{tld: "mq", fixture: "jwhois-mq-registered-recorded.txt", wantDomain: "nic.mq", wantNSCount: 2},
	{tld: "ar", fixture: "nicar-ar-recorded.txt", wantDomain: "nic.ar", wantNSCount: 4},
	{tld: "cr", fixture: "nic-cr-recorded.txt", wantDomain: "nic.cr", wantNSCount: 6},
	{tld: "ls", fixture: "nic-ls-recorded.txt", wantDomain: "nic.ls", wantNSCount: 2},
	{tld: "mk", fixture: "marnet-mk-recorded.txt", wantDomain: "nic.mk", wantNSCount: 3},
	{tld: "mw", fixture: "nic-mw-recorded.txt", wantDomain: "nic.mw", wantNSCount: 4},
	{tld: "tz", fixture: "tznic-tz-recorded.txt", wantDomain: "nic.tz", wantNSCount: 2},
	{tld: "ve", fixture: "nic-ve-recorded.txt", wantDomain: "nic.ve", wantNSCount: 4},
	{tld: "ee", fixture: "tld-ee-recorded.txt", wantDomain: "nic.ee", wantNSCount: 3},
	{tld: "ua", fixture: "hostmaster-ua-recorded.txt", wantDomain: "nic.ua", wantNSCount: 2},
}

func TestTemplateManifest_EveryRegisteredTemplateHasAFixture(t *testing.T) {
	seen := map[string]bool{}
	for _, row := range templateManifest {
		seen[row.tld] = true
		t.Run(row.tld, func(t *testing.T) {
			raw := loadFixture(t, row.fixture)
			f := Parse(raw, row.tld)
			if f.Domain != row.wantDomain {
				t.Errorf("Domain = %q, want %q", f.Domain, row.wantDomain)
			}
			if len(f.Nameservers) != row.wantNSCount {
				t.Errorf("Nameservers = %v, want %d entries", f.Nameservers, row.wantNSCount)
			}
		})
	}
	for tld := range templates {
		if !seen[tld] {
			t.Errorf("template %q is registered in templates.yaml but has no row in templateManifest — every registered template must have a manifest entry with a fixture", tld)
		}
	}
	if len(templates) == 0 {
		t.Fatal("no templates loaded from embedded YAML")
	}
}

func TestParse_DENICSynonymOverride(t *testing.T) {
	raw := loadFixture(t, "denic-de-recorded.txt")
	f := Parse(raw, "de")

	if f.Domain != "denic.de" {
		t.Errorf("Domain = %q, want denic.de", f.Domain)
	}
	wantNS := []string{"ns1.denic.de", "ns2.denic.de", "ns3.denic.de", "ns4.denic.net"}
	if len(f.Nameservers) != len(wantNS) {
		t.Fatalf("Nameservers = %v, want %v", f.Nameservers, wantNS)
	}
	if len(f.Statuses) != 1 || f.Statuses[0] != "connect" {
		t.Errorf("Statuses = %v, want [connect]", f.Statuses)
	}
	if !f.Updated.Parsed {
		t.Fatalf("Updated not parsed (synonym override for 'changed' -> updated failed): %+v", f.Updated)
	}
}

func TestParse_EURIDNestedRegistrarSynonymOverride(t *testing.T) {
	// EURid's real format nests the registrar name under a sub-key
	// ("Registrar:" itself has no value; the name is on the next line's
	// "Name:") -- the generic kv tokenizer treats "Name:" as its own
	// pair (key "name"), which isn't a registrar synonym anywhere else
	// (too generic/ambiguous to add globally), so without a eu-specific
	// override it lands in Unmapped instead of populating Registrar.
	raw := loadFixture(t, "eurid-eu-recorded.txt")
	f := Parse(raw, "eu")

	if f.Domain != "europa.eu" {
		t.Errorf("Domain = %q, want europa.eu", f.Domain)
	}
	if f.Registrar != "ClearMedia NV" {
		t.Errorf("Registrar = %q, want %q (synonym override for 'name' -> registrar failed)", f.Registrar, "ClearMedia NV")
	}
}

func TestParse_EURIDNoNameserverLinesInUnmapped(t *testing.T) {
	// Pins the property, not just the count: an indented "host (glue)"
	// line that fails to tokenize as a nameserver doesn't vanish
	// silently, it lands in Unmapped under a garbage key that still
	// contains the glue's opening paren (e.g. "ns4az1.europa.eu (2a05"
	// when the first colon inside an IPv6 address was mistaken for the
	// key/value separator). Checking for that here means a future
	// recording whose glue shape breaks tokenizeIndent again -- even if
	// dedup happens to keep wantNSCount unchanged, as it did the first
	// time this bug was found -- still fails loudly instead of passing
	// green on a coincidence.
	raw := loadFixture(t, "eurid-eu-recorded.txt")
	f := Parse(raw, "eu")

	for key := range f.Unmapped {
		if strings.Contains(key, "(") {
			t.Errorf("a Name servers line leaked into Unmapped under host-shaped key %q", key)
		}
	}
}

func TestParse_EURIDHasNoStatusOrDates(t *testing.T) {
	// Verified live against whois.eu: EURid's response for a domain has
	// no top-level Status field and no Created/Updated/Expires fields at
	// all -- unlike most registries, it simply never publishes them over
	// WHOIS. Statuses/Created/Updated/Expires must come back empty here
	// because the registry doesn't say, not because plat failed to parse
	// something that was there.
	raw := loadFixture(t, "eurid-eu-recorded.txt")
	f := Parse(raw, "eu")

	if len(f.Statuses) != 0 {
		t.Errorf("Statuses = %v, want none (EURid publishes no status over WHOIS)", f.Statuses)
	}
	if f.Created.Parsed {
		t.Errorf("Created = %+v, want unparsed (EURid publishes no creation date over WHOIS)", f.Created)
	}
	if f.Updated.Parsed {
		t.Errorf("Updated = %+v, want unparsed (EURid publishes no update date over WHOIS)", f.Updated)
	}
	if f.Expires.Parsed {
		t.Errorf("Expires = %+v, want unparsed (EURid publishes no expiry date over WHOIS)", f.Expires)
	}
}

func TestParse_JPRSBracketDialect(t *testing.T) {
	raw := loadFixture(t, "jprs-jp-google-recorded.txt")
	f := Parse(raw, "jp")

	if f.Domain != "GOOGLE.JP" {
		t.Errorf("Domain = %q, want GOOGLE.JP", f.Domain)
	}
	wantNS := []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"}
	if !slices.Equal(f.Nameservers, wantNS) {
		t.Fatalf("Nameservers = %v, want %v (brackets dialect should tokenize [Name Server] lines)", f.Nameservers, wantNS)
	}
	if !f.Created.Parsed || f.Created.Raw != "2005/05/30" {
		t.Errorf("Created = %+v", f.Created)
	}
	if !f.Expires.Parsed || f.Expires.Raw != "2027/05/31" {
		t.Errorf("Expires = %+v", f.Expires)
	}
	// JPRS's "(JST)" timestamps are rewritten to +09:00 before parsing.
	if !f.Updated.Parsed || f.Updated.Raw != "2026/06/01 01:05:03 (JST)" {
		t.Errorf("Updated = %+v", f.Updated)
	}
}

func TestParse_DefaultTemplateForUnknownTLD(t *testing.T) {
	raw := loadFixture(t, "verisign-com-google-recorded.txt")
	f := Parse(raw, "xyz-unregistered-tld")
	if f.Domain != "GOOGLE.COM" {
		t.Errorf("Domain = %q, want GOOGLE.COM (unknown TLD should fall back to generic kv dialect)", f.Domain)
	}
}

func TestParse_FRSynonymOverride(t *testing.T) {
	raw := loadFixture(t, "afnic-fr-recorded.txt")
	f := Parse(raw, "fr")

	if !f.Expires.Parsed || f.Expires.Raw != "2029-12-31T23:00:00Z" {
		t.Errorf("Expires = %+v, want Parsed with Raw 2029-12-31T23:00:00Z (synonym override for 'Expiry Date' -> expires)", f.Expires)
	}
	// AFNIC lists the domain's own record first, then its contacts' --
	// each with its own "registrar:" -- so first-occurrence-wins matters.
	if f.Domain != "nic.fr" || f.Registrar != "Registry Operations" {
		t.Errorf("Domain/Registrar = %q/%q, want nic.fr/Registry Operations", f.Domain, f.Registrar)
	}
}

// Real SIDN output puts the registrar and nameservers on indented lines
// under "Registrar:" and "Domain nameservers:" headers. The kv tokenizer
// skipped both, so google.nl had no registrar or nameservers. The
// fixture this test used before was written with flat
// "Domain nameservers: x" lines SIDN never sends, which is how that hid.
func TestParse_NLIndentedSections(t *testing.T) {
	f := Parse(loadFixture(t, "sidn-nl-google-recorded.txt"), "nl")
	if f.Domain != "google.nl" {
		t.Errorf("Domain = %q, want google.nl", f.Domain)
	}
	if f.Registrar != "MarkMonitor Inc." {
		t.Errorf("Registrar = %q, want MarkMonitor Inc. (the first line under Registrar:, not its address)", f.Registrar)
	}
	wantNS := []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"}
	if !slices.Equal(f.Nameservers, wantNS) {
		t.Errorf("Nameservers = %v, want %v", f.Nameservers, wantNS)
	}
	if f.Created.Raw != "1999-05-27" || f.Updated.Raw != "2025-04-18" {
		t.Errorf("Created/Updated = %q/%q, want 1999-05-27/2025-04-18", f.Created.Raw, f.Updated.Raw)
	}
}
