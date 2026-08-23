package parse

import (
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
	{tld: "de", fixture: "denic-de-example.txt", wantDomain: "example.de", wantNSCount: 2},
	{tld: "jp", fixture: "jprs-jp-example.txt", wantDomain: "EXAMPLE.JP", wantNSCount: 2},
	{tld: "uk", fixture: "nominet-uk-example.txt", wantDomain: "example.uk", wantNSCount: 2},
	{tld: "eu", fixture: "eurid-eu-recorded.txt", wantDomain: "europa.eu", wantNSCount: 12},
	{tld: "fr", fixture: "afnic-fr-example.txt", wantDomain: "example.fr", wantNSCount: 2},
	{tld: "nl", fixture: "sidn-nl-example.txt", wantDomain: "example.nl", wantNSCount: 2},
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
	raw := loadFixture(t, "denic-de-example.txt")
	f := Parse(raw, "de")

	if f.Domain != "example.de" {
		t.Errorf("Domain = %q, want example.de", f.Domain)
	}
	wantNS := []string{"ns1.example.de", "ns2.example.de"}
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
	raw := loadFixture(t, "jprs-jp-example.txt")
	f := Parse(raw, "jp")

	if f.Domain != "EXAMPLE.JP" {
		t.Errorf("Domain = %q, want EXAMPLE.JP", f.Domain)
	}
	wantNS := []string{"a.dns.jp", "b.dns.jp"}
	if len(f.Nameservers) != len(wantNS) {
		t.Fatalf("Nameservers = %v, want %v (brackets dialect should tokenize [Name Server] lines)", f.Nameservers, wantNS)
	}
	if !f.Created.Parsed || f.Created.Raw != "1995/08/14" {
		t.Errorf("Created = %+v", f.Created)
	}
	if !f.Expires.Parsed || f.Expires.Raw != "2026/08/13" {
		t.Errorf("Expires = %+v", f.Expires)
	}
}

func TestParse_DefaultTemplateForUnknownTLD(t *testing.T) {
	raw := loadFixture(t, "verisign-com-example.txt")
	f := Parse(raw, "xyz-unregistered-tld")
	if f.Domain != "EXAMPLE.COM" {
		t.Errorf("Domain = %q, want EXAMPLE.COM (unknown TLD should fall back to generic kv dialect)", f.Domain)
	}
}

func TestParse_FRSynonymOverride(t *testing.T) {
	raw := loadFixture(t, "afnic-fr-example.txt")
	f := Parse(raw, "fr")

	if !f.Expires.Parsed || f.Expires.Raw != "2026-08-13T04:00:00Z" {
		t.Errorf("Expires = %+v, want Parsed with Raw 2026-08-13T04:00:00Z (synonym override for 'Expiry Date' -> expires)", f.Expires)
	}
}

func TestParse_NLIndentedNameserverBlock(t *testing.T) {
	raw := loadFixture(t, "sidn-nl-example.txt")
	f := Parse(raw, "nl")

	if f.Domain != "example.nl" {
		t.Errorf("Domain = %q, want example.nl", f.Domain)
	}
	wantNS := []string{"ns1.example.nl", "ns2.example.nl"}
	if len(f.Nameservers) != len(wantNS) {
		t.Errorf("Nameservers = %v, want %v", f.Nameservers, wantNS)
	}
}
