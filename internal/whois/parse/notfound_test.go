package parse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A 2026-09-27 sweep of every country-code TLD found 74 free names that
// plat reported as registered (exit 0): each registry's not-found wording
// matched no marker, so the answer counted as a successful, empty lookup.
// Each fixture is that registry's real answer for a name that does not
// exist. See #113.
func TestParse_CCTLDNotFoundWordings(t *testing.T) {
	for _, fixture := range []string{
		"cocca-ke-notfound-recorded.txt",    // The queried object does not exist: No Object Found
		"cocca-pe-notfound-recorded.txt",    // Domain Status: No Object Found
		"cocca-sr-notfound-recorded.txt",    // Message: No Object Found
		"jwhois-tg-notfound-recorded.txt",   // NO OBJECT FOUND! ... type: domain
		"jwhois-mq-notfound-recorded.txt",   // the same, JWhoisServer's other layout
		"tucows-in-notfound-recorded.txt",   // Domain ... is available for registration
		"nicar-ar-notfound-recorded.txt",    // El dominio no se encuentra registrado
		"nicat-at-notfound-recorded.txt",    // % nothing found
		"register-bg-notfound-recorded.txt", // registration status: available
		"cctld-by-notfound-recorded.txt",    // object does not exist
		"hkirc-hk-notfound-recorded.txt",    // The domain has not been registered.
		"kaznic-kz-notfound-recorded.txt",   // *** Nothing found for this query.
		"nic-ls-notfound-recorded.txt",      // No record found for '...'
		"dnslu-lu-notfound-recorded.txt",    // % No such domain
		"nicmx-mx-notfound-recorded.txt",    // No_Se_Encontro_El_Objeto/Object_Not_Found
		"pknic-pk-notfound-recorded.txt",    // Status: Not Registered, and may be available
		"nask-pl-notfound-recorded.txt",     // No information available about domain name
		"rnids-rs-notfound-recorded.txt",    // %ERROR:103: Domain is not registered
		"nictm-tm-notfound-recorded.txt",    // Domain ... is available for purchase
		"twnic-tw-notfound-recorded.txt",    // No Found
		"ws-notfound-recorded.txt",          // The queried object does not exist: <name>.
		"nicbo-bo-notfound-recorded.txt",    // .bo footer and nothing else (#116)
	} {
		t.Run(fixture, func(t *testing.T) {
			f := Parse(loadFixture(t, fixture), "")
			if !f.NotFound {
				t.Error("NotFound = false; a free name would be reported as registered")
			}
		})
	}
}

func TestParse_CCTLDRateLimitAndRefusal(t *testing.T) {
	if f := Parse(loadFixture(t, "aw-ratelimited-recorded.txt"), ""); !f.RateLimited {
		t.Error("\"Error: ratelimit exceeded\" not recognised as a rate limit")
	}
	for _, fixture := range []string{
		"freenom-gq-refused-recorded.txt", // This TLD has no whois server.
	} {
		f := Parse(loadFixture(t, fixture), "")
		if !f.Unsupported {
			t.Errorf("%s: Unsupported = false, want a refused query", fixture)
		}
		if f.NotFound {
			t.Errorf("%s: NotFound = true; a refusal says nothing about the name", fixture)
		}
	}
}

// JWhoisServer prints "NO OBJECT FOUND!" for each missing contact inside
// a registered domain's answer, so that phrase alone cannot mean the
// domain is free. Only a missing object of type domain does.
func TestParse_JWhoisRegisteredWithMissingContactsIsFound(t *testing.T) {
	f := Parse(loadFixture(t, "jwhois-mq-registered-recorded.txt"), "")
	if f.NotFound {
		t.Error("NotFound = true for registered nic.mq; its missing contacts are not the domain")
	}
	if f.Domain != "nic.mq" {
		t.Errorf("Domain = %q, want nic.mq", f.Domain)
	}
}

// No registered answer in testdata may trip a not-found, refusal,
// rate-limit or restricted marker: a marker that does makes a taken domain look free.
// Every fixture whose name does not say otherwise is a registered answer.
func TestParse_NoRegisteredFixtureTripsAMarker(t *testing.T) {
	paths, err := filepath.Glob("../../../testdata/whois/*.txt")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no fixtures found: %v", err)
	}
	checked := 0
	for _, p := range paths {
		name := filepath.Base(p)
		if strings.Contains(name, "notfound") || strings.Contains(name, "ratelimited") ||
			strings.Contains(name, "refused") || strings.Contains(name, "not-supported") ||
			strings.Contains(name, "restricted") {
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		f := Parse(string(raw), "")
		if f.NotFound || f.RateLimited || f.Unsupported || f.Restricted {
			t.Errorf("%s: NotFound=%v RateLimited=%v Unsupported=%v Restricted=%v, want all false for a registered answer",
				name, f.NotFound, f.RateLimited, f.Unsupported, f.Restricted)
		}
		checked++
	}
	if checked < 20 {
		t.Errorf("checked only %d registered fixtures; the name filter is too broad", checked)
	}
}

// Some registries answer that a name is reserved, prohibited or otherwise
// restricted: neither registered nor available. Those answers matched no
// marker and counted as a registered domain with no fields (exit 0). They
// must not read as "not registered" either, which would suggest the name
// is free. See #111.
func TestParse_RestrictedNames(t *testing.T) {
	for _, fixture := range []string{
		"uganda-ug-restricted-recorded.txt",    // This domain violates registry policy.
		"dm-restricted-recorded.txt",           // Domain name matches a restricted word
		"bocra-bw-restricted-recorded.txt",     // Prohibited String - Domain Cannot Be Registered
		"qdr-qa-restricted-recorded.txt",       // Reserved by QDR
		"qdr-qa-nic-restricted-recorded.txt",   // The Domain Name is not Available
		"om-nic-restricted-recorded.txt",       // Reserved Domain Name
		"cira-ca-nic-restricted-recorded.txt",  // ...has usage restrictions applied to it
		"cnnic-cn-nic-restricted-recorded.txt", // ...can not be registered online
		"hkirc-hk-nic-restricted-recorded.txt", // currently not available for registration
		"pknic-pk-nic-restricted-recorded.txt", // This domain cannot be registered because of...
	} {
		t.Run(fixture, func(t *testing.T) {
			f := Parse(loadFixture(t, fixture), "")
			if !f.Restricted {
				t.Error("Restricted = false; a reserved name would be reported as registered")
			}
			if f.NotFound {
				t.Error("NotFound = true; a reserved name would be reported as free")
			}
		})
	}
}

// .bo ends every answer with "whois.nic.bo solo acepta consultas con
// dominios .bo" -- a registered domain's full record included. v0.9.0
// took that footer for a refusal, so every registered .bo domain failed
// (exit 3; .bo has no RDAP). Only an answer that is the footer and
// nothing else means there is no record. See #116.
func TestParse_BOFooterIsNotARefusal(t *testing.T) {
	f := Parse(loadFixture(t, "nicbo-bo-registered-recorded.txt"), "bo")
	if f.Unsupported || f.NotFound {
		t.Errorf("Unsupported=%v NotFound=%v for registered nic.bo; its footer is boilerplate", f.Unsupported, f.NotFound)
	}
}
