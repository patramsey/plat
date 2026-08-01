package collect

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/whois"
	"github.com/patramsey/plat/internal/whois/parse"
)

var errDeadline = context.DeadlineExceeded

func loadWHOISFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../testdata/whois/" + name)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return string(b)
}

func TestFromWHOIS_RegistryAndRegistrarHops(t *testing.T) {
	registryRaw := loadWHOISFixture(t, "verisign-com-example.txt")
	registrarRaw := "Domain Name: example.com\nRegistrant Organization: Example Corp\nRegistrar: Example Registrar, Inc.\n"

	result := &whois.Result{
		Domain: "example.com",
		Hops: []whois.Hop{
			{Server: "whois.iana.org", Latency: 5 * time.Millisecond}, // IANA hop — not a data source
			{Server: "whois.verisign-grs.com", Raw: registryRaw, Fields: parse.Parse(registryRaw, "com"), Latency: 20 * time.Millisecond},
			{Server: "whois.example-registrar.example", Raw: registrarRaw, Fields: parse.Parse(registrarRaw, "com"), Latency: 15 * time.Millisecond},
		},
	}

	sources := FromWHOIS(result)

	if len(sources) != 2 {
		t.Fatalf("FromWHOIS returned %d sources, want 2 (IANA hop skipped)", len(sources))
	}
	if sources[0].Meta.Source != model.SourceRegistryWHOIS {
		t.Errorf("sources[0].Meta.Source = %q, want %q", sources[0].Meta.Source, model.SourceRegistryWHOIS)
	}
	if sources[1].Meta.Source != model.SourceRegistrarWHOIS {
		t.Errorf("sources[1].Meta.Source = %q, want %q", sources[1].Meta.Source, model.SourceRegistrarWHOIS)
	}
	if sources[0].Registrar.IANAID != "1234" {
		t.Errorf("registry hop Registrar.IANAID = %q, want %q (read from Fields.Unmapped)", sources[0].Registrar.IANAID, "1234")
	}
	if sources[0].Registrar.AbuseEmail != "abuse@example-registrar.example" {
		t.Errorf("registry hop Registrar.AbuseEmail = %q, want %q", sources[0].Registrar.AbuseEmail, "abuse@example-registrar.example")
	}
	if sources[1].Registrar.Name != "Example Registrar, Inc." {
		t.Errorf("registrar hop Registrar.Name = %q, want %q", sources[1].Registrar.Name, "Example Registrar, Inc.")
	}
}

func TestFromWHOIS_RedactedRegistrant(t *testing.T) {
	raw := loadWHOISFixture(t, "gdpr-redacted-de.txt")
	result := &whois.Result{
		Domain: "example.de",
		Hops: []whois.Hop{
			{Server: "whois.iana.org"},
			{Server: "whois.denic.de", Raw: raw, Fields: parse.Parse(raw, "de")},
		},
	}

	sources := FromWHOIS(result)
	if len(sources) != 1 {
		t.Fatalf("FromWHOIS returned %d sources, want 1 (registry hop only)", len(sources))
	}
	if sources[0].Registrar.Name != "" {
		t.Errorf("Registrar.Name = %q, want empty (value should be redacted, not surfaced)", sources[0].Registrar.Name)
	}
	if !sources[0].RedactedFields[model.FieldRegistrarName] {
		t.Error("expected RedactedFields[registrar.name] = true")
	}
}

func TestFromWHOIS_HopError(t *testing.T) {
	result := &whois.Result{
		Domain: "example.com",
		Hops: []whois.Hop{
			{Server: "whois.iana.org"},
			{Server: "whois.verisign-grs.com", Err: errDeadline},
		},
	}
	sources := FromWHOIS(result)
	if len(sources) != 1 {
		t.Fatalf("FromWHOIS returned %d sources, want 1", len(sources))
	}
	if sources[0].Present {
		t.Error("expected Present = false for a failed hop")
	}
	if sources[0].Meta.OK {
		t.Error("expected Meta.OK = false for a failed hop")
	}
}

func TestFromWHOIS_TooFewHops(t *testing.T) {
	if got := FromWHOIS(&whois.Result{Hops: []whois.Hop{{Server: "whois.iana.org"}}}); len(got) != 0 {
		t.Errorf("FromWHOIS with only an IANA hop = %v, want empty", got)
	}
	if got := FromWHOIS(nil); len(got) != 0 {
		t.Errorf("FromWHOIS(nil) = %v, want empty", got)
	}
}

func TestFromWHOIS_NotFoundHop(t *testing.T) {
	raw := loadWHOISFixture(t, "notfound.txt")
	result := &whois.Result{
		Domain: "nonexistent-domain-xyz.com",
		Hops: []whois.Hop{
			{Server: "whois.iana.org"},
			{Server: "whois.verisign-grs.com", Raw: raw, Fields: parse.Parse(raw, "com")},
		},
	}
	sources := FromWHOIS(result)
	if len(sources) != 1 {
		t.Fatalf("FromWHOIS returned %d sources, want 1", len(sources))
	}
	if !sources[0].Meta.NotFound {
		t.Error("Meta.NotFound = false, want true")
	}
	if sources[0].Meta.OK {
		t.Error("Meta.OK = true, want false for a not-found WHOIS hop")
	}
}

func TestFromWHOIS_UnsupportedHop(t *testing.T) {
	// Reproduces Identity Digital's shared WHOIS refusing .ninja outright
	// ("TLD is not supported.") rather than either domain data or a
	// registrar referral. This must NOT be reported as NotFound: the
	// service refusing the query says nothing about whether the domain
	// exists, unlike a genuine "no match" response.
	raw := loadWHOISFixture(t, "tld-not-supported.txt")
	result := &whois.Result{
		Domain: "fro.ninja",
		Hops: []whois.Hop{
			{Server: "whois.iana.org"},
			{Server: "whois.nic.ninja", Raw: raw, Fields: parse.Parse(raw, "ninja")},
		},
	}
	sources := FromWHOIS(result)
	if len(sources) != 1 {
		t.Fatalf("FromWHOIS returned %d sources, want 1", len(sources))
	}
	if sources[0].Meta.OK {
		t.Error("Meta.OK = true, want false: the registry refused the query")
	}
	if sources[0].Meta.NotFound {
		t.Error("Meta.NotFound = true, want false: a refused query is not a confirmed non-existence claim")
	}
	if sources[0].Meta.Err == "" {
		t.Error("Meta.Err is empty, want a diagnostic message explaining the refusal (surfaced in -v output)")
	}
	if sources[0].Present {
		t.Error("Present = true, want false: no usable data was extracted")
	}
}

func TestFromWHOIS_RateLimitedHop(t *testing.T) {
	// A rate-limit refusal ("Query rate limit exceeded...") must not be
	// reported as OK/Present: the server refused to answer, it didn't
	// confirm an empty-but-valid record. Same shape as the Unsupported
	// case above -- fromHop previously checked Unsupported but not
	// RateLimited, so this fell through to Meta.OK=true with all fields
	// empty, indistinguishable from a genuine successful lookup.
	raw := loadWHOISFixture(t, "ratelimited.txt")
	result := &whois.Result{
		Domain: "example.com",
		Hops: []whois.Hop{
			{Server: "whois.iana.org"},
			{Server: "whois.example-registry.example", Raw: raw, Fields: parse.Parse(raw, "com")},
		},
	}
	sources := FromWHOIS(result)
	if len(sources) != 1 {
		t.Fatalf("FromWHOIS returned %d sources, want 1", len(sources))
	}
	if sources[0].Meta.OK {
		t.Error("Meta.OK = true, want false: the server refused the query due to rate limiting")
	}
	if sources[0].Meta.NotFound {
		t.Error("Meta.NotFound = true, want false: a rate-limit refusal is not a confirmed non-existence claim")
	}
	if sources[0].Meta.Err == "" {
		t.Error("Meta.Err is empty, want a diagnostic message explaining the rate limit (surfaced in -v output)")
	}
	if sources[0].Present {
		t.Error("Present = true, want false: no usable data was extracted")
	}
}

// TestFromWHOIS_IANAHopNetworkErrorIsSurfaced covers the case the
// TestFromWHOIS_TooFewHops case above doesn't: an IANA hop that failed
// outright (DNS failure, connection refused, deadline exceeded), not one
// that succeeded with no referral. Both used to produce zero
// SourceRecords via the same len(Hops) < 2 guard, making a genuine
// network failure indistinguishable from "this TLD has no WHOIS
// coverage" -- unlike the RDAP branch, which always surfaces a fetch
// error as its own SourceRecord (see FromRDAP).
func TestFromWHOIS_IANAHopNetworkErrorIsSurfaced(t *testing.T) {
	result := &whois.Result{
		Domain: "example.com",
		Hops: []whois.Hop{
			{Server: "whois.iana.org", Err: errDeadline},
		},
	}
	sources := FromWHOIS(result)
	if len(sources) != 1 {
		t.Fatalf("FromWHOIS returned %d sources, want 1 (the failed IANA hop surfaced as registry-whois)", len(sources))
	}
	if sources[0].Meta.Source != model.SourceRegistryWHOIS {
		t.Errorf("sources[0].Meta.Source = %q, want %q", sources[0].Meta.Source, model.SourceRegistryWHOIS)
	}
	if sources[0].Meta.OK {
		t.Error("Meta.OK = true, want false: the IANA hop itself failed")
	}
	if sources[0].Meta.Err == "" {
		t.Error("Meta.Err is empty, want a diagnostic message explaining the network failure")
	}
	if sources[0].Present {
		t.Error("Present = true, want false: no data was ever fetched")
	}
}
