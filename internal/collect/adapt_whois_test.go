package collect

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/source"

	"github.com/patramsey/plat/internal/whois"
	"github.com/patramsey/plat/internal/whois/parse"
	"github.com/patramsey/plat/model"
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
	registryRaw := loadWHOISFixture(t, "verisign-com-google-recorded.txt")
	registrarRaw := loadWHOISFixture(t, "markmonitor-registrar-google-recorded.txt")

	result := &whois.Result{
		Domain: "google.com",
		Hops: []whois.Hop{
			{Server: "whois.iana.org", Latency: 5 * time.Millisecond}, // IANA hop — not a data source
			{Server: "whois.verisign-grs.com", Raw: registryRaw, Fields: parse.Parse(registryRaw, "com"), Latency: 20 * time.Millisecond},
			{Server: "whois.markmonitor.com", Raw: registrarRaw, Fields: parse.Parse(registrarRaw, ""), Latency: 15 * time.Millisecond},
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
	if sources[0].Registrar.IANAID != "292" {
		t.Errorf("registry hop Registrar.IANAID = %q, want %q (read from Fields.Unmapped)", sources[0].Registrar.IANAID, "292")
	}
	if sources[0].Registrar.AbuseEmail != "abusecomplaints@markmonitor.com" {
		t.Errorf("registry hop Registrar.AbuseEmail = %q, want %q", sources[0].Registrar.AbuseEmail, "abusecomplaints@markmonitor.com")
	}
	// The registrar spells its own name differently from the registry.
	if sources[1].Registrar.Name != "MarkMonitor, Inc." {
		t.Errorf("registrar hop Registrar.Name = %q, want %q", sources[1].Registrar.Name, "MarkMonitor, Inc.")
	}
}

// No registry in the 2026-09 sweeps redacts a registrar's name, so there
// is no recording of one; this input is synthetic, and says so. It
// exercises the placeholder rule itself: a registrar value that is a
// known redaction placeholder must not be surfaced as a name.
func TestFromWHOIS_RedactedRegistrant(t *testing.T) {
	raw := "Domain: example.de\nRegistrar: REDACTED FOR PRIVACY\nStatus: connect\n" // synthetic, see above
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
	raw := loadWHOISFixture(t, "verisign-com-notfound-recorded.txt")
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
	raw := loadWHOISFixture(t, "aw-ratelimited-recorded.txt")
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

// A registry answering that the name is reserved or restricted is a
// failed source with that reason: not a registered domain (the old
// behaviour, exit 0) and not a free one (NotFound, exit 1), since the
// name cannot be registered either. See #111.
func TestFromHop_RestrictedIsAFailedSourceWithTheReason(t *testing.T) {
	sr := fromHop(model.SourceRegistryWHOIS, whois.Hop{Fields: parse.Fields{Restricted: true, Domain: "nic.om"}})
	if sr.Meta.OK || sr.Meta.NotFound || sr.Present {
		t.Errorf("Meta = %+v, Present = %v; want a failed source, not found=false, not present", sr.Meta, sr.Present)
	}
	if !strings.Contains(sr.Meta.Err, "restricts this name") {
		t.Errorf("Meta.Err = %q, want the reason", sr.Meta.Err)
	}
}

// A WHOIS answer that yields no fields and matches no not-found, refusal,
// rate-limit or restricted wording is not a registered domain: it is an
// answer plat could not read. Counting it as a success is how 74 free
// ccTLD names were reported as registered (#113) before their wording
// was known. See #120.
func TestFromHop_UnrecognisedAnswerIsAFailedSource(t *testing.T) {
	sr := fromHop(model.SourceRegistryWHOIS, whois.Hop{Raw: "Some wording plat has never seen.\n", Fields: parse.Fields{}})
	if sr.Meta.OK || sr.Meta.NotFound || sr.Present {
		t.Errorf("Meta = %+v, Present = %v; want a failed source", sr.Meta, sr.Present)
	}
	if sr.Meta.Err != source.UnrecognisedReason {
		t.Errorf("Meta.Err = %q, want %q", sr.Meta.Err, source.UnrecognisedReason)
	}
	if string(sr.Meta.Raw) == "" {
		t.Error("Meta.Raw dropped; -v and --raw need the answer that could not be read")
	}
}

// An empty reply has no wording to recognise and nothing for --raw to
// show; its reason says it was empty (#148). Same for IPs and ASNs.
func TestUnreadable_EmptyAnswerSaysSo(t *testing.T) {
	for _, raw := range []string{"", " \r\n\n"} {
		hop := whois.Hop{Raw: raw, IPFields: &parse.IPFields{}, ASNFields: &parse.ASNFields{}}
		for name, sr := range map[string]model.SourceResult{
			"domain": fromHop(model.SourceRegistryWHOIS, hop).Meta,
			"ip":     fromIPHop(model.SourceResult{Source: model.SourceRegistryWHOIS}, hop).Meta,
			"asn":    fromASNHop(model.SourceResult{Source: model.SourceRegistryWHOIS}, hop).Meta,
		} {
			if sr.OK || sr.NotFound || sr.Err != source.EmptyReason {
				t.Errorf("%s, raw %q: Meta = %+v, want a failed source with the empty reason", name, raw, sr)
			}
		}
	}
}

// Anything parsed -- even one field -- is still an answer plat read.
func TestFromHop_AnyParsedFieldIsStillASuccess(t *testing.T) {
	for name, f := range map[string]parse.Fields{
		"domain":      {Domain: "example.tld"},
		"registrar":   {Registrar: "Example Registrar"},
		"nameservers": {Nameservers: []string{"ns1.example.tld"}},
		"status":      {Statuses: []string{"ok"}},
		"expires":     {Expires: parse.ParseDate("2030-01-01")},
	} {
		sr := fromHop(model.SourceRegistryWHOIS, whois.Hop{Fields: f})
		if !sr.Meta.OK {
			t.Errorf("%s only: Meta = %+v, want OK", name, sr.Meta)
		}
	}
}

// A not-found answer keeps meaning "not registered", not "unreadable".
func TestFromHop_NotFoundIsNotUnrecognised(t *testing.T) {
	sr := fromHop(model.SourceRegistryWHOIS, whois.Hop{Fields: parse.Fields{NotFound: true}})
	if !sr.Meta.NotFound || sr.Meta.Err != "" {
		t.Errorf("Meta = %+v, want NotFound with no error", sr.Meta)
	}
}

// A WHOIS server with no service for the name is unavailable, not failed,
// so it does not stop RDAP's not-found from standing (#131).
func TestFromHop_UnsupportedIsUnavailable(t *testing.T) {
	sr := fromHop(model.SourceRegistryWHOIS, whois.Hop{Fields: parse.Fields{Unsupported: true}})
	if !sr.Meta.Unavailable || sr.Meta.OK || sr.Meta.NotFound || sr.Meta.Err == "" {
		t.Errorf("Meta = %+v, want Unavailable with the reason in Err", sr.Meta)
	}
}
