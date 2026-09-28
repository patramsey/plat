package parse

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func loadFixture(t testing.TB, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../../testdata/whois/" + name)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return string(b)
}

func TestParse_ThinComRegistry(t *testing.T) {
	raw := loadFixture(t, "verisign-com-example.txt")
	f := Parse(raw, "com")

	if f.Domain != "EXAMPLE.COM" {
		t.Errorf("Domain = %q, want EXAMPLE.COM", f.Domain)
	}
	if f.Registrar != "Example Registrar, Inc." {
		t.Errorf("Registrar = %q", f.Registrar)
	}
	if f.RegistrarWHOISServer != "whois.example-registrar.example" {
		t.Errorf("RegistrarWHOISServer = %q", f.RegistrarWHOISServer)
	}
	wantStatuses := []string{"clientTransferProhibited", "clientUpdateProhibited"}
	if len(f.Statuses) != len(wantStatuses) {
		t.Fatalf("Statuses = %v, want %v", f.Statuses, wantStatuses)
	}
	for i, s := range wantStatuses {
		if f.Statuses[i] != s {
			t.Errorf("Statuses[%d] = %q, want %q (ICANN URL should be stripped)", i, f.Statuses[i], s)
		}
	}
	wantNS := []string{"A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"}
	if len(f.Nameservers) != len(wantNS) {
		t.Fatalf("Nameservers = %v, want %v", f.Nameservers, wantNS)
	}
	if !f.Created.Parsed || f.Created.Raw != "1995-08-14T04:00:00Z" {
		t.Errorf("Created = %+v", f.Created)
	}
	if !f.Expires.Parsed || f.Expires.Raw != "2026-08-13T04:00:00Z" {
		t.Errorf("Expires = %+v", f.Expires)
	}
	if f.RateLimited {
		t.Error("RateLimited = true, want false")
	}
}

func TestParse_ThickOrgRegistry(t *testing.T) {
	raw := loadFixture(t, "pir-org-example.txt")
	f := Parse(raw, "org")

	if f.Domain != "EXAMPLE.ORG" {
		t.Errorf("Domain = %q, want EXAMPLE.ORG", f.Domain)
	}
	if f.Registrar != "Example Registrar, Inc." {
		t.Errorf("Registrar = %q", f.Registrar)
	}
	if len(f.Nameservers) != 2 {
		t.Errorf("Nameservers = %v, want 2 entries", f.Nameservers)
	}
	if !f.Created.Parsed {
		t.Errorf("Created not parsed: %+v", f.Created)
	}
}

func TestParse_RateLimited(t *testing.T) {
	raw := loadFixture(t, "ratelimited.txt")
	f := Parse(raw, "com")
	if !f.RateLimited {
		t.Error("RateLimited = false, want true")
	}
}

func TestParse_UnmappedFieldsRetained(t *testing.T) {
	raw := loadFixture(t, "verisign-com-example.txt")
	f := Parse(raw, "com")
	if _, ok := f.Unmapped["registrar iana id"]; !ok {
		t.Errorf("expected 'registrar iana id' in Unmapped, got %v", f.Unmapped)
	}
}

func TestParse_NotFoundDetection(t *testing.T) {
	raw := loadFixture(t, "notfound.txt")
	f := Parse(raw, "com")
	if !f.NotFound {
		t.Error("NotFound = false, want true")
	}
}

func TestParse_FoundDomainNotFlaggedNotFound(t *testing.T) {
	raw := loadFixture(t, "verisign-com-example.txt")
	f := Parse(raw, "com")
	if f.NotFound {
		t.Error("NotFound = true, want false for a real registered-domain response")
	}
}

func TestParse_UnsupportedDetection(t *testing.T) {
	// Reproduces Identity Digital's shared WHOIS refusing .ninja
	// (and other of its newer gTLDs) outright with "TLD is not
	// supported." rather than either domain data or a registrar
	// referral.
	raw := loadFixture(t, "tld-not-supported.txt")
	f := Parse(raw, "ninja")
	if !f.Unsupported {
		t.Error("Unsupported = false, want true")
	}
	if f.NotFound {
		t.Error("NotFound = true, want false: a service refusing the query is not the same claim as \"this domain doesn't exist\"")
	}
}

func TestParse_FoundDomainNotFlaggedUnsupported(t *testing.T) {
	raw := loadFixture(t, "verisign-com-example.txt")
	f := Parse(raw, "com")
	if f.Unsupported {
		t.Error("Unsupported = true, want false for a real registered-domain response")
	}
}

func TestTokenizeIndent_UKFixture(t *testing.T) {
	raw := loadFixture(t, "nominet-uk-recorded.txt")
	pairs := tokenizeIndent(raw)

	// Every line of a real Nominet response is indented: section headers
	// by four spaces, their bodies by eight. Nameserver lines carry glue
	// addresses, IPv6 ones included, whose colons are not key separators.
	want := map[string][]string{
		"domain name":         {"bbc.co.uk"},
		"registrar":           {"British Broadcasting Corporation [Tag = BBC]"},
		"url":                 {"https://www.bbc.co.uk"},
		"registered on":       {"before Aug-1996"},
		"expiry date":         {"13-Dec-2034"},
		"last updated":        {"29-Oct-2025"},
		"registration status": {"Registered until expiry date."},
		"name servers": {
			"ddns0.bbc.co.uk           148.163.199.1  2607:f740:e04e::1",
			"ddns0.bbc.com",
			"ddns1.bbc.co.uk           148.163.199.65  2607:f740:e04e:4::1",
			"ddns1.bbc.com",
			"dns0.bbc.co.uk            198.51.44.9  2620:4d:4000:6259:7:9:0:1",
			"dns0.bbc.com",
			"dns1.bbc.co.uk            198.51.45.9  2a00:edc0:6259:7:9::2",
			"dns1.bbc.com",
		},
	}
	got := map[string][]string{}
	for _, p := range pairs {
		got[p.key] = append(got[p.key], p.val)
	}
	for key, wantVals := range want {
		gotVals, ok := got[key]
		if !ok {
			t.Errorf("missing key %q in tokenizeIndent output", key)
			continue
		}
		if len(gotVals) != len(wantVals) {
			t.Errorf("key %q: got %v, want %v", key, gotVals, wantVals)
			continue
		}
		for i := range wantVals {
			if gotVals[i] != wantVals[i] {
				t.Errorf("key %q[%d] = %q, want %q", key, i, gotVals[i], wantVals[i])
			}
		}
	}
	// The trailing "WHOIS lookup made on ..." line is not a "Header:"
	// line and not indented — it must produce no pair at all.
	for _, p := range pairs {
		if strings.Contains(p.val, "WHOIS lookup made on") || strings.Contains(p.key, "whois lookup") {
			t.Errorf("trailing timestamp line leaked into output: %+v", p)
		}
	}
}

func TestTokenizeIndent_FlatKeyValueLines(t *testing.T) {
	// EURid's ".eu" responses open with non-indented lines that already
	// carry their own value ("Domain: europa.eu", "Script: LATIN")
	// before any indented section -- the flatKeyPattern branch this
	// pins independently of the eu template's synonym table.
	raw := "Domain: example.eu\nScript: LATIN\n\nRegistrant:\n        NOT DISCLOSED!\n"
	pairs := tokenizeIndent(raw)

	want := map[string]string{
		"domain": "example.eu",
		"script": "LATIN",
	}
	got := map[string]string{}
	for _, p := range pairs {
		got[p.key] = p.val
	}
	for key, wantVal := range want {
		if got[key] != wantVal {
			t.Errorf("key %q = %q, want %q", key, got[key], wantVal)
		}
	}

	// A prose line whose only colon sits deep inside a sentence (not a
	// short label) must not be mistaken for a flat key/value pair --
	// this is what flatKeyPattern's word-count/letters-only gate exists
	// to reject.
	prose := "WHOIS lookup made on Sun, 12 Jul 2026 at 09:15:00"
	pairs = tokenizeIndent(raw + "\n" + prose + "\n")
	for _, p := range pairs {
		if strings.Contains(p.val, "lookup made on") || strings.Contains(p.key, "whois lookup") {
			t.Errorf("prose line leaked into flat key/value output: %+v", p)
		}
	}
}

func TestParse_IndentIPv6OnlyGlueNameserver(t *testing.T) {
	// Regression: tokenizeIndent's indented-content branch used to split
	// an indented line on the FIRST colon it found. For a nameserver
	// whose only glue is IPv6 -- "ns1.example.eu (2a05:d018:c5f:3701::1)"
	// -- that first colon sits inside the address itself, so the line
	// tokenized as key "ns1.example.eu (2a05" / value
	// "d018:c5f:3701::1)" and landed in Unmapped under that garbage key
	// instead of reaching stripGlue. Unlike a real recording where an
	// affected host might also have an IPv4-glued sibling line that
	// rescues it via dedup, this fixture gives ns1 only IPv6 glue, so a
	// regression here can't hide behind a duplicate.
	raw := "Domain: example.eu\nName servers:\n        ns1.example.eu (2a05:d018:c5f:3701::1)\n        ns2.example.eu (192.0.2.9)\n"
	f := Parse(raw, "eu")

	wantNS := []string{"ns1.example.eu", "ns2.example.eu"}
	if len(f.Nameservers) != len(wantNS) {
		t.Fatalf("Nameservers = %v, want %v", f.Nameservers, wantNS)
	}
	for i := range wantNS {
		if f.Nameservers[i] != wantNS[i] {
			t.Errorf("Nameservers[%d] = %q, want %q", i, f.Nameservers[i], wantNS[i])
		}
	}
	for key := range f.Unmapped {
		if strings.Contains(key, "ns1.example.eu") {
			t.Errorf("IPv6-glued nameserver line leaked into Unmapped under key %q", key)
		}
	}
}

func TestParse_UKTemplateEndToEnd(t *testing.T) {
	raw := loadFixture(t, "nominet-uk-recorded.txt")
	f := Parse(raw, "uk")

	if f.Domain != "bbc.co.uk" {
		t.Errorf("Domain = %q, want bbc.co.uk", f.Domain)
	}
	if f.Registrar != "British Broadcasting Corporation" {
		t.Errorf("Registrar = %q", f.Registrar)
	}
	wantNS := []string{
		"ddns0.bbc.co.uk", "ddns0.bbc.com", "ddns1.bbc.co.uk", "ddns1.bbc.com",
		"dns0.bbc.co.uk", "dns0.bbc.com", "dns1.bbc.co.uk", "dns1.bbc.com",
	}
	if !slices.Equal(f.Nameservers, wantNS) {
		t.Errorf("Nameservers = %v, want %v", f.Nameservers, wantNS)
	}
	// Nominet reports registrations predating its records as "before
	// Aug-1996" -- not a date, so it must not parse as one.
	if f.Created.Parsed || f.Created.Raw != "before Aug-1996" {
		t.Errorf("Created = %+v, want unparsed with Raw %q", f.Created, "before Aug-1996")
	}
	if !f.Expires.Parsed || f.Expires.Raw != "13-Dec-2034" {
		t.Errorf("Expires = %+v, want Parsed with Raw 13-Dec-2034", f.Expires)
	}
	if !f.Updated.Parsed || f.Updated.Raw != "29-Oct-2025" {
		t.Errorf("Updated = %+v, want Parsed with Raw 29-Oct-2025", f.Updated)
	}
	if f.NotFound {
		t.Error("NotFound = true for a registered domain")
	}
}

func TestParse_UKNotFound(t *testing.T) {
	f := Parse(loadFixture(t, "nominet-uk-notfound-recorded.txt"), "uk")
	if !f.NotFound {
		t.Error("NotFound = false, want true for Nominet's \"No match for\" response")
	}
	if f.Domain != "" {
		t.Errorf("Domain = %q, want empty for a not-found response", f.Domain)
	}
}

func TestParse_IDNFixture(t *testing.T) {
	raw := loadFixture(t, "idn-example.txt")
	f := Parse(raw, "de")

	if f.Domain != "XN--MNCHEN-3YA.DE" {
		t.Errorf("Domain = %q, want XN--MNCHEN-3YA.DE (WHOIS reports the punycode/LDH form)", f.Domain)
	}
	if !f.Created.Parsed || !f.Expires.Parsed {
		t.Errorf("expected both Created and Expires to parse, got Created=%+v Expires=%+v", f.Created, f.Expires)
	}
}

func TestParse_ExpiredDomainFixture(t *testing.T) {
	raw := loadFixture(t, "expired-example.txt")
	f := Parse(raw, "com")

	if f.Domain != "EXPIRED-EXAMPLE.COM" {
		t.Errorf("Domain = %q, want EXPIRED-EXAMPLE.COM", f.Domain)
	}
	wantStatuses := []string{"pendingDelete", "redemptionPeriod"}
	if len(f.Statuses) != len(wantStatuses) {
		t.Fatalf("Statuses = %v, want %v", f.Statuses, wantStatuses)
	}
	for i, want := range wantStatuses {
		if f.Statuses[i] != want {
			t.Errorf("Statuses[%d] = %q, want %q", i, f.Statuses[i], want)
		}
	}
	if !f.Expires.Parsed {
		t.Fatal("expected Expires to parse")
	}
	if !f.Expires.Time.Before(f.Updated.Time) {
		t.Errorf("expected Expires (%v) to be before Updated (%v) for an expired-then-updated domain", f.Expires.Time, f.Updated.Time)
	}
}

func TestParse_RegistrarExpirationDateSynonym(t *testing.T) {
	// Namecheap's registrar-whois response labels the expiration field
	// "Registrar Registration Expiration Date:", a full ICANN-standard
	// field name distinct from the shorter "Expiration Date:"/"Registry
	// Expiry Date:" synonyms already covered above — this was previously
	// missing from the synonym table, silently dropping expires for any
	// registrar using this exact label.
	raw := "Domain Name: FOR.NINJA\r\n" +
		"Registrar Registration Expiration Date: 2026-09-27T14:13:46.52Z\r\n"
	f := Parse(raw, "ninja")
	if !f.Expires.Parsed || f.Expires.Raw != "2026-09-27T14:13:46.52Z" {
		t.Errorf("Expires = %+v, want Parsed with Raw 2026-09-27T14:13:46.52Z", f.Expires)
	}
}

func TestParse_RegistrarExpirationDateShortVariant(t *testing.T) {
	// trellis.law's registrar-whois response labels the field "Registrar
	// Expiration Date:" -- a shorter variant of the same ICANN-standard
	// field as "Registrar Registration Expiration Date:" above, missing
	// the "Registration" word. Confirmed live via a slow retry of an
	// earlier rate-limited audit batch.
	raw := "Registrar Expiration Date: 2031-06-07T01:22:48+00:00\r\n"
	f := Parse(raw, "law")
	if !f.Expires.Parsed || f.Expires.Raw != "2031-06-07T01:22:48+00:00" {
		t.Errorf("Expires = %+v, want Parsed with Raw 2031-06-07T01:22:48+00:00", f.Expires)
	}
}

func TestParse_BareWhoisKeyIsRegistryReferralSynonym(t *testing.T) {
	// Confirmed live for every TLD checked (.com, .org, .net, .jp, .de,
	// .edu): whois.iana.org's real responses label the registry referral
	// field "whois:", never the conventionally-expected "refer:". Before
	// this synonym existed, "whois:" fell into Unmapped and Refer stayed
	// empty, so internal/whois's IANA -> registry -> registrar referral
	// chain (referral.go's Lookup) never proceeded past the bare IANA
	// hop for any live domain -- confirmed via a 1000-domain live audit,
	// where registry-whois never once appeared as a successful source.
	raw := "whois:        whois.verisign-grs.com\ndomain:       COM\n"
	f := Parse(raw, "")
	if f.Refer != "whois.verisign-grs.com" {
		t.Errorf("Refer = %q, want %q", f.Refer, "whois.verisign-grs.com")
	}
}

func TestParse_WhoisServerKeysStayDistinctFromBareWhois(t *testing.T) {
	// The new bare "whois" synonym must not swallow the pre-existing,
	// semantically distinct "whois server"/"registrar whois server" keys
	// (a *different* field, RegistrarWHOISServer, not Refer) -- the
	// tokenizer's key is the trimmed text before the colon verbatim, so
	// "whois server" and "whois" are different map keys entirely, but
	// this locks that invariant in explicitly.
	raw := "Registrar WHOIS Server: whois.markmonitor.com\n"
	f := Parse(raw, "com")
	if f.RegistrarWHOISServer != "whois.markmonitor.com" {
		t.Errorf("RegistrarWHOISServer = %q, want %q", f.RegistrarWHOISServer, "whois.markmonitor.com")
	}
	if f.Refer != "" {
		t.Errorf("Refer = %q, want empty (this line is not a bare \"whois:\" key)", f.Refer)
	}
}

func TestParse_LiveAuditSynonyms(t *testing.T) {
	// Each raw line below is copied verbatim from a real, live query
	// against the named TLD's registry during a 2433-domain audit
	// spanning 892 distinct TLDs -- not guessed from the label alone.
	tests := []struct {
		name string
		raw  string
		get  func(f Fields) Date
		want string
	}{
		{"jp Registered Date", "Registered Date: 2002/11/21\n", func(f Fields) Date { return f.Created }, "2002/11/21"},
		{"jp Connected Date", "Connected Date: 2002/11/21\n", func(f Fields) Date { return f.Created }, "2002/11/21"},
		{"nz Original Created", "Original Created: 2014-10-01T02:43:39Z\n", func(f Fields) Date { return f.Created }, "2014-10-01T02:43:39Z"},
		{"kz Domain created", "Domain created: 1999-06-07 14:01:43 (GMT+0:00)\n", func(f Fields) Date { return f.Created }, "1999-06-07 14:01:43 (GMT+0:00)"},
		{"generic Record created", "Record created: 2010-01-01\n", func(f Fields) Date { return f.Created }, "2010-01-01"},
		{"rs Registration date", "Registration date: 2010-01-01\n", func(f Fields) Date { return f.Created }, "2010-01-01"},
		{"st created-date", "created-date: 2010-01-01\n", func(f Fields) Date { return f.Created }, "2010-01-01"},
		{"hk Domain Name Commencement Date", "Domain Name Commencement Date: 2010-01-01\n", func(f Fields) Date { return f.Created }, "2010-01-01"},
		{"sn date de création", "date de création: 2010-01-01\n", func(f Fields) Date { return f.Created }, "2010-01-01"},
		{"jp Last Update (bare)", "Last Update: 2026/03/27 05:19:30 (JST)\n", func(f Fields) Date { return f.Updated }, "2026/03/27 05:19:30 (JST)"},
		{"fr last-update", "last-update: 2010-01-01\n", func(f Fields) Date { return f.Updated }, "2010-01-01"},
		{"by Update date", "Update date: 2010-01-01\n", func(f Fields) Date { return f.Updated }, "2010-01-01"},
		{"mx Last Updated On", "Last Updated On: 2026-01-29\n", func(f Fields) Date { return f.Updated }, "2026-01-29"},
		{"rs Modification date", "Modification date: 2010-01-01\n", func(f Fields) Date { return f.Updated }, "2010-01-01"},
		{"edu Domain record last updated", "Domain record last updated: 2010-01-01\n", func(f Fields) Date { return f.Updated }, "2010-01-01"},
		{"st updated-date", "updated-date: 2010-01-01\n", func(f Fields) Date { return f.Updated }, "2010-01-01"},
		{"tr Last Update Time", "Last Update Time: 2026-07-15T07:46:43+03:00\n", func(f Fields) Date { return f.Updated }, "2026-07-15T07:46:43+03:00"},
		{"kg Record last updated on", "Record last updated on: 2010-01-01\n", func(f Fields) Date { return f.Updated }, "2010-01-01"},
		{"bn Modified date", "Modified date: 2010-01-01\n", func(f Fields) Date { return f.Updated }, "2010-01-01"},
		{"ee Expire", "Expire: 2027-01-01\n", func(f Fields) Date { return f.Expires }, "2027-01-01"},
		{"se Expires (bare)", "expires: 2027-01-01\n", func(f Fields) Date { return f.Expires }, "2027-01-01"},
		{"symmetric Expiry (bare)", "expiry: 2027-01-01\n", func(f Fields) Date { return f.Expires }, "2027-01-01"},
		{"it Expire date", "Expire Date: 2027-01-01\n", func(f Fields) Date { return f.Expires }, "2027-01-01"},
		{"cn Expiration Time", "Expiration Time: 2027-01-01\n", func(f Fields) Date { return f.Expires }, "2027-01-01"},
		{"edu Domain expires", "Domain expires: 2027-01-01\n", func(f Fields) Date { return f.Expires }, "2027-01-01"},
		{"st expiration-date", "expiration-date: 2027-01-01\n", func(f Fields) Date { return f.Expires }, "2027-01-01"},
		{"sk Valid Until", "Valid Until: 2027-01-01\n", func(f Fields) Date { return f.Expires }, "2027-01-01"},
		{"kg Record expires on", "Record expires on: 2027-01-01\n", func(f Fields) Date { return f.Expires }, "2027-01-01"},
		{"sn date d'expiration", "date d'expiration: 2027-01-01\n", func(f Fields) Date { return f.Expires }, "2027-01-01"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := Parse(tt.raw, "")
			got := tt.get(f)
			if !got.Parsed && got.Raw == "" {
				t.Fatalf("field never populated from raw line %q", tt.raw)
			}
			if got.Raw != tt.want {
				t.Errorf("Raw = %q, want %q", got.Raw, tt.want)
			}
		})
	}
}

func TestParse_LiveAuditFalsePositivesStayUnmapped(t *testing.T) {
	// Deliberately excluded during the same audit: near-misses whose
	// label CONTAINS a temporal-looking word but whose actual meaning
	// isn't the same concept as Created/Updated/Expires -- mapping them
	// would inject wrong data, not just miss right data.
	tests := []struct {
		name string
		raw  string
	}{
		{"kz Registar created holds a registrar name, not a date", "Registar created: KAZNIC\n"},
		{"ru free-date is a later, distinct post-grace-period deletion date", "free-date: 2026-11-01\n"},
		{"fr eligdate is an AFNIC-specific eligibility field, not creation/update/expiry", "eligdate: 2010-01-01\n"},
		{"fr reachdate is an AFNIC-specific reachability field, not creation/update/expiry", "reachdate: 2010-01-01\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := Parse(tt.raw, "")
			if f.Created.Raw != "" || f.Updated.Raw != "" || f.Expires.Raw != "" {
				t.Errorf("expected this line to stay Unmapped, got Created=%+v Updated=%+v Expires=%+v", f.Created, f.Updated, f.Expires)
			}
			if len(f.Unmapped) == 0 {
				t.Error("expected the line to land in Unmapped")
			}
		})
	}
}

func TestParse_TrailingDotPaddingStripped(t *testing.T) {
	// .tr's registry right-pads field labels with a run of dots for
	// fixed-width alignment before the colon (confirmed live against
	// whois.trabis.gov.tr): "Created on..............: 2001-Aug-23."
	// Without stripping the trailing dots, this key never matches the
	// existing "created on"/"expires on" synonyms at all.
	raw := "Created on..............: 2001-Aug-23.\nExpires on..............: 2026-Aug-22.\n"
	f := Parse(raw, "")
	if f.Created.Raw != "2001-Aug-23." {
		t.Errorf("Created.Raw = %q, want %q", f.Created.Raw, "2001-Aug-23.")
	}
	if f.Expires.Raw != "2026-Aug-22." {
		t.Errorf("Expires.Raw = %q, want %q", f.Expires.Raw, "2026-Aug-22.")
	}
}

// TestParse_StripsGlueAddressesFromNameservers guards against registries
// appending glue IP addresses onto the nameserver line: DENIC packs them
// space-separated, CZ.NIC parenthesised. Both fixtures were recorded live
// against the named registry on 2026-08-23 (see the fixture files' own
// header comments); the `want` order matches the order each registry
// actually emitted, not alphabetical -- CZ.NIC's response lists
// d.ns.nic.cz before a.ns.nic.cz and b.ns.nic.cz.
func TestParse_StripsGlueAddressesFromNameservers(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		tld     string
		want    []string
	}{
		{
			name:    "denic space-separated glue",
			fixture: "denic-de-recorded.txt",
			tld:     "de",
			want:    []string{"ns1.denic.de", "ns2.denic.de", "ns3.denic.de", "ns4.denic.net"},
		},
		{
			name:    "cznic parenthesised glue",
			fixture: "cznic-cz-recorded.txt",
			tld:     "cz",
			want:    []string{"d.ns.nic.cz", "a.ns.nic.cz", "b.ns.nic.cz"},
		},
		{
			// NASK's "nameservers:" value spans four lines, but only the
			// first carries the "nameservers:" key -- the other three are
			// bare continuation lines with no key of their own, and the
			// two of those with bracketed IPv6 glue contain a colon that
			// the default kv tokenizer mistakes for its own key/value
			// separator, so they land in Unmapped instead of
			// Nameservers. bilbo.nask.org.pl is the only nameserver the
			// current tokenizer actually recovers from this dialect; this
			// pins that real (still-limited) behavior rather than the
			// four hosts the raw response lists.
			name:    "nask bracketed glue, multi-line value",
			fixture: "nask-pl-recorded.txt",
			tld:     "pl",
			want:    []string{"bilbo.nask.org.pl"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "whois", tt.fixture))
			if err != nil {
				t.Fatalf("reading fixture: %v", err)
			}
			got := Parse(string(raw), tt.tld).Nameservers
			if !slices.Equal(got, tt.want) {
				t.Errorf("nameservers = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestStripGlue covers the dialects whose registries are not recorded as
// fixtures here, so the rule is pinned for all five shapes seen live.
func TestStripGlue(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"ns1.denic.de 77.67.63.106 2001:668:1f:11:0:0:0:106", "ns1.denic.de"},
		{"d.ns.nic.cz (193.29.206.1, 2001:678:1::1)", "d.ns.nic.cz"},
		{"bilbo.nask.org.pl. [195.187.245.51]", "bilbo.nask.org.pl"},
		{"ns5.nic.ru. 31.177.67.100, 2a02:2090:e800:9000:31:177:67:100", "ns5.nic.ru"},
		{"ns1.domreg.lt\t[185.150.40.44 2a07:ab40::44]", "ns1.domreg.lt"},
		{"ns4.denic.net", "ns4.denic.net"},
		{"", ""},
	} {
		if got := stripGlue(tt.in); got != tt.want {
			t.Errorf("stripGlue(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// .lt uses the singular "Nameserver:" key rather than "Name Server:" or
// "nserver:" -- without the "nameserver" entry in defaultSynonyms routing
// it to fNameservers, the whole line falls into Unmapped and Nameservers
// comes back empty. TestStripGlue exercises the same .lt-shaped glue
// through stripGlue alone, which says nothing about whether the key ever
// reaches stripGlue in the first place; this test guards that routing.
func TestParse_LTSingularNameserverSynonym(t *testing.T) {
	raw := "Nameserver:\t\tns1.domreg.lt\t[185.150.40.44 2a07:ab40::44]\n"
	got := Parse(raw, "lt").Nameservers
	want := []string{"ns1.domreg.lt"}
	if !slices.Equal(got, want) {
		t.Errorf("nameservers = %q, want %q", got, want)
	}
}

// EURid lists the same host once per address family. After glue is
// stripped those collapse to duplicates, which must not reach the record.
func TestParse_DeduplicatesNameserversWithinASource(t *testing.T) {
	raw := "Name server: ns1.example.eu (192.0.2.1)\nName server: ns1.example.eu (2001:db8::1)\nName server: ns2.example.eu\n"
	got := Parse(raw, "example").Nameservers
	want := []string{"ns1.example.eu", "ns2.example.eu"}
	if !slices.Equal(got, want) {
		t.Errorf("nameservers = %q, want %q", got, want)
	}
}

// A status carrying the ICANN <eppCode> <url> form is truncated to the
// code; a registry that puts an English phrase there keeps the phrase.
func TestParse_TruncatesStatusOnlyForTheICANNURLForm(t *testing.T) {
	for _, tt := range []struct {
		name, raw string
		want      []string
	}{
		{
			name: "icann form with url",
			raw:  "Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n",
			want: []string{"clientTransferProhibited"},
		},
		{
			name: "free-text ccTLD phrase survives whole",
			raw:  "status: Sponsoring registrar change forbidden\n",
			want: []string{"Sponsoring registrar change forbidden"},
		},
		{
			name: "bare code untouched",
			raw:  "status: connect\n",
			want: []string{"connect"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := Parse(tt.raw, "example").Statuses; !slices.Equal(got, tt.want) {
				t.Errorf("statuses = %q, want %q", got, tt.want)
			}
		})
	}
}

// JPRS prefixes third-level (.ad.jp, .co.jp) record lines with a lettered
// ordinal -- "a. [Domain Name]" -- which the bracket tokenizer's ^\[ anchor
// could not match, so those records came back with no domain, status or
// nameservers at all.
func TestParse_JPRSOrdinalPrefixedLines(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "whois", "jprs-adjp-recorded.txt"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	f := Parse(string(raw), "jp")
	if f.Domain == "" {
		t.Error("domain not parsed from an ordinal-prefixed [Domain Name] line")
	}
	if len(f.Statuses) == 0 {
		t.Error("no status parsed; JPRS uses [State] for third-level records")
	}
}

func TestTokenizeBrackets_AcceptsOrdinalPrefix(t *testing.T) {
	got := tokenizeBrackets("a. [Domain Name]                NIC.AD.JP\n[State]   Connected\n")
	want := []kvPair{{"domain name", "NIC.AD.JP"}, {"state", "Connected"}}
	if !slices.Equal(got, want) {
		t.Errorf("pairs = %+v, want %+v", got, want)
	}
}

// Nominet appends its own registrar tag to the name ("[Tag = BBC]"),
// which RDAP does not carry, so leaving it on made every .uk lookup
// report a registrar conflict between two sources naming the same one.
func TestParse_UKRegistrarDropsNominetTag(t *testing.T) {
	f := Parse(loadFixture(t, "nominet-uk-recorded.txt"), "uk")
	if f.Registrar != "British Broadcasting Corporation" {
		t.Errorf("Registrar = %q, want %q", f.Registrar, "British Broadcasting Corporation")
	}
}

// A domain registered directly with Nominet has no registrar, and
// Nominet says so in prose. That sentence is not a registrar's name.
func TestParse_UKNoRegistrarListedIsAbsent(t *testing.T) {
	f := Parse(loadFixture(t, "nominet-uk-noregistrar-recorded.txt"), "uk")
	if f.Registrar != "" {
		t.Errorf("Registrar = %q, want empty", f.Registrar)
	}
	if f.Domain != "nominet.uk" {
		t.Errorf("Domain = %q, want nominet.uk", f.Domain)
	}
	if len(f.Nameservers) != 8 {
		t.Errorf("Nameservers = %v, want 8 entries", f.Nameservers)
	}
}

// In these registries' responses the domain's own object comes first and
// contact, nsset and keyset objects follow with the same keys. Assigning
// on every match let the last object win: seznam.cz reported the
// trailing CZ.NIC contact's registrar and creation date, google.it the
// tech contact's dates, and google.com.br a contact's creation date.
func TestParse_MultiObjectResponseKeepsTheDomainsOwnValues(t *testing.T) {
	type date struct {
		raw    string
		parsed bool
	}
	for _, tt := range []struct {
		fixture, tld, registrar   string
		created, updated, expires date
	}{
		{
			fixture: "cznic-cz-seznam-recorded.txt", tld: "cz", registrar: "REG-SEZNAM",
			created: date{"07.10.1996 02:00:00", true},
			updated: date{"05.09.2022 14:21:11", true},
			expires: date{"29.10.2027", true},
		},
		{
			fixture: "nicit-it-google-recorded.txt", tld: "it", registrar: "MarkMonitor International Limited",
			created: date{"1999-12-10 00:00:00", true},
			updated: date{"2026-06-09 23:13:34", true},
			expires: date{"2027-04-21", true},
		},
		{
			// registro.br annotates the creation date with a ticket
			// number, which must not stop it parsing.
			fixture: "registrobr-br-google-recorded.txt", tld: "br",
			created: date{"19990518 #162310", true},
			updated: date{"20260421", true},
			expires: date{"20270518", true},
		},
	} {
		t.Run(tt.fixture, func(t *testing.T) {
			f := Parse(loadFixture(t, tt.fixture), tt.tld)
			if f.Registrar != tt.registrar {
				t.Errorf("Registrar = %q, want %q", f.Registrar, tt.registrar)
			}
			for _, c := range []struct {
				name string
				got  Date
				want date
			}{{"Created", f.Created, tt.created}, {"Updated", f.Updated, tt.updated}, {"Expires", f.Expires, tt.expires}} {
				if c.got.Raw != c.want.raw || c.got.Parsed != c.want.parsed {
					t.Errorf("%s = {Raw:%q Parsed:%v}, want {Raw:%q Parsed:%v}", c.name, c.got.Raw, c.got.Parsed, c.want.raw, c.want.parsed)
				}
			}
		})
	}
}

// .mx contact blocks carry "State: Nuevo Leon" -- the Mexican state. A
// global "state" synonym, there for .jp third-level records, turned it
// into four copies of a domain status rendered as "nuevoLeon".
func TestParse_MXContactStateIsNotAStatus(t *testing.T) {
	f := Parse(loadFixture(t, "nicmx-mx-recorded.txt"), "mx")
	if len(f.Statuses) != 0 {
		t.Errorf("Statuses = %v, want none (.mx publishes no domain status)", f.Statuses)
	}
	wantNS := []string{"a.nic.mx", "b.nic.mx", "c.nic.mx"}
	if !slices.Equal(f.Nameservers, wantNS) {
		t.Errorf("Nameservers = %v, want %v", f.Nameservers, wantNS)
	}
}

// TCI (.ru) and IIS (.se) publish the domain's status as "state:". This
// pins the global "state" synonym: scoping it to .jp alone (to stop .mx
// contact states reading as statuses) emptied yandex.ru's status.
func TestParse_StateIsDomainStatusForRUAndSE(t *testing.T) {
	for _, tt := range []struct {
		fixture, tld string
		want         []string
	}{
		{"tcinet-ru-yandex-recorded.txt", "ru", []string{"REGISTERED, DELEGATED, VERIFIED"}},
		{"iis-se-recorded.txt", "se", []string{"active", "ok"}},
	} {
		t.Run(tt.tld, func(t *testing.T) {
			f := Parse(loadFixture(t, tt.fixture), tt.tld)
			if !slices.Equal(f.Statuses, tt.want) {
				t.Errorf("Statuses = %q, want %q", f.Statuses, tt.want)
			}
		})
	}
}

// SWITCH (.ch, .li) refuses port-43 queries outright. Nothing matched
// the refusal, so fromHop counted it as a successful response with no
// fields and `plat nic.ch` exited 0 with an empty record.
func TestParse_SWITCHRefusalIsUnsupported(t *testing.T) {
	f := Parse(loadFixture(t, "switch-ch-refused-recorded.txt"), "ch")
	if !f.Unsupported {
		t.Error("Unsupported = false, want true for SWITCH's refusal")
	}
	if f.NotFound {
		t.Error("NotFound = true; a refusal says nothing about whether the domain exists")
	}
}

// The refusal marker must be SWITCH's sentence, not "not permitted":
// terms-of-use text on real answers says that constantly.
func TestParse_TermsOfUseNotPermittedIsNotARefusal(t *testing.T) {
	f := Parse("Domain Name: example.com\nUse of this data for marketing is not permitted.\n", "com")
	if f.Unsupported {
		t.Error("Unsupported = true for a real answer whose terms say \"not permitted\"")
	}
}

// DNS Belgium: tab-indented sections, the registrar's name nested under
// "Registrar:" / "Name:", glue in parentheses (IPv6 included), and a
// "Registered:" date with an unpadded day.
func TestParse_BEIndentedSections(t *testing.T) {
	f := Parse(loadFixture(t, "dnsbe-be-recorded.txt"), "be")
	if f.Domain != "dns.be" {
		t.Errorf("Domain = %q, want dns.be", f.Domain)
	}
	if f.Registrar != "DNS BE vzw/asbl" {
		t.Errorf("Registrar = %q, want DNS BE vzw/asbl", f.Registrar)
	}
	wantNS := []string{"ns1.dns.be", "ns2.dns.be", "ns3.dns.be", "ns5.dns.be"}
	if !slices.Equal(f.Nameservers, wantNS) {
		t.Errorf("Nameservers = %v, want %v", f.Nameservers, wantNS)
	}
	if !f.Created.Parsed || f.Created.Raw != "Mon Jan 1 1996" {
		t.Errorf("Created = %+v, want Parsed with Raw \"Mon Jan 1 1996\"", f.Created)
	}
	if f.NotFound {
		t.Error("NotFound = true for a registered domain (its status is NOT AVAILABLE)")
	}
}

// DNS Belgium answers an unregistered name with "Status: AVAILABLE", and
// no not-found marker matched it: a free .be name rendered as a
// registered domain and exited 0.
func TestParse_BEAvailableIsNotFound(t *testing.T) {
	f := Parse(loadFixture(t, "dnsbe-be-notfound-recorded.txt"), "be")
	if !f.NotFound {
		t.Error("NotFound = false for DNS Belgium's \"Status: AVAILABLE\"")
	}
}

func TestParse_CNSponsoringRegistrarAndRegistrationTime(t *testing.T) {
	f := Parse(loadFixture(t, "cnnic-cn-baidu-recorded.txt"), "cn")
	if f.Registrar == "" {
		t.Error("Registrar empty; CNNIC names it \"Sponsoring Registrar\"")
	}
	if !f.Created.Parsed || f.Created.Raw != "2003-03-17 12:20:05" {
		t.Errorf("Created = %+v, want Parsed with Raw 2003-03-17 12:20:05 (\"Registration Time\")", f.Created)
	}
}

func TestParse_ATChangedIsUpdated(t *testing.T) {
	f := Parse(loadFixture(t, "nicat-at-recorded.txt"), "at")
	if !f.Updated.Parsed || f.Updated.Raw != "20200427 16:03:40" {
		t.Errorf("Updated = %+v, want Parsed with Raw \"20200427 16:03:40\" (the domain's own changed:, not a contact's)", f.Updated)
	}
}

// .it's section headers ("Nameservers", "Registrar") carry no colon, so
// nothing under them was read.
func TestParse_ITNameserversUnderColonlessHeader(t *testing.T) {
	f := Parse(loadFixture(t, "nicit-it-google-recorded.txt"), "it")
	wantNS := []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"}
	if !slices.Equal(f.Nameservers, wantNS) {
		t.Errorf("Nameservers = %v, want %v", f.Nameservers, wantNS)
	}
}
