package parse

import (
	"os"
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
	raw := loadFixture(t, "nominet-uk-example.txt")
	pairs := tokenizeIndent(raw)

	want := map[string][]string{
		"domain name":         {"example.uk"},
		"registrant":          {"Example Organisation Ltd"},
		"registrant type":     {"UK Limited Company (Company number 12345678)"},
		"registrar":           {"Example Registrar Ltd t/a Example Registrar [Tag = EXAMPLE]"},
		"url":                 {"http://www.example-registrar.co.uk"},
		"registered on":       {"14-Aug-1995"},
		"expiry date":         {"13-Aug-2026"},
		"last updated":        {"14-Jan-2025"},
		"registration status": {"Registered until expiry date."},
		"name servers":        {"ns1.example.uk", "ns2.example.uk"},
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

func TestParse_UKTemplateEndToEnd(t *testing.T) {
	raw := loadFixture(t, "nominet-uk-example.txt")
	f := Parse(raw, "uk")

	if f.Domain != "example.uk" {
		t.Errorf("Domain = %q, want example.uk", f.Domain)
	}
	if f.Registrar != "Example Registrar Ltd t/a Example Registrar [Tag = EXAMPLE]" {
		t.Errorf("Registrar = %q", f.Registrar)
	}
	wantNS := []string{"ns1.example.uk", "ns2.example.uk"}
	if len(f.Nameservers) != len(wantNS) || f.Nameservers[0] != wantNS[0] || f.Nameservers[1] != wantNS[1] {
		t.Errorf("Nameservers = %v, want %v", f.Nameservers, wantNS)
	}
	if !f.Created.Parsed || f.Created.Raw != "14-Aug-1995" {
		t.Errorf("Created = %+v, want Parsed with Raw 14-Aug-1995", f.Created)
	}
	if !f.Expires.Parsed || f.Expires.Raw != "13-Aug-2026" {
		t.Errorf("Expires = %+v, want Parsed with Raw 13-Aug-2026", f.Expires)
	}
	if !f.Updated.Parsed || f.Updated.Raw != "14-Jan-2025" {
		t.Errorf("Updated = %+v, want Parsed with Raw 14-Jan-2025", f.Updated)
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
