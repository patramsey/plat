package parse

import (
	"slices"
	"testing"
	"time"
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

// Registries whose dates were in the answer but came out empty: keys no
// synonym mapped (.il, .pl's "last modified", .mq's "changed"), and
// formats no layout matched (.il day-first, .pl dotted with a time, .gg's
// sentence). .pl and .cz write local time with no zone; each expected
// value below is the one their registry RDAP gives.
func TestParse_RegistryDates(t *testing.T) {
	for _, tt := range []struct {
		fixture, tld              string
		created, updated, expires string // RFC 3339 date-times, "" for absent
	}{
		{fixture: "isoc-il-recorded.txt", tld: "il",
			created: "1996-01-11T00:00:00Z", expires: "2029-01-11T00:00:00Z"},
		{fixture: "nask-pl-google-recorded.txt", tld: "pl",
			created: "2002-09-19T11:00:00Z", updated: "2026-08-17T10:47:01Z", expires: "2027-09-18T12:00:00Z"},
		// "renewal date: not defined" stays unparsed rather than inventing one.
		{fixture: "nask-pl-recorded.txt", tld: "pl",
			created: "1998-01-26T11:00:00Z", updated: "2015-04-20T09:41:34Z"},
		// Winter (CET) and summer (CEST); the bare expiry date is not shifted.
		{fixture: "cznic-cz-recorded.txt", tld: "cz",
			created: "1997-10-30T00:00:00Z", updated: "2020-11-17T13:25:52Z", expires: "2027-03-15T00:00:00Z"},
		{fixture: "cznic-cz-seznam-recorded.txt", tld: "cz",
			created: "1996-10-07T00:00:00Z", updated: "2022-09-05T12:21:11Z", expires: "2027-10-29T00:00:00Z"},
		{fixture: "cidr-gg-recorded.txt", tld: "gg", created: "1997-04-24T00:00:00Z"},
		// FRED and NIC Argentina: "registered:" is the domain's creation;
		// the "created:" lines after it are contacts', and were read as
		// the domain's. .cr and .tz write local time (checked against
		// their RDAP), the others are read as UTC.
		{fixture: "nicar-ar-recorded.txt", tld: "ar",
			created: "1998-05-29T00:00:00Z", updated: "2023-07-17T17:23:05Z", expires: "2100-12-31T00:00:00Z"},
		{fixture: "nic-cr-recorded.txt", tld: "cr",
			created: "1996-01-01T00:00:00Z", updated: "2024-03-16T21:44:06Z", expires: "2035-01-01T00:00:00Z"},
		{fixture: "nic-ls-recorded.txt", tld: "ls",
			created: "2017-04-24T19:08:24Z", updated: "2019-09-20T16:14:52Z", expires: "2029-04-24T00:00:00Z"},
		{fixture: "marnet-mk-recorded.txt", tld: "mk",
			created: "2008-05-07T14:00:00Z", updated: "2026-02-25T13:53:54Z", expires: "2027-05-07T00:00:00Z"},
		{fixture: "nic-mw-recorded.txt", tld: "mw",
			created: "2014-09-17T11:26:09Z", updated: "2019-09-30T13:53:30Z", expires: "2027-12-17T00:00:00Z"},
		{fixture: "tznic-tz-recorded.txt", tld: "tz",
			created: "2015-01-28T12:14:03Z", updated: "2025-06-25T12:11:49Z", expires: "2030-01-28T00:00:00Z"},
		{fixture: "nic-ve-recorded.txt", tld: "ve",
			created: "2019-08-08T18:04:00Z", updated: "2026-07-07T14:39:42Z", expires: "2034-12-31T00:00:00Z"},
		// Offsets written after a space (.ee) or as hours alone (.ua).
		{fixture: "tld-ee-recorded.txt", tld: "ee",
			created: "2010-07-04T01:21:15Z", updated: "2025-10-16T10:22:04Z", expires: "2030-11-30T00:00:00Z"},
		{fixture: "hostmaster-ua-recorded.txt", tld: "ua",
			created: "2007-10-04T10:40:19Z", updated: "2026-09-29T11:28:52Z", expires: "2031-10-04T10:40:18Z"},
		{fixture: "nicat-at-registered-recorded.txt", tld: "at",
			created: "2000-08-25T20:16:35Z", updated: "2020-04-27T16:03:40Z"},
		{fixture: "cidr-je-recorded.txt", tld: "je", created: "1997-04-24T00:00:00Z"},
		{fixture: "jwhois-mq-registered-recorded.txt", tld: "mq",
			updated: "2022-02-22T00:00:00Z"},
	} {
		t.Run(tt.fixture, func(t *testing.T) {
			f := Parse(loadFixture(t, tt.fixture), tt.tld)
			for _, c := range []struct {
				name string
				got  Date
				want string
			}{{"Created", f.Created, tt.created}, {"Updated", f.Updated, tt.updated}, {"Expires", f.Expires, tt.expires}} {
				got := ""
				if c.got.Parsed {
					got = c.got.Time.Format(time.RFC3339)
				}
				if got != c.want {
					t.Errorf("%s = %q (raw %q), want %q", c.name, got, c.got.Raw, c.want)
				}
			}
		})
	}
}

// .gg/.je write the day as an ordinal; every suffix must parse.
// Synthetic: the recordings only have "24th".
func TestParse_CIDROrdinalDates(t *testing.T) {
	for in, want := range map[string]string{
		"1st May 2001": "2001-05-01", "2nd May 2001": "2001-05-02", "3rd May 2001": "2001-05-03",
		"11th May 2001": "2001-05-11", "22nd May 2001": "2001-05-22", "31st May 2001": "2001-05-31",
	} {
		raw := "Relevant dates:\n     Registered on " + in + " at 00:00:00.000\n"
		f := Parse(raw, "gg")
		if got := f.Created.Time.Format("2006-01-02"); !f.Created.Parsed || got != want {
			t.Errorf("%q: Created = %s (parsed %v), want %s", in, got, f.Created.Parsed, want)
		}
	}
}

// A template's time zone applies only to a time of day with no offset of
// its own. Synthetic.
func TestParse_TemplateTimezone(t *testing.T) {
	f := Parse("domain: example.pl\ncreated: 2020-07-01T10:00:00Z\n", "pl")
	if want := "2020-07-01T10:00:00Z"; f.Created.Time.Format(time.RFC3339) != want {
		t.Errorf("Created = %s, want %s: an explicit zone was overridden", f.Created.Time.Format(time.RFC3339), want)
	}
	if f := Parse("domain: example.zz\ncreated: 2002.09.19 13:00:00\n", ""); f.Created.Time.Hour() != 13 {
		t.Errorf("Created hour = %d without a template, want 13 (UTC)", f.Created.Time.Hour())
	}
}

func TestLoadTimezones_RejectsUnknownZone(t *testing.T) {
	if err := loadTimezones(map[string]Template{"zz": {Timezone: "Europe/Nowhere"}}); err == nil {
		t.Error("loadTimezones accepted Europe/Nowhere")
	}
}

// A template's dateLayouts apply to that TLD only: ".il"'s day-first
// layout must not read another registry's "11-01-2029" at all, since
// for a month-first registry it would be the wrong day.
func TestParse_TemplateDateLayoutsAreScoped(t *testing.T) {
	raw := "domain: example.zz\nexpires: 11-01-2029\n"
	if f := Parse(raw, ""); f.Expires.Parsed {
		t.Errorf("Expires parsed as %v without the .il template; the day-first layout leaked", f.Expires.Time)
	}
	f := Parse(raw, "il")
	if want := time.Date(2029, 1, 11, 0, 0, 0, 0, time.UTC); !f.Expires.Parsed || !f.Expires.Time.Equal(want) {
		t.Errorf("Expires under .il = %v (parsed %v), want %v", f.Expires.Time, f.Expires.Parsed, want)
	}
}
