package parse

import (
	"regexp"
	"slices"
	"strings"
)

// Fields is a normalized, package-scoped view of one raw WHOIS response.
// It intentionally does not model contacts/registrant details or perform
// cross-vocabulary EPP status normalization — both are the shared model's
// job in a later milestone.
type Fields struct {
	Domain               string
	Registrar            string
	RegistrarWHOISServer string
	Refer                string
	Statuses             []string
	Nameservers          []string
	Created              Date
	Updated              Date
	Expires              Date
	RateLimited          bool
	NotFound             bool
	Unsupported          bool
	Unmapped             map[string][]string
}

type kvPair struct{ key, val string }

const (
	fDomain               = "domain"
	fRegistrar            = "registrar"
	fRegistrarWHOISServer = "registrarwhoisserver"
	fRefer                = "refer"
	fStatus               = "status"
	fNameservers          = "nameservers"
	fCreated              = "created"
	fUpdated              = "updated"
	fExpires              = "expires"
)

var defaultSynonyms = map[string]string{
	"domain name":            fDomain,
	"domain":                 fDomain,
	"registrar":              fRegistrar,
	"registrar whois server": fRegistrarWHOISServer,
	"whois server":           fRegistrarWHOISServer,
	"refer":                  fRefer,
	// "whois" (bare, no "server" suffix -- distinct from "whois server"/
	// "registrar whois server" above, which are a different field
	// entirely) is what whois.iana.org's REAL responses actually use for
	// the registry referral, confirmed live for every TLD checked
	// (.com, .org, .net, .jp, .de, .edu): "whois: whois.verisign-grs.com"
	// etc. "refer:" is the conventional WHOIS-referral field name and
	// stays supported too, but it never once matched a real IANA
	// response -- meaning the registry-WHOIS hop (and everything after
	// it: the registrar-WHOIS hop reached by following the registry
	// response's own "Registrar WHOIS Server:" line) silently never fired
	// for any live domain before this fix. Confirmed via a 1000-domain
	// live audit: registry-whois never once appeared as a successful
	// source across the entire run.
	"whois":                                  fRefer,
	"domain status":                          fStatus,
	"status":                                 fStatus,
	"state":                                  fStatus, // .jp third-level records
	"name server":                            fNameservers,
	"name servers":                           fNameservers,
	"domain nameservers":                     fNameservers,
	"nserver":                                fNameservers,
	"nameservers":                            fNameservers,
	"nameserver":                             fNameservers, // .lt uses the singular; without this synonym its nameservers were dropped entirely
	"creation date":                          fCreated,
	"created":                                fCreated,
	"created on":                             fCreated,
	"registered on":                          fCreated,
	"domain registration date":               fCreated,
	"registry expiry date":                   fExpires,
	"expiry date":                            fExpires,
	"expiration date":                        fExpires,
	"expires on":                             fExpires,
	"paid-till":                              fExpires,
	"renewal date":                           fExpires,
	"registrar registration expiration date": fExpires,
	"registry registration expiration date":  fExpires,
	"registrar expiration date":              fExpires, // .law's trellis.law -- shorter variant of the same ICANN-standard field above, confirmed live
	"updated date":                           fUpdated,
	"updated":                                fUpdated,
	"last updated":                           fUpdated,

	// Everything below was found via a live 2433-domain audit spanning
	// 892 distinct TLDs, each individually confirmed against the real
	// registry (not guessed from the label alone) -- several near-misses
	// were deliberately left OUT: .kz's "Registar created" holds a
	// registrar name ("KAZNIC"), not a date; .ru's "free-date" is the
	// later post-grace-period deletion date, a distinct concept from
	// expires that would misrepresent data if merged; .fr's "eligdate"/
	// "reachdate" are AFNIC-specific regulatory fields unrelated to
	// creation/update/expiry.
	"registered date":               fCreated, // .jp -- same value as "Registered Date" alongside JPRS's own "Connected Date"
	"connected date":                fCreated, // .jp -- JPRS's alias for the same creation date
	"original created":              fCreated, // .nz -- same value as "Creation Date" on the same record
	"domain created":                fCreated, // .kz
	"record created":                fCreated,
	"registration date":             fCreated, // .rs
	"created-date":                  fCreated, // .st
	"domain name commencement date": fCreated, // .hk
	"date de création":              fCreated, // .sn (French)
	"last update":                   fUpdated, // .jp -- bare, distinct from "last updated" above
	"last-update":                   fUpdated, // .fr
	"update date":                   fUpdated, // .by -- distinct from "updated date" above
	"last updated on":               fUpdated, // .mx
	"modification date":             fUpdated, // .rs
	"domain record last updated":    fUpdated, // .edu
	"updated-date":                  fUpdated, // .st
	"last update time":              fUpdated, // .tr
	"record last updated on":        fUpdated, // .kg
	"modified date":                 fUpdated, // .bn
	"expire":                        fExpires, // .ee
	"expires":                       fExpires, // .se
	"expiry":                        fExpires, // symmetric with "expire"/"expires" above
	"expire date":                   fExpires, // .it
	"expiration time":               fExpires, // .cn
	"domain expires":                fExpires, // .edu
	"expiration-date":               fExpires, // .st
	"valid until":                   fExpires, // .sk
	"record expires on":             fExpires, // .kg
	"date d'expiration":             fExpires, // .sn (French)
}

var rateLimitMarkers = []string{
	"query rate limit exceeded",
	"exceeded query limit",
	"too many requests",
	"quota exceeded",
}

var notFoundMarkers = []string{
	"no match",
	"not found",
	"no entries found",
	"no data found",
	"status: free",
}

// unsupportedMarkers flag a registry WHOIS service flatly refusing a
// query for reasons unrelated to whether the domain exists — e.g.
// Identity Digital's shared WHOIS returning "TLD is not supported." for
// several of its newer gTLDs, apparently because it doesn't run WHOIS
// for them at all (RDAP-only). This is a distinct condition from
// notFoundMarkers: "not found" is a positive claim the domain doesn't
// exist, while "not supported" says nothing about the domain either way
// — it's the service itself that's unavailable for this query. Treating
// the latter as NotFound would surface a factually wrong "domain doesn't
// exist" (exit code 1) for a domain that may well exist.
var unsupportedMarkers = []string{
	"not supported",
	"unsupported tld",
}

// tokenizeKV handles the default "Key: value" dialect used by most
// registries (thin .com-style, thick .org-style, IANA's own format).
// Lines starting with "%" or "#" are comments and skipped.
func tokenizeKV(raw string) []kvPair {
	var out []kvPair
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		// .tr's registry right-pads field labels with a run of dots for
		// fixed-width alignment before the colon -- e.g. "Created
		// on..............: 2001-Aug-23." (confirmed live). Trimming
		// trailing dots lets "created on.............." match the same
		// "created on" synonym a normal "Created on: ..." line would,
		// instead of needing one exact-dot-count entry per label length.
		// A real field label never legitimately ends in a literal period.
		key := strings.ToLower(strings.TrimRight(strings.TrimSpace(line[:idx]), "."))
		val := strings.TrimSpace(line[idx+1:])
		if val == "" {
			continue
		}
		out = append(out, kvPair{key, val})
	}
	return out
}

// stripGlue reduces a WHOIS nameserver value to its hostname.
//
// Registries append glue addresses to the nameserver line in at least five
// dialects -- space-separated (.de), parenthesised (.cz, .eu), bracketed
// (.pl, .lt), and comma-separated after a trailing dot (.ru). In every one
// of them the hostname is the first whitespace-delimited token, so that is
// the whole rule. Glue is discarded rather than kept: model.Record has no
// field for it, so carrying it inside the hostname string does not preserve
// data, it produces a value that is not a hostname.
func stripGlue(v string) string {
	fields := strings.Fields(v)
	if len(fields) == 0 {
		return ""
	}
	return strings.TrimSuffix(fields[0], ".")
}

func firstToken(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// tokenizeBrackets handles JPRS-style "[Key]    value" lines.
//
// A leading "a. " / "b. " ordinal appears on JPRS's third-level records
// (.ad.jp, .co.jp) and nowhere else; the optional group keeps second-level
// .jp records matching exactly as before.
var bracketLine = regexp.MustCompile(`^(?:[a-z]\.\s+)?\[([^\]]+)\]\s*(.*)$`)

// flatKeyPattern matches a short, letters-only, at-most-three-word label --
// used by tokenizeIndent to recognize a non-indented "Key: value" line
// (e.g. EURid's flat "Domain: europa.eu") without also swallowing prose
// that happens to contain a colon, like a trailing "WHOIS lookup made on
// Sun, 12 Jul 2026 at 09:15:00" timestamp line.
var flatKeyPattern = regexp.MustCompile(`^[A-Za-z]+(?: [A-Za-z]+){0,2}$`)

func tokenizeBrackets(raw string) []kvPair {
	var out []kvPair
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		m := bracketLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(m[1]))
		val := strings.TrimSpace(m[2])
		if val == "" {
			continue
		}
		out = append(out, kvPair{key, val})
	}
	return out
}

// indexTopLevelColon returns the index of the first ':' in s that is not
// enclosed in parentheses, or -1 if there is none. A colon inside an
// unmatched '(' is glue (an IPv6 address parenthesised after a
// nameserver hostname), not a key/value separator.
func indexTopLevelColon(s string) int {
	depth := 0
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ':':
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// tokenizeIndent handles Nominet-style ".uk" WHOIS output: a
// non-indented "Header:" line introduces a section, followed by one or
// more indented lines holding that section's content. An indented line
// containing its own "sub-key: value" pair (e.g. "Registered on:
// 14-Aug-1995" inside a "Relevant dates:" section) is tokenized using
// that sub-key directly, since Nominet nests several distinct fields
// under one section header. An indented line with no colon uses the
// enclosing section's header as the key, so multiple indented lines
// under "Name servers:" each become a separate pair sharing that key —
// exactly like tokenizeKV's repeated "Name Server:" lines do for other
// registries. A non-indented line that already carries its own value
// under a short, label-like key (e.g. EURid's ".eu" responses open with
// flat "Domain: europa.eu" / "Script: LATIN" lines before any indented
// section) is emitted as its own pair immediately rather than treated as
// a section header, since it has no indented body of its own. The
// flatKeyPattern check keeps this narrow: it must not swallow prose that
// happens to contain a colon, like a trailing "WHOIS lookup made on Sun,
// 12 Jul 2026 at 09:15:00" timestamp line (digits/commas/many words),
// which tokenizeIndent must keep dropping the same as before. Blank
// lines and any other non-indented, non-header, non-label-valued line
// are ignored, the same way tokenizeKV skips comment lines. Within an
// indented line, the key/value separator is the first colon *not*
// nested inside parentheses -- an indented "host (glue)" line like
// EURid's "ns1.example.eu (2a05:d018:c5f:3701::1)" carries colons inside
// its IPv6 glue that must not be mistaken for that separator, or the
// whole line (and its hostname) is lost into Unmapped under a garbage
// key instead of reaching stripGlue.
func tokenizeIndent(raw string) []kvPair {
	var out []kvPair
	section := ""
	for _, line := range strings.Split(raw, "\n") {
		trimmedRight := strings.TrimRight(line, "\r")
		if strings.TrimSpace(trimmedRight) == "" {
			continue
		}
		if !strings.HasPrefix(trimmedRight, " ") && !strings.HasPrefix(trimmedRight, "\t") {
			trimmed := strings.TrimSpace(trimmedRight)
			section = ""
			switch {
			case strings.HasSuffix(trimmed, ":"):
				section = strings.ToLower(strings.TrimSuffix(trimmed, ":"))
			default:
				if idx := strings.Index(trimmed, ":"); idx >= 0 {
					key := strings.TrimSpace(trimmed[:idx])
					val := strings.TrimSpace(trimmed[idx+1:])
					if val != "" && flatKeyPattern.MatchString(key) {
						out = append(out, kvPair{strings.ToLower(key), val})
					}
				}
			}
			continue
		}
		if section == "" {
			continue
		}
		content := strings.TrimSpace(trimmedRight)
		if idx := indexTopLevelColon(content); idx >= 0 && strings.TrimSpace(content[idx+1:]) != "" {
			key := strings.ToLower(strings.TrimSpace(content[:idx]))
			val := strings.TrimSpace(content[idx+1:])
			out = append(out, kvPair{key, val})
			continue
		}
		out = append(out, kvPair{section, content})
	}
	return out
}

// Parse extracts normalized Fields from a raw WHOIS response for tld,
// applying tld's template (dialect + synonym overrides) if one is
// registered in templates.yaml.
func Parse(raw, tld string) Fields {
	tmpl := templateFor(tld)

	var pairs []kvPair
	switch tmpl.Format {
	case "brackets":
		pairs = tokenizeBrackets(raw)
	case "indent":
		pairs = tokenizeIndent(raw)
	default:
		pairs = tokenizeKV(raw)
	}

	synonyms := defaultSynonyms
	if len(tmpl.Synonyms) > 0 {
		merged := make(map[string]string, len(defaultSynonyms)+len(tmpl.Synonyms))
		for k, v := range defaultSynonyms {
			merged[k] = v
		}
		for k, v := range tmpl.Synonyms {
			merged[k] = v
		}
		synonyms = merged
	}

	f := Fields{Unmapped: map[string][]string{}}

	lowerRaw := strings.ToLower(raw)
	for _, marker := range rateLimitMarkers {
		if strings.Contains(lowerRaw, marker) {
			f.RateLimited = true
			break
		}
	}
	for _, marker := range notFoundMarkers {
		if strings.Contains(lowerRaw, marker) {
			f.NotFound = true
			break
		}
	}
	for _, marker := range unsupportedMarkers {
		if strings.Contains(lowerRaw, marker) {
			f.Unsupported = true
			break
		}
	}

	for _, p := range pairs {
		canon, ok := synonyms[p.key]
		if !ok {
			f.Unmapped[p.key] = append(f.Unmapped[p.key], p.val)
			continue
		}
		switch canon {
		case fDomain:
			f.Domain = p.val
		case fRegistrar:
			f.Registrar = p.val
		case fRegistrarWHOISServer:
			f.RegistrarWHOISServer = p.val
		case fRefer:
			f.Refer = p.val
		case fStatus:
			// ICANN's gTLD convention is "<eppCode> <url>", so the code is the
			// first token. A registry that puts an English phrase here (CZ.NIC:
			// "Sponsoring registrar change forbidden") must keep the phrase --
			// truncating it yields a meaningless fragment presented next to
			// genuine EPP codes.
			val := p.val
			if strings.Contains(val, "http://") || strings.Contains(val, "https://") {
				val = firstToken(val)
			}
			if val != "" {
				f.Statuses = append(f.Statuses, val)
			}
		case fNameservers:
			ns := stripGlue(p.val)
			if ns == "" {
				break
			}
			// EURid lists one line per address family for the same host, so
			// a source can repeat a name once glue is stripped.
			if !slices.ContainsFunc(f.Nameservers, func(existing string) bool {
				return strings.EqualFold(existing, ns)
			}) {
				f.Nameservers = append(f.Nameservers, ns)
			}
		case fCreated:
			f.Created = ParseDate(p.val)
		case fUpdated:
			f.Updated = ParseDate(p.val)
		case fExpires:
			f.Expires = ParseDate(p.val)
		}
	}
	return f
}
