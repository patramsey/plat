package parse

import (
	"regexp"
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
	"name server":                            fNameservers,
	"name servers":                           fNameservers,
	"domain nameservers":                     fNameservers,
	"nserver":                                fNameservers,
	"nameservers":                            fNameservers,
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

func firstToken(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// tokenizeBrackets handles JPRS-style "[Key]    value" lines.
var bracketLine = regexp.MustCompile(`^\[([^\]]+)\]\s*(.*)$`)

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
// registries. Blank lines and any other non-indented, non-header line
// (e.g. a trailing "WHOIS lookup made on ..." timestamp line) are
// ignored, the same way tokenizeKV skips comment lines.
func tokenizeIndent(raw string) []kvPair {
	var out []kvPair
	section := ""
	for _, line := range strings.Split(raw, "\n") {
		trimmedRight := strings.TrimRight(line, "\r")
		if strings.TrimSpace(trimmedRight) == "" {
			continue
		}
		if !strings.HasPrefix(trimmedRight, " ") && !strings.HasPrefix(trimmedRight, "\t") {
			if strings.HasSuffix(strings.TrimSpace(trimmedRight), ":") {
				section = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(trimmedRight), ":"))
			} else {
				section = ""
			}
			continue
		}
		if section == "" {
			continue
		}
		content := strings.TrimSpace(trimmedRight)
		if idx := strings.Index(content, ":"); idx >= 0 && strings.TrimSpace(content[idx+1:]) != "" {
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
			f.Statuses = append(f.Statuses, firstToken(p.val))
		case fNameservers:
			f.Nameservers = append(f.Nameservers, p.val)
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
