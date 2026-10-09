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
	// Restricted is set when the registry answers that the name is
	// reserved, prohibited or otherwise restricted: neither registered
	// nor available (see restrictedMarkers).
	Restricted  bool
	NotFound    bool
	Unsupported bool
	Unmapped    map[string][]string
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
	"sponsoring registrar":                   fRegistrar, // CNNIC (.cn)
	"registrar name":                         fRegistrar, // .il, .au
	"registration time":                      fCreated,   // CNNIC (.cn)
	"nserver":                                fNameservers,
	"nameservers":                            fNameservers,
	"state":                                  fStatus,      // .jp third-level records, .ru, .se
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
	"ratelimit exceeded",         // "Error: ratelimit exceeded" (.aw, .nl under load)
	"has reached rate limit",     // "IP Address Has Reached Rate Limit" (Web.com registrars)
	"maximum query rate reached", // "%% Maximum query rate reached" (.lu)
}

// The entries after "status: free" come from a 2026-09-27 sweep of every
// country-code TLD, which found 74 free names reported as registered
// because their registry's wording matched none of the above (#113).
// Each was checked against 183 registered answers from the same sweep and
// every registered fixture, and matched none of them; keep it that way --
// TestParse_NoRegisteredFixtureTripsAMarker guards the fixtures. That is
// why CoCCA's "No Object Found" is matched only after "status:" or
// "message:", never alone: JWhoisServer prints "NO OBJECT FOUND!" for
// each missing contact inside a registered domain's answer (see
// notFoundPatterns for its domain-level form).
var notFoundMarkers = []string{
	"no match",
	"not found",
	"no entries found",
	"no data found",
	"status: free",
	"status: no object found",                      // CoCCA-style registries
	"message: no object found",                     // .sr
	"object does not exist",                        // CoCCA-style, .by, .ws
	"object_not_found",                             // .mx, for a free name
	"is available for registration",                // Tucows registry: .in .my .bh .ky .pw .to
	"is available for purchase",                    // .tm
	"registration status: available",               // .bg
	"not registered, and may be available",         // .pk
	"no information available about domain",        // .pl
	"no record found for",                          // .ls
	"no such domain",                               // .lu
	"nothing found",                                // .at, .kz
	"has not been registered",                      // .hk
	"domain is not registered",                     // .rs
	"no se encuentra registrado",                   // .ar
	"no found",                                     // .tw
	"no information was found matching that query", // ZACR (.africa)
}

// restrictedMarkers identify an answer that the name is reserved,
// prohibited or otherwise restricted -- neither registered nor available.
// Reporting it as registered (the old behaviour: no marker matched) or as
// not registered (which reads as "free") would both be wrong; collect
// turns it into a failed source with the reason, so the lookup is
// inconclusive. From the 2026-09-27 ccTLD sweep (#111), each checked
// against the sweep's registered answers and genuinely-free answers and
// matching neither. "Not available" alone is not a marker: some
// registries describe a registered domain that way.
var restrictedMarkers = []string{
	"violates registry policy",                         // .ug
	"matches a restricted word",                        // .dm
	"prohibited string - domain cannot be registered",  // CoCCA-style (.bw, .ke)
	"this domain cannot be registered",                 // .pk
	"reserved by qdr",                                  // .qa
	"the domain name is not available",                 // .qa
	"reserved domain name",                             // .om
	"has usage restrictions applied",                   // .ca, .nz
	"can not be registered online",                     // .cn
	"currently not available for registration",         // .hk
	"restricted to specifically qualified registrants", // .kr (KISA)
}

// bareNotFoundAnswers are lines some registries append to every answer,
// and send on their own when there is no record. The line alone is
// boilerplate; an answer consisting of nothing else means "no record".
// .bo's footer was once a refusal marker, which failed every registered
// .bo domain -- whose full record ends with the same line (#116).
var bareNotFoundAnswers = []string{
	"whois.nic.bo solo acepta consultas con dominios .bo",
}

// isBareNotFoundAnswer reports whether raw's only content line is one of
// bareNotFoundAnswers.
func isBareNotFoundAnswer(raw string) bool {
	var content []string
	for _, l := range strings.Split(raw, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			content = append(content, l)
		}
	}
	return len(content) == 1 && slices.Contains(bareNotFoundAnswers, strings.ToLower(content[0]))
}

// hasContentLine reports whether raw has any line that is neither blank
// nor a "%" or "#" comment.
func hasContentLine(raw string) bool {
	for _, l := range strings.Split(raw, "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "%") && !strings.HasPrefix(l, "#") {
			return true
		}
	}
	return false
}

// notFoundPatterns are not-found signals that need more context than a
// substring. JWhoisServer (.tg .tn .gf .mq) reports a missing object as
// "NO OBJECT FOUND!" followed by the object and its type; only a missing
// object of type domain means the queried domain is free.
var notFoundPatterns = []*regexp.Regexp{
	regexp.MustCompile(`no object found!\s*\n\s*object:[ .]*\S+\s*\n\s*type:[ .]*domain\b`),
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
	// SWITCH (.ch, .li) refuses port-43 queries and points to its web
	// form. Matched as the whole sentence: "not permitted" alone appears
	// in the terms of use of countless real answers.
	"requests of this client are not permitted",
	"this tld has no whois server",   // Freenom's former TLDs (.gq)
	"whois service has been retired", // gTLD registries under ICANN\'s RDAP transition (GMO: .shop, .tokyo)
}

// tokenizeKV handles the default "Key: value" dialect used by most
// registries (thin .com-style, thick .org-style, IANA's own format).
// Lines starting with "%" or "#" are comments and skipped.
//
// With continued set, an indented line following a key is another value
// for that key, read whole: NASK (.pl) writes a nameserver list as one
// "nameservers:" line and then indented bare hosts. It is a template
// option rather than the default because .com-style answers indent
// lines that are not continuations.
func tokenizeKV(raw string, continued bool) []kvPair {
	var out []kvPair
	for _, line := range strings.Split(raw, "\n") {
		if continued && len(out) > 0 && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
			if v := strings.TrimSpace(line); v != "" {
				out = append(out, kvPair{out[len(out)-1].key, v})
				continue
			}
		}
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

// tokenizeIndent handles Nominet-style ".uk" WHOIS output: a "Header:"
// line introduces a section, followed by one or more lines indented
// deeper than that header holding the section's content. Indentation is
// relative, not absolute: real Nominet responses indent every line --
// headers by four spaces, bodies by eight -- while EURid's headers sit at
// column zero, so a header is recognized by its trailing colon and its
// body by being indented past it. A line indented no deeper than the
// current header ends that section.
//
// A body line containing its own "sub-key: value" pair (e.g. "Registered
// on: before Aug-1996" inside a "Relevant dates:" section) is tokenized
// using that sub-key directly, since Nominet nests several distinct
// fields under one section header. Any other body line uses the enclosing
// section's header as the key, so multiple lines under "Name servers:"
// each become a separate pair sharing that key -- exactly like
// tokenizeKV's repeated "Name Server:" lines do for other registries.
//
// A sub-key must pass flatKeyPattern, and its colon must be the first one
// not nested inside parentheses. Both guard nameserver glue: Nominet's
// "ddns0.bbc.co.uk   148.163.199.1  2607:f740:e04e::1" and EURid's
// "ns1.example.eu (2a05:d018:c5f:3701::1)" both carry IPv6 colons that
// are not separators, and splitting on them loses the hostname into
// Unmapped under a garbage key instead of letting it reach stripGlue.
//
// A line outside any section that already carries its own value under a
// short, label-like key (e.g. EURid's ".eu" responses open with flat
// "Domain: europa.eu" / "Script: LATIN" lines before any indented
// section) is emitted as its own pair rather than treated as a header,
// since it has no body of its own. flatKeyPattern keeps this narrow too:
// it must not swallow prose that happens to contain a colon, like
// Nominet's trailing "WHOIS lookup made at 14:44:39 26-Sep-2026" line.
// Blank lines and any other line outside a section are ignored, the same
// way tokenizeKV skips comment lines.
func tokenizeIndent(raw string) []kvPair {
	var out []kvPair
	section := ""
	sectionIndent := 0
	for _, line := range strings.Split(raw, "\n") {
		trimmedRight := strings.TrimRight(line, "\r")
		content := strings.TrimSpace(trimmedRight)
		if content == "" {
			continue
		}
		indent := len(trimmedRight) - len(strings.TrimLeft(trimmedRight, " \t"))

		if section != "" && indent > sectionIndent {
			if idx := indexTopLevelColon(content); idx >= 0 {
				key := strings.TrimSpace(content[:idx])
				val := strings.TrimSpace(content[idx+1:])
				if val != "" && flatKeyPattern.MatchString(key) {
					out = append(out, kvPair{strings.ToLower(key), val})
					// The same sub-key also under its section's name
					// ("registrar organization"), for a template to map
					// where the bare sub-key is ambiguous: .it's
					// registrar and contacts all have "Organization:".
					// Unmapped, it only lands in Unmapped.
					out = append(out, kvPair{section + " " + strings.ToLower(key), val})
					continue
				}
			}
			out = append(out, kvPair{section, content})
			continue
		}

		section = ""
		// .it writes its headers with no colon at all ("Registrar",
		// "Nameservers"). A colon-less line outside a section is taken as
		// a header too; if nothing indented follows it, the next line
		// simply ends the empty section.
		if strings.HasSuffix(content, ":") || !strings.Contains(content, ":") {
			section = strings.ToLower(strings.TrimSuffix(content, ":"))
			sectionIndent = indent
			continue
		}
		if idx := strings.Index(content, ":"); idx >= 0 {
			key := strings.TrimSpace(content[:idx])
			val := strings.TrimSpace(content[idx+1:])
			if val != "" && flatKeyPattern.MatchString(key) {
				out = append(out, kvPair{strings.ToLower(key), val})
			}
		}
	}
	return out
}

// nominetTag matches the registrar tag Nominet appends to a .uk
// registrar's name ("British Broadcasting Corporation [Tag = BBC]").
var nominetTag = regexp.MustCompile(`\s*\[Tag = [^\]]*\]$`)

// registrarName strips what Nominet adds to a registrar line that is not
// the registrar's name: its trailing "[Tag = X]", which RDAP does not
// carry and so made every .uk lookup report a registrar conflict, and its
// "No registrar listed." sentence for a domain registered directly with
// Nominet, which means there is no registrar rather than naming one.
// Neither shape appears in any other registry's output.
func registrarName(val string) string {
	if strings.HasPrefix(val, "No registrar listed.") {
		return ""
	}
	return nominetTag.ReplaceAllString(val, "")
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
		pairs = tokenizeKV(raw, tmpl.ContinuationLines)
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
	if !f.NotFound && isBareNotFoundAnswer(raw) {
		f.NotFound = true
	}
	if !f.NotFound && tmpl.CommentOnlyIsNotFound && !hasContentLine(raw) {
		f.NotFound = true
	}
	if !f.NotFound {
		normalized := strings.ReplaceAll(lowerRaw, "\r", "")
		for _, p := range notFoundPatterns {
			if p.MatchString(normalized) {
				f.NotFound = true
				break
			}
		}
	}
	for _, marker := range unsupportedMarkers {
		if strings.Contains(lowerRaw, marker) {
			f.Unsupported = true
			break
		}
	}
	for _, marker := range restrictedMarkers {
		if strings.Contains(lowerRaw, marker) {
			f.Restricted = true
			break
		}
	}

	for _, p := range pairs {
		// A template can map a key to "" to say it is not a synonym for
		// that TLD, keeping it in Unmapped (see mx in templates.yaml).
		canon, ok := synonyms[p.key]
		if !ok || canon == "" {
			f.Unmapped[p.key] = append(f.Unmapped[p.key], p.val)
			continue
		}
		// Single-valued fields keep their first occurrence. A response
		// describes the domain first and then its contact, nsset and
		// keyset objects, which reuse the same keys (CZ.NIC's contacts
		// carry their own "registrar:" and "created:", .it's their own
		// "Created:" and "Last Update:"), so assigning on every match
		// let the last contact's values replace the domain's own.
		switch canon {
		case fDomain:
			if f.Domain == "" {
				f.Domain = p.val
			}
		case fRegistrar:
			if f.Registrar == "" {
				f.Registrar = registrarName(p.val)
			}
		case fRegistrarWHOISServer:
			if f.RegistrarWHOISServer == "" {
				f.RegistrarWHOISServer = p.val
			}
		case fRefer:
			if f.Refer == "" {
				f.Refer = p.val
			}
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
			if f.Created.Raw == "" {
				f.Created = parseDateWith(p.val, tmpl)
			}
		case fUpdated:
			if f.Updated.Raw == "" {
				f.Updated = parseDateWith(p.val, tmpl)
			}
		case fExpires:
			if f.Expires.Raw == "" {
				f.Expires = parseDateWith(p.val, tmpl)
			}
		}
	}
	// DNS Belgium answers an unregistered name with "Status: AVAILABLE"
	// (and a registered one with "NOT AVAILABLE"). Matched on the exact
	// status value rather than as a marker in the raw text, where
	// "available" is a substring of the registered answer.
	if slices.ContainsFunc(f.Statuses, func(s string) bool { return strings.EqualFold(strings.TrimSpace(s), "available") }) {
		f.NotFound = true
	}
	// A restricted name is not a free one, whatever else the answer says.
	if f.Restricted {
		f.NotFound = false
	}
	return f
}
