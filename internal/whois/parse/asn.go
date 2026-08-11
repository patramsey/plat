package parse

import "strings"

// ASNFields is the autonomous-system counterpart to Fields and IPFields.
// Kept as its own type rather than folded into IPFields for the same
// reason IPFields is kept separate from Fields: an ASN has no netblock
// range, CIDR, or netname, and an IP allocation has no as-name or
// aut-num handle.
type ASNFields struct {
	Number     string
	Name       string
	Handle     string
	Type       string
	OrgName    string
	OrgID      string
	Country    string
	Registered string
	Updated    string
	AbuseEmail string
	AbusePhone string
	Statuses   []string

	// descr holds RPSL's free-text `descr:` line, kept separate from
	// OrgName for the same reason IPFields.descr is: in a live RIPE
	// aut-num object, descr (e.g. "Reseaux IP Europeens Network
	// Coordination Centre (RIPE NCC)") is the only org-identity text the
	// object carries -- there is no separate "org-name:" key inside the
	// aut-num object itself (unlike an inetnum object, which has both).
	// ParseASN falls back to descr for OrgName only when no explicit
	// OrgName (ARIN's own key) ever appeared, after the full scan
	// completes.
	descr string
}

// asnSynonyms maps the lowercased WHOIS key to the ASNFields member it
// populates, covering both ARIN's CamelCase vocabulary (ASNumber, OrgName)
// and the RPSL-style vocabulary RIPE, APNIC, LACNIC and AFRINIC share
// (aut-num, as-name, descr). A key already set is never overwritten, so
// the first occurrence wins -- see ParseASN's doc comment for why the
// as-block object (which RIPE places before the aut-num object in the
// same response) must never reach this table at all.
var asnSynonyms = map[string]func(*ASNFields, string){
	"asnumber": func(f *ASNFields, v string) { f.Number = v },
	"aut-num": func(f *ASNFields, v string) {
		f.Handle = v
		f.Number = strings.TrimPrefix(strings.ToUpper(v), "AS")
	},
	"asname":        func(f *ASNFields, v string) { f.Name = v },
	"as-name":       func(f *ASNFields, v string) { f.Name = v },
	"ashandle":      func(f *ASNFields, v string) { f.Handle = v },
	"orgname":       func(f *ASNFields, v string) { f.OrgName = v },
	"descr":         func(f *ASNFields, v string) { f.descr = v },
	"orgid":         func(f *ASNFields, v string) { f.OrgID = v },
	"org":           func(f *ASNFields, v string) { f.OrgID = v },
	"country":       func(f *ASNFields, v string) { f.Country = v },
	"regdate":       func(f *ASNFields, v string) { f.Registered = v },
	"created":       func(f *ASNFields, v string) { f.Registered = v },
	"updated":       func(f *ASNFields, v string) { f.Updated = v },
	"last-modified": func(f *ASNFields, v string) { f.Updated = v },
	"orgabuseemail": func(f *ASNFields, v string) { f.AbuseEmail = v },
	"abuse-mailbox": func(f *ASNFields, v string) { f.AbuseEmail = v },
	"orgabusephone": func(f *ASNFields, v string) { f.AbusePhone = v },
	"status":        func(f *ASNFields, v string) { f.Statuses = append(f.Statuses, v) },
}

// asnFieldGet reports whether the member a key maps to is already
// populated, so first-occurrence-wins can be enforced without reflection.
var asnFieldGet = map[string]func(*ASNFields) string{
	"asnumber":      func(f *ASNFields) string { return f.Number },
	"aut-num":       func(f *ASNFields) string { return f.Handle },
	"asname":        func(f *ASNFields) string { return f.Name },
	"as-name":       func(f *ASNFields) string { return f.Name },
	"ashandle":      func(f *ASNFields) string { return f.Handle },
	"orgname":       func(f *ASNFields) string { return f.OrgName },
	"descr":         func(f *ASNFields) string { return f.descr },
	"orgid":         func(f *ASNFields) string { return f.OrgID },
	"org":           func(f *ASNFields) string { return f.OrgID },
	"country":       func(f *ASNFields) string { return f.Country },
	"regdate":       func(f *ASNFields) string { return f.Registered },
	"created":       func(f *ASNFields) string { return f.Registered },
	"updated":       func(f *ASNFields) string { return f.Updated },
	"last-modified": func(f *ASNFields) string { return f.Updated },
	"orgabuseemail": func(f *ASNFields) string { return f.AbuseEmail },
	"abuse-mailbox": func(f *ASNFields) string { return f.AbuseEmail },
	"orgabusephone": func(f *ASNFields) string { return f.AbusePhone },
}

// ParseASN extracts autonomous-system fields from a raw RIR WHOIS
// response, handling both ARIN's and the RPSL-style vocabularies in one
// pass. When no authoritative org identity (ARIN's OrgName) was found
// anywhere in the response, it falls back to RPSL's descr line -- see the
// descr field doc comment on ASNFields for why that can't just be folded
// into the first-occurrence-wins scan itself.
//
// RIPE (and, per RFC 9083's shared RPSL heritage, potentially other RIRs)
// answers an ASN query with an as-block object listing the whole
// allocated range (e.g. "AS3209 - AS3353") BEFORE the aut-num object for
// the specific ASN queried. Every RPSL key the as-block object carries --
// descr, created, last-modified, source -- is also a key the aut-num
// object carries, so under plain first-occurrence-wins the block's own
// values (e.g. descr "RIPE NCC ASN block") would permanently shadow the
// ASN's real ones. ParseASN tracks which object the current line belongs
// to (an object starts with a line whose key is "as-block" or "aut-num"
// and ends at the next blank line, per RPSL's object-separator rule) and
// skips every line belonging to an as-block object outright.
//
// APNIC (verified live against AS4808) can additionally place a "role"
// object -- an administrative contact, not the as-block -- between the
// as-block and the aut-num object. That role object carries its own
// "country" and "last-modified" (the contact's own address/record-update
// time, e.g. APNIC's own hostmaster team), which share asnSynonyms keys
// with the aut-num object's identically-named but semantically unrelated
// fields. Skipping as-block alone isn't enough to keep that from
// shadowing the real ASN data, and there's no closed list of every
// RPSL contact-object class name (role, person, organisation, irt,
// mntner...) that might similarly precede aut-num across RIRs. Rather
// than skip every non-aut-num object by name, ParseASN instead lets the
// aut-num object's own values always win: once inAutNum, set()
// unconditionally overwrites (instead of the usual first-occurrence-wins
// skip-if-already-set), so whatever a preceding object incidentally
// captured is corrected the moment the real aut-num data is reached.
// Objects after aut-num (e.g. an "irt" object supplying abuse-mailbox,
// which aut-num itself never carries) still use ordinary
// first-occurrence-wins, so they keep filling in fields aut-num left
// empty exactly as before.
func ParseASN(raw string) ASNFields {
	var f ASNFields
	inASBlock := false
	inAutNum := false
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			inASBlock = false
			inAutNum = false
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "%") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)

		switch key {
		case "as-block":
			inASBlock = true
		case "aut-num":
			inASBlock = false
			inAutNum = true
		}
		if inASBlock {
			continue
		}

		if val == "" {
			continue
		}
		set, known := asnSynonyms[key]
		if !known {
			continue
		}
		if !inAutNum {
			if get, ok := asnFieldGet[key]; ok && get(&f) != "" {
				continue // first occurrence wins
			}
		}
		set(&f, val)
	}
	if f.OrgName == "" {
		f.OrgName = f.descr
	}
	return f
}
