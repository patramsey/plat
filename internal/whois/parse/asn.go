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
//
// "status" is deliberately NOT listed here even though it's part of the
// RPSL vocabulary this table otherwise covers: it's append-valued (every
// "status:" line accumulates, unlike every other key's overwrite-once
// scalar), and ParseASN handles it on its own dedicated path for that
// reason -- see the comment there. Adding a "status" entry to this table
// would just be dead code, since ParseASN's main loop intercepts and
// `continue`s on that key before ever consulting this map.
var asnSynonyms = map[string]func(*ASNFields, string){
	"asnumber": func(f *ASNFields, v string) { f.Number = v },
	"aut-num": func(f *ASNFields, v string) {
		f.Handle = v
		f.Number = strings.TrimPrefix(strings.ToUpper(v), "AS")
	},
	"asname":   func(f *ASNFields, v string) { f.Name = v },
	"as-name":  func(f *ASNFields, v string) { f.Name = v },
	"ashandle": func(f *ASNFields, v string) { f.Handle = v },
	"orgname":  func(f *ASNFields, v string) { f.OrgName = v },
	// "org-name" is AFRINIC's own vocabulary (its aut-num's "org:" line
	// points at a separate "organisation:" object, which carries
	// "org-name:" for the actual identity string) -- already present in
	// ipSynonyms for the identical inetnum/organisation-object shape, but
	// missing here until now. Without it, AFRINIC's org.name only ever
	// came from "descr", which happens to agree with org-name for most
	// AFRINIC records today but isn't guaranteed to.
	"org-name": func(f *ASNFields, v string) { f.OrgName = v },
	// "owner" is LACNIC's RPSL vocabulary for the aut-num holder's name --
	// LACNIC does not use "orgname"/"org-name"/"descr" for this at all, so
	// without this entry LACNIC WHOIS contributed no org identity
	// whatsoever (confirmed live against AS28573).
	"owner":         func(f *ASNFields, v string) { f.OrgName = v },
	"descr":         func(f *ASNFields, v string) { f.descr = v },
	"orgid":         func(f *ASNFields, v string) { f.OrgID = v },
	"org":           func(f *ASNFields, v string) { f.OrgID = v },
	"country":       func(f *ASNFields, v string) { f.Country = v },
	"regdate":       func(f *ASNFields, v string) { f.Registered = v },
	"created":       func(f *ASNFields, v string) { f.Registered = v },
	"updated":       func(f *ASNFields, v string) { f.Updated = v },
	"last-modified": func(f *ASNFields, v string) { f.Updated = v },
	// "changed" is LACNIC's RPSL vocabulary for last-modified -- distinct
	// from "updated"/"last-modified", which LACNIC's aut-num response
	// never emits (confirmed live against AS28573).
	"changed":       func(f *ASNFields, v string) { f.Updated = v },
	"orgabuseemail": func(f *ASNFields, v string) { f.AbuseEmail = v },
	"abuse-mailbox": func(f *ASNFields, v string) { f.AbuseEmail = v },
	"orgabusephone": func(f *ASNFields, v string) { f.AbusePhone = v },
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
	"org-name":      func(f *ASNFields) string { return f.OrgName },
	"owner":         func(f *ASNFields) string { return f.OrgName },
	"descr":         func(f *ASNFields) string { return f.descr },
	"orgid":         func(f *ASNFields) string { return f.OrgID },
	"org":           func(f *ASNFields) string { return f.OrgID },
	"country":       func(f *ASNFields) string { return f.Country },
	"regdate":       func(f *ASNFields) string { return f.Registered },
	"created":       func(f *ASNFields) string { return f.Registered },
	"updated":       func(f *ASNFields) string { return f.Updated },
	"last-modified": func(f *ASNFields) string { return f.Updated },
	"changed":       func(f *ASNFields) string { return f.Updated },
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
// APNIC (verified live against AS4608/AS4808) can additionally place a
// "role" object -- an administrative contact, not the as-block --
// between the as-block and the aut-num object. That role object carries
// its own "country" and "last-modified" (the contact's own
// address/record-update time, e.g. APNIC's own hostmaster team), which
// share asnSynonyms keys with the aut-num object's identically-named but
// semantically unrelated fields. Skipping as-block alone isn't enough to
// keep that from shadowing the real ASN data, and there's no closed list
// of every RPSL contact-object class name (role, person, organisation,
// irt, mntner...) that might similarly precede aut-num across RIRs.
// Rather than skip every non-aut-num object by name, ParseASN instead
// lets the aut-num object's own values win over anything a *different*
// object already captured -- but, critically, only once per field: the
// first occurrence *within* the aut-num object itself still wins over
// later ones in the same object. This matters because a single aut-num
// object can carry a field's key more than once for entirely legitimate
// RPSL reasons -- APNIC's aut-num for AS4608 has seven "descr:" lines,
// the first being the org name ("Asia Pacific Network Information
// Centre") and the rest a multi-line postal address ending in
// "Australia". Plain last-occurrence-wins inside aut-num would report
// the postal address's country line as the org name. ParseASN tracks,
// per field key, whether the currently-stored value came from the
// aut-num object (fromAutNum): inside aut-num, a field already sourced
// from aut-num itself is left alone (first-occurrence-wins, scoped to
// the object); a field whose current value came from some earlier,
// different object is overwritten (aut-num's own data always
// supersedes a preceding object's). Objects after aut-num (e.g. an
// "irt" object supplying abuse-mailbox, which aut-num itself never
// carries) still use ordinary first-occurrence-wins against whatever is
// already set, so they keep filling in fields aut-num left empty exactly
// as before.
func ParseASN(raw string) ASNFields {
	var f ASNFields
	inASBlock := false
	inAutNum := false
	fromAutNum := map[string]bool{}
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

		// "status" is append-valued (asnSynonyms accumulates every
		// occurrence into f.Statuses, unlike every other key here, which
		// overwrites a single scalar) and deliberately absent from
		// asnFieldGet as a result -- there's no single "current value" to
		// ask "is this already populated?" about. The fromAutNum[key]
		// short-circuit below exists to enforce first-occurrence-wins for
		// *scalar* fields inside aut-num; applied to status it instead
		// silently drops every status line after the first one a given
		// aut-num object carries (APNIC and RIPE both routinely report
		// more than one, e.g. "ASSIGNED" and a routing-policy status
		// together). And outside aut-num, status has no asnFieldGet entry
		// to gate it at all, so a stray "status:" line from an unrelated
		// preceding or following RPSL object (a role/person/organisation
		// contact object; APNIC is known to place one between as-block
		// and aut-num, see ParseASN's doc comment) leaks straight into
		// f.Statuses -- the exact inverse of the intended precedence:
		// legitimate aut-num statuses truncated, illegitimate foreign
		// ones accumulated. So status is handled on its own path here,
		// which accumulates every "status:" line while inAutNum is true
		// (no first-occurrence gating -- that's the whole point of an
		// append field) and ignores the key entirely everywhere else,
		// aut-num or not.
		if key == "status" {
			if inAutNum {
				f.Statuses = append(f.Statuses, val)
			}
			continue
		}

		set, known := asnSynonyms[key]
		if !known {
			continue
		}

		if inAutNum {
			if fromAutNum[key] {
				continue // first occurrence within aut-num wins
			}
			set(&f, val)
			fromAutNum[key] = true
			continue
		}
		if get, ok := asnFieldGet[key]; ok && get(&f) != "" {
			continue // first occurrence wins
		}
		set(&f, val)
	}
	if f.OrgName == "" {
		f.OrgName = f.descr
	}
	return f
}
