package parse

import "strings"

// ASNFields is the autonomous-system counterpart to Fields and IPFields.
// Kept as its own type rather than folded into IPFields for the same
// reason IPFields is kept separate from Fields: an ASN has no netblock
// range, CIDR, or netname, and an IP allocation has no as-name or
// aut-num handle.
type ASNFields struct {
	CommonFields

	Number string
	Name   string
	Type   string
}

// asnFields maps the lowercased WHOIS key to the setter/getter pair for the
// ASNFields member it populates. It's built from two parts: the
// type-specific keys declared directly below (ARIN's CamelCase ASNumber and
// the RPSL-style aut-num/as-name vocabulary, neither of which any other
// object type has), plus the 16 keys shared with IPFields -- orgname/
// owner/descr, org identity, country, dates, abuse contacts -- which
// commonFields declares once and buildFields lifts in here so they can
// never drift out of sync with ip.go's table again. A key already set is
// never overwritten, so the first occurrence wins -- see ParseASN's doc
// comment for why the as-block object (which RIPE places before the
// aut-num object in the same response) must never reach this table at
// all.
//
// "status" is deliberately NOT listed here even though it's part of the
// RPSL vocabulary this table otherwise covers: it's append-valued (every
// "status:" line accumulates, unlike every other key's overwrite-once
// scalar), and ParseASN handles it on its own dedicated path for that
// reason -- see the comment there. Adding a "status" entry to this table
// would just be dead code, since ParseASN's main loop intercepts and
// `continue`s on that key before ever consulting this map.
var asnFields = buildFields(map[string]fieldRef[ASNFields]{
	"asnumber": {set: func(f *ASNFields, v string) { f.Number = v }, get: func(f *ASNFields) string { return f.Number }},
	"aut-num": {
		set: func(f *ASNFields, v string) {
			f.Handle = v
			f.Number = strings.TrimPrefix(strings.ToUpper(v), "AS")
		},
		get: func(f *ASNFields) string { return f.Handle },
	},
	"asname":   {set: func(f *ASNFields, v string) { f.Name = v }, get: func(f *ASNFields) string { return f.Name }},
	"as-name":  {set: func(f *ASNFields, v string) { f.Name = v }, get: func(f *ASNFields) string { return f.Name }},
	"ashandle": {set: func(f *ASNFields, v string) { f.Handle = v }, get: func(f *ASNFields) string { return f.Handle }},
}, func(f *ASNFields) *CommonFields { return &f.CommonFields })

// ParseASN extracts autonomous-system fields from a raw RIR WHOIS
// response, handling both ARIN's and the RPSL-style vocabularies in one
// pass. When no authoritative org identity (ARIN's OrgName) was found
// anywhere in the response, it falls back to RPSL's descr line -- see the
// descr field doc comment on CommonFields for why that can't just be folded
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
// share asnFields keys with the aut-num object's identically-named but
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

		// "status" is append-valued (accumulates every occurrence into
		// f.Statuses, unlike every other key here, which overwrites a
		// single scalar) and deliberately absent from asnFields as a
		// result -- there's no single "current value" to ask "is this
		// already populated?" about. The fromAutNum[key] short-circuit
		// below exists to enforce first-occurrence-wins for *scalar*
		// fields inside aut-num; applied to status it instead silently
		// drops every status line after the first one a given aut-num
		// object carries (APNIC and RIPE both routinely report more than
		// one, e.g. "ASSIGNED" and a routing-policy status together). And
		// outside aut-num, status has no asnFields entry to gate it at
		// all, so a stray "status:" line from an unrelated preceding or
		// following RPSL object (a role/person/organisation contact
		// object; APNIC is known to place one between as-block and
		// aut-num, see ParseASN's doc comment) leaks straight into
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

		ref, known := asnFields[key]
		if !known {
			continue
		}

		if inAutNum {
			if fromAutNum[key] {
				continue // first occurrence within aut-num wins
			}
			ref.set(&f, val)
			fromAutNum[key] = true
			continue
		}
		// A nil get (no asnFields entry has one today) falls through to
		// set unconditionally -- this exactly restores base's semantics
		// (`if get, ok := asnFieldGet[key]; ok && get(&f) != ""`), which
		// also fell through to set on a getter-less key. Guards against a
		// future getter-less shared key panicking here instead of a
		// silent, harmless no-op.
		if ref.get != nil && ref.get(&f) != "" {
			continue // first occurrence wins
		}
		ref.set(&f, val)
	}
	if f.OrgName == "" {
		f.OrgName = f.descr
	}
	return f
}
