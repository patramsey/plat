package collect

import (
	"strconv"
	"strings"

	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/rdap"
	"github.com/patramsey/plat/internal/whois"
	"github.com/patramsey/plat/internal/whois/parse"
)

// fromASNRDAP adapts an RDAP autnum response into a model.ASNSourceRecord
// tagged as src. Mirrors fromIPRDAP's shape, but for rdap.ASNResponse: org
// identity comes from the "registrant" entity's vCard full name, abuse
// contact from the "abuse" entity's vCard email/tel -- see
// RegistrantEntity/AbuseEntity on ASNResponse (internal/rdap/types.go).
//
// StartAutnum/EndAutnum are uint32 on rdap.ASNResponse but string on
// model.ASNSourceRecord -- see the doc comment on model.ASNRecord for why
// (mergeState.scalar, shared with the domain and IP merge paths, is
// Field[string]-specific). Converted here at the adapter boundary via
// strconv.FormatUint.
func fromASNRDAP(meta model.SourceResult, resp *rdap.ASNResponse) model.ASNSourceRecord {
	if resp == nil {
		meta.OK = false
		return model.ASNSourceRecord{Meta: meta}
	}

	sr := model.ASNSourceRecord{
		Meta:           meta,
		Handle:         normalizeASNHandle(resp.Handle),
		Name:           resp.Name,
		Type:           resp.Type,
		Country:        resp.Country,
		RedactedFields: map[string]bool{},
	}

	if resp.StartAutnum != 0 {
		sr.StartAutnum = strconv.FormatUint(uint64(resp.StartAutnum), 10)
	}
	if resp.EndAutnum != 0 {
		sr.EndAutnum = strconv.FormatUint(uint64(resp.EndAutnum), 10)
	}

	// Like an IP network's status (RIR-specific vocabulary, not RFC 8056
	// EPP), an autnum's status is RIR-specific too -- running it through
	// model.NormalizeEPPStatus mangled multi-word values into meaningless
	// tokens. RIR statuses pass through unchanged, per docs/schema.md's
	// documented contract (same reasoning as fromIPRDAP).
	sr.Status = append(sr.Status, resp.Status...)

	if registered, ok := resp.Registered(); ok {
		sr.Registered = model.TimeValue{Time: registered.Time, Raw: registered.Raw, Parsed: registered.Parsed}
	}
	if updated, ok := resp.Updated(); ok {
		sr.Updated = model.TimeValue{Time: updated.Time, Raw: updated.Raw, Parsed: updated.Parsed}
	}

	if regEntity, ok := resp.RegistrantEntity(); ok {
		if model.IsRedactedPlaceholder(regEntity.VCardArray.FullName) {
			sr.RedactedFields[model.FieldOrgName] = true
			// RedactedFields alone is not enough to surface a redaction
			// notice: mergeState.scalar (internal/merge/merge.go, shared
			// with the domain and IP paths and not touched by this fix)
			// checks c.Redacted only after an empty-value guard that
			// fires first for every ASN redaction, since OrgName is
			// deliberately left empty above -- so a RedactedFields-only
			// signal is silently dropped before the record ever sees it.
			// Appending directly to sr.Redactions here bypasses that
			// broken path entirely and is what merge.MergeASN
			// (internal/merge/asn.go) actually surfaces as
			// ASNRecord.Redacted.
			sr.Redactions = append(sr.Redactions, model.RedactionNotice{
				Field:  model.FieldOrgName,
				Source: meta.Source,
				Reason: "redacted",
			})
		} else {
			sr.OrgName = regEntity.VCardArray.FullName
		}
	}
	if abuseEntity, ok := resp.AbuseEntity(); ok {
		sr.AbuseEmail = abuseEntity.VCardArray.Email
		sr.AbusePhone = abuseEntity.VCardArray.Tel
	}

	// A second, independent redaction signal: some RIRs annotate a
	// redacted autnum with an explicit remark (RFC 9537-adjacent, not a
	// full evaluation of it -- see RedactionRemarks) rather than (or in
	// addition to) a placeholder vCard value. Mirrors FromRDAP's identical
	// handling for domains (internal/collect/adapt_rdap.go); "unknown" is
	// used for Field here too since a remark isn't tied to one specific
	// field the way the vCard-placeholder check above is.
	for _, rem := range resp.RedactionRemarks() {
		sr.Redactions = append(sr.Redactions, model.RedactionNotice{
			Field:  "unknown",
			Source: meta.Source,
			Reason: rem.Title,
		})
	}

	sr.Present = asnRDAPPresent(sr)
	return sr
}

// normalizeASNHandle prefixes a bare numeric RDAP autnum handle with "AS",
// so it compares equal to WHOIS's handle -- verified live against LACNIC
// (AS28573), whose RDAP autnum response reports handle as the bare
// number "28573" while every other tested RIR (ARIN, RIPE, APNIC,
// AFRINIC) reports the conventional "AS28573" form, matching what
// asnFields's "aut-num"/"ashandle" mappings always produce on the
// WHOIS side (the RPSL aut-num class attribute and ARIN's ASHandle key
// are both already prefixed by construction). Without this, an
// otherwise-agreeing RDAP/WHOIS pair reports a false handle conflict --
// same failure mode as the IP feature's Parent-handle formatting bug
// (see parentHandleFromWHOIS), just on the RDAP side instead of WHOIS's.
// A handle that already carries the prefix (case-insensitively), or
// isn't purely numeric, is returned unchanged.
func normalizeASNHandle(handle string) string {
	if handle == "" || strings.HasPrefix(strings.ToUpper(handle), "AS") {
		return handle
	}
	if _, err := strconv.ParseUint(handle, 10, 32); err != nil {
		return handle
	}
	return "AS" + handle
}

// asnRDAPPresent reports whether resp yielded any non-empty field,
// mirroring ipRDAPPresent's reasoning for autnum responses.
func asnRDAPPresent(sr model.ASNSourceRecord) bool {
	return sr.Handle != "" || sr.Name != "" || sr.Type != "" || sr.StartAutnum != "" ||
		sr.EndAutnum != "" || sr.Country != "" || sr.OrgName != "" || sr.AbuseEmail != "" ||
		sr.AbusePhone != "" || len(sr.Status) > 0 || sr.Registered.Raw != "" || sr.Updated.Raw != "" ||
		len(sr.RedactedFields) > 0
}

// fromASNHop adapts one WHOIS hop's parsed ASN fields into a
// model.ASNSourceRecord tagged as src. Mirrors fromIPHop's shape, using
// parse.ParseDate for Registered/Updated -- the same tolerant multi-format
// date parser the domain and IP WHOIS adapters use.
func fromASNHop(meta model.SourceResult, hop whois.Hop) model.ASNSourceRecord {
	if hop.Err != nil {
		meta.OK = false
		return model.ASNSourceRecord{Meta: meta}
	}
	if hop.ASNFields == nil {
		meta.OK = false
		return model.ASNSourceRecord{Meta: meta}
	}
	// hop.Fields (not ASNFields) is where parse.Parse's refusal signals
	// land -- mirrors fromIPHop's identical reasoning: without checking
	// these here, a rate-limited or refusing RIR would fall through to
	// Meta.OK=true below, reported as "registry-whois: ok" under -v with
	// an empty record -- silent wrong data.
	if hop.Fields.Unsupported {
		meta.OK = false
		meta.Err = "registry does not support WHOIS for this autnum"
		return model.ASNSourceRecord{Meta: meta}
	}
	if hop.Fields.RateLimited {
		meta.OK = false
		meta.Err = "WHOIS server rate-limited this query"
		return model.ASNSourceRecord{Meta: meta}
	}
	meta.OK = true
	f := hop.ASNFields

	// Unlike WHOIS's IP netblock objects (which report a hyphenated
	// "<start> - <end>" NetRange for the whole allocation), a WHOIS
	// aut-num/ASNumber object describes exactly one ASN -- there is no
	// separate start/end vocabulary to split apart the way fromIPHop
	// splits NetRange. f.Number is used for both StartAutnum and
	// EndAutnum so a single-ASN WHOIS hop compares equal to an RDAP
	// autnum response whose startAutnum/endAutnum both equal the same
	// queried ASN (the common case; only a block-level RDAP query would
	// ever report a genuinely differing pair).
	sr := model.ASNSourceRecord{
		Meta:           meta,
		Handle:         f.Handle,
		Name:           f.Name,
		Type:           f.Type,
		StartAutnum:    f.Number,
		EndAutnum:      f.Number,
		Country:        f.Country,
		OrgID:          f.OrgID,
		AbuseEmail:     f.AbuseEmail,
		AbusePhone:     f.AbusePhone,
		RedactedFields: map[string]bool{},
	}

	if model.IsRedactedPlaceholder(f.OrgName) {
		sr.RedactedFields[model.FieldOrgName] = true
		// See fromASNRDAP's identical reasoning: mergeState.scalar never
		// surfaces a RedactedFields-only signal when the value is left
		// empty (as it deliberately is here), so sr.Redactions is
		// populated directly.
		sr.Redactions = append(sr.Redactions, model.RedactionNotice{
			Field:  model.FieldOrgName,
			Source: meta.Source,
			Reason: "redacted",
		})
	} else {
		sr.OrgName = f.OrgName
	}

	// See fromASNRDAP's identical reasoning: RIR status vocabulary isn't
	// EPP, so it passes through unchanged rather than being mangled by
	// model.NormalizeEPPStatus.
	sr.Status = append(sr.Status, f.Statuses...)

	if registered := parse.ParseDate(f.Registered); registered.Raw != "" {
		sr.Registered = model.TimeValue{Time: registered.Time, Raw: registered.Raw, Parsed: registered.Parsed}
	}
	if updated := parse.ParseDate(f.Updated); updated.Raw != "" {
		sr.Updated = model.TimeValue{Time: updated.Time, Raw: updated.Raw, Parsed: updated.Parsed}
	}

	sr.Present = asnHopPresent(sr)
	return sr
}

// asnHopPresent reports whether hop yielded any non-empty field, mirroring
// ipHopPresent's reasoning for the WHOIS side.
func asnHopPresent(sr model.ASNSourceRecord) bool {
	return sr.Handle != "" || sr.Name != "" || sr.Type != "" || sr.StartAutnum != "" ||
		sr.EndAutnum != "" || sr.Country != "" || sr.OrgName != "" || sr.OrgID != "" ||
		sr.AbuseEmail != "" || sr.AbusePhone != "" || len(sr.Status) > 0 ||
		sr.Registered.Raw != "" || sr.Updated.Raw != "" || len(sr.RedactedFields) > 0
}
