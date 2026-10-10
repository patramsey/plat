package collect

import (
	"errors"
	"strings"
	"time"

	"github.com/patramsey/plat/internal/rdap"
	"github.com/patramsey/plat/internal/source"
	"github.com/patramsey/plat/model"
)

// FromRDAP adapts an RDAP client result into a source.SourceRecord tagged
// as src (SourceRegistryRDAP or SourceRegistrarRDAP — the caller decides
// which, since the same DomainResponse shape serves both hops).
//
// Registrar identity is populated only from the shallow jCard fields
// (RegistrarEntity's "fn", AbuseEntity's "email"/"tel") — IANA ID and URL
// are not extracted from RDAP in M3 (that would require parsing the
// entity's publicIds array, out of scope for this milestone's "shallow"
// jCard reading); those fields are populated from WHOIS only, if at all.
func FromRDAP(src model.SourceID, result *rdap.Result, latency time.Duration, fetchErr error) source.SourceRecord {
	meta := model.SourceResult{Source: src, Latency: latency}
	if result != nil {
		meta.Raw = result.Raw
	}
	if fetchErr != nil {
		meta.OK = false
		meta.Err = fetchErr.Error()
		meta.NotFound = errors.Is(fetchErr, rdap.ErrDomainNotFound)
		return source.SourceRecord{Meta: meta}
	}
	if result == nil || result.Domain == nil {
		meta.OK = false
		return source.SourceRecord{Meta: meta}
	}
	meta.OK = true
	d := result.Domain

	sr := source.SourceRecord{
		Meta:           meta,
		Present:        true,
		Handle:         d.Handle,
		RedactedFields: map[string]bool{},
	}
	if d.UnicodeName != "" {
		sr.Domain = d.UnicodeName
	} else {
		sr.Domain = d.LDHName
	}

	for _, st := range d.Status {
		sr.Status = append(sr.Status, source.NormalizeEPPStatus(st))
	}

	if created, ok := d.Created(); ok {
		sr.Created = model.TimeValue{Time: created.Time, Raw: created.Raw, Parsed: created.Parsed}
	}
	if updated, ok := d.Updated(); ok {
		sr.Updated = model.TimeValue{Time: updated.Time, Raw: updated.Raw, Parsed: updated.Parsed}
	}
	if expires, ok := d.Expires(); ok {
		sr.Expires = model.TimeValue{Time: expires.Time, Raw: expires.Raw, Parsed: expires.Parsed}
	}

	for _, ns := range d.Nameservers {
		name := ns.LDHName
		if ns.UnicodeName != "" {
			name = ns.UnicodeName
		}
		if name != "" {
			sr.Nameservers = append(sr.Nameservers, name)
		}
	}

	if regEntity, ok := d.RegistrarEntity(); ok {
		// A registrar is an organisation, so its card's "org" is its name
		// when given: .uz's "fn" is a person at the registrar.
		name := regEntity.VCardArray.Org
		if name == "" {
			name = regEntity.VCardArray.FullName
		}
		if source.IsRedactedPlaceholder(name) {
			sr.RedactedFields[model.FieldRegistrarName] = true
		} else {
			sr.Registrar.Name = name
		}
	}
	if abuseEntity, ok := d.AbuseEntity(); ok {
		sr.Registrar.AbuseEmail = abuseEntity.VCardArray.Email
		sr.Registrar.AbusePhone = abuseEntity.VCardArray.Tel
	}

	applyRFC9537(&sr, d.Redacted)

	for _, rem := range d.RedactionRemarks() {
		sr.Redactions = append(sr.Redactions, model.RedactionNotice{
			Field:  "unknown",
			Source: src,
			Reason: rem.Title,
		})
	}

	return sr
}

// redactedField maps an RFC 9537 redaction onto the field plat shows that
// it withheld, or "" when plat shows no such field. Registries redact
// the Registry Domain ID ($.handle) and, overwhelmingly, contact data --
// which plat deliberately does not show, so those map to nothing. The
// registrar-name and abuse paths follow the ICANN RDAP Response Profile;
// no sampled registry redacts them, but README promises a redacted
// registrar identity is modelled. Abuse paths are matched before the
// registrar's own fn, since both sit inside the registrar entity (#134).
func redactedField(r rdap.Redaction) string {
	name := strings.ToLower(strings.TrimSpace(r.Name.Type + " " + r.Name.Description))
	path := strings.ToLower(r.PrePath + " " + r.PostPath + " " + r.ReplacementPath)
	registrar := strings.Contains(path, "roles[0]=='registrar'")
	switch {
	case strings.TrimSpace(r.PrePath) == "$.handle" || name == "registry domain id":
		return model.FieldHandle
	case registrar && strings.Contains(path, "'abuse'") && strings.Contains(path, "'email'"),
		name == "registrar abuse contact email":
		return model.FieldRegistrarAbuseEmail
	case registrar && strings.Contains(path, "'abuse'") && strings.Contains(path, "'tel'"),
		name == "registrar abuse contact phone":
		return model.FieldRegistrarAbusePhone
	case registrar && !strings.Contains(path, "'abuse'") && strings.Contains(path, "'fn'"),
		name == "registrar name":
		return model.FieldRegistrarName
	}
	return ""
}

// applyRFC9537 marks each field the response's RFC 9537 entries withheld
// as redacted, and clears any placeholder a "replacementValue" or
// "emptyValue" left in it, so the merge reports the redaction instead of
// showing the placeholder as data.
func applyRFC9537(sr *source.SourceRecord, redacted rdap.RedactionList) {
	for _, r := range redacted {
		switch f := redactedField(r); f {
		case model.FieldHandle:
			sr.Handle = ""
			sr.RedactedFields[f] = true
		case model.FieldRegistrarName:
			sr.Registrar.Name = ""
			sr.RedactedFields[f] = true
		case model.FieldRegistrarAbuseEmail:
			sr.Registrar.AbuseEmail = ""
			sr.RedactedFields[f] = true
		case model.FieldRegistrarAbusePhone:
			sr.Registrar.AbusePhone = ""
			sr.RedactedFields[f] = true
		}
	}
}
