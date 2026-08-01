package collect

import (
	"errors"
	"time"

	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/rdap"
)

// FromRDAP adapts an RDAP client result into a model.SourceRecord tagged
// as src (SourceRegistryRDAP or SourceRegistrarRDAP — the caller decides
// which, since the same DomainResponse shape serves both hops).
//
// Registrar identity is populated only from the shallow jCard fields
// (RegistrarEntity's "fn", AbuseEntity's "email"/"tel") — IANA ID and URL
// are not extracted from RDAP in M3 (that would require parsing the
// entity's publicIds array, out of scope for this milestone's "shallow"
// jCard reading); those fields are populated from WHOIS only, if at all.
func FromRDAP(src model.SourceID, result *rdap.Result, latency time.Duration, fetchErr error) model.SourceRecord {
	meta := model.SourceResult{Source: src, Latency: latency}
	if result != nil {
		meta.Raw = result.Raw
	}
	if fetchErr != nil {
		meta.OK = false
		meta.Err = fetchErr.Error()
		meta.NotFound = errors.Is(fetchErr, rdap.ErrDomainNotFound)
		return model.SourceRecord{Meta: meta}
	}
	if result == nil || result.Domain == nil {
		meta.OK = false
		return model.SourceRecord{Meta: meta}
	}
	meta.OK = true
	d := result.Domain

	sr := model.SourceRecord{
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
		sr.Status = append(sr.Status, model.NormalizeEPPStatus(st))
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
		if model.IsRedactedPlaceholder(regEntity.VCardArray.FullName) {
			sr.RedactedFields[model.FieldRegistrarName] = true
		} else {
			sr.Registrar.Name = regEntity.VCardArray.FullName
		}
	}
	if abuseEntity, ok := d.AbuseEntity(); ok {
		sr.Registrar.AbuseEmail = abuseEntity.VCardArray.Email
		sr.Registrar.AbusePhone = abuseEntity.VCardArray.Tel
	}

	for _, rem := range d.RedactionRemarks() {
		sr.Redactions = append(sr.Redactions, model.RedactionNotice{
			Field:  "unknown",
			Source: src,
			Reason: rem.Title,
		})
	}

	return sr
}
