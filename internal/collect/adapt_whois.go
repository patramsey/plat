package collect

import (
	"strings"

	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/whois"
)

// FromWHOIS adapts a WHOIS lookup's hop chain into per-hop
// model.SourceRecords. It skips Hops[0] (the IANA referral hop — never a
// data source, per whois.Client.Lookup's documented hop order) and maps
// the registry hop (Hops[1], if present) to SourceRegistryWHOIS and the
// registrar hop (Hops[2], if present) to SourceRegistrarWHOIS.
//
// If the IANA hop itself failed (network error), that's surfaced as its
// own failed SourceRegistryWHOIS record rather than returning zero
// records — otherwise a genuine network failure is indistinguishable
// from a TLD that simply has no WHOIS coverage (both would otherwise hit
// the len(Hops) < 2 case below), unlike the RDAP branch, which always
// surfaces a fetch error as its own SourceRecord (see FromRDAP).
func FromWHOIS(result *whois.Result) []model.SourceRecord {
	if result == nil || len(result.Hops) == 0 {
		return nil
	}
	if ianaHop := result.Hops[0]; ianaHop.Err != nil {
		return []model.SourceRecord{{Meta: model.SourceResult{
			Source:  model.SourceRegistryWHOIS,
			Latency: ianaHop.Latency,
			OK:      false,
			Err:     ianaHop.Err.Error(),
		}}}
	}
	if len(result.Hops) < 2 {
		return nil
	}
	var out []model.SourceRecord
	out = append(out, fromHop(model.SourceRegistryWHOIS, result.Hops[1]))
	if len(result.Hops) >= 3 {
		out = append(out, fromHop(model.SourceRegistrarWHOIS, result.Hops[2]))
	}
	return out
}

func fromHop(src model.SourceID, hop whois.Hop) model.SourceRecord {
	meta := model.SourceResult{
		Source:  src,
		Latency: hop.Latency,
		Raw:     []byte(hop.Raw),
	}
	if hop.Err != nil {
		meta.OK = false
		meta.Err = hop.Err.Error()
		return model.SourceRecord{Meta: meta}
	}
	f := hop.Fields
	if f.Unsupported {
		// The server responded, but refused the query outright (e.g.
		// Identity Digital's shared WHOIS returning "TLD is not
		// supported." for several of its newer gTLDs) — this says
		// nothing about whether the domain exists, so it must not be
		// treated as NotFound (which asserts the opposite: that the
		// domain confirmedly doesn't exist).
		meta.OK = false
		meta.Err = "registry does not support WHOIS for this TLD"
		return model.SourceRecord{Meta: meta}
	}
	if f.RateLimited {
		// Same reasoning as Unsupported above: a rate-limit refusal is a
		// server declining to answer, not a successful-but-empty lookup.
		// Without this check it fell through to Meta.OK=true below,
		// indistinguishable from a genuine successful response.
		meta.OK = false
		meta.Err = "WHOIS server rate-limited this query"
		return model.SourceRecord{Meta: meta}
	}
	meta.OK = !f.NotFound
	meta.NotFound = f.NotFound

	sr := model.SourceRecord{
		Meta:           meta,
		Present:        true,
		Domain:         f.Domain,
		RedactedFields: map[string]bool{},
	}

	if model.IsRedactedPlaceholder(f.Registrar) {
		sr.RedactedFields[model.FieldRegistrarName] = true
	} else {
		sr.Registrar.Name = f.Registrar
	}

	for _, st := range f.Statuses {
		sr.Status = append(sr.Status, model.NormalizeEPPStatus(st))
	}

	sr.Created = model.TimeValue{Time: f.Created.Time, Raw: f.Created.Raw, Parsed: f.Created.Parsed}
	sr.Updated = model.TimeValue{Time: f.Updated.Time, Raw: f.Updated.Raw, Parsed: f.Updated.Parsed}
	sr.Expires = model.TimeValue{Time: f.Expires.Time, Raw: f.Expires.Raw, Parsed: f.Expires.Parsed}
	sr.Nameservers = append(sr.Nameservers, f.Nameservers...)

	if v, ok := firstUnmapped(f.Unmapped, "registrar iana id"); ok {
		sr.Registrar.IANAID = v
	}
	if v, ok := firstUnmapped(f.Unmapped, "registrar url"); ok {
		sr.Registrar.URL = v
	}
	if v, ok := firstUnmapped(f.Unmapped, "registrar abuse contact email"); ok {
		sr.Registrar.AbuseEmail = v
	}
	if v, ok := firstUnmapped(f.Unmapped, "registrar abuse contact phone"); ok {
		sr.Registrar.AbusePhone = v
	}
	if v, ok := firstUnmapped(f.Unmapped, "dnssec"); ok {
		signed := strings.EqualFold(strings.TrimSpace(v), "signed")
		sr.DNSSEC = &signed
	}

	return sr
}

func firstUnmapped(m map[string][]string, key string) (string, bool) {
	vals, ok := m[key]
	if !ok || len(vals) == 0 {
		return "", false
	}
	return vals[0], true
}
