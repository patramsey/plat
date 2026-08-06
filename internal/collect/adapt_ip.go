package collect

import (
	"strings"

	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/rdap"
	"github.com/patramsey/plat/internal/whois"
	"github.com/patramsey/plat/internal/whois/parse"
)

// fromIPRDAP adapts an RDAP IP-network response into a model.IPSourceRecord
// tagged as src. Mirrors FromRDAP's shape and redaction handling, but for
// IPNetworkResponse instead of DomainResponse: org identity comes from the
// "registrant" entity's vCard full name, abuse contact from the "abuse"
// entity's vCard email/tel -- see RegistrantEntity/AbuseEntity on
// IPNetworkResponse (internal/rdap/types.go), added alongside this task
// since DomainResponse's RegistrarEntity/AbuseEntity/Created/Updated are
// bound to *DomainResponse and can't be called on an IPNetworkResponse.
func fromIPRDAP(meta model.SourceResult, resp *rdap.IPNetworkResponse) model.IPSourceRecord {
	if resp == nil {
		meta.OK = false
		return model.IPSourceRecord{Meta: meta}
	}

	sr := model.IPSourceRecord{
		Meta:           meta,
		Handle:         resp.Handle,
		Name:           resp.Name,
		Type:           resp.Type,
		StartAddress:   resp.StartAddress,
		EndAddress:     resp.EndAddress,
		IPVersion:      resp.IPVersion,
		ParentHandle:   resp.ParentHandle,
		Country:        resp.Country,
		RedactedFields: map[string]bool{},
	}

	if len(resp.CIDR0CIDRs) > 0 {
		sr.CIDR = resp.CIDR0CIDRs[0].Prefix()
	}

	for _, st := range resp.Status {
		sr.Status = append(sr.Status, model.NormalizeEPPStatus(st))
	}

	if registered, ok := resp.Registered(); ok {
		sr.Registered = model.TimeValue{Time: registered.Time, Raw: registered.Raw, Parsed: registered.Parsed}
	}
	if updated, ok := resp.Updated(); ok {
		sr.Updated = model.TimeValue{Time: updated.Time, Raw: updated.Raw, Parsed: updated.Parsed}
	}

	if regEntity, ok := resp.RegistrantEntity(); ok {
		if model.IsRedactedPlaceholder(regEntity.VCardArray.FullName) {
			sr.RedactedFields[model.FieldOrgName] = true
		} else {
			sr.OrgName = regEntity.VCardArray.FullName
		}
	}
	if abuseEntity, ok := resp.AbuseEntity(); ok {
		sr.AbuseEmail = abuseEntity.VCardArray.Email
		sr.AbusePhone = abuseEntity.VCardArray.Tel
	}

	sr.Present = ipRDAPPresent(sr)
	return sr
}

// ipRDAPPresent reports whether resp yielded any non-empty field, mirroring
// how FromRDAP implicitly treats a successfully-decoded Domain as present.
func ipRDAPPresent(sr model.IPSourceRecord) bool {
	return sr.Handle != "" || sr.Name != "" || sr.Type != "" || sr.StartAddress != "" ||
		sr.EndAddress != "" || sr.CIDR != "" || sr.IPVersion != "" || sr.ParentHandle != "" ||
		sr.Country != "" || sr.OrgName != "" || sr.AbuseEmail != "" || sr.AbusePhone != "" ||
		len(sr.Status) > 0 || sr.Registered.Raw != "" || sr.Updated.Raw != "" ||
		len(sr.RedactedFields) > 0
}

// fromIPHop adapts one WHOIS hop's parsed IP fields into a
// model.IPSourceRecord tagged as src. Mirrors fromHop's shape, using
// parse.ParseDate for Registered/Updated -- the same tolerant multi-format
// date parser the domain WHOIS adapter uses -- so IP dates get the same
// handling domain dates do.
//
// f.NetRange and f.Parent are deliberately left untouched by parse.ParseIP
// (it stores each vocabulary's line as-is, since that's the only sense in
// which it is a faithful WHOIS parser rather than a merge-comparability
// layer). But model.IPSourceRecord.StartAddress/EndAddress/ParentHandle
// are meant to hold the same shape of value RDAP's fromIPRDAP produces
// (a bare start address, a bare end address, a bare parent handle) so
// merge.MergeIP is comparing like with like across sources -- ARIN/RIPE's
// combined "<start> - <end>" NetRange/inetnum line and ARIN's
// "<name> (<handle>)" Parent line both need splitting apart here, at the
// adapter boundary, rather than either being left raw (which would make
// every ARIN-backed IPv4 lookup report a false startAddress/parentHandle
// conflict against RDAP -- both sides genuinely agree, they're just
// spelled differently) or "fixed" by loosening merge's own comparison
// (which would blur a genuine cross-source disagreement on these same
// fields, and merge is shared with the domain path).
func fromIPHop(meta model.SourceResult, hop whois.Hop) model.IPSourceRecord {
	if hop.Err != nil {
		meta.OK = false
		return model.IPSourceRecord{Meta: meta}
	}
	if hop.IPFields == nil {
		meta.OK = false
		return model.IPSourceRecord{Meta: meta}
	}
	meta.OK = true
	f := hop.IPFields
	start, end := splitNetRange(f.NetRange)

	sr := model.IPSourceRecord{
		Meta:           meta,
		Handle:         f.Handle,
		Name:           f.NetName,
		Type:           f.NetType,
		StartAddress:   start,
		EndAddress:     end,
		CIDR:           f.CIDR,
		ParentHandle:   parentHandleFromWHOIS(f.Parent),
		Country:        f.Country,
		OrgID:          f.OrgID,
		AbuseEmail:     f.AbuseEmail,
		AbusePhone:     f.AbusePhone,
		RedactedFields: map[string]bool{},
	}

	if model.IsRedactedPlaceholder(f.OrgName) {
		sr.RedactedFields[model.FieldOrgName] = true
	} else {
		sr.OrgName = f.OrgName
	}

	for _, st := range f.Statuses {
		sr.Status = append(sr.Status, model.NormalizeEPPStatus(st))
	}

	if registered := parse.ParseDate(f.Registered); registered.Raw != "" {
		sr.Registered = model.TimeValue{Time: registered.Time, Raw: registered.Raw, Parsed: registered.Parsed}
	}
	if updated := parse.ParseDate(f.Updated); updated.Raw != "" {
		sr.Updated = model.TimeValue{Time: updated.Time, Raw: updated.Raw, Parsed: updated.Parsed}
	}

	sr.Present = ipHopPresent(sr)
	return sr
}

// ipHopPresent reports whether hop yielded any non-empty field, mirroring
// ipRDAPPresent's reasoning for the WHOIS side.
func ipHopPresent(sr model.IPSourceRecord) bool {
	return sr.Handle != "" || sr.Name != "" || sr.Type != "" || sr.StartAddress != "" ||
		sr.EndAddress != "" || sr.CIDR != "" || sr.IPVersion != "" || sr.ParentHandle != "" ||
		sr.Country != "" || sr.OrgName != "" || sr.OrgID != "" || sr.AbuseEmail != "" || sr.AbusePhone != "" ||
		len(sr.Status) > 0 || sr.Registered.Raw != "" || sr.Updated.Raw != "" ||
		len(sr.RedactedFields) > 0
}

// splitNetRange splits a WHOIS NetRange/inetnum/inet6num value of the
// "<start> - <end>" shape ARIN, RIPE, APNIC, LACNIC, and AFRINIC all use
// (see ipSynonyms in internal/whois/parse/ip.go, which maps all three keys
// onto the same NetRange field) into its bare start and end addresses.
// Any input that isn't cleanly two hyphen-separated, non-empty halves --
// empty, no hyphen at all, or a hyphen with nothing (or only whitespace)
// on one side -- degrades to ("", ""): an unparseable range must not
// surface as a malformed StartAddress/EndAddress value merge.MergeIP
// would then treat as real, disagreeing data.
func splitNetRange(raw string) (start, end string) {
	parts := strings.SplitN(raw, "-", 2)
	if len(parts) != 2 {
		return "", ""
	}
	start = strings.TrimSpace(parts[0])
	end = strings.TrimSpace(parts[1])
	if start == "" || end == "" {
		return "", ""
	}
	return start, end
}

// parentHandleFromWHOIS extracts the bare handle from ARIN's
// "<org name> (<handle>)" Parent value (e.g. "NET8 (NET-8-0-0-0-0)" ->
// "NET-8-0-0-0-0"), so it compares equal to RDAP's parentHandle, which is
// always just the bare handle. A value with no parenthesized part (RIPE
// and friends report the parent inetnum's bare range/handle directly, no
// name prefix) is returned unchanged.
func parentHandleFromWHOIS(raw string) string {
	raw = strings.TrimSpace(raw)
	open := strings.LastIndex(raw, "(")
	closeIdx := strings.LastIndex(raw, ")")
	if open == -1 || closeIdx == -1 || closeIdx < open {
		return raw
	}
	handle := strings.TrimSpace(raw[open+1 : closeIdx])
	if handle == "" {
		return raw
	}
	return handle
}
