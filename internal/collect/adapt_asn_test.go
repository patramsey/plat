package collect

import (
	"testing"

	"github.com/patramsey/plat/internal/merge"
	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/rdap"
	"github.com/patramsey/plat/internal/whois"
	"github.com/patramsey/plat/internal/whois/parse"
)

// arinLikeASN returns an *rdap.ASNResponse shaped like ARIN's real response
// for AS15169 (Google).
func arinLikeASN(t *testing.T) *rdap.ASNResponse {
	t.Helper()
	return &rdap.ASNResponse{
		ObjectClassName: "autnum",
		Handle:          "AS15169",
		StartAutnum:     15169,
		EndAutnum:       15169,
		Name:            "GOOGLE",
		Type:            "DIRECT ALLOCATION",
		Country:         "US",
		Status:          rdap.StatusList{"active"},
		Events: []rdap.Event{
			{Action: "registration", Date: rdapTime(t, "2000-03-30T00:00:00-05:00")},
			{Action: "last changed", Date: rdapTime(t, "2023-12-29T09:10:00-05:00")},
		},
		Entities: rdap.EntityList{
			{Roles: []string{"registrant"}, VCardArray: rdap.VCardArray{FullName: "Google LLC"}},
			{Roles: []string{"abuse"}, VCardArray: rdap.VCardArray{Email: "network-abuse@google.com", Tel: "+1-650-253-0000"}},
		},
	}
}

func TestFromASNRDAP_ARINFixture(t *testing.T) {
	resp := arinLikeASN(t)
	meta := model.SourceResult{Source: model.SourceRegistryRDAP, OK: true}

	sr := fromASNRDAP(meta, resp)

	if !sr.Present {
		t.Fatal("Present = false, want true")
	}
	if sr.Meta.Source != model.SourceRegistryRDAP {
		t.Errorf("Meta.Source = %q, want %q", sr.Meta.Source, model.SourceRegistryRDAP)
	}
	if sr.Handle != "AS15169" {
		t.Errorf("Handle = %q, want AS15169", sr.Handle)
	}
	if sr.Name != "GOOGLE" {
		t.Errorf("Name = %q, want GOOGLE", sr.Name)
	}
	if sr.Type != "DIRECT ALLOCATION" {
		t.Errorf("Type = %q, want DIRECT ALLOCATION", sr.Type)
	}
	if sr.StartAutnum != "15169" || sr.EndAutnum != "15169" {
		t.Errorf("StartAutnum/EndAutnum = %q/%q, want 15169/15169 (converted from uint32)", sr.StartAutnum, sr.EndAutnum)
	}
	if sr.Country != "US" {
		t.Errorf("Country = %q, want US", sr.Country)
	}
	if len(sr.Status) != 1 || sr.Status[0] != "active" {
		t.Errorf("Status = %v, want [active]", sr.Status)
	}

	if !sr.Registered.Parsed {
		t.Errorf("Registered.Parsed = false, want true: %+v", sr.Registered)
	}
	if sr.Registered.Raw != "2000-03-30T00:00:00-05:00" {
		t.Errorf("Registered.Raw = %q, want 2000-03-30T00:00:00-05:00", sr.Registered.Raw)
	}
	if !sr.Updated.Parsed {
		t.Errorf("Updated.Parsed = false, want true: %+v", sr.Updated)
	}
	if sr.Updated.Raw != "2023-12-29T09:10:00-05:00" {
		t.Errorf("Updated.Raw = %q, want 2023-12-29T09:10:00-05:00", sr.Updated.Raw)
	}
	if sr.Registered.Raw == sr.Updated.Raw {
		t.Error("Registered and Updated carry the same Raw value, want the two distinct events kept separate")
	}

	if sr.OrgName != "Google LLC" {
		t.Errorf("OrgName = %q, want Google LLC (from the registrant entity)", sr.OrgName)
	}
	if sr.AbuseEmail != "network-abuse@google.com" {
		t.Errorf("AbuseEmail = %q, want network-abuse@google.com", sr.AbuseEmail)
	}
	if sr.AbusePhone != "+1-650-253-0000" {
		t.Errorf("AbusePhone = %q, want +1-650-253-0000", sr.AbusePhone)
	}
}

func TestFromASNRDAP_FetchError(t *testing.T) {
	meta := model.SourceResult{Source: model.SourceRegistryRDAP, OK: false, Err: "connection refused"}

	sr := fromASNRDAP(meta, nil)

	if sr.Present {
		t.Error("Present = true, want false on a fetch error")
	}
	if sr.Meta.OK {
		t.Error("Meta.OK = true, want false")
	}
	if sr.Meta.Err != "connection refused" {
		t.Errorf("Meta.Err = %q, want connection refused (preserved from the caller)", sr.Meta.Err)
	}
}

func TestFromASNRDAP_NotFound(t *testing.T) {
	meta := model.SourceResult{Source: model.SourceRegistryRDAP, OK: false, NotFound: true, Err: "rdap: autnum not found"}

	sr := fromASNRDAP(meta, nil)

	if sr.Present {
		t.Error("Present = true, want false for a not-found response")
	}
	if !sr.Meta.NotFound {
		t.Error("Meta.NotFound = false, want true (preserved from the caller)")
	}
}

func TestFromASNRDAP_EmptyResponse(t *testing.T) {
	// A non-nil but entirely empty ASNResponse (e.g. a malformed document
	// that still decoded to a zero value) must not be reported present
	// either. Note StartAutnum/EndAutnum being 0 (the zero value) must not
	// be reported as the literal string "0" -- that would make an empty
	// response look present.
	sr := fromASNRDAP(model.SourceResult{Source: model.SourceRegistryRDAP, OK: true}, &rdap.ASNResponse{})

	if sr.Present {
		t.Error("Present = true, want false for an entirely empty ASNResponse")
	}
	if sr.StartAutnum != "" || sr.EndAutnum != "" {
		t.Errorf("StartAutnum/EndAutnum = %q/%q, want empty strings for a zero-value response", sr.StartAutnum, sr.EndAutnum)
	}
}

func TestFromASNRDAP_RedactedOrgName(t *testing.T) {
	resp := &rdap.ASNResponse{
		Handle: "AS64512",
		Entities: rdap.EntityList{
			{Roles: []string{"registrant"}, VCardArray: rdap.VCardArray{FullName: "REDACTED FOR PRIVACY"}},
		},
	}

	sr := fromASNRDAP(model.SourceResult{Source: model.SourceRegistryRDAP, OK: true}, resp)

	if sr.OrgName != "" {
		t.Errorf("OrgName = %q, want empty (redacted placeholder must not surface as a real value)", sr.OrgName)
	}
	if !sr.RedactedFields[model.FieldOrgName] {
		t.Error("RedactedFields[org.name] = false, want true")
	}
	if !sr.Present {
		t.Error("Present = false, want true (Handle is populated even though OrgName is redacted)")
	}
}

// TestFromASNRDAP_RedactedOrgName_ProducesRedactionNoticeEndToEnd is a
// regression test for a real defect caught during whole-branch review: a
// redacted registrant vCard set RedactedFields[org.name] but left
// sr.Redactions empty, and merge.MergeASN's shared scalar() helper only
// checks a candidate's Redacted flag AFTER an empty-value guard that
// fires first (since the redacted OrgName is deliberately left ""). The
// notice was silently dropped -- RedactedFields was set, but
// ASNRecord.Redacted always came back []. Feeding fromASNRDAP's real
// output through merge.MergeASN (not a hand-built ASNRecord, which is
// what let this slip past both docs/schema.md and testdata/schema/
// asn-record.json) must now produce a real redacted[] entry, and the
// lower-precedence WHOIS source's org name must win instead.
func TestFromASNRDAP_RedactedOrgName_ProducesRedactionNoticeEndToEnd(t *testing.T) {
	rdapResp := &rdap.ASNResponse{
		Handle: "AS64512",
		Entities: rdap.EntityList{
			{Roles: []string{"registrant"}, VCardArray: rdap.VCardArray{FullName: "REDACTED FOR PRIVACY"}},
		},
	}
	rdapSR := fromASNRDAP(model.SourceResult{Source: model.SourceRegistryRDAP, OK: true}, rdapResp)

	whoisSR := fromASNHop(model.SourceResult{Source: model.SourceRegistryWHOIS, OK: true}, whois.Hop{
		ASNFields: &parse.ASNFields{CommonFields: parse.CommonFields{Handle: "AS64512", OrgName: "Example Holdings LLC"}},
	})

	rec := merge.MergeASN([]model.ASNSourceRecord{rdapSR, whoisSR})

	if rec.Org.Name.Value != "Example Holdings LLC" {
		t.Errorf("Org.Name = %q, want the WHOIS source's value (registry-rdap's was redacted)", rec.Org.Name.Value)
	}
	found := false
	for _, notice := range rec.Redacted {
		if notice.Field == model.FieldOrgName && notice.Source == model.SourceRegistryRDAP {
			found = true
		}
	}
	if !found {
		t.Errorf("rec.Redacted = %+v, want an org.name notice attributed to registry-rdap", rec.Redacted)
	}
}

// TestFromASNRDAP_RIRStatusPassesThroughVerbatim is fromASNHop's RDAP-side
// sibling, mirroring the identical regression pinned for IP networks:
// RIR status vocabulary ("ALLOCATED NON-PORTABLE" and friends) must not be
// run through model.NormalizeEPPStatus, which is designed for EPP's
// single-word/camelCase vocabulary and mangles multi-word RIR values into
// meaningless tokens.
func TestFromASNRDAP_RIRStatusPassesThroughVerbatim(t *testing.T) {
	resp := &rdap.ASNResponse{
		Handle: "test",
		Status: rdap.StatusList{"ALLOCATED NON-PORTABLE"},
	}

	sr := fromASNRDAP(model.SourceResult{Source: model.SourceRegistryRDAP, OK: true}, resp)

	if len(sr.Status) != 1 || sr.Status[0] != "ALLOCATED NON-PORTABLE" {
		t.Errorf("Status = %v, want [\"ALLOCATED NON-PORTABLE\"] unchanged (RIR vocabulary, not EPP)", sr.Status)
	}
}

// TestFromASNRDAP_LACNICBareHandleGetsASPrefix is a regression test for a
// real defect caught during live verification against AS28573: LACNIC's
// RDAP autnum response reports handle as the bare number "28573", unlike
// every other tested RIR's "AS28573" form -- and unlike WHOIS's aut-num-
// derived Handle, which is always prefixed by construction (see
// normalizeASNHandle's doc comment). Left unnormalized, this produced a
// false handle conflict between two sources that genuinely agree on the
// same ASN.
func TestFromASNRDAP_LACNICBareHandleGetsASPrefix(t *testing.T) {
	resp := &rdap.ASNResponse{
		Handle:      "28573",
		StartAutnum: 28573,
		EndAutnum:   28573,
	}

	sr := fromASNRDAP(model.SourceResult{Source: model.SourceRegistryRDAP, OK: true}, resp)

	if sr.Handle != "AS28573" {
		t.Errorf("Handle = %q, want AS28573 (bare RDAP handle normalized to match WHOIS's prefixed form)", sr.Handle)
	}
}

func TestNormalizeASNHandle(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"bare numeric gets prefixed", "28573", "AS28573"},
		{"already prefixed unchanged", "AS15169", "AS15169"},
		{"already prefixed lowercase unchanged", "as15169", "as15169"},
		{"empty stays empty", "", ""},
		{"non-numeric handle unchanged", "test", "test"},
		{"non-numeric org-style handle unchanged", "ORG-BAdI1-AFRINIC", "ORG-BAdI1-AFRINIC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeASNHandle(tt.in); got != tt.want {
				t.Errorf("normalizeASNHandle(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestFromASNHop_PopulatedFields(t *testing.T) {
	hop := whois.Hop{
		ASNFields: &parse.ASNFields{
			CommonFields: parse.CommonFields{
				Handle:     "AS15169",
				OrgName:    "Google LLC",
				OrgID:      "GOGL",
				Country:    "US",
				Registered: "2000-03-30",
				Updated:    "2023-12-29",
				AbuseEmail: "network-abuse@google.com",
				AbusePhone: "+1-650-253-0000",
				Statuses:   []string{"active"},
			},
			Number: "15169",
			Name:   "GOOGLE",
			Type:   "Direct Allocation",
		},
	}

	sr := fromASNHop(model.SourceResult{Source: model.SourceRegistryWHOIS, OK: true}, hop)

	if !sr.Present {
		t.Fatal("Present = false, want true")
	}
	if sr.StartAutnum != "15169" || sr.EndAutnum != "15169" {
		t.Errorf("StartAutnum/EndAutnum = %q/%q, want 15169/15169 (a WHOIS aut-num object describes a single ASN)", sr.StartAutnum, sr.EndAutnum)
	}
	if sr.Name != "GOOGLE" {
		t.Errorf("Name = %q, want GOOGLE", sr.Name)
	}
	if sr.Handle != "AS15169" {
		t.Errorf("Handle = %q, want AS15169", sr.Handle)
	}
	if sr.Type != "Direct Allocation" {
		t.Errorf("Type = %q, want Direct Allocation", sr.Type)
	}
	if sr.OrgName != "Google LLC" {
		t.Errorf("OrgName = %q, want Google LLC", sr.OrgName)
	}
	if sr.OrgID != "GOGL" {
		t.Errorf("OrgID = %q, want GOGL", sr.OrgID)
	}
	if sr.Country != "US" {
		t.Errorf("Country = %q, want US", sr.Country)
	}
	if sr.AbuseEmail != "network-abuse@google.com" {
		t.Errorf("AbuseEmail = %q, want network-abuse@google.com", sr.AbuseEmail)
	}
	if sr.AbusePhone != "+1-650-253-0000" {
		t.Errorf("AbusePhone = %q, want +1-650-253-0000", sr.AbusePhone)
	}
	if len(sr.Status) != 1 || sr.Status[0] != "active" {
		t.Errorf("Status = %v, want [active]", sr.Status)
	}

	if !sr.Registered.Parsed {
		t.Errorf("Registered.Parsed = false, want true: %+v", sr.Registered)
	}
	if sr.Registered.Raw != "2000-03-30" {
		t.Errorf("Registered.Raw = %q, want 2000-03-30", sr.Registered.Raw)
	}
	if !sr.Updated.Parsed {
		t.Errorf("Updated.Parsed = false, want true: %+v", sr.Updated)
	}
	if sr.Updated.Raw != "2023-12-29" {
		t.Errorf("Updated.Raw = %q, want 2023-12-29", sr.Updated.Raw)
	}
}

func TestFromASNHop_NilASNFields(t *testing.T) {
	// A domain or IP hop (or a hop where ASN parsing never ran) carries a
	// nil ASNFields pointer -- this must degrade to Present:false, not
	// panic.
	hop := whois.Hop{Raw: "some raw text that was never ASN-parsed"}

	sr := fromASNHop(model.SourceResult{Source: model.SourceRegistryWHOIS, OK: true}, hop)

	if sr.Present {
		t.Error("Present = true, want false when hop.ASNFields is nil")
	}
	if sr.Meta.OK {
		t.Error("Meta.OK = true, want false when hop.ASNFields is nil")
	}
}

func TestFromASNHop_HopError(t *testing.T) {
	hop := whois.Hop{Err: errDeadline}

	sr := fromASNHop(model.SourceResult{Source: model.SourceRegistryWHOIS, OK: true}, hop)

	if sr.Present {
		t.Error("Present = true, want false when hop.Err is set")
	}
	if sr.Meta.OK {
		t.Error("Meta.OK = true, want false when hop.Err is set")
	}
}

func TestFromASNHop_RateLimited(t *testing.T) {
	hop := whois.Hop{
		Fields:    parse.Fields{RateLimited: true},
		ASNFields: &parse.ASNFields{CommonFields: parse.CommonFields{Handle: "AS64512"}},
	}

	sr := fromASNHop(model.SourceResult{Source: model.SourceRegistryWHOIS, OK: true}, hop)

	if sr.Meta.OK {
		t.Error("Meta.OK = true, want false for a rate-limited response")
	}
	if sr.Present {
		t.Error("Present = true, want false for a rate-limited response")
	}
	if sr.Meta.Err == "" {
		t.Error("Meta.Err is empty, want a message explaining the rate-limit refusal")
	}
}

func TestFromASNHop_Unsupported(t *testing.T) {
	hop := whois.Hop{
		Fields:    parse.Fields{Unsupported: true},
		ASNFields: &parse.ASNFields{CommonFields: parse.CommonFields{Handle: "AS64512"}},
	}

	sr := fromASNHop(model.SourceResult{Source: model.SourceRegistryWHOIS, OK: true}, hop)

	if sr.Meta.OK {
		t.Error("Meta.OK = true, want false for an unsupported-query refusal")
	}
	if sr.Present {
		t.Error("Present = true, want false for an unsupported-query refusal")
	}
	if sr.Meta.Err == "" {
		t.Error("Meta.Err is empty, want a message explaining the refusal")
	}
}

// TestFromASNHop_RIRStatusPassesThroughVerbatim is a regression guard
// mirroring TestFromIPHop_RIRStatusPassesThroughVerbatim: RIR status
// vocabulary is not EPP (RFC 8056), so it must not be run through
// model.NormalizeEPPStatus.
func TestFromASNHop_RIRStatusPassesThroughVerbatim(t *testing.T) {
	hop := whois.Hop{
		ASNFields: &parse.ASNFields{
			CommonFields: parse.CommonFields{
				Handle:   "test",
				Statuses: []string{"ASSIGNED PA"},
			},
		},
	}

	sr := fromASNHop(model.SourceResult{Source: model.SourceRegistryWHOIS, OK: true}, hop)

	if len(sr.Status) != 1 || sr.Status[0] != "ASSIGNED PA" {
		t.Errorf("Status = %v, want [\"ASSIGNED PA\"] unchanged (RIR vocabulary, not EPP)", sr.Status)
	}
}

func TestFromASNHop_RedactedOrgName(t *testing.T) {
	hop := whois.Hop{
		ASNFields: &parse.ASNFields{
			CommonFields: parse.CommonFields{
				Handle:  "AS64512",
				OrgName: "REDACTED FOR PRIVACY",
			},
		},
	}

	sr := fromASNHop(model.SourceResult{Source: model.SourceRegistryWHOIS, OK: true}, hop)

	if sr.OrgName != "" {
		t.Errorf("OrgName = %q, want empty (redacted placeholder), matching fromIPHop's treatment of a redacted org name", sr.OrgName)
	}
	if !sr.RedactedFields[model.FieldOrgName] {
		t.Error("RedactedFields[org.name] = false, want true")
	}
	if !sr.Present {
		t.Error("Present = false, want true (Handle is populated even though OrgName is redacted)")
	}
}
