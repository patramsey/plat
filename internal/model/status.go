package model

import (
	"strings"
	"unicode"
)

func isMixedCase(s string) bool {
	hasUpper, hasLower := false, false
	for _, r := range s {
		if unicode.IsUpper(r) {
			hasUpper = true
		}
		if unicode.IsLower(r) {
			hasLower = true
		}
	}
	return hasUpper && hasLower
}

// canonicalEPPStatus maps the lowercase form of every status defined by
// RFC 5731 (domain statuses) and RFC 3915 (grace-period statuses) to its
// canonical spelling.
//
// It exists because registrars do not agree on casing: Cloudflare's
// registrar WHOIS emits "clientdeleteprohibited" where registry RDAP emits
// "clientDeleteProhibited". Without folding, the merge treats them as two
// different statuses and the record lists every restriction twice -- plat
// reporting its own normalisation gap as data.
var canonicalEPPStatus = map[string]string{
	"clientdeleteprohibited":   "clientDeleteProhibited",
	"clienthold":               "clientHold",
	"clientrenewprohibited":    "clientRenewProhibited",
	"clienttransferprohibited": "clientTransferProhibited",
	"clientupdateprohibited":   "clientUpdateProhibited",
	"serverdeleteprohibited":   "serverDeleteProhibited",
	"serverhold":               "serverHold",
	"serverrenewprohibited":    "serverRenewProhibited",
	"servertransferprohibited": "serverTransferProhibited",
	"serverupdateprohibited":   "serverUpdateProhibited",
	"pendingcreate":            "pendingCreate",
	"pendingdelete":            "pendingDelete",
	"pendingrenew":             "pendingRenew",
	"pendingtransfer":          "pendingTransfer",
	"pendingupdate":            "pendingUpdate",
	"pendingrestore":           "pendingRestore",
	"addperiod":                "addPeriod",
	"autorenewperiod":          "autoRenewPeriod",
	"renewperiod":              "renewPeriod",
	"transferperiod":           "transferPeriod",
	"redemptionperiod":         "redemptionPeriod",
	"inactive":                 "inactive",
	"ok":                       "ok",
}

// NormalizeEPPStatus canonicalizes a domain status string from either RDAP
// (space-separated, e.g. Verisign's "client transfer prohibited") or WHOIS
// (already camelCase, e.g. "clientTransferProhibited") into one camelCase
// EPP form, so the merge engine can union/compare status sets across
// sources regardless of which vocabulary spelling each one used. After
// the casing pass it also folds the result through canonicalEPPStatus,
// so two sources that agree on the status but disagree on casing (e.g.
// RDAP's "clientDeleteProhibited" vs. a registrar WHOIS's
// "clientdeleteprohibited") end up as the exact same string instead of
// two spellings of one fact.
func NormalizeEPPStatus(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	var out string
	fields := strings.Fields(s)
	if len(fields) == 1 {
		tok := fields[0]
		if isMixedCase(tok) {
			// Genuine camelCase already — preserve internal casing, just
			// lowercase the leading rune.
			r := []rune(tok)
			r[0] = unicode.ToLower(r[0])
			out = string(r)
		} else {
			// Uniform case (all-upper "ACTIVE" or all-lower "active") — lowercase it.
			out = strings.ToLower(tok)
		}
	} else {
		// Space-separated form -> camelCase.
		var b strings.Builder
		for i, w := range fields {
			lw := strings.ToLower(w)
			if i == 0 {
				b.WriteString(lw)
				continue
			}
			r := []rune(lw)
			r[0] = unicode.ToUpper(r[0])
			b.WriteString(string(r))
		}
		out = b.String()
	}
	// Fold known EPP codes to their canonical spelling regardless of what
	// casing this source used, so the merge engine sees one status instead
	// of two spellings of the same fact (see canonicalEPPStatus).
	if canon, ok := canonicalEPPStatus[strings.ToLower(out)]; ok {
		return canon
	}
	return out
}
