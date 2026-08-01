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

// NormalizeEPPStatus canonicalizes a domain status string from either RDAP
// (space-separated, e.g. Verisign's "client transfer prohibited") or WHOIS
// (already camelCase, e.g. "clientTransferProhibited") into one camelCase
// EPP form, so the merge engine can union/compare status sets across
// sources regardless of which vocabulary spelling each one used.
func NormalizeEPPStatus(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	fields := strings.Fields(s)
	if len(fields) == 1 {
		tok := fields[0]
		if isMixedCase(tok) {
			// Genuine camelCase already — preserve internal casing, just
			// lowercase the leading rune.
			r := []rune(tok)
			r[0] = unicode.ToLower(r[0])
			return string(r)
		}
		// Uniform case (all-upper "ACTIVE" or all-lower "active") — lowercase it.
		return strings.ToLower(tok)
	}
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
	return b.String()
}
