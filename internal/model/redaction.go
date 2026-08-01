package model

import "strings"

var redactedPlaceholders = []string{
	"redacted for privacy",
	"data redacted",
	"data protected",
	"not disclosed",
	"gdpr masked",
	"statutory masking enabled",
	"redacted",
	"registration private",
}

// IsRedactedPlaceholder reports whether s is a known WHOIS/RDAP
// placeholder for a withheld value (e.g. "REDACTED FOR PRIVACY"), rather
// than a genuine value. Comparison is case-insensitive and requires an
// EXACT match after trimming whitespace, not a substring match — a real
// organization name that happens to contain "redact" must not be
// misclassified.
func IsRedactedPlaceholder(s string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(s))
	if trimmed == "" {
		return false
	}
	for _, p := range redactedPlaceholders {
		if trimmed == p {
			return true
		}
	}
	return false
}
