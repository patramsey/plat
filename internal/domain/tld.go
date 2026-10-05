package domain

import (
	"slices"

	"golang.org/x/net/publicsuffix"
)

// KnownTLD reports whether tld is a top-level domain in the Public Suffix
// List's ICANN section, which lists every delegated TLD. The list is
// compiled in and can lag a brand-new delegation, so this is for
// explaining a lookup that found nothing to query, never for refusing
// one up front. The probe goes through a child name because a TLD known
// only by a wildcard rule (*.ck) does not match on its own.
func KnownTLD(tld string) bool {
	_, icann := publicsuffix.PublicSuffix("x." + tld)
	return icann
}

// commonTLDs ranks SuggestTLDs' candidates: a typo of "com" is likelier
// meant as .com than as .cm or .bom.
var commonTLDs = []string{
	"com", "net", "org", "de", "uk", "cn", "nl", "ru", "br", "au",
	"fr", "it", "jp", "io", "co", "in", "info", "eu", "ca", "ch",
}

// SuggestTLDs returns up to three known TLDs one edit away from tld (a
// swap of adjacent letters, a deletion, a substitution, or an insertion),
// common TLDs first -- "com" for "comm" or "cmo", "org" for "ogr".
func SuggestTLDs(tld string) []string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	seen := map[string]bool{tld: true}
	var out []string
	try := func(c string) {
		if !seen[c] && len(c) >= 2 && KnownTLD(c) {
			out = append(out, c)
		}
		seen[c] = true
	}
	for i := range len(tld) - 1 {
		try(tld[:i] + string(tld[i+1]) + string(tld[i]) + tld[i+2:])
	}
	for i := range len(tld) {
		try(tld[:i] + tld[i+1:])
	}
	for i := range len(tld) {
		for _, r := range letters {
			try(tld[:i] + string(r) + tld[i+1:])
		}
	}
	for i := range len(tld) + 1 {
		for _, r := range letters {
			try(tld[:i] + string(r) + tld[i:])
		}
	}
	rank := func(s string) int {
		if i := slices.Index(commonTLDs, s); i >= 0 {
			return i
		}
		return len(commonTLDs)
	}
	slices.SortStableFunc(out, func(a, b string) int { return rank(a) - rank(b) })
	return out[:min(len(out), 3)]
}
