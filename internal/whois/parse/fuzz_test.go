package parse

import "testing"

// FuzzParse exercises Parse against corrupted/adversarial variants of real
// WHOIS responses. Parse's inputs are always untrusted network text (see
// SECURITY.md's "Parser panics ... triggered by malformed or hostile
// server responses"), and Parse is a hand-rolled heuristic parser -- not
// something like encoding/json with its own battle-tested fuzz corpus
// upstream -- so it's the highest-value fuzz target in this codebase.
// Parse has no error return; the only failure mode a fuzz run can catch is
// a panic (out-of-range index, nil map write, etc.), which is exactly
// what this guards against.
//
// Seeds cover all three tokenizer formats templates.yaml selects between
// (kv default, brackets for jp, indent for uk) plus every registered
// template's synonym table (de, eu, fr, nl), so mutation starts from
// input that already exercises every code path, not just the default kv
// tokenizer.
func FuzzParse(f *testing.F) {
	seeds := []struct {
		fixture string
		tld     string
	}{
		{"verisign-com-example.txt", "com"},
		{"pir-org-example.txt", "org"},
		{"ratelimited.txt", "com"},
		{"notfound.txt", "com"},
		{"tld-not-supported.txt", "ninja"},
		{"nominet-uk-example.txt", "uk"},
		{"idn-example.txt", "de"},
		{"expired-example.txt", "com"},
		{"gdpr-redacted-de.txt", "de"},
		{"denic-de-example.txt", "de"},
		{"eurid-eu-example.txt", "eu"},
		{"jprs-jp-example.txt", "jp"},
		{"afnic-fr-example.txt", "fr"},
		{"sidn-nl-example.txt", "nl"},
	}
	for _, s := range seeds {
		f.Add(loadFixture(f, s.fixture), s.tld)
	}
	f.Add("", "")
	f.Add("\x00\x01\x02", "de")

	f.Fuzz(func(t *testing.T, raw, tld string) {
		Parse(raw, tld)
	})
}

// FuzzParseDate targets ParseDate directly: it's reachable with fully
// attacker-controlled content (any WHOIS "Creation Date:"-style value),
// and does its own string manipulation (titleCaseWords) ahead of
// time.Parse, rather than relying solely on time.Parse's own (already
// panic-free) error handling.
func FuzzParseDate(f *testing.F) {
	seeds := []string{
		"",
		"2024-08-02T02:17:33Z",
		"2024-08-02 02:17:33Z",
		"02-Aug-2024",
		"02-AUG-2024 02:17:33",
		"2024/08/02",
		"2024.08.02",
		"02.08.2024",
		"August 2, 2024",
		"Fri Aug 02 2024",
		"not a date at all",
		"\x00\x01\x02",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		ParseDate(s)
	})
}
