package parse

import (
	"strings"
	"time"
	"unicode"
)

// Date is a tolerant, never-failing parse of a WHOIS date string. WHOIS
// registries use well over a dozen date formats with inconsistent casing
// and separators; Raw always holds the original string so a format this
// parser doesn't recognize is still visible rather than silently dropped.
type Date struct {
	Raw    string
	Time   time.Time
	Parsed bool
}

var dateLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05Z07:00",
	"2006-01-02 15:04:05",
	"2006-01-02",
	// "20060102" is LACNIC's compact, unpunctuated aut-num created/changed
	// form (e.g. "20031127") -- confirmed live against AS28573. Listed
	// after "2006-01-02" rather than before it since it's the less common
	// shape; ordering only matters for ambiguous inputs, and an 8-digit
	// run has no punctuation for any earlier layout to partially match.
	"20060102",
	"02-Jan-2006 15:04:05",
	"02-Jan-2006",
	"2006/01/02",
	"2006.01.02",
	"02.01.2006",
	"January 2, 2006",
	"Mon Jan 02 2006",
}

// ParseDate tries each known WHOIS date layout in turn, on both the raw
// string and a title-cased variant (WHOIS month abbreviations appear in
// any case: "aug", "Aug", "AUG"). It never errors — an unrecognized format
// leaves Parsed false with Raw preserved.
func ParseDate(s string) Date {
	raw := strings.TrimSpace(s)
	d := Date{Raw: raw}
	if raw == "" {
		return d
	}
	candidates := []string{raw, titleCaseWords(raw)}
	for _, cand := range candidates {
		for _, layout := range dateLayouts {
			if t, err := time.Parse(layout, cand); err == nil {
				d.Time = t.UTC()
				d.Parsed = true
				return d
			}
		}
	}
	for _, cand := range candidates {
		stripped, ok := stripUTCAbbreviation(cand)
		if !ok {
			continue
		}
		for _, layout := range noZoneLayoutsForUTCStrip {
			if t, err := time.Parse(layout, stripped); err == nil {
				d.Time = t.UTC()
				d.Parsed = true
				return d
			}
		}
	}
	return d
}

// titleCaseWords upper-cases the first letter of each run of letters and
// lowercases the rest, e.g. "14-aug-1995" -> "14-Aug-1995".
func titleCaseWords(s string) string {
	var b strings.Builder
	prevAlpha := false
	for _, r := range s {
		if unicode.IsLetter(r) {
			if !prevAlpha {
				b.WriteRune(unicode.ToUpper(r))
			} else {
				b.WriteRune(unicode.ToLower(r))
			}
			prevAlpha = true
		} else {
			b.WriteRune(r)
			prevAlpha = false
		}
	}
	return b.String()
}

// utcAbbreviations are the only timezone abbreviations ParseDate treats
// specially: both UTC and GMT unambiguously mean offset+0 with no DST,
// so stripping either and parsing the remainder as a naive timestamp is
// safe. Other common abbreviations (PST, MST, EST, CET, ...) are
// deliberately NOT handled this way — Go's time.Parse zone-abbreviation
// matching for those is environment-dependent and was confirmed locally
// to silently produce offset+0 for at least PST and EST (both actually
// non-zero offsets), which would be a confidently wrong parsed Time fed
// straight into merge.Merge's clock-skew conflict detection. Leaving an
// unrecognized abbreviation unparsed (Raw preserved, Parsed false) is
// safer than a silently incorrect one.
var utcAbbreviations = []string{" UTC", " GMT"}

// noZoneLayoutsForUTCStrip are tried against the remainder after a
// trailing UTC/GMT abbreviation is stripped — the layouts themselves
// have no zone component, since the abbreviation already told us the
// answer is UTC+0.
var noZoneLayoutsForUTCStrip = []string{
	"Mon, 02 Jan 2006 15:04:05",
	"Mon Jan 02 2006 15:04:05",
}

// stripUTCAbbreviation removes a trailing " UTC" or " GMT" (case
// insensitive) from s, reporting whether it found one.
func stripUTCAbbreviation(s string) (string, bool) {
	upper := strings.ToUpper(s)
	for _, suffix := range utcAbbreviations {
		if strings.HasSuffix(upper, suffix) {
			return strings.TrimSpace(s[:len(s)-len(suffix)]), true
		}
	}
	return s, false
}
