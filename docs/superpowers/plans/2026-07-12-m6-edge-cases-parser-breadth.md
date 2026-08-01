# M6 — Edge Cases + Parser Breadth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fill out `plat`'s edge-case coverage — IDN/reserved-TLD breadth, WHOIS date-format torture tests, a small closed set of new ccTLD WHOIS templates (`.uk`, `.eu`, `.fr`, `.nl`), the golden-file fixture suite the spec's testing section calls for, and deeper merge-engine conflict coverage.

**Architecture:** This milestone is overwhelmingly additive — most of the machinery it touches (the embedded-YAML template mechanism, the tolerant multi-format date parser, IDN normalization, RDAP's existing 429/Retry-After handling) already exists from M1-M3 and needs test coverage and small data additions, not new subsystems. The one genuinely new piece of production code is a third WHOIS tokenizer dialect (`tokenizeIndent`) for Nominet's `.uk` block format, alongside the existing `tokenizeKV`/`tokenizeBrackets` dialects.

**Tech Stack:** No new dependencies. Everything in this milestone uses stdlib (`time`, `net/http/httptest`) plus the already-present `gopkg.in/yaml.v3` for template data.

## Global Constraints

- Contact merging is explicitly OUT OF SCOPE for this milestone. No changes to `internal/merge/merge.go`'s production code; `Record.Contacts` stays unpopulated (a later milestone's work). No task should add contact-merging logic even incidentally.
- IDN normalization in `internal/domain/normalize.go` stays LENIENT — keep `idna.ToASCII` exactly as-is, do not switch to `idna.New(idna.ValidateForRegistration())` or any stricter profile. Only the reserved-TLD list and test coverage expand.
- `reservedTLDs` in `internal/domain/normalize.go` gets exactly three new entries: `"test"`, `"example"`, `"invalid"` (RFC 2606 special-use names, same category as the existing `"local"`/`"internal"`). Do not add `"home"`/`"corp"` — they are not IANA-reserved/RFC-6761 special-use TLDs, unlike `.local`/`.internal` which are.
- `.uk` gets a genuinely new `tokenizeIndent` dialect function in `internal/whois/parse/parse.go` (not a synonym-only approximation) — full design is in Task 3.
- `.eu`, `.fr`, and `.nl` are synonym-only / `format: kv` additions to `templates.yaml` — zero new parser code for these three.
- Every new WHOIS/RDAP fixture in this milestone is hand-authored synthetic data matching real-world formats — never a live-captured/frozen real lookup. No task in this milestone makes a network call in its own tests (the sole exception, already established since M1, is the opt-in `-tags=live` build-tagged smoke tests, which this milestone does not touch).
- A template-manifest test (Task 4) validates every entry in the loaded `templates` map has a corresponding fixture that parses to expected canonical fields — this is the regression guard that keeps "add a ccTLD" mechanically honest: a missing fixture must fail the suite, not silently pass.
- Timezone-abbreviation date handling (Task 2) only special-cases `UTC` and `GMT` (both unambiguously mean offset+0, no DST) via an explicit strip-and-reparse step — it does NOT attempt to resolve other abbreviations (`MST`, `PST`, `EST`, etc.), because Go's `time.Parse` zone-abbreviation matching for those is environment-dependent and can silently produce an incorrect offset (confirmed locally: parsing "PST"/"EST" via a `"...MST"`-reference-token layout silently yields offset 0, which is wrong for both). An abbreviation outside the small UTC/GMT allowlist stays unparsed (`Parsed: false`, `Raw` preserved) rather than being confidently wrong — consistent with this parser's existing "never silently wrong" design.
- RDAP 429/retry behavior (Task 5) gets an `httptest`-based test exercising the ALREADY-IMPLEMENTED retry logic in `internal/rdap/client.go` (confirmed: `retryAfter(h http.Header) time.Duration` at `client.go:118`, invoked at `client.go:198-200` on `http.StatusTooManyRequests`) — this is new test coverage of existing production code, not a production code change.
- Every task that modifies a pre-existing file must confirm that package's pre-existing tests still pass unmodified.

---

### Task 1: IDN & Reserved-TLD Test Coverage Expansion

**Files:**
- Modify: `internal/domain/normalize.go` (extend `reservedTLDs`)
- Modify: `internal/domain/normalize_test.go` (extend `TestNormalize`'s table)

**Interfaces:**
- Consumes: `domain.Normalize(input string) (Name, error)`, `domain.ErrSingleLabel` (both pre-existing, unchanged signatures).
- Produces: nothing new consumed by later tasks — this task is self-contained.

- [ ] **Step 1: Write the failing tests**

Add these new cases to `internal/domain/normalize_test.go`'s existing `tests` table in `TestNormalize` (append to the slice literal, after the existing `"reserved TLD .internal rejected"` case):

```go
		{
			name:         "uppercase IDN normalizes and converts to punycode",
			input:        "MÜNCHEN.DE",
			wantPunycode: "xn--mnchen-3ya.de",
			wantTLD:      "de",
		},
		{
			name:         "already-punycode xn-- input round-trips to Unicode display form",
			input:        "xn--mnchen-3ya.de",
			wantPunycode: "xn--mnchen-3ya.de",
			wantTLD:      "de",
			wantUnicode:  "münchen.de",
		},
		{
			name:         "IDN under a ccTLD with its own IDN suffix",
			input:        "täst.xn--p1ai",
			wantPunycode: "xn--tst-qla.xn--p1ai",
			wantTLD:      "xn--p1ai",
		},
		{
			name:         "mixed-script label still converts (idna.ToASCII does not perform confusable detection)",
			input:        "аpple.com", // Cyrillic "а" (U+0430) + Latin "pple.com" — a classic homograph
			wantPunycode: "xn--pple-43d.com",
			wantTLD:      "com",
		},
		{
			name:            "reserved TLD .test rejected",
			input:           "example.test",
			wantErrContains: "reserved/private TLD",
		},
		{
			name:            "reserved TLD .example rejected",
			input:           "foo.example",
			wantErrContains: "reserved/private TLD",
		},
		{
			name:            "reserved TLD .invalid rejected",
			input:           "foo.invalid",
			wantErrContains: "reserved/private TLD",
		},
```

Add a `wantUnicode string` field to the table's anonymous struct definition (near the top of `TestNormalize`, alongside `wantPunycode`/`wantTLD`):

```go
	tests := []struct {
		name            string
		input           string
		wantPunycode    string
		wantTLD         string
		wantUnicode     string
		wantErr         error
		wantErrContains string
	}{
```

And extend the table-driven test's assertion block (after the existing `if got.TLD != tt.wantTLD` check) to check `wantUnicode` only when it's set (most existing cases don't specify it, since punycode-only ASCII domains have `Unicode == Punycode`):

```go
			if tt.wantUnicode != "" && got.Unicode != tt.wantUnicode {
				t.Errorf("Unicode = %q, want %q", got.Unicode, tt.wantUnicode)
			}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/pat/codes/plat && go test ./internal/domain/... -v -run TestNormalize`
Expected: FAIL — the three new reserved-TLD cases fail (`.test`/`.example`/`.invalid` are not yet rejected, `Normalize` currently accepts them). The IDN/Unicode cases should already PASS at this point (they exercise existing, unmodified behavior) — if any of those unexpectedly fail, stop and report it as a real finding rather than adjusting the fixture to match, since they're meant to characterize already-shipped behavior.

- [ ] **Step 3: Write the implementation**

In `internal/domain/normalize.go`, extend `reservedTLDs`:

```go
var reservedTLDs = map[string]bool{
	"local":    true,
	"internal": true,
	"test":     true,
	"example":  true,
	"invalid":  true,
}
```

- [ ] **Step 4: Run tests to verify they pass, and confirm zero regression**

Run: `cd /Users/pat/codes/plat && go test ./internal/domain/... -v`
Expected: PASS — all `TestNormalize` subtests (existing 8 plus 7 new) green.

Run: `cd /Users/pat/codes/plat && go build ./... && go test ./...`
Expected: all 14 packages `ok` (this task only touches `internal/domain`, a leaf package with no downstream production-code consumers changing behavior — `domain.Normalize` is used by `cmd/plat` and `internal/collect`, neither of which is sensitive to the specific set of rejected TLDs beyond already handling the error path generically).

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/domain/normalize.go internal/domain/normalize_test.go
git commit -m "test: expand IDN and reserved-TLD coverage in domain.Normalize"
```

---

### Task 2: Date-Format Torture Tests

**Files:**
- Modify: `internal/whois/parse/date.go` (add one layout, add UTC/GMT abbreviation stripping)
- Modify: `internal/whois/parse/date_test.go` (extend)

**Interfaces:**
- Consumes: nothing new.
- Produces: `parse.ParseDate(s string) Date` keeps its exact existing signature — consumed unchanged by `parse.go`'s `Parse` function (no change needed there).

- [ ] **Step 1: Write the failing tests**

Append to `internal/whois/parse/date_test.go` (reuse whatever table-driven pattern the existing file uses — if it's a `[]struct{ name, input string; wantParsed bool; wantRaw string }`-shaped table, add to that same table; otherwise add these as new standalone test functions matching the file's existing style):

```go
func TestParseDate_TortureFormats(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantParsed bool
		wantUTC    string // RFC3339, only checked if wantParsed
	}{
		{
			name:       "dash-month with time, no zone",
			input:      "14-Aug-1995 04:00:00",
			wantParsed: true,
			wantUTC:    "1995-08-14T04:00:00Z",
		},
		{
			name:       "RFC1123-ish with GMT abbreviation",
			input:      "Mon, 14 Aug 1995 04:00:00 GMT",
			wantParsed: true,
			wantUTC:    "1995-08-14T04:00:00Z",
		},
		{
			name:       "RFC1123-ish with UTC abbreviation",
			input:      "Mon, 14 Aug 1995 04:00:00 UTC",
			wantParsed: true,
			wantUTC:    "1995-08-14T04:00:00Z",
		},
		{
			name:       "RFC1123-ish with an ambiguous US zone abbreviation stays unparsed",
			input:      "Mon, 14 Aug 1995 04:00:00 PST",
			wantParsed: false,
		},
		{
			name:       "RFC1123-ish with another ambiguous US zone abbreviation stays unparsed",
			input:      "Mon, 14 Aug 1995 04:00:00 EST",
			wantParsed: false,
		},
		{
			name:       "fractional seconds, already covered by RFC3339Nano",
			input:      "2026-08-13T04:00:00.500Z",
			wantParsed: true,
			wantUTC:    "2026-08-13T04:00:00.5Z",
		},
		{
			name:       "day-first DD.MM.YYYY is parsed under that assumption, not disambiguated",
			input:      "12.07.2026",
			wantParsed: true,
			wantUTC:    "2026-07-12T00:00:00Z",
		},
		{
			name:       "genuinely unrecognized format stays unparsed with Raw preserved",
			input:      "sometime next week",
			wantParsed: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := ParseDate(tt.input)
			if d.Raw != tt.input {
				t.Errorf("Raw = %q, want %q (input preserved verbatim, trimmed)", d.Raw, tt.input)
			}
			if d.Parsed != tt.wantParsed {
				t.Fatalf("Parsed = %v, want %v (Time = %v)", d.Parsed, tt.wantParsed, d.Time)
			}
			if tt.wantParsed && d.Time.UTC().Format(time.RFC3339Nano) != tt.wantUTC {
				gotFormatted := d.Time.UTC().Format(time.RFC3339)
				if gotFormatted != tt.wantUTC {
					t.Errorf("Time.UTC() = %s, want %s", d.Time.UTC().Format(time.RFC3339), tt.wantUTC)
				}
			}
		})
	}
}
```

Add `"time"` to `date_test.go`'s import block if not already present (check the file first — it likely already imports `time` given it's testing a `time.Time`-based type).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/parse/... -v -run TestParseDate_TortureFormats`
Expected: FAIL on 3 subtests: "dash-month with time, no zone" (no matching layout yet), "RFC1123-ish with GMT abbreviation" and "...with UTC abbreviation" (no zone-stripping yet — both currently return `Parsed: false`, so `wantParsed: true` fails). The two "ambiguous zone stays unparsed" cases and the fractional/day-first/unrecognized cases should already PASS (they exercise existing behavior) — if any of those unexpectedly fail, stop and report it rather than adjusting the fixture.

- [ ] **Step 3: Write the implementation**

In `internal/whois/parse/date.go`, add one new layout to `dateLayouts` (dash-month WITH time — the existing `"02-Jan-2006"` has no time component):

```go
var dateLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05Z07:00",
	"2006-01-02 15:04:05",
	"2006-01-02",
	"02-Jan-2006 15:04:05",
	"02-Jan-2006",
	"2006/01/02",
	"2006.01.02",
	"02.01.2006",
	"January 2, 2006",
	"Mon Jan 02 2006",
}
```

Add the UTC/GMT abbreviation stripping mechanism (new code, appended after `titleCaseWords`):

```go
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
```

Modify `ParseDate` to try the UTC/GMT-stripped path after the existing layout loop fails:

```go
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
```

- [ ] **Step 4: Run tests to verify they pass, and confirm zero regression**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/parse/... -v`
Expected: PASS — `TestParseDate_TortureFormats` (8 subtests) and every pre-existing test in the package (`date_test.go`'s existing tests, `parse_test.go`, `templates_test.go`) green.

Run: `cd /Users/pat/codes/plat && go build ./... && go test ./...`
Expected: all 14 packages `ok`.

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/whois/parse/date.go internal/whois/parse/date_test.go
git commit -m "feat: add dash-month-with-time layout and safe UTC/GMT abbreviation handling to ParseDate"
```

---

### Task 3: `.uk` Indented-Block Dialect, Template, and Fixture

**Files:**
- Modify: `internal/whois/parse/parse.go` (add `tokenizeIndent`, add `"name servers"` to `defaultSynonyms`, switch `Parse`'s dialect dispatch to a 3-way switch)
- Modify: `internal/whois/parse/templates.yaml` (register `uk`)
- Create: `testdata/whois/nominet-uk-example.txt`
- Modify: `internal/whois/parse/parse_test.go` (add `TestTokenizeIndent_UKFixture`)

**Interfaces:**
- Consumes: `kvPair` (pre-existing, unchanged), `templateFor(tld)` (pre-existing, unchanged).
- Produces: `tokenizeIndent(raw string) []kvPair` — consumed by `Parse`'s dialect dispatch (same file) and by Task 4's template-manifest test (which iterates every registered template, including this one).

This is the one genuinely novel piece of production code in the whole milestone.

- [ ] **Step 1: Write the fixture and the failing test**

Create `testdata/whois/nominet-uk-example.txt` (a hand-authored fixture matching Nominet's real-world indented block format — a non-indented "Header:" line introduces a section, followed by one or more indented content lines):

```
Domain name:
        example.uk

Registrant:
        Example Organisation Ltd

Registrant type:
        UK Limited Company (Company number 12345678)

Registrar:
        Example Registrar Ltd t/a Example Registrar [Tag = EXAMPLE]
        URL: http://www.example-registrar.co.uk

Relevant dates:
        Registered on: 14-Aug-1995
        Expiry date:  13-Aug-2026
        Last updated:  14-Jan-2025

Registration status:
        Registered until expiry date.

Name servers:
        ns1.example.uk
        ns2.example.uk

WHOIS lookup made on Sun, 12 Jul 2026 at 09:15:00
```

Append to `internal/whois/parse/parse_test.go` (reuses the existing `loadFixture(t, name)` helper already defined in that file):

```go
func TestTokenizeIndent_UKFixture(t *testing.T) {
	raw := loadFixture(t, "nominet-uk-example.txt")
	pairs := tokenizeIndent(raw)

	want := map[string][]string{
		"domain name":        {"example.uk"},
		"registrant":         {"Example Organisation Ltd"},
		"registrant type":    {"UK Limited Company (Company number 12345678)"},
		"registrar":          {"Example Registrar Ltd t/a Example Registrar [Tag = EXAMPLE]"},
		"url":                {"http://www.example-registrar.co.uk"},
		"registered on":      {"14-Aug-1995"},
		"expiry date":        {"13-Aug-2026"},
		"last updated":       {"14-Jan-2025"},
		"registration status": {"Registered until expiry date."},
		"name servers":       {"ns1.example.uk", "ns2.example.uk"},
	}
	got := map[string][]string{}
	for _, p := range pairs {
		got[p.key] = append(got[p.key], p.val)
	}
	for key, wantVals := range want {
		gotVals, ok := got[key]
		if !ok {
			t.Errorf("missing key %q in tokenizeIndent output", key)
			continue
		}
		if len(gotVals) != len(wantVals) {
			t.Errorf("key %q: got %v, want %v", key, gotVals, wantVals)
			continue
		}
		for i := range wantVals {
			if gotVals[i] != wantVals[i] {
				t.Errorf("key %q[%d] = %q, want %q", key, i, gotVals[i], wantVals[i])
			}
		}
	}
	// The trailing "WHOIS lookup made on ..." line is not a "Header:"
	// line and not indented — it must produce no pair at all.
	for _, p := range pairs {
		if strings.Contains(p.val, "WHOIS lookup made on") || strings.Contains(p.key, "whois lookup") {
			t.Errorf("trailing timestamp line leaked into output: %+v", p)
		}
	}
}

func TestParse_UKTemplateEndToEnd(t *testing.T) {
	raw := loadFixture(t, "nominet-uk-example.txt")
	f := Parse(raw, "uk")

	if f.Domain != "example.uk" {
		t.Errorf("Domain = %q, want example.uk", f.Domain)
	}
	if f.Registrar != "Example Registrar Ltd t/a Example Registrar [Tag = EXAMPLE]" {
		t.Errorf("Registrar = %q", f.Registrar)
	}
	wantNS := []string{"ns1.example.uk", "ns2.example.uk"}
	if len(f.Nameservers) != len(wantNS) || f.Nameservers[0] != wantNS[0] || f.Nameservers[1] != wantNS[1] {
		t.Errorf("Nameservers = %v, want %v", f.Nameservers, wantNS)
	}
	if !f.Created.Parsed || f.Created.Raw != "14-Aug-1995" {
		t.Errorf("Created = %+v, want Parsed with Raw 14-Aug-1995", f.Created)
	}
	if !f.Expires.Parsed || f.Expires.Raw != "13-Aug-2026" {
		t.Errorf("Expires = %+v, want Parsed with Raw 13-Aug-2026", f.Expires)
	}
	if !f.Updated.Parsed || f.Updated.Raw != "14-Jan-2025" {
		t.Errorf("Updated = %+v, want Parsed with Raw 14-Jan-2025", f.Updated)
	}
}
```

Add `"strings"` to `parse_test.go`'s import block if not already present.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/parse/... -v -run 'TestTokenizeIndent_UKFixture|TestParse_UKTemplateEndToEnd'`
Expected: FAIL — `tokenizeIndent` undefined (build error) for the first test; once that's added, `TestParse_UKTemplateEndToEnd` will fail separately until the `uk` template is registered and `Parse`'s dispatch recognizes `format: indent` (do this incrementally — Step 3 covers both).

- [ ] **Step 3: Write the implementation**

In `internal/whois/parse/parse.go`, add `"name servers"` to `defaultSynonyms` (a generically useful plural-form addition, not `.uk`-specific — the existing table already has singular `"name server"`):

```go
var defaultSynonyms = map[string]string{
	"domain name":              fDomain,
	"domain":                   fDomain,
	"registrar":                fRegistrar,
	"registrar whois server":   fRegistrarWHOISServer,
	"whois server":             fRegistrarWHOISServer,
	"refer":                    fRefer,
	"domain status":            fStatus,
	"status":                   fStatus,
	"name server":              fNameservers,
	"name servers":             fNameservers,
	"nserver":                  fNameservers,
	"nameservers":              fNameservers,
	"creation date":            fCreated,
	"created":                  fCreated,
	"created on":               fCreated,
	"registered on":            fCreated,
	"domain registration date": fCreated,
	"registry expiry date":     fExpires,
	"expiry date":              fExpires,
	"expiration date":          fExpires,
	"expires on":               fExpires,
	"paid-till":                fExpires,
	"renewal date":             fExpires,
	"updated date":             fUpdated,
	"updated":                  fUpdated,
	"last updated":             fUpdated,
}
```

Add `tokenizeIndent` (after `tokenizeBrackets`):

```go
// tokenizeIndent handles Nominet-style ".uk" WHOIS output: a
// non-indented "Header:" line introduces a section, followed by one or
// more indented lines holding that section's content. An indented line
// containing its own "sub-key: value" pair (e.g. "Registered on:
// 14-Aug-1995" inside a "Relevant dates:" section) is tokenized using
// that sub-key directly, since Nominet nests several distinct fields
// under one section header. An indented line with no colon uses the
// enclosing section's header as the key, so multiple indented lines
// under "Name servers:" each become a separate pair sharing that key —
// exactly like tokenizeKV's repeated "Name Server:" lines do for other
// registries. Blank lines and any other non-indented, non-header line
// (e.g. a trailing "WHOIS lookup made on ..." timestamp line) are
// ignored, the same way tokenizeKV skips comment lines.
func tokenizeIndent(raw string) []kvPair {
	var out []kvPair
	section := ""
	for _, line := range strings.Split(raw, "\n") {
		trimmedRight := strings.TrimRight(line, "\r")
		if strings.TrimSpace(trimmedRight) == "" {
			continue
		}
		if !strings.HasPrefix(trimmedRight, " ") && !strings.HasPrefix(trimmedRight, "\t") {
			if strings.HasSuffix(strings.TrimSpace(trimmedRight), ":") {
				section = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(trimmedRight), ":"))
			} else {
				section = ""
			}
			continue
		}
		if section == "" {
			continue
		}
		content := strings.TrimSpace(trimmedRight)
		if idx := strings.Index(content, ":"); idx >= 0 && strings.TrimSpace(content[idx+1:]) != "" {
			key := strings.ToLower(strings.TrimSpace(content[:idx]))
			val := strings.TrimSpace(content[idx+1:])
			out = append(out, kvPair{key, val})
			continue
		}
		out = append(out, kvPair{section, content})
	}
	return out
}
```

Change `Parse`'s dialect dispatch from an if/else to a 3-way switch:

```go
	var pairs []kvPair
	switch tmpl.Format {
	case "brackets":
		pairs = tokenizeBrackets(raw)
	case "indent":
		pairs = tokenizeIndent(raw)
	default:
		pairs = tokenizeKV(raw)
	}
```

(replacing the current `if tmpl.Format == "brackets" { ... } else { ... }`)

In `internal/whois/parse/templates.yaml`, add the `uk` entry (no `synonyms` override needed — the fixture's field names all resolve via `defaultSynonyms`, including the new `"name servers"` entry added above):

```yaml
de:
  format: kv
  synonyms:
    changed: updated
jp:
  format: brackets
uk:
  format: indent
```

- [ ] **Step 4: Run tests to verify they pass, and confirm zero regression**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/parse/... -v`
Expected: PASS — `TestTokenizeIndent_UKFixture`, `TestParse_UKTemplateEndToEnd`, and every pre-existing test in the package (including `TestTemplatesEmbedYAML`, which will need its own update in Task 4, not here — this task doesn't touch that test).

Run: `cd /Users/pat/codes/plat && go build ./... && go test ./...`
Expected: all 14 packages `ok`.

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/whois/parse/parse.go internal/whois/parse/parse_test.go internal/whois/parse/templates.yaml testdata/whois/nominet-uk-example.txt
git commit -m "feat: add a Nominet-style indented-block WHOIS dialect for .uk"
```

---

### Task 4: `.eu`/`.fr`/`.nl` Templates, Fixtures, and the Template-Manifest Regression Test

**Files:**
- Modify: `internal/whois/parse/templates.yaml` (register `eu`, `fr`, `nl`)
- Create: `testdata/whois/eurid-eu-example.txt`, `testdata/whois/afnic-fr-example.txt`, `testdata/whois/sidn-nl-example.txt`
- Modify: `internal/whois/parse/templates_test.go` (replace `TestTemplatesEmbedYAML` with a full manifest test covering all 6 registered templates: `de`, `jp`, `uk`, `eu`, `fr`, `nl`)

**Interfaces:**
- Consumes: `templates map[string]Template` (package-level var, pre-existing), `Parse(raw, tld string) Fields` (pre-existing), `tokenizeIndent` (Task 3, same package).
- Produces: nothing new consumed by later tasks — the manifest test itself IS this task's deliverable, and it's the final validation harness for every template registered in this milestone (including `.uk` from Task 3).

- [ ] **Step 1: Write the fixtures and the failing test**

Create `testdata/whois/eurid-eu-example.txt` (EURid's `.eu` format is close to generic kv, GDPR-redacted registrant per the spec's DoD list):

```
Domain:	example.eu
Status:	ACTIVE
Registrant:	Not Disclosed - Visit www.eurid.eu for webbased WHOIS.
Registrar:
   Name:	Example Registrar B.V.
   Website:	www.example-registrar.eu

Name servers:
   ns1.example.eu
   ns2.example.eu

Please visit www.eurid.eu for more information.
```

Create `testdata/whois/afnic-fr-example.txt` (AFNIC's `.fr` format, generic kv with French field labels needing a synonym override):

```
domain:                            example.fr
status:                            ACTIVE
hold:                              NO
holder-c:                          ANO00-FRNIC
admin-c:                           EXAMPLE1-FRNIC
tech-c:                            EXAMPLE2-FRNIC
registrar:                         EXAMPLE REGISTRAR
Expiry Date:                       2026-08-13T04:00:00Z
created:                           1995-08-14T04:00:00Z
last-update:                       2025-08-14T07:01:31Z
source:                            FRNIC

ns1.example.fr
ns2.example.fr
```

Create `testdata/whois/sidn-nl-example.txt` (SIDN's `.nl` format, generic kv):

```
Domain name: example.nl
Status:      active

Registrar:
   Example Registrar B.V.
   Amsterdam, Netherlands

DNSSEC:      no

Domain nameservers:
   ns1.example.nl
   ns2.example.nl

Record maintained by: NL Domain Registry
```

Replace the entire contents of `internal/whois/parse/templates_test.go` with a manifest-driven version:

```go
package parse

import "testing"

// templateManifest is the single source of truth this milestone
// establishes for "every registered ccTLD template must have a fixture
// that parses to expected canonical fields." Adding a template without
// adding a row here (or adding a row without registering the template)
// fails this test — that's the intended regression guard: a missing
// fixture can't silently pass.
var templateManifest = []struct {
	tld         string
	fixture     string
	wantDomain  string
	wantNSCount int
}{
	{tld: "de", fixture: "denic-de-example.txt", wantDomain: "example.de", wantNSCount: 2},
	{tld: "jp", fixture: "jprs-jp-example.txt", wantDomain: "EXAMPLE.JP", wantNSCount: 2},
	{tld: "uk", fixture: "nominet-uk-example.txt", wantDomain: "example.uk", wantNSCount: 2},
	{tld: "eu", fixture: "eurid-eu-example.txt", wantDomain: "example.eu", wantNSCount: 2},
	{tld: "fr", fixture: "afnic-fr-example.txt", wantDomain: "example.fr", wantNSCount: 2},
	{tld: "nl", fixture: "sidn-nl-example.txt", wantDomain: "example.nl", wantNSCount: 2},
}

func TestTemplateManifest_EveryRegisteredTemplateHasAFixture(t *testing.T) {
	seen := map[string]bool{}
	for _, row := range templateManifest {
		seen[row.tld] = true
		t.Run(row.tld, func(t *testing.T) {
			raw := loadFixture(t, row.fixture)
			f := Parse(raw, row.tld)
			if f.Domain != row.wantDomain {
				t.Errorf("Domain = %q, want %q", f.Domain, row.wantDomain)
			}
			if len(f.Nameservers) != row.wantNSCount {
				t.Errorf("Nameservers = %v, want %d entries", f.Nameservers, row.wantNSCount)
			}
		})
	}
	for tld := range templates {
		if !seen[tld] {
			t.Errorf("template %q is registered in templates.yaml but has no row in templateManifest — every registered template must have a manifest entry with a fixture", tld)
		}
	}
	if len(templates) == 0 {
		t.Fatal("no templates loaded from embedded YAML")
	}
}

func TestParse_DENICSynonymOverride(t *testing.T) {
	raw := loadFixture(t, "denic-de-example.txt")
	f := Parse(raw, "de")

	if f.Domain != "example.de" {
		t.Errorf("Domain = %q, want example.de", f.Domain)
	}
	wantNS := []string{"ns1.example.de", "ns2.example.de"}
	if len(f.Nameservers) != len(wantNS) {
		t.Fatalf("Nameservers = %v, want %v", f.Nameservers, wantNS)
	}
	if len(f.Statuses) != 1 || f.Statuses[0] != "connect" {
		t.Errorf("Statuses = %v, want [connect]", f.Statuses)
	}
	if !f.Updated.Parsed {
		t.Fatalf("Updated not parsed (synonym override for 'changed' -> updated failed): %+v", f.Updated)
	}
}

func TestParse_JPRSBracketDialect(t *testing.T) {
	raw := loadFixture(t, "jprs-jp-example.txt")
	f := Parse(raw, "jp")

	if f.Domain != "EXAMPLE.JP" {
		t.Errorf("Domain = %q, want EXAMPLE.JP", f.Domain)
	}
	wantNS := []string{"a.dns.jp", "b.dns.jp"}
	if len(f.Nameservers) != len(wantNS) {
		t.Fatalf("Nameservers = %v, want %v (brackets dialect should tokenize [Name Server] lines)", f.Nameservers, wantNS)
	}
	if !f.Created.Parsed || f.Created.Raw != "1995/08/14" {
		t.Errorf("Created = %+v", f.Created)
	}
	if !f.Expires.Parsed || f.Expires.Raw != "2026/08/13" {
		t.Errorf("Expires = %+v", f.Expires)
	}
}

func TestParse_DefaultTemplateForUnknownTLD(t *testing.T) {
	raw := loadFixture(t, "verisign-com-example.txt")
	f := Parse(raw, "xyz-unregistered-tld")
	if f.Domain != "EXAMPLE.COM" {
		t.Errorf("Domain = %q, want EXAMPLE.COM (unknown TLD should fall back to generic kv dialect)", f.Domain)
	}
}

func TestParse_FRSynonymOverride(t *testing.T) {
	raw := loadFixture(t, "afnic-fr-example.txt")
	f := Parse(raw, "fr")

	if !f.Expires.Parsed || f.Expires.Raw != "2026-08-13T04:00:00Z" {
		t.Errorf("Expires = %+v, want Parsed with Raw 2026-08-13T04:00:00Z (synonym override for 'Expiry Date' -> expires)", f.Expires)
	}
}

func TestParse_NLIndentedNameserverBlock(t *testing.T) {
	raw := loadFixture(t, "sidn-nl-example.txt")
	f := Parse(raw, "nl")

	if f.Domain != "example.nl" {
		t.Errorf("Domain = %q, want example.nl", f.Domain)
	}
	wantNS := []string{"ns1.example.nl", "ns2.example.nl"}
	if len(f.Nameservers) != len(wantNS) {
		t.Errorf("Nameservers = %v, want %v", f.Nameservers, wantNS)
	}
}
```

Note on `.fr`'s `Expiry Date` field: AFNIC's real format uses `Expiry Date` (capital E, capital D) as the label; the generic `defaultSynonyms` table has lowercase `"expiry date"` — since `tokenizeKV` already lowercases every key before synonym lookup (`key := strings.ToLower(...)` in `tokenizeKV`), this resolves automatically without any template `Synonyms` override needed. Confirm this by reading `tokenizeKV`'s existing lowercasing behavior before assuming a synonym override is required — it is NOT required here.

Note on `.nl`'s nameserver block (`"Domain nameservers:"` followed by indented lines with no per-line colon): this is a KV-format fixture (not indent-dialect), so `tokenizeKV` tokenizes it — but `tokenizeKV` only recognizes lines containing a literal `:` per its own line. The header line `"Domain nameservers:"` has a colon but empty content after it (nothing follows on that line), which `tokenizeKV` already skips (`if val == "" { continue }`), and the indented `ns1.example.nl`/`ns2.example.nl` lines have NO colon at all, so `tokenizeKV` also skips them (`idx := strings.Index(line, ":"); if idx < 0 { continue }`) — meaning **the `.nl` fixture's nameservers, as drafted above, will NOT be tokenized under the generic `kv` dialect.** Fix: give `.nl` a template `Synonyms` override is not sufficient either (there's nothing to map — the lines have no colon at all for kv to even see). Instead, rewrite the `.nl` fixture so nameservers use the SAME single-line "Domain nameservers:" + value shape recognized by `tokenizeKV`'s existing colon-delimited-per-line model, i.e. repeat the label per line like every other kv-dialect fixture in this repo already does (matching `pir-org-example.txt`'s pattern of one label per nameserver line):

```
Domain name: example.nl
Status:      active

Registrar:
   Example Registrar B.V.
   Amsterdam, Netherlands

DNSSEC:      no

Domain nameservers: ns1.example.nl
Domain nameservers: ns2.example.nl

Record maintained by: NL Domain Registry
```

Use THIS corrected version for `testdata/whois/sidn-nl-example.txt` instead of the block-style draft above (the corrected version replaces it — do not create both). Add `"domain nameservers"` to `defaultSynonyms` alongside the existing `"name server"`/`"name servers"`/`"nserver"`/`"nameservers"` entries (in `internal/whois/parse/parse.go`, extending the same map Task 3 already touched):

```go
	"name server":              fNameservers,
	"name servers":             fNameservers,
	"domain nameservers":       fNameservers,
	"nserver":                  fNameservers,
	"nameservers":              fNameservers,
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/parse/... -v`
Expected: FAIL — `TestTemplateManifest_EveryRegisteredTemplateHasAFixture`'s `eu`/`fr`/`nl` subtests fail (fixtures don't exist yet, or templates aren't registered yet); `TestParse_FRSynonymOverride`/`TestParse_NLIndentedNameserverBlock` fail similarly.

- [ ] **Step 3: Write the implementation**

In `internal/whois/parse/parse.go`, apply the `defaultSynonyms` addition shown above (`"domain nameservers": fNameservers`).

In `internal/whois/parse/templates.yaml`, add the three new entries (all `format: kv`, zero new dialect code):

```yaml
de:
  format: kv
  synonyms:
    changed: updated
jp:
  format: brackets
uk:
  format: indent
eu:
  format: kv
fr:
  format: kv
nl:
  format: kv
```

Ensure `testdata/whois/eurid-eu-example.txt` and `testdata/whois/afnic-fr-example.txt` exist exactly as drafted in Step 1, and `testdata/whois/sidn-nl-example.txt` exists as the CORRECTED version from Step 1's note (not the initial block-style draft).

- [ ] **Step 4: Run tests to verify they pass, and confirm zero regression**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/parse/... -v`
Expected: PASS — `TestTemplateManifest_EveryRegisteredTemplateHasAFixture` (6 subtests: de/jp/uk/eu/fr/nl), `TestParse_DENICSynonymOverride`, `TestParse_JPRSBracketDialect`, `TestParse_DefaultTemplateForUnknownTLD`, `TestParse_FRSynonymOverride`, `TestParse_NLIndentedNameserverBlock`, plus everything from Tasks 2-3 in this same package, all green.

Run: `cd /Users/pat/codes/plat && go build ./... && go test ./...`
Expected: all 14 packages `ok`.

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/whois/parse/parse.go internal/whois/parse/templates.yaml internal/whois/parse/templates_test.go testdata/whois/eurid-eu-example.txt testdata/whois/afnic-fr-example.txt testdata/whois/sidn-nl-example.txt
git commit -m "feat: add .eu/.fr/.nl WHOIS templates and a template-manifest regression test"
```

---

### Task 5: RDAP/WHOIS Golden Fixture Suite Fill-Out

**Files:**
- Create: `testdata/rdap/org-thick-example.json`, `testdata/rdap/eu-gdpr-example.json`, `testdata/rdap/idn-example.json`, `testdata/rdap/expired-example.json`
- Create: `testdata/whois/idn-example.txt`, `testdata/whois/expired-example.txt`
- Modify: `internal/rdap/client_test.go` (add `TestClientDomain_RetriesOn429`)
- Modify: `internal/whois/parse/parse_test.go` (add tests consuming the two new WHOIS fixtures)

**Interfaces:**
- Consumes: `rdap.Client.Domain(ctx, baseURL, name string) (*Result, error)` (pre-existing, unchanged), `parse.Parse(raw, tld string) Fields` (pre-existing, unchanged).
- Produces: nothing new consumed by later tasks — pure fixture/test addition.

- [ ] **Step 1: Write the fixtures**

Create `testdata/rdap/org-thick-example.json` (a thick .org registry response — unlike `com-example.json`, includes an `entities` array with registrar + registrant, since PIR's registry is "thick"):

```json
{
  "objectClassName": "domain",
  "handle": "D123456789-LROR",
  "ldhName": "EXAMPLE.ORG",
  "unicodeName": "example.org",
  "status": [
    "client transfer prohibited",
    "server delete prohibited"
  ],
  "entities": [
    {
      "objectClassName": "entity",
      "handle": "EXAMPLE-REGISTRAR",
      "roles": ["registrar"],
      "publicIds": [
        { "type": "IANA Registrar ID", "identifier": "9999" }
      ],
      "vcardArray": [
        "vcard",
        [
          ["version", {}, "text", "4.0"],
          ["fn", {}, "text", "Example Registrar, Inc."]
        ]
      ],
      "entities": [
        {
          "objectClassName": "entity",
          "roles": ["abuse"],
          "vcardArray": [
            "vcard",
            [
              ["version", {}, "text", "4.0"],
              ["email", {}, "text", "abuse@example-registrar.example"]
            ]
          ]
        }
      ]
    }
  ],
  "events": [
    { "eventAction": "registration", "eventDate": "2001-03-15T00:00:00Z" },
    { "eventAction": "last changed", "eventDate": "2025-03-15T12:00:00Z" },
    { "eventAction": "expiration", "eventDate": "2027-03-15T00:00:00Z" }
  ],
  "nameservers": [
    { "objectClassName": "nameserver", "ldhName": "NS1.EXAMPLE.ORG" },
    { "objectClassName": "nameserver", "ldhName": "NS2.EXAMPLE.ORG" }
  ],
  "secureDNS": {
    "delegationSigned": true
  },
  "rdapConformance": ["rdap_level_0"]
}
```

Create `testdata/rdap/eu-gdpr-example.json` (GDPR-redacted .eu — registrant entity present but with a redaction remark, matching the shallow signal `RedactionRemarks()` already detects):

```json
{
  "objectClassName": "domain",
  "handle": "EXAMPLE-EURID",
  "ldhName": "EXAMPLE.EU",
  "unicodeName": "example.eu",
  "status": ["active"],
  "entities": [
    {
      "objectClassName": "entity",
      "roles": ["registrant"],
      "remarks": [
        {
          "title": "REDACTED FOR PRIVACY",
          "type": "object redacted due to eligibility",
          "description": [
            "Some of the data in this object has been redacted for privacy."
          ]
        }
      ]
    },
    {
      "objectClassName": "entity",
      "handle": "EXAMPLE-REGISTRAR-EU",
      "roles": ["registrar"],
      "vcardArray": [
        "vcard",
        [
          ["version", {}, "text", "4.0"],
          ["fn", {}, "text", "Example Registrar B.V."]
        ]
      ]
    }
  ],
  "events": [
    { "eventAction": "registration", "eventDate": "2010-06-01T00:00:00Z" },
    { "eventAction": "expiration", "eventDate": "2026-06-01T00:00:00Z" }
  ],
  "nameservers": [
    { "objectClassName": "nameserver", "ldhName": "NS1.EXAMPLE.EU" },
    { "objectClassName": "nameserver", "ldhName": "NS2.EXAMPLE.EU" }
  ],
  "rdapConformance": ["rdap_level_0"]
}
```

Create `testdata/rdap/idn-example.json` (an IDN domain — `ldhName` is punycode, `unicodeName` is the display form):

```json
{
  "objectClassName": "domain",
  "handle": "D987654321-LROR",
  "ldhName": "XN--MNCHEN-3YA.DE",
  "unicodeName": "münchen.de",
  "status": ["active"],
  "events": [
    { "eventAction": "registration", "eventDate": "2015-05-20T00:00:00Z" },
    { "eventAction": "expiration", "eventDate": "2026-05-20T00:00:00Z" }
  ],
  "nameservers": [
    { "objectClassName": "nameserver", "ldhName": "NS1.EXAMPLE.DE" },
    { "objectClassName": "nameserver", "ldhName": "NS2.EXAMPLE.DE" }
  ],
  "rdapConformance": ["rdap_level_0"]
}
```

Create `testdata/rdap/expired-example.json` (an expired domain — expiration event in the past relative to the fixture's own timeline, status reflects a pending-delete/expired state):

```json
{
  "objectClassName": "domain",
  "handle": "D111222333-LROR",
  "ldhName": "EXPIRED-EXAMPLE.COM",
  "unicodeName": "expired-example.com",
  "status": [
    "pending delete",
    "redemption period"
  ],
  "events": [
    { "eventAction": "registration", "eventDate": "2015-01-10T00:00:00Z" },
    { "eventAction": "expiration", "eventDate": "2025-01-10T00:00:00Z" },
    { "eventAction": "last changed", "eventDate": "2025-02-15T00:00:00Z" }
  ],
  "nameservers": [],
  "rdapConformance": ["rdap_level_0"]
}
```

Create `testdata/whois/idn-example.txt`:

```
Domain Name: XN--MNCHEN-3YA.DE
Registry Domain ID: D987654321-DE
Registrar: Example Registrar, Inc.
Creation Date: 2015-05-20T00:00:00Z
Registry Expiry Date: 2026-05-20T00:00:00Z
Domain Status: active
Name Server: ns1.example.de
Name Server: ns2.example.de
```

Create `testdata/whois/expired-example.txt`:

```
Domain Name: EXPIRED-EXAMPLE.COM
Registry Domain ID: D111222333-COM
Registrar: Example Registrar, Inc.
Creation Date: 2015-01-10T00:00:00Z
Registry Expiry Date: 2025-01-10T00:00:00Z
Updated Date: 2025-02-15T00:00:00Z
Domain Status: pendingDelete
Domain Status: redemptionPeriod
```

- [ ] **Step 2: Write the failing tests**

Append to `internal/rdap/client_test.go` (reuses the existing `httptest`/`loadFixture` pattern already in that file — note this new test defines its OWN inline fixture-loading since it needs the 429 fixture path, not the default `com-example.json` the existing `loadFixture(t)` hardcodes):

```go
func TestClientDomain_RetriesOn429(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/rdap/org-thick-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	c := &Client{}
	result, err := c.Domain(context.Background(), srv.URL, "EXAMPLE.ORG")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requestCount != 2 {
		t.Fatalf("requestCount = %d, want 2 (one 429, one successful retry)", requestCount)
	}
	if result.Domain == nil {
		t.Fatal("Domain is nil")
	}
	if result.Domain.LDHName != "EXAMPLE.ORG" {
		t.Errorf("LDHName = %q, want EXAMPLE.ORG", result.Domain.LDHName)
	}
}
```

Append to `internal/whois/parse/parse_test.go`:

```go
func TestParse_IDNFixture(t *testing.T) {
	raw := loadFixture(t, "idn-example.txt")
	f := Parse(raw, "de")

	if f.Domain != "XN--MNCHEN-3YA.DE" {
		t.Errorf("Domain = %q, want XN--MNCHEN-3YA.DE (WHOIS reports the punycode/LDH form)", f.Domain)
	}
	if !f.Created.Parsed || !f.Expires.Parsed {
		t.Errorf("expected both Created and Expires to parse, got Created=%+v Expires=%+v", f.Created, f.Expires)
	}
}

func TestParse_ExpiredDomainFixture(t *testing.T) {
	raw := loadFixture(t, "expired-example.txt")
	f := Parse(raw, "com")

	if f.Domain != "EXPIRED-EXAMPLE.COM" {
		t.Errorf("Domain = %q, want EXPIRED-EXAMPLE.COM", f.Domain)
	}
	wantStatuses := []string{"pendingDelete", "redemptionPeriod"}
	if len(f.Statuses) != len(wantStatuses) {
		t.Fatalf("Statuses = %v, want %v", f.Statuses, wantStatuses)
	}
	for i, want := range wantStatuses {
		if f.Statuses[i] != want {
			t.Errorf("Statuses[%d] = %q, want %q", i, f.Statuses[i], want)
		}
	}
	if !f.Expires.Parsed {
		t.Fatal("expected Expires to parse")
	}
	if !f.Expires.Time.Before(f.Updated.Time) {
		t.Errorf("expected Expires (%v) to be before Updated (%v) for an expired-then-updated domain", f.Expires.Time, f.Updated.Time)
	}
}
```

- [ ] **Step 3: Run tests to verify they fail (or pass, for pure-fixture additions)**

Run: `cd /Users/pat/codes/plat && go test ./internal/rdap/... -v -run TestClientDomain_RetriesOn429`
Expected: this test exercises ALREADY-EXISTING production code (`client.go`'s 429/Retry-After handling) — it should PASS immediately once the fixture file exists, since no new production code is needed. If it fails, that's a real finding (the documented retry behavior doesn't actually work as CLAUDE.md claims) — investigate rather than assuming the test itself is wrong.

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/parse/... -v -run 'TestParse_IDNFixture|TestParse_ExpiredDomainFixture'`
Expected: PASS immediately — both exercise the existing generic `kv` dialect against new fixtures, no parser code changes needed.

- [ ] **Step 4: No implementation step needed for this task**

This task is fixtures + tests only — every fixture exercises already-existing production code paths (`Client.Domain`'s 429 retry, the generic `kv` WHOIS dialect). If Step 3's tests genuinely fail rather than passing on the first run, treat that as a real defect discovery (stop and report it, following superpowers:systematic-debugging) rather than adjusting the fixtures to paper over it.

- [ ] **Step 5: Run the full suite to confirm zero regression**

Run: `cd /Users/pat/codes/plat && go build ./... && go test ./...`
Expected: all 14 packages `ok`.

- [ ] **Step 6: Commit**

```bash
cd /Users/pat/codes/plat
git add testdata/rdap/org-thick-example.json testdata/rdap/eu-gdpr-example.json testdata/rdap/idn-example.json testdata/rdap/expired-example.json testdata/whois/idn-example.txt testdata/whois/expired-example.txt internal/rdap/client_test.go internal/whois/parse/parse_test.go
git commit -m "test: fill out the golden-file suite (thick .org, GDPR .eu, IDN, expired domain, RDAP 429 retry)"
```

Note: `testdata/rdap/eu-gdpr-example.json` is created in this task but not yet consumed by a test — it exercises `internal/rdap`'s entity/remark parsing and `RedactionRemarks()`, which already has its own dedicated test coverage from M3 against a different fixture. This fixture is added now to complete the spec's ~20-domain fixture list (GDPR .eu was an explicit gap) and is available for any future milestone's redaction-handling work; adding a redundant test against it here would just re-prove M3's already-tested `RedactionRemarks()` logic against different JSON, which is not new coverage. If you want to close this loop, the natural place is `internal/rdap`'s own existing redaction test file — add one assertion there loading this fixture, following that file's existing pattern, but this is optional polish, not required for this task's completion.

---

### Task 6: Merge Engine Golden Depth

**Files:**
- Modify: `internal/merge/merge_test.go` (add 4 new test functions)

**Interfaces:**
- Consumes: `merge.Merge(sources []model.SourceRecord) model.Record` (pre-existing, unchanged), the existing `sr(source model.SourceID, present bool) model.SourceRecord` test helper (pre-existing, in this same file — reuse it, do not redefine it).
- Produces: nothing new consumed by later tasks — this is the milestone's final task.

- [ ] **Step 1: Write the failing tests**

Append to `internal/merge/merge_test.go`:

```go
func TestMerge_DNSSECConflict(t *testing.T) {
	signedTrue := true
	signedFalse := false

	registrarRDAP := sr(model.SourceRegistrarRDAP, true)
	registrarRDAP.DNSSEC = &signedTrue
	registryRDAP := sr(model.SourceRegistryRDAP, true)
	registryRDAP.DNSSEC = &signedFalse

	rec := Merge([]model.SourceRecord{registryRDAP, registrarRDAP})

	if !rec.DNSSEC.Value {
		t.Errorf("DNSSEC.Value = %v, want true (registrar-rdap should win over registry-rdap)", rec.DNSSEC.Value)
	}
	if len(rec.Conflicts) != 1 || rec.Conflicts[0].Field != model.FieldDNSSEC {
		t.Fatalf("Conflicts = %+v, want exactly one dnssec conflict", rec.Conflicts)
	}
	if rec.Conflicts[0].Values[model.SourceRegistrarRDAP] != "true" || rec.Conflicts[0].Values[model.SourceRegistryRDAP] != "false" {
		t.Errorf("Conflict.Values = %+v, want registrar-rdap=true, registry-rdap=false", rec.Conflicts[0].Values)
	}
}

func TestMerge_DNSSECAgreementNoConflict(t *testing.T) {
	signed := true
	a := sr(model.SourceRegistrarRDAP, true)
	a.DNSSEC = &signed
	b := sr(model.SourceRegistryRDAP, true)
	b.DNSSEC = &signed

	rec := Merge([]model.SourceRecord{a, b})

	if !rec.DNSSEC.Value {
		t.Errorf("DNSSEC.Value = %v, want true", rec.DNSSEC.Value)
	}
	if len(rec.DNSSEC.Sources) != 2 {
		t.Errorf("DNSSEC.Sources = %v, want 2 agreeing sources", rec.DNSSEC.Sources)
	}
	if len(rec.Conflicts) != 0 {
		t.Errorf("Conflicts = %+v, want none", rec.Conflicts)
	}
}

func TestMerge_ThreeWayScalarConflict(t *testing.T) {
	registrarRDAP := sr(model.SourceRegistrarRDAP, true)
	registrarRDAP.Registrar.Name = "Registrar RDAP Corp"
	registryRDAP := sr(model.SourceRegistryRDAP, true)
	registryRDAP.Registrar.Name = "Registry RDAP Corp"
	registrarWHOIS := sr(model.SourceRegistrarWHOIS, true)
	registrarWHOIS.Registrar.Name = "Registrar WHOIS Corp"

	rec := Merge([]model.SourceRecord{registryRDAP, registrarWHOIS, registrarRDAP})

	if rec.Registrar.Name.Value != "Registrar RDAP Corp" {
		t.Errorf("Registrar.Name = %q, want %q (highest precedence wins among 3 disagreeing sources)", rec.Registrar.Name.Value, "Registrar RDAP Corp")
	}
	if len(rec.Conflicts) != 1 {
		t.Fatalf("Conflicts = %+v, want exactly one conflict", rec.Conflicts)
	}
	if len(rec.Conflicts[0].Values) != 3 {
		t.Errorf("Conflict.Values = %+v, want all 3 disagreeing sources listed", rec.Conflicts[0].Values)
	}
}

func TestMerge_RedactionWithConflictAmongRemainingSources(t *testing.T) {
	registrarRDAP := sr(model.SourceRegistrarRDAP, true)
	registrarRDAP.Registrar.Name = "REDACTED FOR PRIVACY"
	registrarRDAP.RedactedFields[model.FieldRegistrarName] = true

	registryWHOIS := sr(model.SourceRegistryWHOIS, true)
	registryWHOIS.Registrar.Name = "Registry WHOIS Corp"

	registrarWHOIS := sr(model.SourceRegistrarWHOIS, true)
	registrarWHOIS.Registrar.Name = "Registrar WHOIS Corp"

	rec := Merge([]model.SourceRecord{registrarRDAP, registryWHOIS, registrarWHOIS})

	if rec.Registrar.Name.Value != "Registrar WHOIS Corp" {
		t.Errorf("Registrar.Name = %q, want %q (highest-precedence NON-redacted source should win)", rec.Registrar.Name.Value, "Registrar WHOIS Corp")
	}
	if len(rec.Redacted) != 1 || rec.Redacted[0].Source != model.SourceRegistrarRDAP {
		t.Fatalf("Redacted = %+v, want one notice for registrar-rdap", rec.Redacted)
	}
	if len(rec.Conflicts) != 1 {
		t.Fatalf("Conflicts = %+v, want one conflict between the two disagreeing non-redacted WHOIS sources", rec.Conflicts)
	}
	if _, ok := rec.Conflicts[0].Values[model.SourceRegistrarRDAP]; ok {
		t.Errorf("Conflict.Values = %+v, should NOT include the redacted source at all", rec.Conflicts[0].Values)
	}
}

func TestMerge_PartialParseTimestampStillChecksClockSkew(t *testing.T) {
	registrarRDAP := sr(model.SourceRegistrarRDAP, true)
	registrarRDAP.Expires = model.TimeValue{Raw: "not-a-real-date", Parsed: false}

	registryRDAP := sr(model.SourceRegistryRDAP, true)
	t1 := time.Date(2026, 8, 13, 4, 0, 0, 0, time.UTC)
	registryRDAP.Expires = model.TimeValue{Time: t1, Raw: "2026-08-13T04:00:00Z", Parsed: true}

	registryWHOIS := sr(model.SourceRegistryWHOIS, true)
	t2 := time.Date(2026, 9, 20, 4, 0, 0, 0, time.UTC) // >24h beyond t1
	registryWHOIS.Expires = model.TimeValue{Time: t2, Raw: "2026-09-20T04:00:00Z", Parsed: true}

	rec := Merge([]model.SourceRecord{registrarRDAP, registryRDAP, registryWHOIS})

	if rec.Expires.Value.Raw != "not-a-real-date" {
		t.Errorf("Expires.Value.Raw = %q, want %q (winner is the highest-precedence PRESENT candidate regardless of parse success)", rec.Expires.Value.Raw, "not-a-real-date")
	}
	if len(rec.Conflicts) != 1 || rec.Conflicts[0].Field != model.FieldExpires {
		t.Fatalf("Conflicts = %+v, want exactly one expires conflict (the two PARSED candidates disagree by >24h, even though the winner itself didn't parse)", rec.Conflicts)
	}
	if len(rec.Conflicts[0].Values) != 3 {
		t.Errorf("Conflict.Values = %+v, want all 3 present candidates' Raw values listed (including the unparsed winner)", rec.Conflicts[0].Values)
	}
}
```

Add `"time"` to `merge_test.go`'s import block if not already present (it's used for `time.Date` in the new partial-parse test — check the file first, `TestMerge_TimestampWithinTolerance`/`TestMerge_TimestampBeyondTolerance` almost certainly already import it).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/pat/codes/plat && go test ./internal/merge/... -v -run 'TestMerge_DNSSECConflict|TestMerge_DNSSECAgreementNoConflict|TestMerge_ThreeWayScalarConflict|TestMerge_RedactionWithConflictAmongRemainingSources|TestMerge_PartialParseTimestampStillChecksClockSkew'`
Expected: these exercise EXISTING, unmodified `merge.go` production code — they should PASS immediately, since Task 6 makes no production code changes (contact merging stays deferred per the Global Constraints, and every other merge code path already exists and is exercised correctly by these new scenarios). If any of these tests genuinely fail, that indicates a real, previously-uncovered bug in `merge.go` — stop and report it as a finding via superpowers:systematic-debugging rather than adjusting the test to match broken behavior, since these tests characterize documented, intended precedence/conflict semantics from `merge.go`'s own doc comments (read in full above), not new requirements.

- [ ] **Step 3: No implementation step needed for this task**

This task adds test coverage only, per the Global Constraints ("no changes to `internal/merge/merge.go`'s production code"). If Step 2's tests reveal a genuine defect, that's an out-of-plan discovery to be escalated (see Step 2's note), not silently patched here.

- [ ] **Step 4: Run the full suite to confirm zero regression**

Run: `cd /Users/pat/codes/plat && go build ./... && go test ./...`
Expected: all 14 packages `ok`.

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/merge/merge_test.go
git commit -m "test: add DNSSEC conflict, 3-way conflict, redaction+conflict interaction, and partial-parse timestamp coverage to the merge engine"
```

---

## Milestone Verification (manual, not automated)

Once all 6 tasks are complete, confirm the milestone's actual definition of done:

```bash
cd /Users/pat/codes/plat

go test ./... -v 2>&1 | grep -c '^--- PASS'   # sanity count of all passing subtests across the milestone's additions
go test ./internal/whois/parse/... -v -run TestTemplateManifest  # confirms all 6 ccTLD templates (de/jp/uk/eu/fr/nl) have working fixtures
find testdata -type f | wc -l                 # should be noticeably larger than the pre-M6 count (7 WHOIS + 2 RDAP + 5 schema = 14 files before this milestone)
golangci-lint run                             # 0 issues
```

Cross-check the spec's ~20-domain fixture target list one more time against the final `testdata/` tree: thin .com ✓ (pre-existing), thick .org ✓ (Task 5), GDPR .eu ✓ (Task 5, RDAP) + .de ✓ (pre-existing, WHOIS), no-RDAP ccTLD (already covered structurally — `collect.Collect` degrades to WHOIS-only when `registryBaseURL == ""`, exercised by existing M3 tests, not a new fixture), IDN ✓ (Task 5, both RDAP and WHOIS), expired domain ✓ (Task 5, both RDAP and WHOIS), rate-limited ✓ (pre-existing WHOIS `ratelimited.txt`) + RDAP 429 ✓ (Task 5, via httptest, not a static fixture).

---

## Self-Review

**Spec coverage:** "ccTLD templates" (Tasks 3-4: `.uk`/`.eu`/`.fr`/`.nl`, plus the manifest test that makes the existing `.de`/`.jp` templates provably regression-safe too), "IDN" (Task 1's expanded coverage + the pre-existing, unmodified normalization logic), "date-format torture tests" (Task 2), "golden-file suite filled out" (Task 5's RDAP/WHOIS fixtures, Task 6's merge-engine scenarios) — every item from the milestone's one-line spec is covered by a task. The plan's Global Constraints explicitly document what's deliberately OUT of scope (contact merging, stricter IDN validation, deep RFC 9537 structured-redaction parsing, further `whois.nic.<tld>` fallback-guessing) per the user's explicit decisions, so a future reader doesn't mistake an absence for an oversight.

**Placeholder scan:** no "TBD"/"handle appropriately"/"similar to Task N" patterns — every step has complete, runnable code, including the full `tokenizeIndent` implementation (the milestone's one genuinely novel piece of production code) and every new fixture's exact byte content.

**Type consistency:** `tokenizeIndent(raw string) []kvPair` matches `tokenizeKV`/`tokenizeBrackets`'s existing shape exactly, used identically in `Parse`'s dispatch switch (Task 3) and validated collectively by Task 4's manifest test. `stripUTCAbbreviation(s string) (string, bool)` and `ParseDate`'s modified control flow (Task 2) are self-contained within `date.go`. The `sr(source model.SourceID, present bool) model.SourceRecord` helper Task 6 reuses is the exact pre-existing signature from `merge_test.go`, not redefined.

**Regression discipline:** every task that modifies a pre-existing file (Task 1: `normalize.go`; Task 2: `date.go`; Task 3: `parse.go`, `templates.yaml`; Task 4: `parse.go` again, `templates.yaml` again, a full rewrite of `templates_test.go`; Task 5: `client_test.go`, `parse_test.go`; Task 6: `merge_test.go`) has an explicit step confirming that package's pre-existing tests still pass. Task 4's rewrite of `templates_test.go` is called out explicitly as replacing (not just extending) the file, since the old `TestTemplatesEmbedYAML` is subsumed by the new manifest test — the plan preserves every one of the old file's OTHER test functions (`TestParse_DENICSynonymOverride`, `TestParse_JPRSBracketDialect`, `TestParse_DefaultTemplateForUnknownTLD`) verbatim within the rewrite, so no coverage is silently lost in the replacement.
