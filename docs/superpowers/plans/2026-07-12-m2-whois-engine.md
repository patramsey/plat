# M2 — WHOIS Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone WHOIS engine — a port-43 client that chases IANA → registry → registrar referrals, with a data-driven per-server quirks table and a tolerant, data-driven generic parser — demoable via a hidden `plat whois <domain>` subcommand.

**Architecture:** Two new packages: `internal/whois/parse` (pure, offline, zero I/O — raw text + TLD in, normalized `Fields` out) and `internal/whois` (all networking/orchestration, imports `parse`). Neither imports `internal/rdap`; there is no shared model yet — that's M3.

**Tech Stack:** Go 1.25 stdlib (`net`, `context`, `text/tabwriter`, `regexp`), `gopkg.in/yaml.v3` (new dependency, for embedded per-registry parser templates).

## Global Constraints

- M2 is WHOIS only. Do NOT build the merge engine, unified `Record`/`Field[T]`/provenance model, or registrar RDAP `related`-link following — those are M3. `internal/whois` and `internal/whois/parse` must have zero imports of `internal/rdap`. Do not create `internal/model` or `internal/merge`.
- Package layout: `internal/whois/{quirks.go, client.go, result.go, referral.go}` + `_test.go` for each, plus `live_test.go` (`//go:build live`). `internal/whois/parse/{date.go, parse.go, templates.go, templates.yaml}` + `_test.go` for each. `testdata/whois/*.txt` fixtures. `cmd/plat/whois.go`.
- New dependency: `gopkg.in/yaml.v3`, added via `go get gopkg.in/yaml.v3`.
- Dependency direction is strict: `internal/whois/parse` does zero I/O and never imports `internal/whois`. `internal/whois` owns all networking and imports `internal/whois/parse` and `internal/domain`.
- Quirks (query construction) are a typed Go table in `internal/whois/quirks.go`, matched by WHOIS-server-hostname suffix — not YAML. Exactly 3 entries for M2: Verisign (`verisign-grs.com` → prefix `"domain "`), JPRS (`jprs.jp` → suffix `"/e"`), DENIC (`denic.de` → prefix `"-T dn,ace "`). The long tail is M6's job, not M2's — do not add more.
- Parser templates (field-mapping overrides) are embedded YAML (`internal/whois/parse/templates.yaml`, `go:embed`), keyed by TLD. M2 ships the generic engine + the override mechanism + exactly 2 real templates: `.de` (a synonym-only override) and `.jp` (a distinct "brackets" tokenizer dialect). The full ~15-ccTLD template table is explicitly M6's job ("ccTLD templates") — do not build more templates now.
- Date parsing (`internal/whois/parse/date.go`) is intentionally **not** shared with `internal/rdap`'s `RDAPTime` — WHOIS needs a much wider format list (month names, slash/dot dates) than RDAP's ISO-ish JSON dates, and sharing would couple this package to `internal/rdap`. A future `internal/timex` extraction is possible but out of scope now.
- Status extraction strips only the appended ICANN reference URL from `Domain Status:` lines (keep the first whitespace-delimited token). Full EPP cross-vocabulary normalization between RDAP and WHOIS spellings is M3's model-layer concern.
- `Result`/`Fields` are per-hop, package-scoped, standalone types — not the shared model. No cross-hop precedence merging. `Result.Deepest()` is a "last successful hop" convenience, explicitly not provenance/precedence merge logic — document it as such in the doc comment.
- A hop erroring is normal, not fatal. `Lookup` always records the IANA hop; proceeds to the registry hop only if the IANA hop succeeded and yielded a non-empty `Refer`; proceeds to the registrar hop only if the registry hop succeeded and yielded a non-empty `RegistrarWHOISServer`. `Lookup` returns a non-nil error only if every attempted hop has `Err != nil`.
- If the IANA hop yields no `refer:` line, M2 stops there — no `whois.nic.<tld>` fallback-guessing table. That heuristic is deferred to M6.
- The demo subcommand `plat whois <domain>` is `Hidden: true` (off `--help`), reuses the existing `usageError`/`exitCode` machinery from `cmd/plat/main.go`, and must NOT import or reuse `internal/render/plain` (that renderer is rdap-typed).
- Automated tests are fully offline — the referral-chasing/timeout/rate-limit tests use real local `net.Listener`s on `127.0.0.1:0`, never real network access. `live_test.go` (`//go:build live`) is excluded from the default `go test ./...` and from CI.
- Existing M1 code (`cmd/plat` cobra wiring + exit codes, `internal/domain.Normalize`, `internal/rdap`, `internal/render/plain`) is not modified except for the one addition to `cmd/plat/main.go` wiring in the `whois` subcommand (Task 8).

---

### Task 1: `internal/whois/parse` — Tolerant Date Parser

**Files:**
- Create: `internal/whois/parse/date.go`
- Test: `internal/whois/parse/date_test.go`

**Interfaces:**
- Consumes: nothing beyond stdlib.
- Produces: `type Date struct{ Raw string; Time time.Time; Parsed bool }`, `func ParseDate(s string) Date` — consumed by `internal/whois/parse/parse.go` (Task 2).

- [ ] **Step 1: Write the failing test**

Write `internal/whois/parse/date_test.go`:
```go
package parse

import (
	"strings"
	"testing"
	"time"
)

func TestParseDate(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantParsed bool
		wantUTC    string
	}{
		{"RFC3339 with zone", "2026-07-12T10:00:00Z", true, "2026-07-12T10:00:00Z"},
		{"RFC3339Nano", "2026-07-12T10:00:00.123456Z", true, "2026-07-12T10:00:00Z"},
		{"no zone assumed UTC", "2026-07-12T10:00:00", true, "2026-07-12T10:00:00Z"},
		{"space instead of T with zone", "2026-07-12 10:00:00Z", true, "2026-07-12T10:00:00Z"},
		{"space no zone", "2026-07-12 10:00:00", true, "2026-07-12T10:00:00Z"},
		{"date only", "2026-07-12", true, "2026-07-12T00:00:00Z"},
		{"legacy dash-month-dash lowercase", "14-aug-1995", true, "1995-08-14T00:00:00Z"},
		{"legacy dash-month-dash titlecase", "14-Aug-1995", true, "1995-08-14T00:00:00Z"},
		{"slash form (.jp)", "2026/07/12", true, "2026-07-12T00:00:00Z"},
		{"dot form", "2026.07.12", true, "2026-07-12T00:00:00Z"},
		{"day.month.year dot form", "12.07.2026", true, "2026-07-12T00:00:00Z"},
		{"verbose month name", "August 14, 1995", true, "1995-08-14T00:00:00Z"},
		{"verbose month name lowercase", "august 14, 1995", true, "1995-08-14T00:00:00Z"},
		{"weekday month day year", "Wed Aug 14 2025", true, "2025-08-14T00:00:00Z"},
		{"garbage never errors", "not-a-date", false, ""},
		{"empty string", "", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseDate(tt.input)
			wantRaw := strings.TrimSpace(tt.input)
			if got.Raw != wantRaw {
				t.Errorf("Raw = %q, want %q", got.Raw, wantRaw)
			}
			if got.Parsed != tt.wantParsed {
				t.Errorf("Parsed = %v, want %v (input %q)", got.Parsed, tt.wantParsed, tt.input)
			}
			if tt.wantParsed && got.Time.Format(time.RFC3339) != tt.wantUTC {
				t.Errorf("Time = %v, want %v", got.Time.Format(time.RFC3339), tt.wantUTC)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/parse/... -v`
Expected: FAIL — build error, `undefined: ParseDate`.

- [ ] **Step 3: Write the implementation**

Write `internal/whois/parse/date.go`:
```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/parse/... -v`
Expected: PASS, all 16 subtests green.

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/whois/parse/date.go internal/whois/parse/date_test.go
git commit -m "feat: add tolerant WHOIS date parser"
```

---

### Task 2: `internal/whois/parse` — Generic Key/Value Parser

**Files:**
- Create: `internal/whois/parse/parse.go`
- Create: `testdata/whois/verisign-com-example.txt`
- Create: `testdata/whois/pir-org-example.txt`
- Create: `testdata/whois/ratelimited.txt`
- Test: `internal/whois/parse/parse_test.go`

**Interfaces:**
- Consumes: `Date`, `ParseDate` from Task 1 (same package).
- Produces: `type Fields struct{ Domain, Registrar, RegistrarWHOISServer, Refer string; Statuses, Nameservers []string; Created, Updated, Expires Date; RateLimited bool; Unmapped map[string][]string }`, `func Parse(raw, tld string) Fields` — consumed by `internal/whois/referral.go` (Task 6). This task's `Parse` uses only the generic `kv` tokenizer and the default synonym table; Task 3 adds template-aware dialect selection and synonym overrides on top of this same function.

- [ ] **Step 1: Create the fixtures**

Write `testdata/whois/verisign-com-example.txt`:
```
   Domain Name: EXAMPLE.COM
   Registry Domain ID: 2336799_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.example-registrar.example
   Registrar URL: http://www.example-registrar.example
   Updated Date: 2025-08-14T07:01:31Z
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: 2026-08-13T04:00:00Z
   Registrar: Example Registrar, Inc.
   Registrar IANA ID: 1234
   Registrar Abuse Contact Email: abuse@example-registrar.example
   Registrar Abuse Contact Phone: +1.5555550100
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
   Name Server: A.IANA-SERVERS.NET
   Name Server: B.IANA-SERVERS.NET
   DNSSEC: unsigned
>>> Last update of WHOIS database: 2026-07-12T09:15:00Z <<<
```

Write `testdata/whois/pir-org-example.txt`:
```
Domain Name: EXAMPLE.ORG
Registry Domain ID: D12345678-LROR
Registrar WHOIS Server: whois.example-registrar.example
Registrar URL: http://www.example-registrar.example
Updated Date: 2025-11-02T10:15:00Z
Creation Date: 1998-03-20T00:00:00Z
Registry Expiry Date: 2026-03-20T00:00:00Z
Registrar: Example Registrar, Inc.
Registrar IANA ID: 1234
Registrant Organization: Example Nonprofit Org
Registrant Country: US
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Name Server: NS1.EXAMPLE.ORG
Name Server: NS2.EXAMPLE.ORG
DNSSEC: signedDelegation
```

Write `testdata/whois/ratelimited.txt`:
```
% This query returned too many results.
%
% Your request has exceeded the query rate limit for this WHOIS server.
% Query rate limit exceeded. Please wait and try again later.
```

- [ ] **Step 2: Write the failing test**

Write `internal/whois/parse/parse_test.go`:
```go
package parse

import (
	"os"
	"testing"
)

func loadFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../../testdata/whois/" + name)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return string(b)
}

func TestParse_ThinComRegistry(t *testing.T) {
	raw := loadFixture(t, "verisign-com-example.txt")
	f := Parse(raw, "com")

	if f.Domain != "EXAMPLE.COM" {
		t.Errorf("Domain = %q, want EXAMPLE.COM", f.Domain)
	}
	if f.Registrar != "Example Registrar, Inc." {
		t.Errorf("Registrar = %q", f.Registrar)
	}
	if f.RegistrarWHOISServer != "whois.example-registrar.example" {
		t.Errorf("RegistrarWHOISServer = %q", f.RegistrarWHOISServer)
	}
	wantStatuses := []string{"clientTransferProhibited", "clientUpdateProhibited"}
	if len(f.Statuses) != len(wantStatuses) {
		t.Fatalf("Statuses = %v, want %v", f.Statuses, wantStatuses)
	}
	for i, s := range wantStatuses {
		if f.Statuses[i] != s {
			t.Errorf("Statuses[%d] = %q, want %q (ICANN URL should be stripped)", i, f.Statuses[i], s)
		}
	}
	wantNS := []string{"A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"}
	if len(f.Nameservers) != len(wantNS) {
		t.Fatalf("Nameservers = %v, want %v", f.Nameservers, wantNS)
	}
	if !f.Created.Parsed || f.Created.Raw != "1995-08-14T04:00:00Z" {
		t.Errorf("Created = %+v", f.Created)
	}
	if !f.Expires.Parsed || f.Expires.Raw != "2026-08-13T04:00:00Z" {
		t.Errorf("Expires = %+v", f.Expires)
	}
	if f.RateLimited {
		t.Error("RateLimited = true, want false")
	}
}

func TestParse_ThickOrgRegistry(t *testing.T) {
	raw := loadFixture(t, "pir-org-example.txt")
	f := Parse(raw, "org")

	if f.Domain != "EXAMPLE.ORG" {
		t.Errorf("Domain = %q, want EXAMPLE.ORG", f.Domain)
	}
	if f.Registrar != "Example Registrar, Inc." {
		t.Errorf("Registrar = %q", f.Registrar)
	}
	if len(f.Nameservers) != 2 {
		t.Errorf("Nameservers = %v, want 2 entries", f.Nameservers)
	}
	if !f.Created.Parsed {
		t.Errorf("Created not parsed: %+v", f.Created)
	}
}

func TestParse_RateLimited(t *testing.T) {
	raw := loadFixture(t, "ratelimited.txt")
	f := Parse(raw, "com")
	if !f.RateLimited {
		t.Error("RateLimited = false, want true")
	}
}

func TestParse_UnmappedFieldsRetained(t *testing.T) {
	raw := loadFixture(t, "verisign-com-example.txt")
	f := Parse(raw, "com")
	if _, ok := f.Unmapped["registrar iana id"]; !ok {
		t.Errorf("expected 'registrar iana id' in Unmapped, got %v", f.Unmapped)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/parse/... -v`
Expected: FAIL — build error, `undefined: Fields` / `undefined: Parse`.

- [ ] **Step 4: Write the implementation**

Write `internal/whois/parse/parse.go`:
```go
package parse

import "strings"

// Fields is a normalized, package-scoped view of one raw WHOIS response.
// It intentionally does not model contacts/registrant details or perform
// cross-vocabulary EPP status normalization — both are the shared model's
// job in a later milestone.
type Fields struct {
	Domain               string
	Registrar            string
	RegistrarWHOISServer string
	Refer                string
	Statuses             []string
	Nameservers          []string
	Created              Date
	Updated              Date
	Expires              Date
	RateLimited          bool
	Unmapped             map[string][]string
}

type kvPair struct{ key, val string }

const (
	fDomain               = "domain"
	fRegistrar            = "registrar"
	fRegistrarWHOISServer = "registrarwhoisserver"
	fRefer                = "refer"
	fStatus               = "status"
	fNameservers          = "nameservers"
	fCreated              = "created"
	fUpdated              = "updated"
	fExpires              = "expires"
)

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

var rateLimitMarkers = []string{
	"query rate limit exceeded",
	"exceeded query limit",
	"too many requests",
	"quota exceeded",
}

// tokenizeKV handles the default "Key: value" dialect used by most
// registries (thin .com-style, thick .org-style, IANA's own format).
// Lines starting with "%" or "#" are comments and skipped.
func tokenizeKV(raw string) []kvPair {
	var out []kvPair
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])
		if val == "" {
			continue
		}
		out = append(out, kvPair{key, val})
	}
	return out
}

func firstToken(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// Parse extracts normalized Fields from a raw WHOIS response for tld.
func Parse(raw, tld string) Fields {
	pairs := tokenizeKV(raw)

	f := Fields{Unmapped: map[string][]string{}}

	lowerRaw := strings.ToLower(raw)
	for _, marker := range rateLimitMarkers {
		if strings.Contains(lowerRaw, marker) {
			f.RateLimited = true
			break
		}
	}

	for _, p := range pairs {
		canon, ok := defaultSynonyms[p.key]
		if !ok {
			f.Unmapped[p.key] = append(f.Unmapped[p.key], p.val)
			continue
		}
		switch canon {
		case fDomain:
			f.Domain = p.val
		case fRegistrar:
			f.Registrar = p.val
		case fRegistrarWHOISServer:
			f.RegistrarWHOISServer = p.val
		case fRefer:
			f.Refer = p.val
		case fStatus:
			f.Statuses = append(f.Statuses, firstToken(p.val))
		case fNameservers:
			f.Nameservers = append(f.Nameservers, p.val)
		case fCreated:
			f.Created = ParseDate(p.val)
		case fUpdated:
			f.Updated = ParseDate(p.val)
		case fExpires:
			f.Expires = ParseDate(p.val)
		}
	}
	return f
}
```

Note: `tld` is unused by this task's implementation (Task 3 wires it into template selection). Go does not error on an unused function parameter, only unused local variables/imports, so this compiles cleanly as-is.

- [ ] **Step 5: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/parse/... -v`
Expected: PASS, all subtests in `date_test.go` and `parse_test.go` green.

- [ ] **Step 6: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/whois/parse/parse.go testdata/whois/verisign-com-example.txt testdata/whois/pir-org-example.txt testdata/whois/ratelimited.txt internal/whois/parse/parse_test.go
git commit -m "feat: add generic WHOIS key/value parser"
```

---

### Task 3: `internal/whois/parse` — Per-Registry Templates (YAML)

**Files:**
- Create: `internal/whois/parse/templates.go`
- Create: `internal/whois/parse/templates.yaml`
- Create: `testdata/whois/denic-de-example.txt`
- Create: `testdata/whois/jprs-jp-example.txt`
- Modify: `internal/whois/parse/parse.go` (add the `brackets` tokenizer and template-aware dialect/synonym selection to `Parse`)
- Test: `internal/whois/parse/templates_test.go`
- Test: extend `internal/whois/parse/parse_test.go`

**Interfaces:**
- Consumes: `Fields`, `Parse`, `defaultSynonyms`, `tokenizeKV` from Task 2 (same package).
- Produces: `type Template struct{ Format string; Synonyms map[string]string }`, `func templateFor(tld string) Template` (unexported — internal to the package), and the template-aware `Parse` — consumed by `internal/whois/referral.go` (Task 6) only through the already-established `Parse(raw, tld string) Fields` signature (unchanged from Task 2's signature).

- [ ] **Step 1: Add the yaml.v3 dependency**

Run:
```bash
cd /Users/pat/codes/plat && go get gopkg.in/yaml.v3
```
Expected: succeeds, adds a `require` line to `go.mod` and entries to `go.sum`.

- [ ] **Step 2: Create the fixtures**

Write `testdata/whois/denic-de-example.txt`:
```
Domain: example.de
Nserver: ns1.example.de
Nserver: ns2.example.de
Status: connect
Changed: 2025-08-14T07:01:31+02:00
```

Write `testdata/whois/jprs-jp-example.txt`:
```
[Domain Name]                  EXAMPLE.JP

[Registrant]                   Example Corp

[Name Server]                  a.dns.jp
[Name Server]                  b.dns.jp
[Status]                       Active
[Created on]                   1995/08/14
[Expires on]                   2026/08/13
[Last Updated]                 2025/08/14
```

- [ ] **Step 3: Write the embedded template data**

Write `internal/whois/parse/templates.yaml`:
```yaml
de:
  format: kv
  synonyms:
    changed: updated
jp:
  format: brackets
```

Note: `.de`'s only override is `changed -> updated` — DENIC's `Changed:` key isn't in the generic default synonym table, so this proves the synonym-override mechanism. `.jp` needs no synonym overrides at all — its bracketed keys (`domain name`, `name server`, `status`, `created on`, `expires on`) already match the generic default table once tokenized; only the `format: brackets` tokenizer-dialect selector is needed, proving that axis independently.

- [ ] **Step 4: Write the failing test**

Write `internal/whois/parse/templates_test.go`:
```go
package parse

import "testing"

func TestTemplatesEmbedYAML(t *testing.T) {
	if len(templates) == 0 {
		t.Fatal("no templates loaded from embedded YAML")
	}
	if _, ok := templates["de"]; !ok {
		t.Error(`expected "de" template to be registered`)
	}
	if _, ok := templates["jp"]; !ok {
		t.Error(`expected "jp" template to be registered`)
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
```

- [ ] **Step 5: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/parse/... -v`
Expected: FAIL — build error, `undefined: templates` / the `.de`/`.jp` assertions fail since `Parse` doesn't consult templates yet.

- [ ] **Step 6: Write the implementation**

Write `internal/whois/parse/templates.go`:
```go
package parse

import (
	_ "embed"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed templates.yaml
var templatesYAML []byte

// Template describes per-TLD overrides to the generic parsing engine: an
// alternate line-tokenizer dialect and/or extra synonym-table entries.
// The zero Template (empty Format, nil Synonyms) means "use the generic
// kv dialect with no overrides."
type Template struct {
	Format   string            `yaml:"format"`
	Synonyms map[string]string `yaml:"synonyms"`
}

var templates map[string]Template

func init() {
	if err := yaml.Unmarshal(templatesYAML, &templates); err != nil {
		panic("parse: embedded templates.yaml is invalid: " + err.Error())
	}
}

// templateFor returns the template registered for tld, or the zero
// Template if none is registered. This only fails (panics, at init time)
// if the embedded templates.yaml itself is malformed — a build-time
// asset, not runtime input, so a panic on invalid embedded data is
// deliberate rather than plumbing an error through every caller.
func templateFor(tld string) Template {
	return templates[strings.ToLower(tld)]
}
```

Modify `internal/whois/parse/parse.go` — add the brackets tokenizer and wire template-aware dialect/synonym selection into `Parse`. Replace the existing `Parse` function body with:
```go
// Parse extracts normalized Fields from a raw WHOIS response for tld,
// applying tld's template (dialect + synonym overrides) if one is
// registered in templates.yaml.
func Parse(raw, tld string) Fields {
	tmpl := templateFor(tld)

	var pairs []kvPair
	if tmpl.Format == "brackets" {
		pairs = tokenizeBrackets(raw)
	} else {
		pairs = tokenizeKV(raw)
	}

	synonyms := defaultSynonyms
	if len(tmpl.Synonyms) > 0 {
		merged := make(map[string]string, len(defaultSynonyms)+len(tmpl.Synonyms))
		for k, v := range defaultSynonyms {
			merged[k] = v
		}
		for k, v := range tmpl.Synonyms {
			merged[k] = v
		}
		synonyms = merged
	}

	f := Fields{Unmapped: map[string][]string{}}

	lowerRaw := strings.ToLower(raw)
	for _, marker := range rateLimitMarkers {
		if strings.Contains(lowerRaw, marker) {
			f.RateLimited = true
			break
		}
	}

	for _, p := range pairs {
		canon, ok := synonyms[p.key]
		if !ok {
			f.Unmapped[p.key] = append(f.Unmapped[p.key], p.val)
			continue
		}
		switch canon {
		case fDomain:
			f.Domain = p.val
		case fRegistrar:
			f.Registrar = p.val
		case fRegistrarWHOISServer:
			f.RegistrarWHOISServer = p.val
		case fRefer:
			f.Refer = p.val
		case fStatus:
			f.Statuses = append(f.Statuses, firstToken(p.val))
		case fNameservers:
			f.Nameservers = append(f.Nameservers, p.val)
		case fCreated:
			f.Created = ParseDate(p.val)
		case fUpdated:
			f.Updated = ParseDate(p.val)
		case fExpires:
			f.Expires = ParseDate(p.val)
		}
	}
	return f
}
```

Add the brackets tokenizer to `internal/whois/parse/parse.go` (near `tokenizeKV`), and add `"regexp"` to its import block:
```go
// tokenizeBrackets handles JPRS-style "[Key]    value" lines.
var bracketLine = regexp.MustCompile(`^\[([^\]]+)\]\s*(.*)$`)

func tokenizeBrackets(raw string) []kvPair {
	var out []kvPair
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		m := bracketLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(m[1]))
		val := strings.TrimSpace(m[2])
		if val == "" {
			continue
		}
		out = append(out, kvPair{key, val})
	}
	return out
}
```

- [ ] **Step 7: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/parse/... -v`
Expected: PASS, all subtests across `date_test.go`, `parse_test.go`, `templates_test.go` green.

- [ ] **Step 8: Commit**

```bash
cd /Users/pat/codes/plat
git add go.mod go.sum internal/whois/parse/templates.go internal/whois/parse/templates.yaml internal/whois/parse/parse.go testdata/whois/denic-de-example.txt testdata/whois/jprs-jp-example.txt internal/whois/parse/templates_test.go
git commit -m "feat: add data-driven per-registry WHOIS parser templates"
```

---

### Task 4: `internal/whois` — Quirks Table

**Files:**
- Create: `internal/whois/quirks.go`
- Test: `internal/whois/quirks_test.go`

**Interfaces:**
- Consumes: nothing beyond stdlib.
- Produces: `func BuildQuery(server, domain string) string` — consumed by `internal/whois/client.go` (Task 5).

- [ ] **Step 1: Write the failing test**

Write `internal/whois/quirks_test.go`:
```go
package whois

import "testing"

func TestBuildQuery(t *testing.T) {
	tests := []struct {
		name   string
		server string
		domain string
		want   string
	}{
		{"verisign prefix", "whois.verisign-grs.com", "example.com", "domain example.com"},
		{"verisign prefix with port", "whois.verisign-grs.com:43", "example.com", "domain example.com"},
		{"jprs suffix", "whois.jprs.jp", "example.jp", "example.jp/e"},
		{"denic prefix", "whois.denic.de", "example.de", "-T dn,ace example.de"},
		{"unknown server default", "whois.example-registry.example", "example.tld", "example.tld"},
		{"local test address default", "127.0.0.1:54321", "example.com", "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildQuery(tt.server, tt.domain)
			if got != tt.want {
				t.Errorf("BuildQuery(%q, %q) = %q, want %q", tt.server, tt.domain, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/... -v`
Expected: FAIL — build error, `undefined: BuildQuery`.

- [ ] **Step 3: Write the implementation**

Write `internal/whois/quirks.go`:
```go
package whois

import (
	"net"
	"strings"
)

// Quirk describes how to construct a WHOIS query for servers that don't
// accept a bare domain name — some registries require a prefix or suffix
// to avoid ambiguous matches or to request non-default output.
type Quirk struct {
	HostSuffix string
	Prefix     string
	Suffix     string
}

var quirks = []Quirk{
	{HostSuffix: "verisign-grs.com", Prefix: "domain "},
	{HostSuffix: "jprs.jp", Suffix: "/e"},
	{HostSuffix: "denic.de", Prefix: "-T dn,ace "},
}

// BuildQuery constructs the exact query line (without the trailing CRLF)
// to send to server for domain, applying any matching quirk. server may
// be a bare hostname or a host:port pair (quirk matching strips the port).
func BuildQuery(server, domain string) string {
	host := server
	if h, _, err := net.SplitHostPort(server); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	for _, q := range quirks {
		if strings.HasSuffix(host, q.HostSuffix) {
			return q.Prefix + domain + q.Suffix
		}
	}
	return domain
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/... -v`
Expected: PASS, all 6 subtests green.

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/whois/quirks.go internal/whois/quirks_test.go
git commit -m "feat: add data-driven WHOIS server quirks table"
```

---

### Task 5: `internal/whois` — Result Types and Single-Hop TCP Client

**Files:**
- Create: `internal/whois/result.go`
- Create: `internal/whois/client.go`
- Test: extend `internal/whois/client_test.go` (created fresh here; Task 6 adds more tests to the same file)

**Interfaces:**
- Consumes: `parse.Fields` from Task 2/3 (`internal/whois/parse`), `BuildQuery` from Task 4 (same package).
- Produces: `type Hop struct{ Server, Query, Raw string; Fields parse.Fields; Latency time.Duration; Err error }`, `type Result struct{ Domain string; Hops []Hop }`, `func (*Result) Deepest() *Hop`, `type Client struct{ IANAServer string; Timeout time.Duration; Dialer *net.Dialer }`, unexported `func (*Client) query(ctx, server, domain string) (string, error)` — consumed by `internal/whois/referral.go` (Task 6).

- [ ] **Step 1: Write the failing test**

Write `internal/whois/client_test.go`:
```go
package whois

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestClient_EchoesExactQuery(t *testing.T) {
	var received string
	done := make(chan struct{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		received = string(buf[:n])
		_, _ = conn.Write([]byte("domain: TEST\n"))
	}()

	c := &Client{Timeout: 2 * time.Second}
	_, err = c.query(context.Background(), ln.Addr().String(), "example.com")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	<-done

	if received != "example.com\r\n" {
		t.Errorf("received query = %q, want %q (127.0.0.1 address matches no quirk, so bare domain + CRLF)", received, "example.com\r\n")
	}
}

func TestClient_HopTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		time.Sleep(2 * time.Second)
	}()

	c := &Client{Timeout: 200 * time.Millisecond}
	start := time.Now()
	_, err = c.query(context.Background(), ln.Addr().String(), "example.com")
	elapsed := time.Since(start)

	if elapsed > 1*time.Second {
		t.Fatalf("query took %v, want well under the listener's 2s stall (timeout should have fired around 200ms)", elapsed)
	}
	if err == nil {
		t.Fatal("expected a timeout error")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/... -v`
Expected: FAIL — build error, `undefined: Client`.

- [ ] **Step 3: Write the implementation**

Write `internal/whois/result.go`:
```go
package whois

import (
	"time"

	"github.com/patramsey/plat/internal/whois/parse"
)

// Hop is one WHOIS server queried during a lookup: the exact query sent,
// the raw response, the parsed view of that response, and how long it
// took (or the error that stopped it).
type Hop struct {
	Server  string
	Query   string
	Raw     string
	Fields  parse.Fields
	Latency time.Duration
	Err     error
}

// Result is the standalone, package-scoped outcome of a WHOIS lookup: an
// ordered chain of hops (IANA, then registry, then registrar if
// discovered). It intentionally performs no cross-hop reconciliation —
// picking a winning value across hops is the shared merge engine's job in
// a later milestone.
type Result struct {
	Domain string
	Hops   []Hop
}

// Deepest returns the last hop that succeeded (Err == nil), walking from
// the end of the chain. This is a "last hop present" convenience for
// simple callers (like the demo CLI command) — it is explicitly not a
// provenance/precedence merge; an earlier hop in the chain may hold a
// field this one lacks.
func (r *Result) Deepest() *Hop {
	for i := len(r.Hops) - 1; i >= 0; i-- {
		if r.Hops[i].Err == nil {
			return &r.Hops[i]
		}
	}
	return nil
}
```

Write `internal/whois/client.go`:
```go
package whois

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

// Client performs port-43 WHOIS lookups with IANA -> registry -> registrar
// referral chasing.
type Client struct {
	// IANAServer is the WHOIS server queried first to resolve a TLD's
	// registry server. Defaults to "whois.iana.org".
	IANAServer string
	// Timeout bounds each individual hop. Defaults to 5s.
	Timeout time.Duration
	// Dialer is used to open each TCP connection. Defaults to &net.Dialer{}.
	Dialer *net.Dialer
}

func (c *Client) ianaServer() string {
	if c.IANAServer != "" {
		return c.IANAServer
	}
	return "whois.iana.org"
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 5 * time.Second
}

func (c *Client) dialer() *net.Dialer {
	if c.Dialer != nil {
		return c.Dialer
	}
	return &net.Dialer{}
}

// query performs one TCP round-trip: dial server (appending the default
// port 43 if server doesn't already specify one), send the quirk-adjusted
// query for domain, and read the response to EOF. Bounded to 1 MiB to
// defend against a runaway or hostile server.
func (c *Client) query(ctx context.Context, server, domain string) (string, error) {
	addr := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		addr = net.JoinHostPort(server, "43")
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	conn, err := c.dialer().DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("whois: dialing %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	q := BuildQuery(server, domain) + "\r\n"
	if _, err := conn.Write([]byte(q)); err != nil {
		return "", fmt.Errorf("whois: writing query to %s: %w", addr, err)
	}

	body, err := io.ReadAll(io.LimitReader(conn, 1<<20))
	if err != nil {
		return "", fmt.Errorf("whois: reading response from %s: %w", addr, err)
	}
	return string(body), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/... -v`
Expected: PASS, all subtests green (the `HopTimeout` test takes ~200ms, not the full 2s).

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/whois/result.go internal/whois/client.go internal/whois/client_test.go
git commit -m "feat: add WHOIS result types and single-hop TCP client"
```

---

### Task 6: `internal/whois` — Referral Chasing

**Files:**
- Create: `internal/whois/referral.go`
- Modify: `internal/whois/client_test.go` (add referral-chasing and rate-limit tests to the file created in Task 5)

**Interfaces:**
- Consumes: `domain.Name`, `domain.Normalize` from `internal/domain` (M1, existing); `Client`, `Hop`, `Result` from Task 5; `parse.Parse` from Task 2/3.
- Produces: `func (*Client) Lookup(ctx context.Context, name domain.Name) (*Result, error)` — consumed by `cmd/plat/whois.go` (Task 8).

- [ ] **Step 1: Write the failing test**

Append to `internal/whois/client_test.go` (add `"context"`, `"fmt"`, `"strings"` to the existing import block if not already present, and add `"github.com/patramsey/plat/internal/domain"`):
```go
func startListener(t *testing.T, respond func(query string) string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		query := strings.TrimRight(string(buf[:n]), "\r\n")
		_, _ = conn.Write([]byte(respond(query)))
	}()
	return ln.Addr().String()
}

func TestClient_ReferralChasing(t *testing.T) {
	registrarAddr := startListener(t, func(query string) string {
		return "Domain Name: example.com\nRegistrant Organization: Example Corp\nRegistrar: Example Registrar, Inc.\n"
	})

	registryAddr := startListener(t, func(query string) string {
		return fmt.Sprintf("Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: %s\nRegistrar: Example Registrar, Inc.\n", registrarAddr)
	})

	ianaAddr := startListener(t, func(query string) string {
		return fmt.Sprintf("refer:        %s\ndomain:       COM\n", registryAddr)
	})

	c := &Client{IANAServer: ianaAddr, Timeout: 2 * time.Second}
	name, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	result, err := c.Lookup(context.Background(), name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(result.Hops) != 3 {
		t.Fatalf("Hops = %d, want 3", len(result.Hops))
	}
	if result.Hops[0].Server != ianaAddr {
		t.Errorf("hop 0 server = %q, want %q", result.Hops[0].Server, ianaAddr)
	}
	if result.Hops[1].Server != registryAddr {
		t.Errorf("hop 1 server = %q, want %q", result.Hops[1].Server, registryAddr)
	}
	if result.Hops[2].Server != registrarAddr {
		t.Errorf("hop 2 server = %q, want %q", result.Hops[2].Server, registrarAddr)
	}
	if result.Hops[2].Fields.Registrar != "Example Registrar, Inc." {
		t.Errorf("registrar = %q, want %q", result.Hops[2].Fields.Registrar, "Example Registrar, Inc.")
	}
}

func TestClient_LookupTimeoutReturnsPartialResult(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		time.Sleep(2 * time.Second)
	}()

	c := &Client{IANAServer: ln.Addr().String(), Timeout: 200 * time.Millisecond}
	name, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	start := time.Now()
	result, err := c.Lookup(context.Background(), name)
	elapsed := time.Since(start)

	if elapsed > 1*time.Second {
		t.Fatalf("Lookup took %v, want well under the listener's 2s stall", elapsed)
	}
	if err == nil {
		t.Fatal("expected an error since the only hop timed out")
	}
	if len(result.Hops) != 1 {
		t.Fatalf("Hops = %d, want 1 (partial result should still be returned)", len(result.Hops))
	}
	if result.Hops[0].Err == nil {
		t.Error("expected hop 0 to have a timeout error")
	}
}

func TestClient_RateLimitDetected(t *testing.T) {
	ianaAddr := startListener(t, func(query string) string {
		return "% Query rate limit exceeded. Please wait and try again later.\n"
	})

	c := &Client{IANAServer: ianaAddr, Timeout: 2 * time.Second}
	name, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	result, err := c.Lookup(context.Background(), name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(result.Hops) != 1 {
		t.Fatalf("Hops = %d, want 1 (no refer: line means no further hops)", len(result.Hops))
	}
	if !result.Hops[0].Fields.RateLimited {
		t.Error("expected RateLimited = true on the IANA hop")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/... -v`
Expected: FAIL — build error, `undefined: (*Client).Lookup` (and `TestClient_HopTimeout` from Task 5 still passes; the three new tests fail to build).

- [ ] **Step 3: Write the implementation**

Write `internal/whois/referral.go`:
```go
package whois

import (
	"context"
	"fmt"
	"time"

	"github.com/patramsey/plat/internal/domain"
	"github.com/patramsey/plat/internal/whois/parse"
)

func (c *Client) hop(ctx context.Context, server, queryDomain, tld string) Hop {
	start := time.Now()
	raw, err := c.query(ctx, server, queryDomain)
	h := Hop{
		Server:  server,
		Query:   BuildQuery(server, queryDomain),
		Raw:     raw,
		Latency: time.Since(start),
		Err:     err,
	}
	if err == nil {
		h.Fields = parse.Parse(raw, tld)
	}
	return h
}

// Lookup performs IANA -> registry -> registrar referral chasing for
// name. A hop erroring is normal, not fatal: Lookup always records the
// IANA hop, proceeds to the registry hop only if IANA yielded a `refer:`
// server, and proceeds to the registrar hop only if the registry yielded
// a `Registrar WHOIS Server:` line. It returns a non-nil error only if
// every attempted hop failed.
func (c *Client) Lookup(ctx context.Context, name domain.Name) (*Result, error) {
	result := &Result{Domain: name.Punycode}

	ianaHop := c.hop(ctx, c.ianaServer(), name.TLD, name.TLD)
	result.Hops = append(result.Hops, ianaHop)

	if ianaHop.Err == nil && ianaHop.Fields.Refer != "" {
		registryHop := c.hop(ctx, ianaHop.Fields.Refer, name.Punycode, name.TLD)
		result.Hops = append(result.Hops, registryHop)

		if registryHop.Err == nil && registryHop.Fields.RegistrarWHOISServer != "" {
			registrarHop := c.hop(ctx, registryHop.Fields.RegistrarWHOISServer, name.Punycode, name.TLD)
			result.Hops = append(result.Hops, registrarHop)
		}
	}

	for _, h := range result.Hops {
		if h.Err == nil {
			return result, nil
		}
	}
	return result, fmt.Errorf("whois: all hops failed for %s", name.Punycode)
}
```

Note: the IANA hop is queried with `name.TLD` (IANA's WHOIS indexes by TLD, e.g. querying `"com"` not `"example.com"`); the registry and registrar hops are queried with `name.Punycode` (the full domain). `parse.Parse` always receives `name.TLD` regardless of hop, so registry/registrar hops pick up `.jp`/`.de` templates correctly — this is harmless for the IANA hop since its response format is always plain default-dialect kv text.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/... -v`
Expected: PASS, all subtests in `quirks_test.go` and `client_test.go` green.

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/whois/referral.go internal/whois/client_test.go
git commit -m "feat: add IANA to registry to registrar WHOIS referral chasing"
```

---

### Task 7: `internal/whois` — Live Integration Test

**Files:**
- Create: `internal/whois/live_test.go`

**Interfaces:**
- Consumes: `Client`, `Lookup`, `Result.Deepest` from Tasks 5-6; `domain.Normalize` from `internal/domain`.
- Produces: nothing consumed by later tasks — this is a leaf, opt-in verification file excluded from the default build/test.

- [ ] **Step 1: Write the live test**

Write `internal/whois/live_test.go`:
```go
//go:build live

package whois

import (
	"context"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/domain"
)

func TestLive_GoogleCom(t *testing.T) {
	name, err := domain.Normalize("google.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	c := &Client{Timeout: 10 * time.Second}
	result, err := c.Lookup(context.Background(), name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	deepest := result.Deepest()
	if deepest == nil {
		t.Fatal("no successful hop")
	}
	if deepest.Fields.Registrar == "" {
		t.Error("expected a registrar name from the deepest successful hop")
	}
	t.Logf("chain: %d hops, deepest server %s, registrar %q", len(result.Hops), deepest.Server, deepest.Fields.Registrar)
}
```

- [ ] **Step 2: Verify it's excluded from the default test run**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/... -v`
Expected: PASS, and `TestLive_GoogleCom` does NOT appear in the output (the `//go:build live` tag excludes it).

- [ ] **Step 3: Verify it compiles under the live tag (without running it over the network here)**

Run: `cd /Users/pat/codes/plat && go vet -tags=live ./internal/whois/...`
Expected: succeeds with no errors (confirms the file is syntactically and type-correct, without actually making a network call in this step).

- [ ] **Step 4: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/whois/live_test.go
git commit -m "test: add opt-in live WHOIS integration test"
```

---

### Task 8: `cmd/plat` — Hidden `whois` Demo Subcommand

**Files:**
- Create: `cmd/plat/whois.go`
- Modify: `cmd/plat/main.go` (wire the new subcommand into `root`)
- Modify: `cmd/plat/main_test.go` (add coverage for the new subcommand's arg validation and hidden status)

**Interfaces:**
- Consumes: `usageError` type (from `cmd/plat/main.go`, existing), `domain.Normalize` (existing), `whois.Client`, `whois.Client.Lookup`, `whois.Result.Deepest` (Tasks 5-6).
- Produces: nothing consumed by later tasks — this is M2's final, demoable deliverable.

- [ ] **Step 1: Write the failing test**

Append to `cmd/plat/main_test.go` (add `"strings"` to the existing import block if not already present):
```go
func TestRun_WhoisSubcommandRegistered(t *testing.T) {
	var stdout, stderr bytes.Buffer
	_ = run([]string{"whois", "--help"}, &stdout, &stderr)
	if !strings.Contains(stdout.String(), "Look up domain ownership via WHOIS") {
		t.Errorf("expected whois subcommand help text in output, got:\n%s", stdout.String())
	}
}

func TestRun_WhoisRejectsWrongArgCount(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no args", []string{"whois"}},
		{"two args", []string{"whois", "example.com", "example.org"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := run(tt.args, &stdout, &stderr)
			if got != 2 {
				t.Errorf("run(%v) exit code = %d, want 2 (usage error)", tt.args, got)
			}
		})
	}
}

func TestRun_WhoisHiddenFromHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	_ = run([]string{"--help"}, &stdout, &stderr)
	if strings.Contains(stdout.String(), "whois") {
		t.Errorf("expected 'whois' subcommand to be hidden from --help output, got:\n%s", stdout.String())
	}
}
```

Note on `TestRun_WhoisRejectsWrongArgCount`: this test's exit-code assertion (`== 2`) will actually already pass even before this task's implementation exists — `run(["whois"])` falls through to the *root* command today, and `domain.Normalize("whois")` already rejects it as a single-label domain with exit 2, coincidentally the same code the new subcommand should also produce. It's kept because it verifies real, desired behavior, but it is **not** the test that proves this task's code is what's running — `TestRun_WhoisSubcommandRegistered` is the one that can only pass once `whois.go` exists, since no text about WHOIS appears anywhere in the root command's own help.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./cmd/plat/... -v`
Expected: FAIL — `TestRun_WhoisSubcommandRegistered` fails: `stdout` contains root's help text (no `whois` subcommand exists yet), which doesn't include "Look up domain ownership via WHOIS". (`TestRun_WhoisRejectsWrongArgCount` and `TestRun_WhoisHiddenFromHelp` will likely already pass at this point — that's expected per the note above, not a problem.)

- [ ] **Step 3: Write the implementation**

Write `cmd/plat/whois.go`:
```go
package main

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/patramsey/plat/internal/domain"
	"github.com/patramsey/plat/internal/whois"
)

// newWhoisCommand builds the hidden `plat whois <domain>` debug/demo
// subcommand. It is Hidden (off --help) because proper --source whois
// wiring into the root command is reserved for a later milestone; this
// exists to prove the WHOIS engine end to end during development.
func newWhoisCommand(stdout io.Writer) *cobra.Command {
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:    "whois <domain>",
		Short:  "Look up domain ownership via WHOIS (debug/demo command)",
		Hidden: true,
		Args: func(cmd *cobra.Command, cliArgs []string) error {
			if len(cliArgs) != 1 {
				return usageError{fmt.Errorf("expected exactly one domain argument, got %d", len(cliArgs))}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, cliArgs []string) error {
			return whoisLookup(cmd.Context(), stdout, cliArgs[0], timeout)
		},
	}
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "per-hop timeout for WHOIS queries")
	return cmd
}

func whoisLookup(ctx context.Context, stdout io.Writer, input string, timeout time.Duration) error {
	name, err := domain.Normalize(input)
	if err != nil {
		return usageError{err}
	}

	client := &whois.Client{Timeout: timeout}
	result, err := client.Lookup(ctx, name)
	if err != nil {
		return err
	}

	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	for i, h := range result.Hops {
		status := "ok"
		if h.Err != nil {
			status = h.Err.Error()
		}
		_, _ = fmt.Fprintf(tw, "Hop %d:\t%s\t%s\t%s\n", i+1, h.Server, h.Latency.Round(time.Millisecond), status)
	}
	if deepest := result.Deepest(); deepest != nil {
		_, _ = fmt.Fprintf(tw, "Registrar:\t%s\n", deepest.Fields.Registrar)
		_, _ = fmt.Fprintf(tw, "Domain status:\t%v\n", deepest.Fields.Statuses)
		_, _ = fmt.Fprintf(tw, "Nameservers:\t%v\n", deepest.Fields.Nameservers)
	}
	return tw.Flush()
}
```

Modify `cmd/plat/main.go`: read the file first to find the existing block that reads:
```go
	root.AddCommand(&cobra.Command{
		Use:   "version",
		...
	})
```
Immediately after that `root.AddCommand(...)` call for `version` (still inside the `run` function, before `err := root.Execute()`), add:
```go
	root.AddCommand(newWhoisCommand(stdout))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./... -v 2>&1 | tail -60`
Expected: PASS across all packages (`cmd/plat`, `internal/bootstrap`, `internal/domain`, `internal/rdap`, `internal/render/plain`, `internal/whois`, `internal/whois/parse`).

- [ ] **Step 5: Full-program verification**

Run:
```bash
cd /Users/pat/codes/plat && go mod tidy && go build ./... && go vet ./... && golangci-lint run && go test ./...
```
Expected: all commands succeed, `golangci-lint run` reports 0 issues, all packages report `ok`.

- [ ] **Step 6: Commit**

```bash
cd /Users/pat/codes/plat
git add cmd/plat/whois.go cmd/plat/main.go cmd/plat/main_test.go
git commit -m "feat: add hidden plat whois demo subcommand"
```

---

## Milestone Verification (manual, not automated)

Once all 8 tasks are complete, confirm the milestone's actual definition of done — this requires live network access and is deliberately not part of the automated test suite:

```bash
cd /Users/pat/codes/plat

go run ./cmd/plat whois google.com     # expect: 3-hop chain (IANA/Verisign/registrar), registrar name printed, exit 0
echo $?

go run ./cmd/plat whois nic.jp         # expect: exercises the /e quirk + brackets template
echo $?

go run ./cmd/plat whois example.de     # expect: exercises the -T dn,ace quirk + .de template
echo $?

go run ./cmd/plat whois localhost      # expect: friendly single-label error, exit 2 (reuses domain.Normalize)
echo $?

go test -tags=live ./internal/whois/... -v   # expect: TestLive_GoogleCom passes against real infra
```

If a real-world response the parser mishandles turns up during this verification (a new date format, a missing referral, an unexpected key), that's a genuine finding — capture the raw response into `testdata/whois/` and extend the offline tests rather than special-casing it in code, consistent with how M1 handled real-world RDAP surprises.
