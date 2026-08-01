# M3 — Registrar RDAP Hop + Merge Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn M1's registry-RDAP path and M2's WHOIS path into one unified, provenance-annotated `model.Record`, by adding the registrar RDAP hop (following a registry response's `related` link) and a pure merge engine with precedence, redaction override, and conflict detection.

**Architecture:** Three new packages — `internal/model` (pure types, zero internal deps), `internal/merge` (pure precedence/redaction/conflict engine, imports only `internal/model`), `internal/collect` (adapters + fan-out orchestration, imports `internal/model`/`internal/rdap`/`internal/whois`/`internal/domain`, deliberately NOT `internal/bootstrap` — see Task 8). `internal/rdap` gets additive-only extensions (new fields/methods; zero changes to existing behavior). `cmd/plat` gets a new hidden demo subcommand; the root command is untouched.

**Tech Stack:** Go 1.25 stdlib only for the new packages — no new third-party dependencies this milestone.

## Global Constraints

- M3 is registrar RDAP hop + merge engine only. Do NOT build the styled human renderer (lipgloss, M5), JSON/NDJSON machine output (M4), or new WHOIS protocol/parser breadth (M6).
- Zero changes to `internal/whois`, `internal/whois/parse`, `internal/domain`, `internal/bootstrap`, `internal/render/plain`. M3 reads their existing outputs only.
- `internal/rdap` changes are additive-only: new struct fields, new types, new methods, one refactor (`Domain` extracts a shared `domainAt` helper) that must not change `Domain`'s observable behavior. All of `internal/rdap`'s existing tests (`client_test.go`, `types_test.go`) must keep passing UNMODIFIED throughout this milestone.
- `plat <domain>` (the root command) is UNCHANGED — still registry-RDAP-only plain text, exactly as M1 left it. M3 ships as a new hidden `plat merge <domain>` demo subcommand, mirroring M2's `plat whois` hidden subcommand exactly (`Hidden: true`, reuses the existing `usageError`/`exitCode` machinery, its own throwaway `text/tabwriter` printer in `cmd/plat` — NOT `internal/render/plain`, which is `rdap.DomainResponse`-typed).
- `internal/collect` does NOT import `internal/bootstrap`. `Collect` takes an already-resolved `registryBaseURL string` (empty string = no RDAP coverage for this TLD, degrade to WHOIS-only) rather than a `*bootstrap.Resolver` — the caller (`cmd/plat`) does the `bootstrap.Load`/`BaseURL` call and passes the plain string in. This keeps `Collect` fully offline-testable with `httptest` servers directly, without needing to fake bootstrap resolution (`bootstrap.Resolver`'s TLD map is unexported and only populated via real fetch/cache/embed, so there is no way to construct one pointing at a local test server from outside the `bootstrap` package).
- Precedence order (most to least trusted): `registrar-rdap` > `registry-rdap` > `registrar-whois` > `registry-whois`.
- Redaction override: a higher-precedence source's value is skipped as a merge candidate if flagged redacted for that field. The winner is the first present, non-empty, non-redacted source in precedence order. A skipped higher-precedence redacted source generates a `RedactionNotice`.
- Conflict detection: any present, non-redacted, non-empty source whose value differs from the winner becomes part of a `Conflict` for that field — never silently dropped.
- Timestamp conflict tolerance: 24h clock-skew constant. Compare only `Parsed==true` candidates pairwise. An unparsed date can still win by precedence but never triggers a conflict.
- Nameservers: normalize (lowercase, strip trailing dot) before comparing. Merged value is the union across all present sources. A conflict is recorded if two present sources' normalized sets are unequal — value stays the union either way.
- Status: each adapter EPP-normalizes every status string via `model.NormalizeEPPStatus` before it reaches the merge engine. The engine unions the normalized set; differing status sets across sources are NOT a conflict (vocabularies legitimately vary by thick/thin registry — deliberate, not an oversight).
- Redaction placeholder detection (`model.IsRedactedPlaceholder`): case-insensitive EXACT match (after trimming) against a curated literal list — not a substring match, so a real value that happens to contain "redacted" isn't misclassified.
- Contact/entity modeling: `model.Record` includes the full `Contacts map[Role]Contact` shape, but M3 only POPULATES registrar identity (name, abuse email/phone from a shallow RDAP jCard read; IANA ID/URL from WHOIS only). Registrant/admin/tech/billing contact VALUES are deferred to M6 — this ties to the project's own WHOIS-consolidating-onto-RDAP context, so deep contact/jCard modeling isn't worth building now.
- RDAP entity/jCard parsing is SHALLOW and defensive: extract only `fn` (full name) and, for an entity whose role includes "abuse", `email`/`tel` — everything else in the jCard is ignored. Malformed/absent jCard must degrade to empty extraction, never panic or error (same tolerant philosophy as `StatusList`/`RDAPTime`).
- The registrar `related` link's `href` is the full registrar domain-object URL, fetched directly via a new `DomainURL` method — NOT `base + "/domain/" + name` like `Domain` does.
- A registrar-hop failure (network error, 404, malformed response, bad/loop-guarded URL) is non-fatal — the `registrar-rdap` source record is simply absent/not-OK, never an overall lookup failure.

---

### Task 1: `internal/model` — Core Types + EPP Status Normalization

**Files:**
- Create: `internal/model/source.go`
- Create: `internal/model/record.go`
- Create: `internal/model/status.go`
- Test: `internal/model/status_test.go`

**Interfaces:**
- Consumes: nothing beyond stdlib.
- Produces: `type SourceID string` + the 4 source constants, `var Precedence []SourceID`, `func Rank(s SourceID) int`, `type Field[T any] struct{ Value T; Sources []SourceID }` + `func (f Field[T]) Present() bool`, `type TimeValue struct{ Time time.Time; Raw string; Parsed bool }`, `type Role string` + 4 role constants, `type Contact struct{...}`, `type RegistrarInfo struct{...}`, `type Conflict struct{ Field string; Values map[SourceID]string }`, `type RedactionNotice struct{ Field string; Source SourceID; Reason string }`, `type SourceResult struct{...}`, `type Record struct{...}`, `type RegistrarFields struct{...}`, `type SourceRecord struct{...}`, field-name constants (`FieldDomain`, `FieldHandle`, `FieldRegistrarName`, `FieldRegistrarIANAID`, `FieldRegistrarURL`, `FieldRegistrarAbuseEmail`, `FieldRegistrarAbusePhone`, `FieldStatus`, `FieldCreated`, `FieldUpdated`, `FieldExpires`, `FieldNameservers`, `FieldDNSSEC`), `func NormalizeEPPStatus(raw string) string` — consumed by `internal/merge` (Task 6) and `internal/collect` (Task 7).

- [ ] **Step 1: Write the failing test**

Write `internal/model/status_test.go`:
```go
package model

import "testing"

func TestNormalizeEPPStatus(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"space separated verisign form", "client transfer prohibited", "clientTransferProhibited"},
		{"already camelCase", "clientTransferProhibited", "clientTransferProhibited"},
		{"space separated all caps", "CLIENT TRANSFER PROHIBITED", "clientTransferProhibited"},
		{"space separated, different words", "client delete prohibited", "clientDeleteProhibited"},
		{"single lowercase word", "active", "active"},
		{"single uppercase word", "ACTIVE", "active"},
		{"already camelCase, server prefix", "serverDeleteProhibited", "serverDeleteProhibited"},
		{"single word, no case ambiguity", "connect", "connect"},
		{"two-letter lowercase", "ok", "ok"},
		{"two-letter uppercase", "OK", "ok"},
		{"already camelCase, pendingDelete", "pendingDelete", "pendingDelete"},
		{"empty string", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeEPPStatus(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeEPPStatus(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/model/... -v`
Expected: FAIL — build error, `undefined: NormalizeEPPStatus` (the `internal/model` package itself doesn't exist yet).

- [ ] **Step 3: Write the implementation**

Write `internal/model/source.go`:
```go
package model

// SourceID identifies which of the four possible sources a piece of data
// came from.
type SourceID string

const (
	SourceRegistrarRDAP  SourceID = "registrar-rdap"
	SourceRegistryRDAP   SourceID = "registry-rdap"
	SourceRegistrarWHOIS SourceID = "registrar-whois"
	SourceRegistryWHOIS  SourceID = "registry-whois"
)

// Precedence is the merge trust order, most to least trusted. A source's
// index in this slice is its precedence rank (lower is more trusted).
var Precedence = []SourceID{
	SourceRegistrarRDAP,
	SourceRegistryRDAP,
	SourceRegistrarWHOIS,
	SourceRegistryWHOIS,
}

// Rank returns s's index in Precedence, or len(Precedence) if s is not a
// known source (sorts unknown sources last).
func Rank(s SourceID) int {
	for i, p := range Precedence {
		if p == s {
			return i
		}
	}
	return len(Precedence)
}
```

Write `internal/model/record.go`:
```go
package model

import "time"

// Field-name constants used as Conflict.Field / RedactionNotice.Field
// values, so callers never hand-type a field name string more than once.
const (
	FieldDomain              = "domain"
	FieldHandle              = "handle"
	FieldRegistrarName       = "registrar.name"
	FieldRegistrarIANAID     = "registrar.ianaId"
	FieldRegistrarURL        = "registrar.url"
	FieldRegistrarAbuseEmail = "registrar.abuseEmail"
	FieldRegistrarAbusePhone = "registrar.abusePhone"
	FieldStatus              = "status"
	FieldCreated             = "created"
	FieldUpdated             = "updated"
	FieldExpires             = "expires"
	FieldNameservers         = "nameservers"
	FieldDNSSEC              = "dnssec"
)

// Field carries a merged value plus the sources that agree on it.
type Field[T any] struct {
	Value   T
	Sources []SourceID
}

// Present reports whether any source contributed to this field.
func (f Field[T]) Present() bool { return len(f.Sources) > 0 }

// TimeValue parallels rdap.RDAPTime and parse.Date so adapters can map
// either into it 1:1 without losing the raw string when parsing failed.
type TimeValue struct {
	Time   time.Time
	Raw    string
	Parsed bool
}

// Role identifies a contact's relationship to the domain.
type Role string

const (
	RoleRegistrant Role = "registrant"
	RoleAdmin      Role = "admin"
	RoleTech       Role = "tech"
	RoleBilling    Role = "billing"
)

// Contact models one contact role. M3 defines the shape but does not
// populate values for any role — that's deferred to a later milestone.
type Contact struct {
	Name         Field[string]
	Organization Field[string]
	Email        Field[string]
	Phone        Field[string]
}

// RegistrarInfo is the registrar's own identity — distinct from Contacts,
// which models the domain's registrant/admin/tech/billing contacts.
type RegistrarInfo struct {
	Name       Field[string]
	IANAID     Field[string]
	URL        Field[string]
	AbuseEmail Field[string]
	AbusePhone Field[string]
}

// Conflict records a field where present sources disagree. Values maps
// each disagreeing source (including the winner) to its rendered value,
// so the conflict is self-describing without cross-referencing Record.
type Conflict struct {
	Field  string
	Values map[SourceID]string
}

// RedactionNotice records that a higher-precedence source's value for
// Field was withheld (matched a known redaction placeholder), and a
// lower-precedence source's value was used instead — or no value was
// available at all if every source was redacted.
type RedactionNotice struct {
	Field  string
	Source SourceID
	Reason string
}

// SourceResult is the per-source metadata that ends up in Record.Sources
// — one row per source actually attempted, regardless of whether it
// yielded usable data.
type SourceResult struct {
	Source  SourceID
	OK      bool
	Latency time.Duration
	Err     string
	Raw     []byte
}

// Record is the unified, provenance-annotated domain lookup result — the
// output of merge.Merge.
type Record struct {
	Domain      Field[string]
	Handle      Field[string]
	Registrar   RegistrarInfo
	Status      Field[[]string]
	Created     Field[TimeValue]
	Updated     Field[TimeValue]
	Expires     Field[TimeValue]
	Nameservers Field[[]string]
	DNSSEC      Field[bool]
	Contacts    map[Role]Contact
	Redacted    []RedactionNotice
	Sources     []SourceResult
	Conflicts   []Conflict
}

// RegistrarFields is the plain-string registrar identity an adapter
// extracts from one source, before merge.Merge turns it into
// Record.Registrar's Field[string]s with provenance.
type RegistrarFields struct {
	Name       string
	IANAID     string
	URL        string
	AbuseEmail string
	AbusePhone string
}

// SourceRecord is merge.Merge's input shape — one per source that was
// attempted, produced by internal/collect's adapters from rdap.Result /
// whois.Hop.
type SourceRecord struct {
	Meta           SourceResult
	Present        bool
	Domain         string
	Handle         string
	Registrar      RegistrarFields
	Status         []string // already EPP-normalized by the adapter
	Created        TimeValue
	Updated        TimeValue
	Expires        TimeValue
	Nameservers    []string // already normalized: lowercase, no trailing dot
	DNSSEC         *bool    // nil = source said nothing about DNSSEC
	RedactedFields map[string]bool
	Redactions     []RedactionNotice
}
```

Write `internal/model/status.go`:
```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./internal/model/... -v`
Expected: PASS, all 12 subtests green.

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/model/source.go internal/model/record.go internal/model/status.go internal/model/status_test.go
git commit -m "feat: add unified model types and EPP status normalization"
```

---

### Task 2: `internal/model` — Redaction Placeholder Detection

**Files:**
- Create: `internal/model/redaction.go`
- Test: `internal/model/redaction_test.go`

**Interfaces:**
- Consumes: nothing beyond stdlib.
- Produces: `func IsRedactedPlaceholder(s string) bool` — consumed by `internal/collect`'s adapters (Task 7).

- [ ] **Step 1: Write the failing test**

Write `internal/model/redaction_test.go`:
```go
package model

import "testing"

func TestIsRedactedPlaceholder(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"exact canonical form", "REDACTED FOR PRIVACY", true},
		{"lowercase", "redacted for privacy", false /* placeholder below is exact-match on the canonical casing families; verify actual casing tolerance in the case-insensitive tests */},
	}
	_ = tests // replaced by the table below; kept here only to show intent
}

func TestIsRedactedPlaceholder_CaseInsensitive(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"exact uppercase", "REDACTED FOR PRIVACY", true},
		{"exact lowercase", "redacted for privacy", true},
		{"mixed case", "Redacted For Privacy", true},
		{"data redacted", "Data Redacted", true},
		{"data protected", "DATA PROTECTED", true},
		{"not disclosed", "Not Disclosed", true},
		{"gdpr masked", "GDPR Masked", true},
		{"statutory masking enabled", "Statutory Masking Enabled", true},
		{"bare redacted", "REDACTED", true},
		{"registration private", "Registration Private", true},
		{"leading/trailing whitespace", "  REDACTED FOR PRIVACY  ", true},
		{"real organization name", "Redacted Solutions LLC", false},
		{"real name containing redact as substring", "The Redactions Group", false},
		{"empty string", "", false},
		{"unrelated value", "Example Corp", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsRedactedPlaceholder(tt.input)
			if got != tt.want {
				t.Errorf("IsRedactedPlaceholder(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
```

Note: the first `TestIsRedactedPlaceholder` function above is intentionally a no-op placeholder that documents intent but asserts nothing new — DELETE it and keep only `TestIsRedactedPlaceholder_CaseInsensitive`, which is the real test. (This note exists because a first draft of this table had a duplicate/confusing case; the single table below is authoritative.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/model/... -v -run TestIsRedactedPlaceholder`
Expected: FAIL — build error, `undefined: IsRedactedPlaceholder`.

- [ ] **Step 3: Write the implementation**

Write `internal/model/redaction.go`:
```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./internal/model/... -v`
Expected: PASS, all subtests in `status_test.go` and `redaction_test.go` green. Confirm `TestIsRedactedPlaceholder` (the no-op placeholder function) was deleted per the Step 1 note, leaving only `TestIsRedactedPlaceholder_CaseInsensitive`.

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/model/redaction.go internal/model/redaction_test.go
git commit -m "feat: add redaction placeholder detection"
```

---

### Task 3: `internal/rdap` — Related-Link Following (Additive)

**Files:**
- Modify: `internal/rdap/types.go` (add `Link`, `LinkList`, `Links` field, `RelatedRegistrarURL`)
- Test: `internal/rdap/links_test.go`

**Interfaces:**
- Consumes: nothing new — additive to the existing `DomainResponse`.
- Produces: `type Link struct{ Value, Rel, Href, Type string }`, `type LinkList []Link` (tolerant unmarshal), `DomainResponse.Links LinkList`, `func (d *DomainResponse) RelatedRegistrarURL() (string, bool)` — consumed by `internal/collect`'s orchestration (Task 8).

- [ ] **Step 1: Write the failing test**

Write `internal/rdap/links_test.go`:
```go
package rdap

import (
	"encoding/json"
	"os"
	"testing"
)

func TestLinkListUnmarshal(t *testing.T) {
	tests := []struct {
		name string
		json string
		want int // expected number of links
	}{
		{"single link array", `[{"rel":"self","href":"https://x/","type":"application/rdap+json"}]`, 1},
		{"null", `null`, 0},
		{"empty array", `[]`, 0},
		{"malformed (object instead of array) degrades to empty", `{"rel":"self"}`, 0},
		{"malformed (number) degrades to empty", `42`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got LinkList
			if err := json.Unmarshal([]byte(tt.json), &got); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.want {
				t.Fatalf("got %d links, want %d", len(got), tt.want)
			}
		})
	}
}

func TestRelatedRegistrarURL(t *testing.T) {
	tests := []struct {
		name string
		d    DomainResponse
		want string
		ok   bool
	}{
		{
			name: "no links at all",
			d:    DomainResponse{},
			want: "", ok: false,
		},
		{
			name: "only a self link, no related",
			d: DomainResponse{Links: LinkList{
				{Rel: "self", Href: "https://registry.example/domain/x", Type: "application/rdap+json"},
			}},
			want: "", ok: false,
		},
		{
			name: "related link present",
			d: DomainResponse{Links: LinkList{
				{Rel: "self", Href: "https://registry.example/domain/x", Type: "application/rdap+json"},
				{Rel: "related", Href: "https://registrar.example/rdap/domain/x", Type: "application/rdap+json"},
			}},
			want: "https://registrar.example/rdap/domain/x", ok: true,
		},
		{
			name: "related link, case-insensitive rel match",
			d: DomainResponse{Links: LinkList{
				{Rel: "Related", Href: "https://registrar.example/rdap/domain/x", Type: "application/rdap+json"},
			}},
			want: "https://registrar.example/rdap/domain/x", ok: true,
		},
		{
			name: "prefers application/rdap+json related link over a non-rdap+json related link",
			d: DomainResponse{Links: LinkList{
				{Rel: "related", Href: "https://registrar.example/html/x", Type: "text/html"},
				{Rel: "related", Href: "https://registrar.example/rdap/domain/x", Type: "application/rdap+json"},
			}},
			want: "https://registrar.example/rdap/domain/x", ok: true,
		},
		{
			name: "falls back to a related link without application/rdap+json type if that's all there is",
			d: DomainResponse{Links: LinkList{
				{Rel: "related", Href: "https://registrar.example/html/x", Type: "text/html"},
			}},
			want: "https://registrar.example/html/x", ok: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.d.RelatedRegistrarURL()
			if got != tt.want || ok != tt.ok {
				t.Errorf("RelatedRegistrarURL() = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestExistingFixtureHasNoRelatedLink(t *testing.T) {
	// Regression guard: the M1 fixture (a "self"-only links array) must
	// still decode cleanly and report no related link, proving this
	// task's additions don't disturb the existing decode path.
	b, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	var d DomainResponse
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(d.Links) != 1 {
		t.Fatalf("Links = %v, want 1 entry (the existing self link)", d.Links)
	}
	if _, ok := d.RelatedRegistrarURL(); ok {
		t.Error("expected no related link in the M1 fixture")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/rdap/... -v -run 'TestLinkListUnmarshal|TestRelatedRegistrarURL|TestExistingFixtureHasNoRelatedLink'`
Expected: FAIL — build error, `undefined: Link` / `undefined: LinkList`.

- [ ] **Step 3: Write the implementation**

Modify `internal/rdap/types.go`. Add `Links LinkList \`json:"links"\`` as a new field on `DomainResponse` (add it to the existing struct definition, after `Nameservers`):
```go
type DomainResponse struct {
	ObjectClassName string       `json:"objectClassName"`
	LDHName         string       `json:"ldhName"`
	UnicodeName     string       `json:"unicodeName"`
	Handle          string       `json:"handle"`
	Status          StatusList   `json:"status"`
	Events          []Event      `json:"events"`
	Nameservers     []Nameserver `json:"nameservers"`
	Links           LinkList     `json:"links"`
}
```

Append to `internal/rdap/types.go`:
```go
// Link is a trimmed RFC 9083 link object.
type Link struct {
	Value string `json:"value"`
	Rel   string `json:"rel"`
	Href  string `json:"href"`
	Type  string `json:"type"`
}

// LinkList tolerates the "links" array being malformed (missing, wrong
// shape, or containing non-object entries) — it degrades to an empty list
// rather than aborting the whole document's decode, matching StatusList's
// philosophy.
type LinkList []Link

func (l *LinkList) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" {
		*l = nil
		return nil
	}
	var links []Link
	if err := json.Unmarshal(b, &links); err != nil {
		*l = nil
		return nil
	}
	*l = links
	return nil
}

// RelatedRegistrarURL returns the href of the first "related" link,
// preferring one whose type is application/rdap+json but falling back to
// any related link if none match. Returns false if no related link exists.
func (d *DomainResponse) RelatedRegistrarURL() (string, bool) {
	var fallback string
	haveFallback := false
	for _, link := range d.Links {
		if !strings.EqualFold(link.Rel, "related") {
			continue
		}
		if strings.EqualFold(link.Type, "application/rdap+json") {
			return link.Href, true
		}
		if !haveFallback {
			fallback = link.Href
			haveFallback = true
		}
	}
	if haveFallback {
		return fallback, true
	}
	return "", false
}
```

- [ ] **Step 4: Run test to verify it passes, and confirm no regression**

Run: `cd /Users/pat/codes/plat && go test ./internal/rdap/... -v`
Expected: PASS — the new tests AND every pre-existing test in `client_test.go`/`types_test.go` from M1 all green, with zero modifications needed to those files.

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/rdap/types.go internal/rdap/links_test.go
git commit -m "feat: add tolerant RDAP links parsing and related-registrar-URL lookup"
```

---

### Task 4: `internal/rdap` — `DomainURL` (Registrar Hop Fetch)

**Files:**
- Modify: `internal/rdap/client.go` (extract `domainAt`, add `DomainURL`)
- Test: `internal/rdap/domain_url_test.go`

**Interfaces:**
- Consumes: `Result`, `ErrDomainNotFound`, `MalformedResponseError` (all existing, unchanged).
- Produces: `func (c *Client) DomainURL(ctx context.Context, rawURL string) (*Result, error)` — consumed by `internal/collect`'s orchestration (Task 8).

This is the highest-risk task in the milestone so far: it refactors the internals of the already-shipped `Domain` method. The refactor must be a pure extraction — `Domain`'s observable behavior (every existing test) must be provably unchanged.

- [ ] **Step 1: Write the failing test**

Write `internal/rdap/domain_url_test.go`:
```go
package rdap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestDomainURL_HappyPath(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		w.Write(fixture)
	}))
	defer srv.Close()

	c := &Client{}
	result, err := c.DomainURL(context.Background(), srv.URL+"/rdap/domain/EXAMPLE.COM")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Domain == nil || result.Domain.LDHName != "EXAMPLE.COM" {
		t.Fatalf("Domain = %+v", result.Domain)
	}
}

func TestDomainURL_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"errorCode":404,"title":"Not Found"}`))
	}))
	defer srv.Close()

	c := &Client{}
	_, err := c.DomainURL(context.Background(), srv.URL+"/rdap/domain/nonexistent.example.com")
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestDomainURL_RejectsBadScheme(t *testing.T) {
	tests := []string{
		"javascript:alert(1)",
		"file:///etc/passwd",
		"ftp://example.com/domain/x",
		"not-a-url-at-all",
		"",
	}
	c := &Client{}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			_, err := c.DomainURL(context.Background(), raw)
			if err == nil {
				t.Errorf("DomainURL(%q) expected an error, got nil", raw)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/rdap/... -v -run TestDomainURL`
Expected: FAIL — build error, `undefined: (*Client).DomainURL`.

- [ ] **Step 3: Write the implementation**

Modify `internal/rdap/client.go`. Replace the entire existing `Domain` method with this (the refactor: `Domain` now just builds the URL and delegates; the rest of the logic moves unchanged into the new private `domainAt`, and a new public `DomainURL` is added):
```go
// Domain queries baseURL for the given punycode domain name and returns
// the parsed result. baseURL is the RDAP service base (typically resolved
// from IANA bootstrap); punycode is the ASCII domain name to look up.
func (c *Client) Domain(ctx context.Context, baseURL, punycode string) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	reqURL := strings.TrimRight(baseURL, "/") + "/domain/" + url.PathEscape(punycode)
	return c.domainAt(ctx, reqURL)
}

// DomainURL fetches and parses the RDAP domain object at rawURL directly
// — used to follow a registry response's registrar "related" link, whose
// href is already a complete domain-object URL, not a base to append
// "/domain/{name}" to. rawURL must be a valid http(s) URL; anything else
// (a bad scheme, an unparseable string) is rejected before any network
// call is attempted.
func (c *Client) DomainURL(ctx context.Context, rawURL string) (*Result, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("rdap: invalid registrar URL %q: %w", rawURL, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("rdap: unsupported URL scheme %q in %q", parsed.Scheme, rawURL)
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	return c.domainAt(ctx, rawURL)
}

// domainAt is the shared fetch-and-parse core for both Domain and
// DomainURL — every existing behavior of Domain (429 retry, 404 handling,
// malformed-response tolerance, the objectClassName check) lives here
// unchanged from before this method was extracted.
func (c *Client) domainAt(ctx context.Context, reqURL string) (*Result, error) {
	resp, err := c.do(ctx, reqURL)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		select {
		case <-time.After(retryAfter(resp.Header)):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		resp, err = c.do(ctx, reqURL)
		if err != nil {
			return nil, err
		}
	}

	contentType := resp.Header.Get("Content-Type")
	mediaType, _, _ := mime.ParseMediaType(contentType)
	conformant := mediaType == "application/rdap+json"

	result := &Result{
		Raw:                 resp.Body,
		StatusCode:          resp.StatusCode,
		ContentType:         contentType,
		MediaTypeConformant: conformant,
	}

	if resp.StatusCode == http.StatusNotFound {
		return result, ErrDomainNotFound
	}

	if resp.StatusCode >= 400 {
		var rerr rdapError
		if json.Unmarshal(bytes.TrimSpace(resp.Body), &rerr) == nil && rerr.Title != "" {
			return result, fmt.Errorf("rdap: %s returned %d: %s", reqURL, resp.StatusCode, rerr.Title)
		}
		return result, &MalformedResponseError{
			URL: reqURL, StatusCode: resp.StatusCode, ContentType: contentType,
			Snippet: snippet(resp.Body),
		}
	}

	trimmed := bytes.TrimSpace(resp.Body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return result, &MalformedResponseError{
			URL: reqURL, StatusCode: resp.StatusCode, ContentType: contentType,
			Snippet: snippet(resp.Body),
		}
	}

	var domain DomainResponse
	if err := json.Unmarshal(trimmed, &domain); err != nil {
		return result, &MalformedResponseError{
			URL: reqURL, StatusCode: resp.StatusCode, ContentType: contentType,
			Snippet: snippet(resp.Body), Err: err,
		}
	}

	if domain.ObjectClassName != "domain" {
		var rerr rdapError
		if json.Unmarshal(trimmed, &rerr) == nil && rerr.ErrorCode != 0 {
			return result, fmt.Errorf("rdap: %s returned errorCode %d: %s", reqURL, rerr.ErrorCode, rerr.Title)
		}
		return result, &MalformedResponseError{
			URL: reqURL, StatusCode: resp.StatusCode, ContentType: contentType,
			Snippet: snippet(resp.Body),
		}
	}

	result.Domain = &domain
	return result, nil
}
```

No import changes are needed — `net/url` is already imported (used by the old `Domain` for `url.PathEscape`), and every other package used in `domainAt` was already imported for the old `Domain` body.

- [ ] **Step 4: Run test to verify it passes, and confirm zero regression**

Run: `cd /Users/pat/codes/plat && go test ./internal/rdap/... -v`
Expected: PASS — the 3 new `DomainURL` tests AND every single pre-existing test (`TestClientDomain_HappyPath`, `TestClientDomain_NotFound`, `TestClientDomain_RateLimitedThenSucceeds`, `TestClientDomain_RateLimitedGivesUp`, `TestClientDomain_NonJSONBody`, `TestClientDomain_MalformedStatusField`, `TestClientDomain_UnparseableEventDate`, `TestClientDomain_NonDomainObjectClass`, plus Task 3's new tests) all green, unmodified. This is the single most important verification in this task — if any pre-existing test fails, the refactor introduced a behavior change and must be fixed before proceeding, not worked around.

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/rdap/client.go internal/rdap/domain_url_test.go
git commit -m "feat: add DomainURL for fetching a registrar RDAP related link directly"
```

---

### Task 5: `internal/rdap` — Shallow Entities/jCard + Remarks (Additive)

**Files:**
- Modify: `internal/rdap/types.go` (add `Entity`, `EntityList`, `VCardArray`, `Entities` field, `Remark`, `RemarkList`, `Remarks` field, accessor methods)
- Test: `internal/rdap/entities_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `type Entity struct{ Roles []string; VCardArray VCardArray }`, `DomainResponse.Entities EntityList`, `func (d *DomainResponse) RegistrarEntity() (Entity, bool)`, `func (d *DomainResponse) AbuseEntity() (Entity, bool)`, `type Remark struct{ Title, Type string; Description []string }`, `DomainResponse.Remarks RemarkList`, `func (d *DomainResponse) RedactionRemarks() []Remark` — consumed by `internal/collect`'s `FromRDAP` adapter (Task 7).

- [ ] **Step 1: Write the failing test**

Write `internal/rdap/entities_test.go`:
```go
package rdap

import (
	"encoding/json"
	"testing"
)

func TestVCardArrayUnmarshal(t *testing.T) {
	tests := []struct {
		name      string
		json      string
		wantFN    string
		wantEmail string
		wantTel   string
	}{
		{
			name: "typical registrar vcard",
			json: `["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Registrar, Inc."]]]`,
			wantFN: "Example Registrar, Inc.",
		},
		{
			name: "abuse vcard with email and tel",
			json: `["vcard",[["fn",{},"text","Abuse Team"],["email",{},"text","abuse@example.example"],["tel",{},"text","+1.5555550100"]]]`,
			wantFN: "Abuse Team", wantEmail: "abuse@example.example", wantTel: "+1.5555550100",
		},
		{
			name: "missing entirely (zero value)",
			json: `null`,
		},
		{
			name: "wrong top-level shape (object, not array) degrades to empty",
			json: `{"not":"a vcard"}`,
		},
		{
			name: "wrong length (only 1 element) degrades to empty",
			json: `["vcard"]`,
		},
		{
			name: "non-string property value (e.g. structured n) is skipped, not fatal",
			json: `["vcard",[["n",{},"text",["Corp","Example",[],[],[]]],["fn",{},"text","Example Corp"]]]`,
			wantFN: "Example Corp",
		},
		{
			name: "property array too short degrades that entry silently",
			json: `["vcard",[["fn",{}],["email",{},"text","real@example.example"]]]`,
			wantEmail: "real@example.example",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v VCardArray
			if err := json.Unmarshal([]byte(tt.json), &v); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if v.FullName != tt.wantFN {
				t.Errorf("FullName = %q, want %q", v.FullName, tt.wantFN)
			}
			if v.Email != tt.wantEmail {
				t.Errorf("Email = %q, want %q", v.Email, tt.wantEmail)
			}
			if v.Tel != tt.wantTel {
				t.Errorf("Tel = %q, want %q", v.Tel, tt.wantTel)
			}
		})
	}
}

func TestEntityAccessors(t *testing.T) {
	d := DomainResponse{
		Entities: EntityList{
			{Roles: []string{"registrar"}, VCardArray: VCardArray{FullName: "Example Registrar, Inc."}},
			{Roles: []string{"abuse"}, VCardArray: VCardArray{Email: "abuse@example.example", Tel: "+1.5555550100"}},
			{Roles: []string{"registrant"}, VCardArray: VCardArray{FullName: "REDACTED FOR PRIVACY"}},
		},
	}
	reg, ok := d.RegistrarEntity()
	if !ok || reg.VCardArray.FullName != "Example Registrar, Inc." {
		t.Errorf("RegistrarEntity() = %+v, %v", reg, ok)
	}
	abuse, ok := d.AbuseEntity()
	if !ok || abuse.VCardArray.Email != "abuse@example.example" {
		t.Errorf("AbuseEntity() = %+v, %v", abuse, ok)
	}

	empty := DomainResponse{}
	if _, ok := empty.RegistrarEntity(); ok {
		t.Error("expected no registrar entity on an empty DomainResponse")
	}
}

func TestRedactionRemarks(t *testing.T) {
	d := DomainResponse{
		Remarks: RemarkList{
			{Title: "Terms of Use", Type: "", Description: []string{"Service subject to Terms of Use."}},
			{Title: "REDACTED FOR PRIVACY", Type: "object redacted due to authorization", Description: []string{"Some data has been removed."}},
		},
	}
	got := d.RedactionRemarks()
	if len(got) != 1 || got[0].Title != "REDACTED FOR PRIVACY" {
		t.Errorf("RedactionRemarks() = %+v, want exactly the redaction-titled remark", got)
	}
}

func TestEntityListToleratesMalformed(t *testing.T) {
	tests := []struct {
		name string
		json string
		want int
	}{
		{"array of entities", `[{"roles":["registrar"]}]`, 1},
		{"null", `null`, 0},
		{"malformed (not an array)", `{"roles":["registrar"]}`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got EntityList
			if err := json.Unmarshal([]byte(tt.json), &got); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.want {
				t.Fatalf("got %d entities, want %d", len(got), tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/rdap/... -v -run 'TestVCardArrayUnmarshal|TestEntityAccessors|TestRedactionRemarks|TestEntityListToleratesMalformed'`
Expected: FAIL — build error, `undefined: Entity` / `undefined: VCardArray`.

- [ ] **Step 3: Write the implementation**

Modify `internal/rdap/types.go`. Add `Entities EntityList \`json:"entities"\`` and `Remarks RemarkList \`json:"remarks"\`` to `DomainResponse`:
```go
type DomainResponse struct {
	ObjectClassName string       `json:"objectClassName"`
	LDHName         string       `json:"ldhName"`
	UnicodeName     string       `json:"unicodeName"`
	Handle          string       `json:"handle"`
	Status          StatusList   `json:"status"`
	Events          []Event      `json:"events"`
	Nameservers     []Nameserver `json:"nameservers"`
	Links           LinkList     `json:"links"`
	Entities        EntityList   `json:"entities"`
	Remarks         RemarkList   `json:"remarks"`
}
```

Append to `internal/rdap/types.go`:
```go
// Entity is a trimmed RFC 9083 entity object — only the fields needed to
// extract a registrar's or abuse contact's identity from its vCard.
// Contact modeling beyond this (registrant/admin/tech/billing values) is
// deferred to a later milestone.
type Entity struct {
	Roles      []string   `json:"roles"`
	VCardArray VCardArray `json:"vcardArray"`
}

// EntityList tolerates the "entities" array being malformed, mirroring
// LinkList's philosophy — degrade to empty rather than aborting the
// decode.
type EntityList []Entity

func (e *EntityList) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" {
		*e = nil
		return nil
	}
	var list []Entity
	if err := json.Unmarshal(b, &list); err != nil {
		*e = nil
		return nil
	}
	*e = list
	return nil
}

// VCardArray tolerates RFC 7095's jCard shape: a 2-element array where
// element 0 is the literal "vcard" and element 1 is an array of property
// arrays ([name, params, valueType, value, ...]). It extracts only "fn"
// (full name), "email", and "tel" — everything else in the vCard (the
// "genuinely unpleasant" bulk of RFC 7095) is deliberately ignored. Any
// deviation from the expected shape — missing elements, wrong types, an
// absent jCard entirely — degrades to an empty extraction rather than
// erroring; jCard is not worth hard-failing a whole document decode over.
type VCardArray struct {
	FullName string
	Email    string
	Tel      string
}

func (v *VCardArray) UnmarshalJSON(b []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil || len(raw) != 2 {
		return nil
	}
	var props []json.RawMessage
	if err := json.Unmarshal(raw[1], &props); err != nil {
		return nil
	}
	for _, p := range props {
		var prop []json.RawMessage
		if err := json.Unmarshal(p, &prop); err != nil || len(prop) < 4 {
			continue
		}
		var name string
		if err := json.Unmarshal(prop[0], &name); err != nil {
			continue
		}
		var value string
		if err := json.Unmarshal(prop[3], &value); err != nil {
			continue // non-string value (e.g. a structured "n" property) — skip it
		}
		switch strings.ToLower(name) {
		case "fn":
			v.FullName = value
		case "email":
			v.Email = value
		case "tel":
			v.Tel = value
		}
	}
	return nil
}

// RegistrarEntity returns the first entity whose Roles includes
// "registrar" (case-insensitive), if any.
func (d *DomainResponse) RegistrarEntity() (Entity, bool) {
	return d.entityByRole("registrar")
}

// AbuseEntity returns the first entity whose Roles includes "abuse". Per
// RDAP convention this may be nested under the registrar entity in some
// implementations; M3 only looks at top-level entities, since abuse
// contact info is frequently duplicated there too — nested traversal is
// left for a later milestone.
func (d *DomainResponse) AbuseEntity() (Entity, bool) {
	return d.entityByRole("abuse")
}

func (d *DomainResponse) entityByRole(role string) (Entity, bool) {
	for _, e := range d.Entities {
		for _, r := range e.Roles {
			if strings.EqualFold(r, role) {
				return e, true
			}
		}
	}
	return Entity{}, false
}

// Remark is a trimmed RFC 9083 remark/notice object.
type Remark struct {
	Title       string   `json:"title"`
	Type        string   `json:"type"`
	Description []string `json:"description"`
}

// RemarkList tolerates the "remarks" array being malformed, mirroring
// LinkList's philosophy.
type RemarkList []Remark

func (r *RemarkList) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" {
		*r = nil
		return nil
	}
	var list []Remark
	if err := json.Unmarshal(b, &list); err != nil {
		*r = nil
		return nil
	}
	*r = list
	return nil
}

// RedactionRemarks returns remarks whose title or type suggests redacted
// data — a shallow, informational signal, not a full RFC 9537 evaluation
// (which is deferred to a later milestone).
func (d *DomainResponse) RedactionRemarks() []Remark {
	var out []Remark
	for _, r := range d.Remarks {
		lt := strings.ToLower(r.Title)
		ly := strings.ToLower(r.Type)
		if strings.Contains(lt, "redact") || strings.Contains(lt, "privacy") ||
			strings.Contains(ly, "redact") || strings.Contains(ly, "privacy") {
			out = append(out, r)
		}
	}
	return out
}
```

- [ ] **Step 4: Run test to verify it passes, and confirm no regression**

Run: `cd /Users/pat/codes/plat && go test ./internal/rdap/... -v`
Expected: PASS — all new tests plus every pre-existing test from M1/Task 3/Task 4 still green.

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/rdap/types.go internal/rdap/entities_test.go
git commit -m "feat: add shallow RDAP entity/jCard and remark parsing"
```

---

### Task 6: `internal/merge` — The Merge Engine (Milestone Centerpiece)

**Files:**
- Create: `internal/merge/merge.go`
- Test: `internal/merge/merge_test.go`

**Interfaces:**
- Consumes: everything from `internal/model` (Task 1).
- Produces: `func Merge(sources []model.SourceRecord) model.Record` — consumed by `cmd/plat`'s merge subcommand (Task 9).

This package is pure — zero I/O, zero imports beyond `internal/model` and stdlib — so every test constructs `model.SourceRecord` values directly in Go with no fixtures needed.

- [ ] **Step 1: Write the failing test**

Write `internal/merge/merge_test.go`:
```go
package merge

import (
	"testing"
	"time"

	"github.com/patramsey/plat/internal/model"
)

func sr(source model.SourceID, present bool) model.SourceRecord {
	return model.SourceRecord{
		Meta:           model.SourceResult{Source: source, OK: present},
		Present:        present,
		RedactedFields: map[string]bool{},
	}
}

func TestMerge_ScalarPrecedence(t *testing.T) {
	registrar := sr(model.SourceRegistrarRDAP, true)
	registrar.Registrar.Name = "Registrar Says Corp"
	registry := sr(model.SourceRegistryRDAP, true)
	registry.Registrar.Name = "Registry Says Corp"

	rec := Merge([]model.SourceRecord{registry, registrar})

	if rec.Registrar.Name.Value != "Registrar Says Corp" {
		t.Errorf("Registrar.Name = %q, want %q (registrar-rdap should win over registry-rdap)", rec.Registrar.Name.Value, "Registrar Says Corp")
	}
	if len(rec.Conflicts) != 1 || rec.Conflicts[0].Field != model.FieldRegistrarName {
		t.Errorf("Conflicts = %+v, want exactly one registrar.name conflict", rec.Conflicts)
	}
}

func TestMerge_RedactionOverride(t *testing.T) {
	registrarRDAP := sr(model.SourceRegistrarRDAP, true)
	registrarRDAP.Registrar.Name = "REDACTED FOR PRIVACY"
	registrarRDAP.RedactedFields[model.FieldRegistrarName] = true

	registryWHOIS := sr(model.SourceRegistryWHOIS, true)
	registryWHOIS.Registrar.Name = "Real Registrar Name"

	rec := Merge([]model.SourceRecord{registrarRDAP, registryWHOIS})

	if rec.Registrar.Name.Value != "Real Registrar Name" {
		t.Errorf("Registrar.Name = %q, want %q (populated value should win over a redacted higher-precedence source)", rec.Registrar.Name.Value, "Real Registrar Name")
	}
	if len(rec.Redacted) != 1 || rec.Redacted[0].Source != model.SourceRegistrarRDAP || rec.Redacted[0].Field != model.FieldRegistrarName {
		t.Errorf("Redacted = %+v, want one notice for registrar-rdap on registrar.name", rec.Redacted)
	}
}

func TestMerge_ScalarAgreement(t *testing.T) {
	a := sr(model.SourceRegistrarRDAP, true)
	a.Registrar.Name = "Same Corp"
	b := sr(model.SourceRegistryWHOIS, true)
	b.Registrar.Name = "Same Corp"

	rec := Merge([]model.SourceRecord{a, b})

	if rec.Registrar.Name.Value != "Same Corp" {
		t.Errorf("Registrar.Name = %q, want %q", rec.Registrar.Name.Value, "Same Corp")
	}
	if len(rec.Registrar.Name.Sources) != 2 {
		t.Errorf("Registrar.Name.Sources = %v, want 2 agreeing sources", rec.Registrar.Name.Sources)
	}
	if len(rec.Conflicts) != 0 {
		t.Errorf("Conflicts = %+v, want none", rec.Conflicts)
	}
}

func TestMerge_TimestampWithinTolerance(t *testing.T) {
	rdapTime, _ := time.Parse(time.RFC3339, "2026-08-13T04:00:00Z")
	whoisTime, _ := time.Parse("2006-01-02", "2026-08-13")

	registry := sr(model.SourceRegistryRDAP, true)
	registry.Expires = model.TimeValue{Time: rdapTime, Raw: "2026-08-13T04:00:00Z", Parsed: true}
	whois := sr(model.SourceRegistryWHOIS, true)
	whois.Expires = model.TimeValue{Time: whoisTime, Raw: "2026-08-13", Parsed: true}

	rec := Merge([]model.SourceRecord{registry, whois})

	if rec.Expires.Value.Raw != "2026-08-13T04:00:00Z" {
		t.Errorf("Expires.Value.Raw = %q, want the higher-precedence registry-rdap value", rec.Expires.Value.Raw)
	}
	if len(rec.Conflicts) != 0 {
		t.Errorf("Conflicts = %+v, want none (dates are within 24h tolerance)", rec.Conflicts)
	}
}

func TestMerge_TimestampBeyondTolerance(t *testing.T) {
	rdapTime, _ := time.Parse(time.RFC3339, "2026-08-13T04:00:00Z")
	whoisTime, _ := time.Parse("2006-01-02", "2026-08-10")

	registry := sr(model.SourceRegistryRDAP, true)
	registry.Expires = model.TimeValue{Time: rdapTime, Raw: "2026-08-13T04:00:00Z", Parsed: true}
	whois := sr(model.SourceRegistryWHOIS, true)
	whois.Expires = model.TimeValue{Time: whoisTime, Raw: "2026-08-10", Parsed: true}

	rec := Merge([]model.SourceRecord{registry, whois})

	if rec.Expires.Value.Raw != "2026-08-13T04:00:00Z" {
		t.Errorf("Expires.Value.Raw = %q, want the higher-precedence value kept despite the conflict", rec.Expires.Value.Raw)
	}
	if len(rec.Conflicts) != 1 || rec.Conflicts[0].Field != model.FieldExpires {
		t.Fatalf("Conflicts = %+v, want exactly one expires conflict", rec.Conflicts)
	}
	if len(rec.Conflicts[0].Values) != 2 {
		t.Errorf("Conflict Values = %v, want both sources' raw dates listed", rec.Conflicts[0].Values)
	}
}

func TestMerge_UnparsedDateNeverConflicts(t *testing.T) {
	rdapTime, _ := time.Parse(time.RFC3339, "2026-08-13T04:00:00Z")

	registry := sr(model.SourceRegistryRDAP, true)
	registry.Expires = model.TimeValue{Time: rdapTime, Raw: "2026-08-13T04:00:00Z", Parsed: true}
	whois := sr(model.SourceRegistryWHOIS, true)
	whois.Expires = model.TimeValue{Raw: "garbage-unparseable-date", Parsed: false}

	rec := Merge([]model.SourceRecord{registry, whois})

	if rec.Expires.Value.Raw != "2026-08-13T04:00:00Z" {
		t.Errorf("Expires.Value.Raw = %q, want the parsed, higher-precedence value", rec.Expires.Value.Raw)
	}
	if len(rec.Conflicts) != 0 {
		t.Errorf("Conflicts = %+v, want none (an unparsed date can't prove disagreement)", rec.Conflicts)
	}
}

func TestMerge_NameserverUnionNoConflict(t *testing.T) {
	a := sr(model.SourceRegistryRDAP, true)
	a.Nameservers = []string{"A.IANA-SERVERS.NET.", "b.iana-servers.net"}
	b := sr(model.SourceRegistryWHOIS, true)
	b.Nameservers = []string{"a.iana-servers.net", "B.IANA-SERVERS.NET"}

	rec := Merge([]model.SourceRecord{a, b})

	if len(rec.Nameservers.Value) != 2 {
		t.Errorf("Nameservers.Value = %v, want 2 entries (case/trailing-dot differences should normalize to the same set)", rec.Nameservers.Value)
	}
	for _, has := range rec.Conflicts {
		if has.Field == model.FieldNameservers {
			t.Errorf("unexpected nameserver conflict: %+v", has)
		}
	}
}

func TestMerge_NameserverGenuineConflict(t *testing.T) {
	a := sr(model.SourceRegistryRDAP, true)
	a.Nameservers = []string{"ns1.example.com", "ns2.example.com"}
	b := sr(model.SourceRegistryWHOIS, true)
	b.Nameservers = []string{"ns1.example.com", "ns3.example.com"}

	rec := Merge([]model.SourceRecord{a, b})

	if len(rec.Nameservers.Value) != 3 {
		t.Errorf("Nameservers.Value = %v, want the 3-entry union", rec.Nameservers.Value)
	}
	found := false
	for _, c := range rec.Conflicts {
		if c.Field == model.FieldNameservers {
			found = true
		}
	}
	if !found {
		t.Error("expected a nameservers conflict since the two sets genuinely differ")
	}
}

func TestMerge_StatusUnionNoConflict(t *testing.T) {
	a := sr(model.SourceRegistryRDAP, true)
	a.Status = []string{"clientTransferProhibited"}
	b := sr(model.SourceRegistryWHOIS, true)
	b.Status = []string{"clientTransferProhibited", "clientUpdateProhibited"}

	rec := Merge([]model.SourceRecord{a, b})

	if len(rec.Status.Value) != 2 {
		t.Errorf("Status.Value = %v, want the 2-entry union", rec.Status.Value)
	}
	for _, c := range rec.Conflicts {
		if c.Field == model.FieldStatus {
			t.Errorf("status differences must not produce a conflict: %+v", c)
		}
	}
}

func TestMerge_ZeroPresentSources(t *testing.T) {
	rec := Merge(nil)
	if rec.Domain.Present() || rec.Registrar.Name.Present() {
		t.Errorf("expected an empty Record from zero sources, got %+v", rec)
	}
}

func TestMerge_AllRedactedFieldStaysEmpty(t *testing.T) {
	a := sr(model.SourceRegistrarRDAP, true)
	a.Registrar.Name = "REDACTED"
	a.RedactedFields[model.FieldRegistrarName] = true

	rec := Merge([]model.SourceRecord{a})

	if rec.Registrar.Name.Present() {
		t.Errorf("Registrar.Name = %+v, want absent (every source was redacted)", rec.Registrar.Name)
	}
	if len(rec.Redacted) != 1 {
		t.Errorf("Redacted = %+v, want one notice", rec.Redacted)
	}
}

func TestMerge_RecordSourcesIncludesEveryAttempt(t *testing.T) {
	ok := sr(model.SourceRegistryRDAP, true)
	failed := model.SourceRecord{Meta: model.SourceResult{Source: model.SourceRegistrarRDAP, OK: false, Err: "connection refused"}, Present: false}

	rec := Merge([]model.SourceRecord{ok, failed})

	if len(rec.Sources) != 2 {
		t.Fatalf("Sources = %+v, want both attempts recorded regardless of success", rec.Sources)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/merge/... -v`
Expected: FAIL — build error, `undefined: Merge` (the `internal/merge` package doesn't exist yet).

- [ ] **Step 3: Write the implementation**

Write `internal/merge/merge.go`:
```go
package merge

import (
	"sort"
	"strings"
	"time"

	"github.com/patramsey/plat/internal/model"
)

const clockSkew = 24 * time.Hour

// Merge combines per-source records into one unified, provenance-
// annotated Record. It is a pure function — no I/O — and never errors: a
// source with no usable data simply doesn't contribute to any field.
func Merge(sources []model.SourceRecord) model.Record {
	rec := model.Record{Contacts: map[model.Role]model.Contact{}}
	for _, s := range sources {
		rec.Sources = append(rec.Sources, s.Meta)
	}

	present := presentSorted(sources)
	st := &mergeState{}

	rec.Domain = st.scalar(model.FieldDomain, scalarCandidates(present, model.FieldDomain, func(s model.SourceRecord) string { return s.Domain }))
	rec.Handle = st.scalar(model.FieldHandle, scalarCandidates(present, model.FieldHandle, func(s model.SourceRecord) string { return s.Handle }))
	rec.Registrar.Name = st.scalar(model.FieldRegistrarName, scalarCandidates(present, model.FieldRegistrarName, func(s model.SourceRecord) string { return s.Registrar.Name }))
	rec.Registrar.IANAID = st.scalar(model.FieldRegistrarIANAID, scalarCandidates(present, model.FieldRegistrarIANAID, func(s model.SourceRecord) string { return s.Registrar.IANAID }))
	rec.Registrar.URL = st.scalar(model.FieldRegistrarURL, scalarCandidates(present, model.FieldRegistrarURL, func(s model.SourceRecord) string { return s.Registrar.URL }))
	rec.Registrar.AbuseEmail = st.scalar(model.FieldRegistrarAbuseEmail, scalarCandidates(present, model.FieldRegistrarAbuseEmail, func(s model.SourceRecord) string { return s.Registrar.AbuseEmail }))
	rec.Registrar.AbusePhone = st.scalar(model.FieldRegistrarAbusePhone, scalarCandidates(present, model.FieldRegistrarAbusePhone, func(s model.SourceRecord) string { return s.Registrar.AbusePhone }))

	rec.Created = st.timestamp(model.FieldCreated, timeCandidates(present, func(s model.SourceRecord) model.TimeValue { return s.Created }))
	rec.Updated = st.timestamp(model.FieldUpdated, timeCandidates(present, func(s model.SourceRecord) model.TimeValue { return s.Updated }))
	rec.Expires = st.timestamp(model.FieldExpires, timeCandidates(present, func(s model.SourceRecord) model.TimeValue { return s.Expires }))

	rec.Nameservers = st.nameservers(present)
	rec.Status = st.status(present)
	rec.DNSSEC = st.dnssec(present)

	for _, s := range present {
		st.redactions = append(st.redactions, s.Redactions...)
	}

	rec.Conflicts = st.conflicts
	rec.Redacted = st.redactions
	return rec
}

type mergeState struct {
	conflicts  []model.Conflict
	redactions []model.RedactionNotice
}

func presentSorted(sources []model.SourceRecord) []model.SourceRecord {
	out := make([]model.SourceRecord, 0, len(sources))
	for _, s := range sources {
		if s.Present {
			out = append(out, s)
		}
	}
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && model.Rank(out[j-1].Meta.Source) > model.Rank(out[j].Meta.Source) {
			out[j-1], out[j] = out[j], out[j-1]
			j--
		}
	}
	return out
}

type scalarCandidate struct {
	Source   model.SourceID
	Value    string
	Redacted bool
}

func scalarCandidates(present []model.SourceRecord, field string, get func(model.SourceRecord) string) []scalarCandidate {
	out := make([]scalarCandidate, len(present))
	for i, s := range present {
		out[i] = scalarCandidate{Source: s.Meta.Source, Value: get(s), Redacted: s.RedactedFields[field]}
	}
	return out
}

// scalar picks the first present, non-empty, non-redacted candidate (in
// precedence order — cands is already sorted) as the winner. A skipped
// higher-precedence redacted candidate generates a RedactionNotice. Every
// present non-redacted candidate whose value matches the winner joins
// Field.Sources; a differing one becomes part of a Conflict.
func (m *mergeState) scalar(field string, cands []scalarCandidate) model.Field[string] {
	var winner *scalarCandidate
	for i := range cands {
		c := &cands[i]
		if c.Value == "" {
			continue
		}
		if c.Redacted {
			if winner == nil {
				m.redactions = append(m.redactions, model.RedactionNotice{Field: field, Source: c.Source, Reason: "redacted"})
			}
			continue
		}
		if winner == nil {
			winner = c
		}
	}
	if winner == nil {
		return model.Field[string]{}
	}

	f := model.Field[string]{Value: winner.Value}
	conflictValues := map[model.SourceID]string{}
	hasConflict := false
	for _, c := range cands {
		if c.Value == "" || c.Redacted {
			continue
		}
		if c.Value == winner.Value {
			f.Sources = append(f.Sources, c.Source)
		} else {
			hasConflict = true
			conflictValues[c.Source] = c.Value
		}
	}
	if hasConflict {
		conflictValues[winner.Source] = winner.Value
		m.conflicts = append(m.conflicts, model.Conflict{Field: field, Values: conflictValues})
	}
	return f
}

type timeCandidate struct {
	Source model.SourceID
	model.TimeValue
}

func timeCandidates(present []model.SourceRecord, get func(model.SourceRecord) model.TimeValue) []timeCandidate {
	out := make([]timeCandidate, len(present))
	for i, s := range present {
		out[i] = timeCandidate{Source: s.Meta.Source, TimeValue: get(s)}
	}
	return out
}

// timestamp picks the first present (non-empty Raw) candidate as the
// winner regardless of whether it parsed. Separately, if any pair of
// present+Parsed candidates differ by more than clockSkew, records one
// Conflict listing every present candidate's Raw value.
func (m *mergeState) timestamp(field string, cands []timeCandidate) model.Field[model.TimeValue] {
	var winner *timeCandidate
	for i := range cands {
		if cands[i].Raw == "" {
			continue
		}
		winner = &cands[i]
		break
	}
	if winner == nil {
		return model.Field[model.TimeValue]{}
	}

	var parsed []timeCandidate
	for _, c := range cands {
		if c.Raw != "" && c.Parsed {
			parsed = append(parsed, c)
		}
	}
	conflictFound := false
	for i := 0; i < len(parsed); i++ {
		for j := i + 1; j < len(parsed); j++ {
			d := parsed[i].Time.Sub(parsed[j].Time)
			if d < 0 {
				d = -d
			}
			if d > clockSkew {
				conflictFound = true
			}
		}
	}
	if conflictFound {
		values := map[model.SourceID]string{}
		for _, c := range cands {
			if c.Raw != "" {
				values[c.Source] = c.Raw
			}
		}
		m.conflicts = append(m.conflicts, model.Conflict{Field: field, Values: values})
	}

	f := model.Field[model.TimeValue]{Value: winner.TimeValue}
	for _, c := range cands {
		if c.Raw != "" {
			f.Sources = append(f.Sources, c.Source)
		}
	}
	return f
}

func normalizeNS(ns string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(ns), "."))
}

// nameservers computes the union of normalized nameserver names across all
// present sources. A Conflict is recorded if two present sources' sets
// (after normalization) are unequal — the merged value stays the union
// either way, since a nameserver a lower-precedence source didn't mention
// isn't necessarily wrong, just possibly stale or incomplete there.
func (m *mergeState) nameservers(present []model.SourceRecord) model.Field[[]string] {
	unionSeen := map[string]bool{}
	var order []string
	var contributors []model.SourceID
	sourceSets := map[model.SourceID]map[string]bool{}

	for _, s := range present {
		if len(s.Nameservers) == 0 {
			continue
		}
		contributors = append(contributors, s.Meta.Source)
		set := map[string]bool{}
		for _, ns := range s.Nameservers {
			n := normalizeNS(ns)
			set[n] = true
			if !unionSeen[n] {
				unionSeen[n] = true
				order = append(order, n)
			}
		}
		sourceSets[s.Meta.Source] = set
	}

	if len(contributors) == 0 {
		return model.Field[[]string]{}
	}

	conflictFound := false
	for i := 0; i < len(contributors); i++ {
		for j := i + 1; j < len(contributors); j++ {
			if !setsEqual(sourceSets[contributors[i]], sourceSets[contributors[j]]) {
				conflictFound = true
			}
		}
	}
	if conflictFound {
		values := map[model.SourceID]string{}
		for src, set := range sourceSets {
			values[src] = strings.Join(sortedKeys(set), ", ")
		}
		m.conflicts = append(m.conflicts, model.Conflict{Field: model.FieldNameservers, Values: values})
	}

	return model.Field[[]string]{Value: order, Sources: contributors}
}

func setsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// status unions the (already EPP-normalized by the adapter) status codes
// across all present sources. Differing status sets are NOT treated as a
// Conflict — thick vs. thin registries legitimately report different
// status vocabularies for the same domain, so a set difference here isn't
// evidence of disagreement the way a differing nameserver or expiry is.
func (m *mergeState) status(present []model.SourceRecord) model.Field[[]string] {
	seen := map[string]bool{}
	var order []string
	var contributors []model.SourceID
	for _, s := range present {
		if len(s.Status) == 0 {
			continue
		}
		contributors = append(contributors, s.Meta.Source)
		for _, st := range s.Status {
			if st == "" || seen[st] {
				continue
			}
			seen[st] = true
			order = append(order, st)
		}
	}
	if len(contributors) == 0 {
		return model.Field[[]string]{}
	}
	return model.Field[[]string]{Value: order, Sources: contributors}
}

// dnssec picks the first present source that expressed an opinion
// (DNSSEC != nil), by precedence. Present-and-differing sources are
// treated as a Conflict, same as any other scalar.
func (m *mergeState) dnssec(present []model.SourceRecord) model.Field[bool] {
	var winner *model.SourceRecord
	for i := range present {
		if present[i].DNSSEC != nil {
			winner = &present[i]
			break
		}
	}
	if winner == nil {
		return model.Field[bool]{}
	}
	f := model.Field[bool]{Value: *winner.DNSSEC}
	conflictValues := map[model.SourceID]string{}
	hasConflict := false
	for _, s := range present {
		if s.DNSSEC == nil {
			continue
		}
		if *s.DNSSEC == *winner.DNSSEC {
			f.Sources = append(f.Sources, s.Meta.Source)
		} else {
			hasConflict = true
			conflictValues[s.Meta.Source] = boolStr(*s.DNSSEC)
		}
	}
	if hasConflict {
		conflictValues[winner.Meta.Source] = boolStr(*winner.DNSSEC)
		m.conflicts = append(m.conflicts, model.Conflict{Field: model.FieldDNSSEC, Values: conflictValues})
	}
	return f
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./internal/merge/... -v`
Expected: PASS, all 13 test functions green.

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/merge/merge.go internal/merge/merge_test.go
git commit -m "feat: add the pure merge engine (precedence, redaction override, conflicts)"
```

---

### Task 7: `internal/collect` — Adapters (`FromRDAP`, `FromWHOIS`)

**Files:**
- Create: `internal/collect/adapt_rdap.go`
- Create: `internal/collect/adapt_whois.go`
- Create: `testdata/rdap/registrar-example.json`
- Create: `testdata/whois/gdpr-redacted-de.txt`
- Test: `internal/collect/adapt_rdap_test.go`
- Test: `internal/collect/adapt_whois_test.go`

**Interfaces:**
- Consumes: `model.SourceRecord`/`model.SourceID`/`model.NormalizeEPPStatus`/`model.IsRedactedPlaceholder`/`model.TimeValue` (Tasks 1-2), `rdap.Result`/`rdap.DomainResponse` (M1 + Tasks 3/5), `whois.Result`/`whois.Hop` (M2), `parse.Parse`/`parse.Fields` (M2, used only in tests to build a `whois.Result` from raw text).
- Produces: `func FromRDAP(src model.SourceID, result *rdap.Result, latency time.Duration, fetchErr error) model.SourceRecord`, `func FromWHOIS(result *whois.Result) []model.SourceRecord` — consumed by `internal/collect`'s orchestration (Task 8).

- [ ] **Step 1: Create the fixtures**

Write `testdata/rdap/registrar-example.json`:
```json
{
  "objectClassName": "domain",
  "handle": "REG-2336799",
  "ldhName": "EXAMPLE.COM",
  "unicodeName": "example.com",
  "status": ["clientTransferProhibited"],
  "events": [
    {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
    {"eventAction": "last changed", "eventDate": "2025-08-14T07:01:31Z"},
    {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"}
  ],
  "nameservers": [
    {"objectClassName": "nameserver", "ldhName": "a.iana-servers.net"},
    {"objectClassName": "nameserver", "ldhName": "b.iana-servers.net"}
  ],
  "entities": [
    {
      "objectClassName": "entity",
      "handle": "1234",
      "roles": ["registrar"],
      "vcardArray": [
        "vcard",
        [
          ["version", {}, "text", "4.0"],
          ["fn", {}, "text", "Example Registrar, Inc."]
        ]
      ]
    },
    {
      "objectClassName": "entity",
      "roles": ["abuse"],
      "vcardArray": [
        "vcard",
        [
          ["version", {}, "text", "4.0"],
          ["fn", {}, "text", "Abuse Team"],
          ["email", {}, "text", "abuse@example-registrar.example"],
          ["tel", {}, "text", "+1.5555550100"]
        ]
      ]
    },
    {
      "objectClassName": "entity",
      "roles": ["registrant"],
      "vcardArray": [
        "vcard",
        [
          ["version", {}, "text", "4.0"],
          ["fn", {}, "text", "REDACTED FOR PRIVACY"]
        ]
      ]
    }
  ],
  "remarks": [
    {
      "title": "REDACTED FOR PRIVACY",
      "type": "object redacted due to authorization",
      "description": ["Some of the data in this object has been removed to protect personal information."]
    }
  ]
}
```

Write `testdata/whois/gdpr-redacted-de.txt`:
```
Domain: example.de
Nserver: ns1.example.de
Nserver: ns2.example.de
Status: connect
Changed: 2025-08-14T07:01:31+02:00
Registrar: REDACTED FOR PRIVACY
```

- [ ] **Step 2: Write the failing tests**

Write `internal/collect/adapt_rdap_test.go`:
```go
package collect

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/rdap"
)

func loadRDAPFixture(t *testing.T, name string) *rdap.DomainResponse {
	t.Helper()
	b, err := os.ReadFile("../../testdata/rdap/" + name)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	var d rdap.DomainResponse
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("unmarshaling fixture %s: %v", name, err)
	}
	return &d
}

func TestFromRDAP_RegistryFixture(t *testing.T) {
	d := loadRDAPFixture(t, "com-example.json")
	result := &rdap.Result{Domain: d, Raw: []byte("raw bytes")}

	sr := FromRDAP(model.SourceRegistryRDAP, result, 50*time.Millisecond, nil)

	if !sr.Present {
		t.Fatal("expected Present = true")
	}
	if sr.Meta.Source != model.SourceRegistryRDAP {
		t.Errorf("Meta.Source = %q, want %q", sr.Meta.Source, model.SourceRegistryRDAP)
	}
	if !sr.Meta.OK {
		t.Error("Meta.OK = false, want true")
	}
	if sr.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q (unicode name preferred)", sr.Domain, "example.com")
	}
	wantStatuses := []string{"clientDeleteProhibited", "clientTransferProhibited", "clientUpdateProhibited"}
	if len(sr.Status) != len(wantStatuses) {
		t.Fatalf("Status = %v, want %v (EPP-normalized from Verisign's spaced form)", sr.Status, wantStatuses)
	}
	for i, want := range wantStatuses {
		if sr.Status[i] != want {
			t.Errorf("Status[%d] = %q, want %q", i, sr.Status[i], want)
		}
	}
	if !sr.Created.Parsed || sr.Created.Raw != "1995-08-14T04:00:00Z" {
		t.Errorf("Created = %+v", sr.Created)
	}
	if len(sr.Nameservers) != 2 {
		t.Errorf("Nameservers = %v, want 2 entries", sr.Nameservers)
	}
}

func TestFromRDAP_RegistrarFixtureWithEntities(t *testing.T) {
	d := loadRDAPFixture(t, "registrar-example.json")
	result := &rdap.Result{Domain: d, Raw: []byte("raw bytes")}

	sr := FromRDAP(model.SourceRegistrarRDAP, result, 30*time.Millisecond, nil)

	if sr.Registrar.Name != "Example Registrar, Inc." {
		t.Errorf("Registrar.Name = %q, want %q", sr.Registrar.Name, "Example Registrar, Inc.")
	}
	if sr.Registrar.AbuseEmail != "abuse@example-registrar.example" {
		t.Errorf("Registrar.AbuseEmail = %q, want %q", sr.Registrar.AbuseEmail, "abuse@example-registrar.example")
	}
	if sr.Registrar.AbusePhone != "+1.5555550100" {
		t.Errorf("Registrar.AbusePhone = %q, want %q", sr.Registrar.AbusePhone, "+1.5555550100")
	}
	if len(sr.Redactions) != 1 {
		t.Errorf("Redactions = %+v, want one entry from the top-level REDACTED FOR PRIVACY remark", sr.Redactions)
	}
}

func TestFromRDAP_FetchError(t *testing.T) {
	sr := FromRDAP(model.SourceRegistrarRDAP, nil, 10*time.Millisecond, rdap.ErrDomainNotFound)

	if sr.Present {
		t.Error("expected Present = false on a fetch error")
	}
	if sr.Meta.OK {
		t.Error("expected Meta.OK = false on a fetch error")
	}
	if sr.Meta.Err == "" {
		t.Error("expected a non-empty Meta.Err")
	}
}

func TestFromRDAP_NilDomain(t *testing.T) {
	result := &rdap.Result{Domain: nil, Raw: []byte("some bytes")}
	sr := FromRDAP(model.SourceRegistryRDAP, result, 10*time.Millisecond, nil)

	if sr.Present {
		t.Error("expected Present = false when Domain is nil even with no error")
	}
}
```

Write `internal/collect/adapt_whois_test.go`:
```go
package collect

import (
	"os"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/whois"
	"github.com/patramsey/plat/internal/whois/parse"
)

func loadWHOISFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../testdata/whois/" + name)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return string(b)
}

func TestFromWHOIS_RegistryAndRegistrarHops(t *testing.T) {
	registryRaw := loadWHOISFixture(t, "verisign-com-example.txt")
	registrarRaw := "Domain Name: example.com\nRegistrant Organization: Example Corp\nRegistrar: Example Registrar, Inc.\n"

	result := &whois.Result{
		Domain: "example.com",
		Hops: []whois.Hop{
			{Server: "whois.iana.org", Latency: 5 * time.Millisecond}, // IANA hop — not a data source
			{Server: "whois.verisign-grs.com", Raw: registryRaw, Fields: parse.Parse(registryRaw, "com"), Latency: 20 * time.Millisecond},
			{Server: "whois.example-registrar.example", Raw: registrarRaw, Fields: parse.Parse(registrarRaw, "com"), Latency: 15 * time.Millisecond},
		},
	}

	sources := FromWHOIS(result)

	if len(sources) != 2 {
		t.Fatalf("FromWHOIS returned %d sources, want 2 (IANA hop skipped)", len(sources))
	}
	if sources[0].Meta.Source != model.SourceRegistryWHOIS {
		t.Errorf("sources[0].Meta.Source = %q, want %q", sources[0].Meta.Source, model.SourceRegistryWHOIS)
	}
	if sources[1].Meta.Source != model.SourceRegistrarWHOIS {
		t.Errorf("sources[1].Meta.Source = %q, want %q", sources[1].Meta.Source, model.SourceRegistrarWHOIS)
	}
	if sources[0].Registrar.IANAID != "1234" {
		t.Errorf("registry hop Registrar.IANAID = %q, want %q (read from Fields.Unmapped)", sources[0].Registrar.IANAID, "1234")
	}
	if sources[0].Registrar.AbuseEmail != "abuse@example-registrar.example" {
		t.Errorf("registry hop Registrar.AbuseEmail = %q, want %q", sources[0].Registrar.AbuseEmail, "abuse@example-registrar.example")
	}
	if sources[1].Registrar.Name != "Example Registrar, Inc." {
		t.Errorf("registrar hop Registrar.Name = %q, want %q", sources[1].Registrar.Name, "Example Registrar, Inc.")
	}
}

func TestFromWHOIS_RedactedRegistrant(t *testing.T) {
	raw := loadWHOISFixture(t, "gdpr-redacted-de.txt")
	result := &whois.Result{
		Domain: "example.de",
		Hops: []whois.Hop{
			{Server: "whois.iana.org"},
			{Server: "whois.denic.de", Raw: raw, Fields: parse.Parse(raw, "de")},
		},
	}

	sources := FromWHOIS(result)
	if len(sources) != 1 {
		t.Fatalf("FromWHOIS returned %d sources, want 1 (registry hop only)", len(sources))
	}
	if sources[0].Registrar.Name != "" {
		t.Errorf("Registrar.Name = %q, want empty (value should be redacted, not surfaced)", sources[0].Registrar.Name)
	}
	if !sources[0].RedactedFields[model.FieldRegistrarName] {
		t.Error("expected RedactedFields[registrar.name] = true")
	}
}

func TestFromWHOIS_HopError(t *testing.T) {
	result := &whois.Result{
		Domain: "example.com",
		Hops: []whois.Hop{
			{Server: "whois.iana.org"},
			{Server: "whois.verisign-grs.com", Err: errDeadline},
		},
	}
	sources := FromWHOIS(result)
	if len(sources) != 1 {
		t.Fatalf("FromWHOIS returned %d sources, want 1", len(sources))
	}
	if sources[0].Present {
		t.Error("expected Present = false for a failed hop")
	}
	if sources[0].Meta.OK {
		t.Error("expected Meta.OK = false for a failed hop")
	}
}

func TestFromWHOIS_TooFewHops(t *testing.T) {
	if got := FromWHOIS(&whois.Result{Hops: []whois.Hop{{Server: "whois.iana.org"}}}); len(got) != 0 {
		t.Errorf("FromWHOIS with only an IANA hop = %v, want empty", got)
	}
	if got := FromWHOIS(nil); len(got) != 0 {
		t.Errorf("FromWHOIS(nil) = %v, want empty", got)
	}
}
```

At the top of `internal/collect/adapt_whois_test.go`, also add this package-level var (used by `TestFromWHOIS_HopError` above) right after the imports:
```go
var errDeadline = context.DeadlineExceeded
```
This requires adding `"context"` to that test file's import block.

- [ ] **Step 3: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/collect/... -v`
Expected: FAIL — build error, `undefined: FromRDAP` / `undefined: FromWHOIS` (the `internal/collect` package doesn't exist yet).

- [ ] **Step 4: Write the implementation**

Write `internal/collect/adapt_rdap.go`:
```go
package collect

import (
	"time"

	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/rdap"
)

// FromRDAP adapts an RDAP client result into a model.SourceRecord tagged
// as src (SourceRegistryRDAP or SourceRegistrarRDAP — the caller decides
// which, since the same DomainResponse shape serves both hops).
//
// Registrar identity is populated only from the shallow jCard fields
// (RegistrarEntity's "fn", AbuseEntity's "email"/"tel") — IANA ID and URL
// are not extracted from RDAP in M3 (that would require parsing the
// entity's publicIds array, out of scope for this milestone's "shallow"
// jCard reading); those fields are populated from WHOIS only, if at all.
func FromRDAP(src model.SourceID, result *rdap.Result, latency time.Duration, fetchErr error) model.SourceRecord {
	meta := model.SourceResult{Source: src, Latency: latency}
	if result != nil {
		meta.Raw = result.Raw
	}
	if fetchErr != nil {
		meta.OK = false
		meta.Err = fetchErr.Error()
		return model.SourceRecord{Meta: meta}
	}
	if result == nil || result.Domain == nil {
		meta.OK = false
		return model.SourceRecord{Meta: meta}
	}
	meta.OK = true
	d := result.Domain

	sr := model.SourceRecord{
		Meta:           meta,
		Present:        true,
		Handle:         d.Handle,
		RedactedFields: map[string]bool{},
	}
	if d.UnicodeName != "" {
		sr.Domain = d.UnicodeName
	} else {
		sr.Domain = d.LDHName
	}

	for _, st := range d.Status {
		sr.Status = append(sr.Status, model.NormalizeEPPStatus(st))
	}

	if created, ok := d.Created(); ok {
		sr.Created = model.TimeValue{Time: created.Time, Raw: created.Raw, Parsed: created.Parsed}
	}
	if updated, ok := d.Updated(); ok {
		sr.Updated = model.TimeValue{Time: updated.Time, Raw: updated.Raw, Parsed: updated.Parsed}
	}
	if expires, ok := d.Expires(); ok {
		sr.Expires = model.TimeValue{Time: expires.Time, Raw: expires.Raw, Parsed: expires.Parsed}
	}

	for _, ns := range d.Nameservers {
		name := ns.LDHName
		if ns.UnicodeName != "" {
			name = ns.UnicodeName
		}
		if name != "" {
			sr.Nameservers = append(sr.Nameservers, name)
		}
	}

	if regEntity, ok := d.RegistrarEntity(); ok {
		sr.Registrar.Name = regEntity.VCardArray.FullName
		if model.IsRedactedPlaceholder(sr.Registrar.Name) {
			sr.RedactedFields[model.FieldRegistrarName] = true
		}
	}
	if abuseEntity, ok := d.AbuseEntity(); ok {
		sr.Registrar.AbuseEmail = abuseEntity.VCardArray.Email
		sr.Registrar.AbusePhone = abuseEntity.VCardArray.Tel
	}

	for _, rem := range d.RedactionRemarks() {
		sr.Redactions = append(sr.Redactions, model.RedactionNotice{
			Field:  "unknown",
			Source: src,
			Reason: rem.Title,
		})
	}

	return sr
}
```

Write `internal/collect/adapt_whois.go`:
```go
package collect

import (
	"strings"

	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/whois"
)

// FromWHOIS adapts a WHOIS lookup's hop chain into per-hop
// model.SourceRecords. It skips Hops[0] (the IANA referral hop — never a
// data source, per whois.Client.Lookup's documented hop order) and maps
// the registry hop (Hops[1], if present) to SourceRegistryWHOIS and the
// registrar hop (Hops[2], if present) to SourceRegistrarWHOIS.
func FromWHOIS(result *whois.Result) []model.SourceRecord {
	if result == nil || len(result.Hops) < 2 {
		return nil
	}
	var out []model.SourceRecord
	out = append(out, fromHop(model.SourceRegistryWHOIS, result.Hops[1]))
	if len(result.Hops) >= 3 {
		out = append(out, fromHop(model.SourceRegistrarWHOIS, result.Hops[2]))
	}
	return out
}

func fromHop(src model.SourceID, hop whois.Hop) model.SourceRecord {
	meta := model.SourceResult{
		Source:  src,
		Latency: hop.Latency,
		Raw:     []byte(hop.Raw),
	}
	if hop.Err != nil {
		meta.OK = false
		meta.Err = hop.Err.Error()
		return model.SourceRecord{Meta: meta}
	}
	meta.OK = true
	f := hop.Fields

	sr := model.SourceRecord{
		Meta:           meta,
		Present:        true,
		Domain:         f.Domain,
		RedactedFields: map[string]bool{},
	}

	if model.IsRedactedPlaceholder(f.Registrar) {
		sr.RedactedFields[model.FieldRegistrarName] = true
	} else {
		sr.Registrar.Name = f.Registrar
	}

	for _, st := range f.Statuses {
		sr.Status = append(sr.Status, model.NormalizeEPPStatus(st))
	}

	sr.Created = model.TimeValue{Time: f.Created.Time, Raw: f.Created.Raw, Parsed: f.Created.Parsed}
	sr.Updated = model.TimeValue{Time: f.Updated.Time, Raw: f.Updated.Raw, Parsed: f.Updated.Parsed}
	sr.Expires = model.TimeValue{Time: f.Expires.Time, Raw: f.Expires.Raw, Parsed: f.Expires.Parsed}
	sr.Nameservers = append(sr.Nameservers, f.Nameservers...)

	if v, ok := firstUnmapped(f.Unmapped, "registrar iana id"); ok {
		sr.Registrar.IANAID = v
	}
	if v, ok := firstUnmapped(f.Unmapped, "registrar url"); ok {
		sr.Registrar.URL = v
	}
	if v, ok := firstUnmapped(f.Unmapped, "registrar abuse contact email"); ok {
		sr.Registrar.AbuseEmail = v
	}
	if v, ok := firstUnmapped(f.Unmapped, "registrar abuse contact phone"); ok {
		sr.Registrar.AbusePhone = v
	}
	if v, ok := firstUnmapped(f.Unmapped, "dnssec"); ok {
		signed := strings.EqualFold(strings.TrimSpace(v), "signed")
		sr.DNSSEC = &signed
	}

	return sr
}

func firstUnmapped(m map[string][]string, key string) (string, bool) {
	vals, ok := m[key]
	if !ok || len(vals) == 0 {
		return "", false
	}
	return vals[0], true
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./internal/collect/... -v`
Expected: PASS, all subtests in both test files green.

- [ ] **Step 6: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/collect/adapt_rdap.go internal/collect/adapt_whois.go internal/collect/adapt_rdap_test.go internal/collect/adapt_whois_test.go testdata/rdap/registrar-example.json testdata/whois/gdpr-redacted-de.txt
git commit -m "feat: add RDAP and WHOIS to model.SourceRecord adapters"
```

---

### Task 8: `internal/collect` — Orchestration (`Collect`)

**Files:**
- Create: `internal/collect/collect.go`
- Test: `internal/collect/collect_test.go`

**Interfaces:**
- Consumes: `FromRDAP`/`FromWHOIS` (Task 7), `rdap.Client`/`rdap.Client.Domain`/`rdap.Client.DomainURL`/`DomainResponse.RelatedRegistrarURL` (M1 + Tasks 3-4), `whois.Client`/`whois.Client.Lookup` (M2), `domain.Name` (M1).
- Produces: `type Options struct{ NoFollow bool; Timeout time.Duration }`, `func Collect(ctx context.Context, name domain.Name, registryBaseURL string, opts Options) []model.SourceRecord` — consumed by `cmd/plat`'s merge subcommand (Task 9).

- [ ] **Step 1: Write the failing test**

Write `internal/collect/collect_test.go`:
```go
package collect

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/domain"
)

func startWHOISListener(t *testing.T, respond func(query string) string) string {
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
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		query := strings.TrimRight(string(buf[:n]), "\r\n")
		_, _ = conn.Write([]byte(respond(query)))
	}()
	return ln.Addr().String()
}

func TestCollect_RegistryAndRegistrarRDAPPlusWHOIS(t *testing.T) {
	registryFixture, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	registrarFixture, err := os.ReadFile("../../testdata/rdap/registrar-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	registrarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(registrarFixture)
	}))
	defer registrarSrv.Close()

	registrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve the registry fixture, but with a "related" link injected
		// pointing at the registrar test server (whose address is only
		// known once it's started, so we can't bake this into a static
		// fixture file).
		body := strings.Replace(
			string(registryFixture),
			`"rdapConformance"`,
			fmt.Sprintf(`"links":[{"rel":"related","href":%q,"type":"application/rdap+json"}],"rdapConformance"`, registrarSrv.URL+"/rdap/domain/EXAMPLE.COM"),
			1,
		)
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer registrySrv.Close()

	registrarWHOISAddr := startWHOISListener(t, func(query string) string {
		return "Domain Name: example.com\nRegistrar: Example Registrar, Inc.\n"
	})
	registryWHOISAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: %s\nRegistrar: Example Registrar, Inc.\n", registrarWHOISAddr)
	})
	ianaWHOISAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("refer:        %s\ndomain:       COM\n", registryWHOISAddr)
	})

	// Point Collect's WHOIS client at the fake IANA server by using an
	// unexported test seam is not available across packages, so this
	// test instead verifies RDAP orchestration (registry + registrar hop
	// following) directly, and verifies WHOIS orchestration separately
	// via TestCollect_WHOISOnly below using a real domain.Normalize name
	// — Collect always attempts WHOIS with its own default IANA server,
	// which is out of scope to fake from this package. Skip verifying
	// the live WHOIS server list here; assert only on the RDAP portion.

	name, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	sources := Collect(context.Background(), name, registrySrv.URL, Options{Timeout: 2 * time.Second})

	var gotRegistryRDAP, gotRegistrarRDAP bool
	for _, s := range sources {
		if s.Meta.Source == "registry-rdap" && s.Present {
			gotRegistryRDAP = true
		}
		if s.Meta.Source == "registrar-rdap" && s.Present {
			gotRegistrarRDAP = true
			if s.Registrar.Name != "Example Registrar, Inc." {
				t.Errorf("registrar-rdap Registrar.Name = %q, want %q", s.Registrar.Name, "Example Registrar, Inc.")
			}
		}
	}
	if !gotRegistryRDAP {
		t.Error("expected a present registry-rdap source")
	}
	if !gotRegistrarRDAP {
		t.Error("expected a present registrar-rdap source (related link should have been followed)")
	}
}

func TestCollect_NoFollowSkipsRegistrarHop(t *testing.T) {
	registrarFixture, err := os.ReadFile("../../testdata/rdap/registrar-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	registrarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("registrar server should not have been contacted when NoFollow is set")
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(registrarFixture)
	}))
	defer registrarSrv.Close()

	registryFixture, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	registrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := strings.Replace(
			string(registryFixture),
			`"rdapConformance"`,
			fmt.Sprintf(`"links":[{"rel":"related","href":%q,"type":"application/rdap+json"}],"rdapConformance"`, registrarSrv.URL+"/rdap/domain/EXAMPLE.COM"),
			1,
		)
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer registrySrv.Close()

	name, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	sources := Collect(context.Background(), name, registrySrv.URL, Options{NoFollow: true, Timeout: 2 * time.Second})

	for _, s := range sources {
		if s.Meta.Source == "registrar-rdap" {
			t.Errorf("expected no registrar-rdap source when NoFollow is set, got %+v", s)
		}
	}
}

func TestCollect_EmptyBaseURLSkipsRDAPEntirely(t *testing.T) {
	name, err := domain.Normalize("example.zz")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	sources := Collect(context.Background(), name, "", Options{Timeout: 500 * time.Millisecond})

	for _, s := range sources {
		if s.Meta.Source == "registry-rdap" || s.Meta.Source == "registrar-rdap" {
			t.Errorf("expected no RDAP sources when registryBaseURL is empty, got %+v", s)
		}
	}
}
```

Note: `TestCollect_RegistryAndRegistrarRDAPPlusWHOIS` and `TestCollect_NoFollowSkipsRegistrarHop` both cause `Collect` to also attempt a real WHOIS lookup against the default `whois.iana.org` (since `Collect` has no seam to redirect the WHOIS client to a fake IANA server from this package — `whois.Client.IANAServer` is a real field, but this test doesn't set it, matching the plan's "WHOIS orchestration is already thoroughly tested in M2, this task only needs to prove RDAP related-link following" scope). This means these two tests make a real network call to `whois.iana.org` as a side effect and are NOT fully offline. **This is a real gap the implementer must fix**: refactor `Collect`'s signature to accept the `whois.Client` (or at least its `IANAServer`) as a parameter, alongside `registryBaseURL`, so tests can point it at `ianaWHOISAddr` (already set up above but currently unused) exactly the way M2's own tests did. Update `Collect`'s signature to `func Collect(ctx context.Context, name domain.Name, registryBaseURL string, whoisIANAServer string, opts Options) []model.SourceRecord`, wire `ianaWHOISAddr` into both RDAP tests above (pass it as the new parameter), and add a `TestCollect_WHOISOnly` test using only the three WHOIS listeners (no RDAP servers, `registryBaseURL: ""`) asserting `registry-whois`/`registrar-whois` sources are present. Do this as part of Step 4's implementation, not as a follow-up — a test suite with a live network call in it is not actually done.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/collect/... -v`
Expected: FAIL — build error, `undefined: Collect` / `undefined: Options`.

- [ ] **Step 3: Write the implementation**

Write `internal/collect/collect.go`:
```go
package collect

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/patramsey/plat/internal/domain"
	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/rdap"
	"github.com/patramsey/plat/internal/whois"
)

// Options controls Collect's behavior.
type Options struct {
	// NoFollow skips the registrar RDAP related-link hop even if the
	// registry response advertises one.
	NoFollow bool
	// Timeout bounds each individual fetch (registry RDAP, registrar
	// RDAP, and the whole WHOIS chain).
	Timeout time.Duration
}

// Collect fans out to registry RDAP (and, unless NoFollow, the registrar
// RDAP hop via the registry's "related" link) and the WHOIS chain, and
// returns one model.SourceRecord per source actually attempted.
// registryBaseURL is the already-resolved RDAP service base for the
// domain's TLD (empty string means no RDAP coverage — Collect degrades to
// WHOIS-only). whoisIANAServer overrides the WHOIS client's IANA server
// (empty string uses whois.Client's own "whois.iana.org" default) — this
// parameter exists so tests can point the WHOIS chain at a local fake
// IANA server, the same way internal/whois's own tests do.
//
// A single source failing is normal, not fatal — Collect never returns an
// error; callers pass the (possibly partial) result straight to
// merge.Merge.
func Collect(ctx context.Context, name domain.Name, registryBaseURL string, whoisIANAServer string, opts Options) []model.SourceRecord {
	var out []model.SourceRecord

	if registryBaseURL != "" {
		rdapClient := &rdap.Client{Timeout: opts.Timeout}
		start := time.Now()
		result, err := rdapClient.Domain(ctx, registryBaseURL, name.Punycode)
		out = append(out, FromRDAP(model.SourceRegistryRDAP, result, time.Since(start), err))

		if !opts.NoFollow && err == nil && result.Domain != nil {
			if registrarURL, ok := result.Domain.RelatedRegistrarURL(); ok && differentHost(registryBaseURL, registrarURL) {
				rStart := time.Now()
				rResult, rErr := rdapClient.DomainURL(ctx, registrarURL)
				out = append(out, FromRDAP(model.SourceRegistrarRDAP, rResult, time.Since(rStart), rErr))
			}
		}
	}

	whoisClient := &whois.Client{Timeout: opts.Timeout, IANAServer: whoisIANAServer}
	wResult, _ := whoisClient.Lookup(ctx, name)
	out = append(out, FromWHOIS(wResult)...)

	return out
}

// differentHost reports whether registrarURL points at a DIFFERENT host
// than registryBaseURL — a loop guard against a registry advertising
// itself as its own registrar, or a misconfigured related link pointing
// back at the same server. Any URL parse failure is treated as "same
// host" (i.e. skip) — DomainURL itself would also reject a genuinely
// malformed or non-http(s) URL, but there's no reason to attempt a fetch
// this function already can't make sense of.
func differentHost(registryBaseURL, registrarURL string) bool {
	rb, err1 := url.Parse(registryBaseURL)
	ru, err2 := url.Parse(registrarURL)
	if err1 != nil || err2 != nil {
		return false
	}
	return !strings.EqualFold(rb.Hostname(), ru.Hostname())
}
```

Now update the test file to use the new 5-argument `Collect` signature and add the offline-only WHOIS test, per the Step 1 note. In `internal/collect/collect_test.go`, change both existing `Collect(...)` calls to pass `ianaWHOISAddr` as the new 4th argument:
```go
sources := Collect(context.Background(), name, registrySrv.URL, ianaWHOISAddr, Options{Timeout: 2 * time.Second})
```
and
```go
sources := Collect(context.Background(), name, registrySrv.URL, ianaWHOISAddr, Options{NoFollow: true, Timeout: 2 * time.Second})
```
And update `TestCollect_EmptyBaseURLSkipsRDAPEntirely` similarly — but since that test doesn't set up WHOIS listeners at all, its `Collect` call would otherwise hit the real network too. Fix it to also be fully offline by adding a WHOIS listener chain:
```go
func TestCollect_EmptyBaseURLSkipsRDAPEntirely(t *testing.T) {
	registrarAddr := startWHOISListener(t, func(query string) string {
		return "Domain Name: example.zz\nRegistrar: Example Registrar\n"
	})
	registryAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("Domain Name: EXAMPLE.ZZ\nRegistrar WHOIS Server: %s\nRegistrar: Example Registrar\n", registrarAddr)
	})
	ianaAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("refer:        %s\ndomain:       ZZ\n", registryAddr)
	})

	name, err := domain.Normalize("example.zz")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	sources := Collect(context.Background(), name, "", ianaAddr, Options{Timeout: 2 * time.Second})

	for _, s := range sources {
		if s.Meta.Source == "registry-rdap" || s.Meta.Source == "registrar-rdap" {
			t.Errorf("expected no RDAP sources when registryBaseURL is empty, got %+v", s)
		}
	}
}
```

Finally, add this new offline test to `internal/collect/collect_test.go`:
```go
func TestCollect_WHOISOnlySources(t *testing.T) {
	registrarAddr := startWHOISListener(t, func(query string) string {
		return "Domain Name: example.com\nRegistrant Organization: Example Corp\nRegistrar: Example Registrar, Inc.\n"
	})
	registryAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: %s\nRegistrar: Example Registrar, Inc.\n", registrarAddr)
	})
	ianaAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("refer:        %s\ndomain:       COM\n", registryAddr)
	})

	name, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	sources := Collect(context.Background(), name, "", ianaAddr, Options{Timeout: 2 * time.Second})

	var gotRegistryWHOIS, gotRegistrarWHOIS bool
	for _, s := range sources {
		if s.Meta.Source == "registry-whois" && s.Present {
			gotRegistryWHOIS = true
		}
		if s.Meta.Source == "registrar-whois" && s.Present {
			gotRegistrarWHOIS = true
		}
	}
	if !gotRegistryWHOIS || !gotRegistrarWHOIS {
		t.Errorf("expected both WHOIS sources present, got registry=%v registrar=%v", gotRegistryWHOIS, gotRegistrarWHOIS)
	}
}
```

- [ ] **Step 4: Run test to verify it passes, fully offline**

Run: `cd /Users/pat/codes/plat && go test ./internal/collect/... -v -count=1`
Expected: PASS, all subtests green, with NO network access attempted (verify by running with network disabled if your environment allows it, or by inspecting that every `Collect` call in the test file now passes a local listener address as `whoisIANAServer` and either a local `httptest` server URL or `""` as `registryBaseURL`).

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/collect/collect.go internal/collect/collect_test.go
git commit -m "feat: add source-collection orchestration with registrar RDAP hop following"
```

---

### Task 9: `cmd/plat` — Hidden `merge` Demo Subcommand

**Files:**
- Create: `cmd/plat/merge.go`
- Modify: `cmd/plat/main.go` (wire the new subcommand into `root`)
- Modify: `cmd/plat/main_test.go` (add coverage for the new subcommand's arg validation and hidden status)

**Interfaces:**
- Consumes: `usageError` (existing, `cmd/plat/main.go`), `domain.Normalize` (M1), `bootstrap.Load`/`bootstrap.Options`/`Resolver.BaseURL` (M1), `collect.Collect`/`collect.Options` (Task 8), `merge.Merge` (Task 6), `model.Record` and its `Field[T]`/`Present()` (Task 1).
- Produces: nothing consumed by later tasks — this is M3's final, demoable deliverable.

- [ ] **Step 1: Write the failing test**

Append to `cmd/plat/main_test.go` (add `"strings"` to the existing import block if not already present — it likely already is, from M2's Task 8):
```go
func TestRun_MergeSubcommandRegistered(t *testing.T) {
	var stdout, stderr bytes.Buffer
	_ = run([]string{"merge", "--help"}, &stdout, &stderr)
	if !strings.Contains(stdout.String(), "merged RDAP+WHOIS") {
		t.Errorf("expected merge subcommand help text in output, got:\n%s", stdout.String())
	}
}

func TestRun_MergeRejectsWrongArgCount(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no args", []string{"merge"}},
		{"two args", []string{"merge", "example.com", "example.org"}},
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

func TestRun_MergeHiddenFromHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	_ = run([]string{"--help"}, &stdout, &stderr)
	if strings.Contains(stdout.String(), "merge") {
		t.Errorf("expected 'merge' subcommand to be hidden from --help output, got:\n%s", stdout.String())
	}
}
```

Note (same caveat as M2's Task 8): `TestRun_MergeRejectsWrongArgCount`'s exit-code assertions will likely already pass before this task's code exists, since `domain.Normalize("merge")` already rejects it as single-label with exit 2 — `TestRun_MergeSubcommandRegistered` is the test that can only pass once `merge.go` exists and is wired in, since no text about "merged RDAP+WHOIS" appears anywhere in the root command's own help.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./cmd/plat/... -v`
Expected: FAIL — `TestRun_MergeSubcommandRegistered` fails: `stdout` contains root's help text, which doesn't include "merged RDAP+WHOIS".

- [ ] **Step 3: Write the implementation**

Write `cmd/plat/merge.go`:
```go
package main

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/patramsey/plat/internal/bootstrap"
	"github.com/patramsey/plat/internal/collect"
	"github.com/patramsey/plat/internal/domain"
	"github.com/patramsey/plat/internal/merge"
	"github.com/patramsey/plat/internal/model"
)

// newMergeCommand builds the hidden `plat merge <domain>` debug/demo
// subcommand. It is Hidden (off --help) for the same reason M2's `whois`
// subcommand is: proper --source/-o wiring into the root command is
// reserved for a later milestone (M4); this exists to prove the merge
// engine end to end during development.
func newMergeCommand(stdout io.Writer) *cobra.Command {
	var timeout time.Duration
	var noFollow bool

	cmd := &cobra.Command{
		Use:    "merge <domain>",
		Short:  "Look up domain ownership via merged RDAP+WHOIS sources (debug/demo command)",
		Hidden: true,
		Args: func(cmd *cobra.Command, cliArgs []string) error {
			if len(cliArgs) != 1 {
				return usageError{fmt.Errorf("expected exactly one domain argument, got %d", len(cliArgs))}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, cliArgs []string) error {
			return mergeLookup(cmd.Context(), stdout, cliArgs[0], timeout, noFollow)
		},
	}
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "per-source timeout for RDAP and WHOIS lookups")
	cmd.Flags().BoolVar(&noFollow, "no-follow", false, "skip the registrar RDAP related-link hop")
	return cmd
}

func mergeLookup(ctx context.Context, stdout io.Writer, input string, timeout time.Duration, noFollow bool) error {
	name, err := domain.Normalize(input)
	if err != nil {
		return usageError{err}
	}

	resolver, err := bootstrap.Load(ctx, bootstrap.Options{Timeout: timeout})
	if err != nil {
		return fmt.Errorf("resolving RDAP bootstrap: %w", err)
	}
	baseURL, _ := resolver.BaseURL(name.TLD) // "" is fine — Collect degrades to WHOIS-only

	sources := collect.Collect(ctx, name, baseURL, "", collect.Options{NoFollow: noFollow, Timeout: timeout})
	record := merge.Merge(sources)

	return printRecord(stdout, record)
}

func printRecord(stdout io.Writer, r model.Record) error {
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	printField(tw, "Domain", r.Domain)
	printField(tw, "Handle", r.Handle)
	printField(tw, "Registrar", r.Registrar.Name)
	printField(tw, "Registrar IANA ID", r.Registrar.IANAID)
	printField(tw, "Abuse Email", r.Registrar.AbuseEmail)
	printField(tw, "Abuse Phone", r.Registrar.AbusePhone)
	if r.Status.Present() {
		_, _ = fmt.Fprintf(tw, "Status:\t%v\t%v\n", r.Status.Value, r.Status.Sources)
	}
	printTimeField(tw, "Created", r.Created)
	printTimeField(tw, "Updated", r.Updated)
	printTimeField(tw, "Expires", r.Expires)
	if r.Nameservers.Present() {
		_, _ = fmt.Fprintf(tw, "Nameservers:\t%v\t%v\n", r.Nameservers.Value, r.Nameservers.Sources)
	}
	_, _ = fmt.Fprintln(tw, "---")
	for _, s := range r.Sources {
		status := "ok"
		if !s.OK {
			status = s.Err
		}
		_, _ = fmt.Fprintf(tw, "Source %s:\t%s\t%s\n", s.Source, s.Latency.Round(time.Millisecond), status)
	}
	if len(r.Conflicts) > 0 {
		_, _ = fmt.Fprintln(tw, "---")
		for _, c := range r.Conflicts {
			_, _ = fmt.Fprintf(tw, "Conflict %s:\t%v\n", c.Field, c.Values)
		}
	}
	if len(r.Redacted) > 0 {
		_, _ = fmt.Fprintln(tw, "---")
		for _, red := range r.Redacted {
			_, _ = fmt.Fprintf(tw, "Redacted %s:\t%s (%s)\n", red.Field, red.Source, red.Reason)
		}
	}
	return tw.Flush()
}

func printField(tw *tabwriter.Writer, label string, f model.Field[string]) {
	if !f.Present() {
		return
	}
	_, _ = fmt.Fprintf(tw, "%s:\t%s\t%v\n", label, f.Value, f.Sources)
}

func printTimeField(tw *tabwriter.Writer, label string, f model.Field[model.TimeValue]) {
	if !f.Present() {
		return
	}
	if f.Value.Parsed {
		_, _ = fmt.Fprintf(tw, "%s:\t%s\t%v\n", label, f.Value.Time.Format(time.RFC3339), f.Sources)
	} else {
		_, _ = fmt.Fprintf(tw, "%s:\t%s (unparsed)\t%v\n", label, f.Value.Raw, f.Sources)
	}
}
```

Modify `cmd/plat/main.go`: read the file first to find the existing block added in M2's Task 8 that reads:
```go
	root.AddCommand(newWhoisCommand(stdout))
```
Immediately after that line (still inside the `run` function, before `err := root.Execute()`), add:
```go
	root.AddCommand(newMergeCommand(stdout))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./... -v 2>&1 | tail -80`
Expected: PASS across all packages (`cmd/plat`, `internal/bootstrap`, `internal/domain`, `internal/model`, `internal/merge`, `internal/collect`, `internal/rdap`, `internal/render/plain`, `internal/whois`, `internal/whois/parse`).

- [ ] **Step 5: Full-program verification**

Run:
```bash
cd /Users/pat/codes/plat && go mod tidy && go build ./... && go vet ./... && golangci-lint run && go test ./...
```
Expected: all commands succeed, `golangci-lint run` reports 0 issues, all packages report `ok`.

- [ ] **Step 6: Commit**

```bash
cd /Users/pat/codes/plat
git add cmd/plat/merge.go cmd/plat/main.go cmd/plat/main_test.go
git commit -m "feat: add hidden plat merge demo subcommand"
```

---

## Milestone Verification (manual, not automated)

Once all 9 tasks are complete, confirm the milestone's actual definition of done — this requires live network access and is deliberately not part of the automated test suite:

```bash
cd /Users/pat/codes/plat

go run ./cmd/plat merge google.com          # expect: merged record with registrar+registry RDAP sources agreeing on most fields, registrar identity populated, exit 0
echo $?

go run ./cmd/plat merge google.com --no-follow   # expect: same, but no registrar-rdap source in the output
echo $?

go run ./cmd/plat merge example.com         # expect: IANA's reserved example.com, sensible partial output
echo $?

go run ./cmd/plat merge localhost           # expect: friendly single-label error, exit 2
echo $?
```

A genuinely GDPR-redacted domain or a genuine cross-source conflict may not be reproducible on demand against real infrastructure — this verification's job is to confirm `plat merge <domain>` runs end to end and produces sensible, provenance-annotated output, not to force a specific conflict/redaction scenario live. If a real lookup surfaces a genuine conflict or redaction, that's a good sign the engine is working, not something to specifically chase.

If a real-world response exposes a gap in the merge/adapter logic (an unexpected `Unmapped` key spelling, a jCard shape the extractor doesn't handle, a related-link `href` that's relative instead of absolute), capture it into a new fixture and extend the offline tests rather than special-casing it in code, consistent with how M1 and M2 handled real-world surprises.
