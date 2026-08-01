# M1 — Skeleton + RDAP Happy Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `plat <domain>` end to end for a single source — normalize input, resolve the TLD's RDAP base URL from a cached/embedded IANA bootstrap file, query registry RDAP, and print a plain-text result — with CI (lint, test, 6-target build matrix).

**Architecture:** Five new packages (`internal/domain`, `internal/bootstrap`, `internal/rdap`, `internal/render/plain`, `cmd/plat`) each with one responsibility, wired together in `cmd/plat/main.go`. No WHOIS, no merge engine, no styled TTY rendering — those are M2+.

**Tech Stack:** Go 1.25, `github.com/spf13/cobra` (CLI), `golang.org/x/net/idna` (IDN), stdlib `net/http`/`encoding/json`/`text/tabwriter` for everything else.

## Global Constraints

- Module path: `github.com/patramsey/plat` — fixed, do not change.
- `go.mod` language version: `go 1.25`.
- Direct dependencies for M1 only: `github.com/spf13/cobra`, `golang.org/x/net`. No other third-party dependencies this milestone — specifically no `github.com/openrdap/rdap`, no lipgloss, no bubbles.
- Packages created this milestone: `cmd/plat`, `internal/domain`, `internal/bootstrap`, `internal/rdap`, `internal/render/plain`. Do **not** create `internal/whois`, `internal/model`, `internal/merge`, `internal/render/human`, `internal/render/machine`, `internal/netx` yet — deferred to M2+.
- Bootstrap cache path uses `os.UserCacheDir()` (OS-idiomatic: `~/.cache` on Linux honoring `$XDG_CACHE_HOME`, `~/Library/Caches` on macOS, `%LocalAppData%` on Windows) — not manual XDG-only logic.
- The RDAP client and types must tolerate non-conformant registry responses (shape variance in `status`, date variance, wrong `Content-Type`, HTML error bodies, "200 OK but body is an error object") without panicking or hard-failing the whole document. See Tasks 3–4 for the exact mechanisms.
- Exit codes: `0` success, `1` domain-not-found, `2` usage/input error, `3` all other failures (network, malformed response, no-RDAP-for-TLD).
- The `test` CI job must run fully offline — no live network calls in any automated test. Live verification is a manual step (see "Milestone Verification" at the end of this plan), not an automated test.
- Build matrix covers `linux/darwin/windows` × `amd64/arm64` (6 targets) with `CGO_ENABLED=0`.
- In-scope CLI flags this milestone: `--refresh-bootstrap`, `--timeout`, `version` subcommand. All other flags (`-o/--output`, `--raw`, `--source`, `--no-follow`, `-q`, `--no-color`, `-v`, `completion`, `man`) are explicitly deferred — name them in a comment, do not implement them.

---

### Task 1: Repo Scaffold, Git Init, and Module Setup

**Files:**
- Create: `/Users/pat/codes/plat/.gitignore`
- Create: `/Users/pat/codes/plat/go.mod`
- Create: `/Users/pat/codes/plat/go.sum`
- Create: `/Users/pat/codes/plat/cmd/plat/main.go` (temporary stub — fully replaced in Task 7)

**Interfaces:**
- Consumes: nothing (first task).
- Produces: an initialized git repo, a Go module at `github.com/patramsey/plat` with `cobra` and `golang.org/x/net` as direct dependencies, and a buildable (empty) `cmd/plat` binary that every later task builds on.

- [ ] **Step 1: Confirm git state and initialize if needed**

Run:
```bash
cd /Users/pat/codes/plat && git status
```
Expected: either normal status output (repo already initialized — skip to Step 2) or `fatal: not a git repository`. If the latter:
```bash
cd /Users/pat/codes/plat && git init
```
Expected: `Initialized empty Git repository in /Users/pat/codes/plat/.git/`

- [ ] **Step 2: Create `.gitignore`**

Write `/Users/pat/codes/plat/.gitignore`:
```
/plat
/dist/
*.test
*.out
```

- [ ] **Step 3: Initialize the Go module**

Run:
```bash
cd /Users/pat/codes/plat && go mod init github.com/patramsey/plat
```
Expected: `go: creating new go.mod: module github.com/patramsey/plat`

- [ ] **Step 4: Pin the go.mod language version to 1.25**

Open the generated `go.mod` and change the `go` directive line (whatever version `go mod init` wrote, e.g. `go 1.26.5`) to exactly:
```
go 1.25
```

- [ ] **Step 5: Create the directory scaffold and a buildable stub**

Run:
```bash
mkdir -p /Users/pat/codes/plat/cmd/plat \
         /Users/pat/codes/plat/internal/domain \
         /Users/pat/codes/plat/internal/bootstrap \
         /Users/pat/codes/plat/internal/rdap \
         /Users/pat/codes/plat/internal/render/plain \
         /Users/pat/codes/plat/testdata/rdap
```

Write `/Users/pat/codes/plat/cmd/plat/main.go`:
```go
package main

func main() {}
```

- [ ] **Step 6: Add direct dependencies**

Run:
```bash
cd /Users/pat/codes/plat && go get github.com/spf13/cobra@latest && go get golang.org/x/net@latest
```
Expected: both commands succeed and add `require` lines to `go.mod` plus entries to `go.sum`. Do **not** run `go mod tidy` yet — `cobra` isn't imported anywhere until Task 7, and `tidy` would prune it as unused, forcing a redundant re-fetch later.

- [ ] **Step 7: Verify the scaffold builds**

Run:
```bash
cd /Users/pat/codes/plat && go build ./...
```
Expected: succeeds silently (produces a `plat` binary in the repo root, which `.gitignore` excludes).

- [ ] **Step 8: Commit**

```bash
cd /Users/pat/codes/plat
git add .gitignore go.mod go.sum cmd/plat/main.go
git commit -m "chore: scaffold go module and directory layout"
```

---

### Task 2: `internal/domain` — Input Normalization

**Files:**
- Create: `/Users/pat/codes/plat/internal/domain/normalize.go`
- Test: `/Users/pat/codes/plat/internal/domain/normalize_test.go`

**Interfaces:**
- Consumes: `golang.org/x/net/idna` (added in Task 1).
- Produces: `type Name struct { Punycode, Unicode, TLD string }`, `func Normalize(input string) (Name, error)`, `var ErrSingleLabel error` — consumed by `cmd/plat/main.go` in Task 7.

- [ ] **Step 1: Write the failing test**

Write `/Users/pat/codes/plat/internal/domain/normalize_test.go`:
```go
package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		wantPunycode    string
		wantTLD         string
		wantErr         error
		wantErrContains string
	}{
		{
			name:         "simple lowercase",
			input:        "example.com",
			wantPunycode: "example.com",
			wantTLD:      "com",
		},
		{
			name:         "uppercase normalizes to lowercase",
			input:        "EXAMPLE.COM",
			wantPunycode: "example.com",
			wantTLD:      "com",
		},
		{
			name:         "trailing dot stripped",
			input:        "example.com.",
			wantPunycode: "example.com",
			wantTLD:      "com",
		},
		{
			name:         "IDN converts to punycode",
			input:        "münchen.de",
			wantPunycode: "xn--mnchen-3ya.de",
			wantTLD:      "de",
		},
		{
			name:         "already-punycode xn-- input passes through",
			input:        "xn--mnchen-3ya.de",
			wantPunycode: "xn--mnchen-3ya.de",
			wantTLD:      "de",
		},
		{
			name:    "single-label input rejected",
			input:   "localhost",
			wantErr: ErrSingleLabel,
		},
		{
			name:            "reserved TLD .local rejected",
			input:           "printer.local",
			wantErrContains: "reserved/private TLD",
		},
		{
			name:            "reserved TLD .internal rejected",
			input:           "svc.internal",
			wantErrContains: "reserved/private TLD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Normalize(tt.input)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Normalize(%q) error = %v, want errors.Is match for %v", tt.input, err, tt.wantErr)
				}
				return
			}
			if tt.wantErrContains != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Fatalf("Normalize(%q) error = %v, want error containing %q", tt.input, err, tt.wantErrContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalize(%q) unexpected error: %v", tt.input, err)
			}
			if got.Punycode != tt.wantPunycode {
				t.Errorf("Punycode = %q, want %q", got.Punycode, tt.wantPunycode)
			}
			if got.TLD != tt.wantTLD {
				t.Errorf("TLD = %q, want %q", got.TLD, tt.wantTLD)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/domain/... -v`
Expected: FAIL — build error, `undefined: Normalize` / `undefined: ErrSingleLabel`.

- [ ] **Step 3: Write the implementation**

Write `/Users/pat/codes/plat/internal/domain/normalize.go`:
```go
package domain

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

// ErrSingleLabel is returned when the input has no dot at all (e.g.
// "localhost"), which can never be a registrable domain.
var ErrSingleLabel = errors.New("domain: single-label input is not a valid domain")

var reservedTLDs = map[string]bool{
	"local":    true,
	"internal": true,
}

// Name holds a normalized domain name in both its ASCII/LDH (punycode) and
// Unicode display forms, plus its top-level label.
type Name struct {
	Punycode string
	Unicode  string
	TLD      string
}

// Normalize lowercases, strips a trailing dot, converts IDN input to
// punycode, extracts the TLD, and rejects single-label or reserved/private
// TLD input with a friendly error.
func Normalize(input string) (Name, error) {
	s := strings.ToLower(strings.TrimSpace(input))
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return Name{}, fmt.Errorf("domain: empty input")
	}

	punycode, err := idna.ToASCII(s)
	if err != nil {
		return Name{}, fmt.Errorf("domain: invalid domain name %q: %w", input, err)
	}

	labels := strings.Split(punycode, ".")
	if len(labels) < 2 {
		return Name{}, fmt.Errorf("%w: %q", ErrSingleLabel, input)
	}

	tld := labels[len(labels)-1]
	if reservedTLDs[tld] {
		return Name{}, fmt.Errorf("domain: %q is a reserved/private TLD and cannot be looked up", tld)
	}

	unicodeName, err := idna.ToUnicode(punycode)
	if err != nil {
		unicodeName = punycode
	}

	return Name{Punycode: punycode, Unicode: unicodeName, TLD: tld}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./internal/domain/... -v`
Expected: PASS, all subtests green.

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/domain/normalize.go internal/domain/normalize_test.go
git commit -m "feat: add domain input normalization"
```

---

### Task 3: `internal/rdap` — Tolerant Types

**Files:**
- Create: `/Users/pat/codes/plat/internal/rdap/types.go`
- Test: `/Users/pat/codes/plat/internal/rdap/types_test.go`

**Interfaces:**
- Consumes: nothing beyond stdlib.
- Produces: `type DomainResponse struct{ ObjectClassName, LDHName, UnicodeName, Handle string; Status StatusList; Events []Event; Nameservers []Nameserver }`, `type StatusList []string`, `type RDAPTime struct{ Raw string; Time time.Time; Parsed bool }`, `type Event struct{ Action string; Date RDAPTime }`, `type Nameserver struct{ LDHName, UnicodeName string }`, and methods `(*DomainResponse) Created() (RDAPTime, bool)`, `Updated() (RDAPTime, bool)`, `Expires() (RDAPTime, bool)` — consumed by `internal/rdap/client.go` (Task 4) and `internal/render/plain/plain.go` (Task 5).

- [ ] **Step 1: Write the failing test**

Write `/Users/pat/codes/plat/internal/rdap/types_test.go`:
```go
package rdap

import (
	"encoding/json"
	"testing"
	"time"
)

func TestStatusListUnmarshal(t *testing.T) {
	tests := []struct {
		name string
		json string
		want StatusList
	}{
		{"array form", `["active","clientTransferProhibited"]`, StatusList{"active", "clientTransferProhibited"}},
		{"bare string form", `"active"`, StatusList{"active"}},
		{"null", `null`, nil},
		{"malformed number degrades to empty", `42`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got StatusList
			if err := json.Unmarshal([]byte(tt.json), &got); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestRDAPTimeUnmarshal(t *testing.T) {
	tests := []struct {
		name       string
		json       string
		wantParsed bool
		wantRaw    string
		wantUTC    string
	}{
		{"RFC3339 with zone", `"2026-07-12T10:00:00Z"`, true, "2026-07-12T10:00:00Z", "2026-07-12T10:00:00Z"},
		{"RFC3339Nano", `"2026-07-12T10:00:00.123456Z"`, true, "2026-07-12T10:00:00.123456Z", "2026-07-12T10:00:00Z"},
		{"no zone assumed UTC", `"2026-07-12T10:00:00"`, true, "2026-07-12T10:00:00", "2026-07-12T10:00:00Z"},
		{"space instead of T", `"2026-07-12 10:00:00Z"`, true, "2026-07-12 10:00:00Z", "2026-07-12T10:00:00Z"},
		{"date only", `"2026-07-12"`, true, "2026-07-12", "2026-07-12T00:00:00Z"},
		{"garbage never errors", `"not-a-date"`, false, "not-a-date", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got RDAPTime
			if err := json.Unmarshal([]byte(tt.json), &got); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Raw != tt.wantRaw {
				t.Errorf("Raw = %q, want %q", got.Raw, tt.wantRaw)
			}
			if got.Parsed != tt.wantParsed {
				t.Errorf("Parsed = %v, want %v", got.Parsed, tt.wantParsed)
			}
			if tt.wantParsed && got.Time.Format(time.RFC3339) != tt.wantUTC {
				t.Errorf("Time = %v, want %v", got.Time.Format(time.RFC3339), tt.wantUTC)
			}
		})
	}
}

func TestDomainResponseEventAccessors(t *testing.T) {
	raw := `{
		"objectClassName": "domain",
		"ldhName": "example.com",
		"events": [
			{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
			{"eventAction": "last changed", "eventDate": "2025-08-14T04:00:00Z"},
			{"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
			{"eventAction": "transfer", "eventDate": "2020-01-01T00:00:00Z"}
		]
	}`
	var d DomainResponse
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	created, ok := d.Created()
	if !ok || created.Raw != "1995-08-14T04:00:00Z" {
		t.Errorf("Created() = %v, %v", created, ok)
	}
	updated, ok := d.Updated()
	if !ok || updated.Raw != "2025-08-14T04:00:00Z" {
		t.Errorf("Updated() = %v, %v", updated, ok)
	}
	expires, ok := d.Expires()
	if !ok || expires.Raw != "2026-08-13T04:00:00Z" {
		t.Errorf("Expires() = %v, %v", expires, ok)
	}
	if len(d.Events) != 4 {
		t.Errorf("Events retained = %d, want 4 (including unknown 'transfer' action)", len(d.Events))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/rdap/... -v`
Expected: FAIL — build error, `undefined: StatusList` / `undefined: RDAPTime` / `undefined: DomainResponse`.

- [ ] **Step 3: Write the implementation**

Write `/Users/pat/codes/plat/internal/rdap/types.go`:
```go
package rdap

import (
	"encoding/json"
	"strings"
	"time"
)

// DomainResponse is a trimmed RFC 9083 domain object view. Entities/jCard
// (registrar name, contacts) parsing is deferred to the merge-engine
// milestone.
type DomainResponse struct {
	ObjectClassName string       `json:"objectClassName"`
	LDHName         string       `json:"ldhName"`
	UnicodeName     string       `json:"unicodeName"`
	Handle          string       `json:"handle"`
	Status          StatusList   `json:"status"`
	Events          []Event      `json:"events"`
	Nameservers     []Nameserver `json:"nameservers"`
}

// Event is a single RDAP domain lifecycle event.
type Event struct {
	Action string   `json:"eventAction"`
	Date   RDAPTime `json:"eventDate"`
}

// Nameserver is a trimmed RFC 9083 nameserver object view.
type Nameserver struct {
	LDHName     string `json:"ldhName"`
	UnicodeName string `json:"unicodeName"`
}

// StatusList tolerates RDAP status being either a JSON array of strings
// (per RFC 9083) or, on some non-conformant servers, a bare string. It
// never fails to unmarshal — a malformed value just degrades to empty
// rather than aborting the whole document's decode.
type StatusList []string

func (s *StatusList) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" {
		*s = nil
		return nil
	}
	if trimmed[0] == '[' {
		var list []string
		if err := json.Unmarshal(b, &list); err != nil {
			*s = nil
			return nil
		}
		*s = list
		return nil
	}
	var single string
	if err := json.Unmarshal(b, &single); err != nil {
		*s = nil
		return nil
	}
	*s = StatusList{single}
	return nil
}

// RDAPTime tolerates real-world event-date variance. Raw always holds the
// original string; Time/Parsed are only meaningful when Parsed is true.
// Unmarshal never fails on a bad date — that would abort parsing of an
// otherwise-good document over one cosmetic field.
type RDAPTime struct {
	Raw    string
	Time   time.Time
	Parsed bool
}

var rdapTimeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05Z07:00",
	"2006-01-02 15:04:05",
	"2006-01-02",
}

func (t *RDAPTime) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		t.Raw = strings.Trim(string(b), `"`)
		t.Parsed = false
		return nil
	}
	t.Raw = s
	for _, layout := range rdapTimeLayouts {
		if ts, err := time.Parse(layout, s); err == nil {
			t.Time = ts.UTC()
			t.Parsed = true
			return nil
		}
	}
	t.Parsed = false
	return nil
}

type eventSlot int

const (
	slotUnknown eventSlot = iota
	slotCreated
	slotUpdated
	slotExpires
)

// normalizeEventAction maps an RDAP eventAction string to a known slot
// using an open-set synonym lookup, not a closed switch on exact RFC 9083
// strings — real registries use variants RFC 9083 doesn't enumerate.
// Unrecognized actions map to slotUnknown; the event is still retained in
// DomainResponse.Events, just not surfaced by the named accessors.
func normalizeEventAction(a string) eventSlot {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case "registration", "registered", "created", "creation":
		return slotCreated
	case "last changed", "last update", "last updated", "updated", "modification":
		return slotUpdated
	case "expiration", "expires", "expiry":
		return slotExpires
	default:
		return slotUnknown
	}
}

func (d *DomainResponse) eventBySlot(slot eventSlot) (RDAPTime, bool) {
	for _, e := range d.Events {
		if normalizeEventAction(e.Action) == slot {
			return e.Date, true
		}
	}
	return RDAPTime{}, false
}

// Created returns the registration event's date, if present.
func (d *DomainResponse) Created() (RDAPTime, bool) { return d.eventBySlot(slotCreated) }

// Updated returns the last-changed event's date, if present.
func (d *DomainResponse) Updated() (RDAPTime, bool) { return d.eventBySlot(slotUpdated) }

// Expires returns the expiration event's date, if present.
func (d *DomainResponse) Expires() (RDAPTime, bool) { return d.eventBySlot(slotExpires) }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./internal/rdap/... -v`
Expected: PASS, all subtests green.

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/rdap/types.go internal/rdap/types_test.go
git commit -m "feat: add tolerant RDAP domain types"
```

---

### Task 4: `internal/rdap` — Client + Fixture

**Files:**
- Create: `/Users/pat/codes/plat/testdata/rdap/com-example.json`
- Create: `/Users/pat/codes/plat/internal/rdap/client.go`
- Test: `/Users/pat/codes/plat/internal/rdap/client_test.go`

**Interfaces:**
- Consumes: `DomainResponse`, `StatusList`, `RDAPTime`, `Event`, `Nameserver` from Task 3 (same package, no import needed).
- Produces: `var ErrDomainNotFound error`, `type MalformedResponseError struct{ URL string; StatusCode int; ContentType string; Snippet string; Err error }`, `type Result struct{ Domain *DomainResponse; Raw []byte; StatusCode int; ContentType string; MediaTypeConformant bool }`, `type Client struct{ HTTP *http.Client; Timeout time.Duration; MaxBody int64; UserAgent string }`, `func (*Client) Domain(ctx context.Context, baseURL, punycode string) (*Result, error)` — consumed by `cmd/plat/main.go` (Task 7). Also produces the shared fixture `testdata/rdap/com-example.json`, reused by Task 5's renderer test.

- [ ] **Step 1: Create the fixture**

Write `/Users/pat/codes/plat/testdata/rdap/com-example.json`:
```json
{
  "objectClassName": "domain",
  "handle": "2336799_DOMAIN_COM-VRSN",
  "ldhName": "EXAMPLE.COM",
  "unicodeName": "example.com",
  "status": [
    "client delete prohibited",
    "client transfer prohibited",
    "client update prohibited"
  ],
  "events": [
    {
      "eventAction": "registration",
      "eventDate": "1995-08-14T04:00:00Z"
    },
    {
      "eventAction": "last changed",
      "eventDate": "2025-08-14T07:01:31Z"
    },
    {
      "eventAction": "expiration",
      "eventDate": "2026-08-13T04:00:00Z"
    },
    {
      "eventAction": "last update of RDAP database",
      "eventDate": "2026-07-12T09:15:00Z"
    }
  ],
  "nameservers": [
    {
      "objectClassName": "nameserver",
      "ldhName": "A.IANA-SERVERS.NET"
    },
    {
      "objectClassName": "nameserver",
      "ldhName": "B.IANA-SERVERS.NET"
    }
  ],
  "links": [
    {
      "value": "https://rdap.verisign.com/com/v1/domain/EXAMPLE.COM",
      "rel": "self",
      "href": "https://rdap.verisign.com/com/v1/domain/EXAMPLE.COM",
      "type": "application/rdap+json"
    }
  ],
  "notices": [
    {
      "title": "Terms of Use",
      "description": [
        "Service subject to Terms of Use."
      ]
    }
  ],
  "rdapConformance": [
    "rdap_level_0"
  ]
}
```
Note: the `status` values use Verisign's real-world "client delete prohibited" (lowercase, spaced) form rather than RFC 8056's `clientDeleteProhibited` camelCase — this is a genuine, documented conformance quirk of `.com`'s RDAP server and deliberately exercises the tolerance built in Task 3. The `links`, `notices`, and `rdapConformance` fields are present (as a real response would have them) but intentionally unparsed by `DomainResponse` — proving unknown fields don't break decoding.

- [ ] **Step 2: Write the failing test**

Write `/Users/pat/codes/plat/internal/rdap/client_test.go`:
```go
package rdap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func loadFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return b
}

func TestClientDomain_HappyPath(t *testing.T) {
	fixture := loadFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/domain/EXAMPLE.COM" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Accept") != "application/rdap+json" {
			t.Errorf("missing Accept header, got %q", r.Header.Get("Accept"))
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		w.Write(fixture)
	}))
	defer srv.Close()

	c := &Client{}
	result, err := c.Domain(context.Background(), srv.URL, "EXAMPLE.COM")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Domain == nil {
		t.Fatal("Domain is nil")
	}
	if result.Domain.LDHName != "EXAMPLE.COM" {
		t.Errorf("LDHName = %q, want EXAMPLE.COM", result.Domain.LDHName)
	}
	if len(result.Domain.Status) != 3 {
		t.Errorf("Status = %v, want 3 entries", result.Domain.Status)
	}
	if len(result.Domain.Nameservers) != 2 {
		t.Errorf("Nameservers = %v, want 2 entries", result.Domain.Nameservers)
	}
	created, ok := result.Domain.Created()
	if !ok || created.Raw != "1995-08-14T04:00:00Z" {
		t.Errorf("Created() = %v, %v", created, ok)
	}
	if !result.MediaTypeConformant {
		t.Errorf("MediaTypeConformant = false, want true")
	}
	if len(result.Raw) == 0 {
		t.Errorf("Raw body not retained")
	}
}

func TestClientDomain_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"errorCode":404,"title":"Not Found"}`))
	}))
	defer srv.Close()

	c := &Client{}
	result, err := c.Domain(context.Background(), srv.URL, "nonexistent-example.com")
	if !errors.Is(err, ErrDomainNotFound) {
		t.Fatalf("error = %v, want ErrDomainNotFound", err)
	}
	if result == nil || len(result.Raw) == 0 {
		t.Errorf("Raw body should still be retained on 404")
	}
}

func TestClientDomain_RateLimitedThenSucceeds(t *testing.T) {
	fixture := loadFixture(t)
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		w.Write(fixture)
	}))
	defer srv.Close()

	c := &Client{}
	result, err := c.Domain(context.Background(), srv.URL, "EXAMPLE.COM")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempts != 2 {
		t.Errorf("attempts = %d, want 2 (one retry)", attempts)
	}
	if result.Domain == nil {
		t.Fatal("Domain is nil")
	}
}

func TestClientDomain_RateLimitedGivesUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := &Client{}
	_, err := c.Domain(context.Background(), srv.URL, "EXAMPLE.COM")
	if err == nil {
		t.Fatal("expected an error after single retry still returns 429")
	}
	var malformed *MalformedResponseError
	if !errors.As(err, &malformed) {
		t.Fatalf("error = %v (%T), want *MalformedResponseError", err, err)
	}
	if malformed.StatusCode != http.StatusTooManyRequests {
		t.Errorf("StatusCode = %d, want 429", malformed.StatusCode)
	}
}

func TestClientDomain_NonJSONBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>upstream error</body></html>`))
	}))
	defer srv.Close()

	c := &Client{}
	_, err := c.Domain(context.Background(), srv.URL, "EXAMPLE.COM")
	var malformed *MalformedResponseError
	if !errors.As(err, &malformed) {
		t.Fatalf("error = %v (%T), want *MalformedResponseError", err, err)
	}
	if !strings.Contains(malformed.Snippet, "upstream error") {
		t.Errorf("Snippet = %q, want to contain body text", malformed.Snippet)
	}
}

func TestClientDomain_MalformedStatusField(t *testing.T) {
	body := `{"objectClassName":"domain","ldhName":"EXAMPLE.COM","status":42}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	}))
	defer srv.Close()

	c := &Client{}
	result, err := c.Domain(context.Background(), srv.URL, "EXAMPLE.COM")
	if err != nil {
		t.Fatalf("unexpected error (status field should degrade gracefully): %v", err)
	}
	if len(result.Domain.Status) != 0 {
		t.Errorf("Status = %v, want empty (malformed field should degrade, not error)", result.Domain.Status)
	}
}

func TestClientDomain_UnparseableEventDate(t *testing.T) {
	body := `{"objectClassName":"domain","ldhName":"EXAMPLE.COM","events":[{"eventAction":"registration","eventDate":"not-a-date"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	}))
	defer srv.Close()

	c := &Client{}
	result, err := c.Domain(context.Background(), srv.URL, "EXAMPLE.COM")
	if err != nil {
		t.Fatalf("unexpected error (bad date should degrade gracefully): %v", err)
	}
	created, ok := result.Domain.Created()
	if !ok {
		t.Fatal("Created() event should still be present")
	}
	if created.Parsed {
		t.Errorf("Parsed = true, want false for unparseable date")
	}
	if created.Raw != "not-a-date" {
		t.Errorf("Raw = %q, want %q", created.Raw, "not-a-date")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/rdap/... -v`
Expected: FAIL — build error, `undefined: Client` / `undefined: ErrDomainNotFound` / `undefined: MalformedResponseError`.

- [ ] **Step 4: Write the implementation**

Write `/Users/pat/codes/plat/internal/rdap/client.go`:
```go
package rdap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrDomainNotFound is returned when the RDAP server responds 404 for a
// domain query — the standard RDAP not-found signal, regardless of what
// (if anything) the response body contains.
var ErrDomainNotFound = errors.New("rdap: domain not found")

// MalformedResponseError is returned when a server's response can't be
// interpreted as RDAP JSON — an HTML error page, plaintext, or truncated
// body, for example — so a conformance surprise is debuggable rather than
// surfacing as a bare json.SyntaxError or a panic.
type MalformedResponseError struct {
	URL         string
	StatusCode  int
	ContentType string
	Snippet     string
	Err         error
}

func (e *MalformedResponseError) Error() string {
	return fmt.Sprintf("rdap: malformed response from %s (status %d, content-type %q): %s",
		e.URL, e.StatusCode, e.ContentType, e.Snippet)
}

func (e *MalformedResponseError) Unwrap() error { return e.Err }

// Result wraps a parsed DomainResponse together with the raw bytes and
// transport metadata needed to debug a conformance surprise. It is
// deliberately lighter than the full multi-source provenance model
// (that's a later milestone) — just enough to not lose information.
type Result struct {
	Domain              *DomainResponse
	Raw                 []byte
	StatusCode          int
	ContentType         string
	MediaTypeConformant bool
}

// Client is a minimal RDAP client for a single registry domain query.
type Client struct {
	HTTP      *http.Client
	Timeout   time.Duration
	MaxBody   int64
	UserAgent string
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 5 * time.Second
}

func (c *Client) maxBody() int64 {
	if c.MaxBody > 0 {
		return c.MaxBody
	}
	return 5 << 20
}

func (c *Client) userAgent() string {
	if c.UserAgent != "" {
		return c.UserAgent
	}
	return "plat/0.1"
}

type rawResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func (c *Client) do(ctx context.Context, reqURL string) (*rawResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("rdap: building request: %w", err)
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", c.userAgent())

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("rdap: requesting %s: %w", reqURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody()))
	if err != nil {
		return nil, fmt.Errorf("rdap: reading response body from %s: %w", reqURL, err)
	}

	return &rawResponse{StatusCode: resp.StatusCode, Header: resp.Header, Body: body}, nil
}

func retryAfter(h http.Header) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return time.Second
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return time.Duration(secs) * time.Second
	}
	if when, err := http.ParseTime(v); err == nil {
		if d := time.Until(when); d > 0 {
			return d
		}
	}
	return time.Second
}

// rdapError is the minimal RFC 9083 error-response shape.
type rdapError struct {
	ErrorCode   int      `json:"errorCode"`
	Title       string   `json:"title"`
	Description []string `json:"description"`
}

func snippet(body []byte) string {
	const max = 512
	s := string(body)
	if len(s) > max {
		s = s[:max]
	}
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\t' || (r >= 0x20 && r != 0x7f) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Domain queries baseURL for the given punycode domain name and returns
// the parsed result. baseURL is the RDAP service base (typically resolved
// from IANA bootstrap); punycode is the ASCII domain name to look up.
func (c *Client) Domain(ctx context.Context, baseURL, punycode string) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	reqURL := strings.TrimRight(baseURL, "/") + "/domain/" + url.PathEscape(punycode)

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
	}

	result.Domain = &domain
	return result, nil
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./internal/rdap/... -v`
Expected: PASS, all subtests in both `types_test.go` and `client_test.go` green.

- [ ] **Step 6: Commit**

```bash
cd /Users/pat/codes/plat
git add testdata/rdap/com-example.json internal/rdap/client.go internal/rdap/client_test.go
git commit -m "feat: add conformance-tolerant registry RDAP client"
```

---

### Task 5: `internal/render/plain` — Plain-Text Renderer

**Files:**
- Create: `/Users/pat/codes/plat/internal/render/plain/plain.go`
- Test: `/Users/pat/codes/plat/internal/render/plain/plain_test.go`

**Interfaces:**
- Consumes: `rdap.DomainResponse` and its `Created()`/`Updated()`/`Expires()` accessors (Task 3); the fixture `testdata/rdap/com-example.json` (Task 4).
- Produces: `func Render(w io.Writer, r *rdap.DomainResponse) error` — consumed by `cmd/plat/main.go` (Task 7).

- [ ] **Step 1: Write the failing test**

Write `/Users/pat/codes/plat/internal/render/plain/plain_test.go`:
```go
package plain

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/patramsey/plat/internal/rdap"
)

func loadFixtureDomain(t *testing.T) *rdap.DomainResponse {
	t.Helper()
	b, err := os.ReadFile("../../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	var d rdap.DomainResponse
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("unmarshaling fixture: %v", err)
	}
	return &d
}

func TestRender_HappyPath(t *testing.T) {
	d := loadFixtureDomain(t)
	var buf bytes.Buffer
	if err := Render(&buf, d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"Domain:", "example.com",
		"Handle:", "2336799_DOMAIN_COM-VRSN",
		"Status:", "client delete prohibited",
		"Created:", "1995-08-14T04:00:00Z",
		"Updated:", "2025-08-14T07:01:31Z",
		"Expires:", "2026-08-13T04:00:00Z",
		"Nameservers:", "A.IANA-SERVERS.NET",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, out)
		}
	}

	for _, b := range []byte(out) {
		if b == 0x1b { // ESC — start of an ANSI escape sequence
			t.Fatalf("output contains ANSI escape byte, want zero ANSI:\n%s", out)
		}
	}
}

func TestRender_UnparsedDateFallback(t *testing.T) {
	raw := []byte(`{"objectClassName":"domain","ldhName":"example.com","events":[{"eventAction":"registration","eventDate":"not-a-date"}]}`)
	var d rdap.DomainResponse
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var buf bytes.Buffer
	if err := Render(&buf, &d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "not-a-date (unparsed)") {
		t.Errorf("output missing unparsed-date fallback, got:\n%s", out)
	}
}

func TestRender_SkipsEmptyRows(t *testing.T) {
	d := &rdap.DomainResponse{
		ObjectClassName: "domain",
		LDHName:         "example.com",
	}
	var buf bytes.Buffer
	if err := Render(&buf, d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "Handle:") {
		t.Errorf("expected Handle row to be skipped when empty, got:\n%s", out)
	}
	if strings.Contains(out, "Status:") {
		t.Errorf("expected Status row to be skipped when empty, got:\n%s", out)
	}
	if strings.Contains(out, "Nameservers:") {
		t.Errorf("expected Nameservers row to be skipped when empty, got:\n%s", out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/render/plain/... -v`
Expected: FAIL — build error, `undefined: Render`.

- [ ] **Step 3: Write the implementation**

Write `/Users/pat/codes/plat/internal/render/plain/plain.go`:
```go
package plain

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/patramsey/plat/internal/rdap"
)

// Render writes a minimal aligned key/value view of a single RDAP domain
// lookup. It never emits ANSI escapes, so it is safe for pipes and for
// terminals that don't support color.
func Render(w io.Writer, r *rdap.DomainResponse) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)

	domainName := r.UnicodeName
	if domainName == "" {
		domainName = r.LDHName
	}
	row(tw, "Domain", domainName)
	row(tw, "Handle", r.Handle)
	if len(r.Status) > 0 {
		row(tw, "Status", strings.Join([]string(r.Status), " · "))
	}
	renderDate(tw, "Created", r.Created)
	renderDate(tw, "Updated", r.Updated)
	renderDate(tw, "Expires", r.Expires)
	if len(r.Nameservers) > 0 {
		names := make([]string, len(r.Nameservers))
		for i, ns := range r.Nameservers {
			names[i] = ns.LDHName
		}
		row(tw, "Nameservers", strings.Join(names, " · "))
	}

	return tw.Flush()
}

func row(tw *tabwriter.Writer, label, value string) {
	if value == "" {
		return
	}
	fmt.Fprintf(tw, "%s:\t%s\n", label, value)
}

func renderDate(tw *tabwriter.Writer, label string, accessor func() (rdap.RDAPTime, bool)) {
	t, ok := accessor()
	if !ok {
		return
	}
	if t.Parsed {
		row(tw, label, t.Time.Format(time.RFC3339))
		return
	}
	row(tw, label, t.Raw+" (unparsed)")
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./internal/render/plain/... -v`
Expected: PASS, all subtests green.

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/render/plain/plain.go internal/render/plain/plain_test.go
git commit -m "feat: add plain-text renderer for a single RDAP lookup"
```

---

### Task 6: `internal/bootstrap` — IANA RDAP Bootstrap (Fetch/Cache/Embed)

**Files:**
- Create: `/Users/pat/codes/plat/internal/bootstrap/dns.json` (real IANA snapshot)
- Create: `/Users/pat/codes/plat/internal/bootstrap/embed.go`
- Create: `/Users/pat/codes/plat/internal/bootstrap/bootstrap.go`
- Test: `/Users/pat/codes/plat/internal/bootstrap/bootstrap_test.go`

**Interfaces:**
- Consumes: nothing beyond stdlib.
- Produces: `type Resolver struct{...}`, `func (*Resolver) BaseURL(tld string) (string, bool)`, `type Options struct{ Refresh bool; Timeout time.Duration }`, `func Load(ctx context.Context, opts Options) (*Resolver, error)` — consumed by `cmd/plat/main.go` (Task 7).

- [ ] **Step 1: Fetch the real IANA bootstrap snapshot**

Run:
```bash
curl -sSL https://data.iana.org/rdap/dns.json -o /Users/pat/codes/plat/internal/bootstrap/dns.json
```
Expected: the file is written and is valid, non-trivial JSON. Verify:
```bash
cd /Users/pat/codes/plat && python3 -c "
import json
d = json.load(open('internal/bootstrap/dns.json'))
tlds = [t for svc in d['services'] for t in svc[0]]
print('service groups:', len(d['services']))
print('has com:', 'com' in tlds)
print('has org:', 'org' in tlds)
"
```
Expected: `has com: True` and `has org: True`. This file is the real production fallback shipped in the binary — it must be genuine IANA data, not a placeholder, since it's what a fully offline/air-gapped run falls back to.

- [ ] **Step 2: Create the embed directive**

Write `/Users/pat/codes/plat/internal/bootstrap/embed.go`:
```go
package bootstrap

import _ "embed"

//go:embed dns.json
var embedded []byte
```

- [ ] **Step 3: Write the failing test**

Write `/Users/pat/codes/plat/internal/bootstrap/bootstrap_test.go`:
```go
package bootstrap

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func withIsolatedCacheDir(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("HOME", tmp)
}

func TestEmbeddedSnapshotParses(t *testing.T) {
	r, err := parseResolver(embedded)
	if err != nil {
		t.Fatalf("parsing embedded snapshot: %v", err)
	}
	if _, ok := r.BaseURL("com"); !ok {
		t.Error(`BaseURL("com") not found in embedded snapshot`)
	}
	if _, ok := r.BaseURL("org"); !ok {
		t.Error(`BaseURL("org") not found in embedded snapshot`)
	}
}

func TestLoad_UsesFreshCache(t *testing.T) {
	withIsolatedCacheDir(t)
	path, ok := cachePath()
	if !ok {
		t.Fatal("cachePath() unexpectedly unavailable")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	fakeDoc := []byte(`{"services":[[["test"],["https://rdap.example.test/"]]]}`)
	if err := os.WriteFile(path, fakeDoc, 0o644); err != nil {
		t.Fatal(err)
	}

	orig := bootstrapURL
	bootstrapURL = "http://127.0.0.1:1/unreachable"
	defer func() { bootstrapURL = orig }()

	r, err := Load(context.Background(), Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	base, ok := r.BaseURL("test")
	if !ok || base != "https://rdap.example.test/" {
		t.Errorf(`BaseURL("test") = %q, %v, want "https://rdap.example.test/", true (fresh cache should win without a fetch)`, base, ok)
	}
}

func TestLoad_StaleCacheTriggersFetchFallback(t *testing.T) {
	withIsolatedCacheDir(t)
	path, ok := cachePath()
	if !ok {
		t.Fatal("cachePath() unexpectedly unavailable")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	staleDoc := []byte(`{"services":[[["stale"],["https://stale.example.test/"]]]}`)
	if err := os.WriteFile(path, staleDoc, 0o644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(path, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	orig := bootstrapURL
	bootstrapURL = "http://127.0.0.1:1/unreachable" // fetch will fail
	defer func() { bootstrapURL = orig }()

	r, err := Load(context.Background(), Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := r.BaseURL("stale"); !ok {
		t.Error(`BaseURL("stale") not found — stale cache should still be used when fetch fails`)
	}
}

func TestLoad_RefreshFailsFallsBackToEmbedded(t *testing.T) {
	withIsolatedCacheDir(t)

	orig := bootstrapURL
	bootstrapURL = "http://127.0.0.1:1/unreachable"
	defer func() { bootstrapURL = orig }()

	r, err := Load(context.Background(), Options{Refresh: true, Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := r.BaseURL("com"); !ok {
		t.Error(`BaseURL("com") not found — should have fallen back to embedded snapshot`)
	}
}

func TestParseResolver_NormalizesTrailingSlash(t *testing.T) {
	doc := []byte(`{"services":[[["xn--test"],["https://rdap.example.test"]]]}`)
	r, err := parseResolver(doc)
	if err != nil {
		t.Fatalf("parseResolver: %v", err)
	}
	base, ok := r.BaseURL("xn--test")
	if !ok || base != "https://rdap.example.test/" {
		t.Errorf("BaseURL = %q, %v, want trailing-slash-normalized URL", base, ok)
	}
}

func TestParseResolver_ValidJSONShape(t *testing.T) {
	var doc bootstrapDoc
	raw := []byte(`{"services":[[["a","b"],["https://x/"]]]}`)
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(doc.Services) != 1 || len(doc.Services[0][0]) != 2 {
		t.Fatalf("unexpected shape: %+v", doc)
	}
}
```

- [ ] **Step 4: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/bootstrap/... -v`
Expected: FAIL — build error, `undefined: parseResolver` / `undefined: cachePath` / `undefined: bootstrapURL` / `undefined: Load` / `undefined: Options` / `undefined: bootstrapDoc`.

- [ ] **Step 5: Write the implementation**

Write `/Users/pat/codes/plat/internal/bootstrap/bootstrap.go`:
```go
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// bootstrapURL is a var (not a const) so tests can point it at an
// unreachable address to deterministically exercise fetch-failure
// fallback paths without touching the network.
var bootstrapURL = "https://data.iana.org/rdap/dns.json"

const (
	cacheTTL      = 7 * 24 * time.Hour
	cacheDirName  = "plat"
	cacheFileName = "bootstrap.json"
)

// Resolver maps a TLD to its RDAP service base URL, as published by IANA's
// RDAP bootstrap registry (RFC 9224).
type Resolver struct {
	byTLD map[string]string
}

// BaseURL returns the RDAP base URL for tld and whether the TLD has RDAP
// coverage at all. tld should not include a leading dot.
func (r *Resolver) BaseURL(tld string) (string, bool) {
	u, ok := r.byTLD[strings.ToLower(tld)]
	return u, ok
}

type bootstrapDoc struct {
	Services [][][]string `json:"services"`
}

func parseResolver(data []byte) (*Resolver, error) {
	var doc bootstrapDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("bootstrap: parsing dns.json: %w", err)
	}
	byTLD := make(map[string]string)
	for _, service := range doc.Services {
		if len(service) < 2 || len(service[1]) == 0 {
			continue
		}
		base := strings.TrimRight(service[1][0], "/") + "/"
		for _, tld := range service[0] {
			byTLD[strings.ToLower(tld)] = base
		}
	}
	return &Resolver{byTLD: byTLD}, nil
}

// Options controls Load's behavior.
type Options struct {
	// Refresh forces a fetch attempt even if a fresh cache entry exists.
	// A failed fetch still falls back to a stale cache or the embedded
	// snapshot rather than erroring.
	Refresh bool
	// Timeout bounds the network fetch. Defaults to 5s.
	Timeout time.Duration
}

func cachePath() (string, bool) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", false
	}
	return filepath.Join(dir, cacheDirName, cacheFileName), true
}

// Load resolves a Resolver using, in order of preference: a fresh local
// cache, a freshly fetched copy of the IANA bootstrap file (which it then
// caches), a stale local cache, or the embedded fallback snapshot. It only
// returns an error if the embedded snapshot itself fails to parse, which
// should not happen in practice — Load never fails startup purely because
// the network is unavailable.
func Load(ctx context.Context, opts Options) (*Resolver, error) {
	path, haveCachePath := cachePath()

	if !opts.Refresh && haveCachePath {
		if data, ok := readFreshCache(path); ok {
			if r, err := parseResolver(data); err == nil {
				return r, nil
			}
		}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if data, err := fetch(ctx, timeout); err == nil {
		if r, perr := parseResolver(data); perr == nil {
			if haveCachePath {
				writeCache(path, data)
			}
			return r, nil
		}
	}

	if haveCachePath {
		if data, err := os.ReadFile(path); err == nil {
			if r, err := parseResolver(data); err == nil {
				return r, nil
			}
		}
	}

	return parseResolver(embedded)
}

func readFreshCache(path string) ([]byte, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, false
	}
	if time.Since(info.ModTime()) >= cacheTTL {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return data, true
}

func writeCache(path string, data []byte) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o644)
}

func fetch(ctx context.Context, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bootstrapURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bootstrap: fetching %s: status %d", bootstrapURL, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 5<<20))
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./internal/bootstrap/... -v`
Expected: PASS, all subtests green. (`TestLoad_RefreshFailsFallsBackToEmbedded` may take up to ~500ms due to the timeout; that's expected.)

- [ ] **Step 7: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/bootstrap/dns.json internal/bootstrap/embed.go internal/bootstrap/bootstrap.go internal/bootstrap/bootstrap_test.go
git commit -m "feat: add IANA RDAP bootstrap fetch/cache/embed"
```

---

### Task 7: `cmd/plat` — Cobra Wiring + Exit Codes

**Files:**
- Modify: `/Users/pat/codes/plat/cmd/plat/main.go` (replaces the Task 1 stub entirely)
- Test: `/Users/pat/codes/plat/cmd/plat/main_test.go`

**Interfaces:**
- Consumes: `domain.Normalize` (Task 2), `rdap.Client`/`rdap.ErrDomainNotFound` (Task 4), `plain.Render` (Task 5), `bootstrap.Load`/`bootstrap.Options` (Task 6).
- Produces: the `plat` binary's exit-code contract (`0`/`1`/`2`/`3`) via `func exitCode(err error, stderr io.Writer) int` and `func run(args []string, stdout, stderr io.Writer) int` — this is the final integration point; no later M1 task consumes these.

- [ ] **Step 1: Write the failing test**

Write `/Users/pat/codes/plat/cmd/plat/main_test.go`:
```go
package main

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/patramsey/plat/internal/rdap"
)

func TestExitCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil error", nil, 0},
		{"usage error", usageError{errors.New("bad input")}, 2},
		{"domain not found", rdap.ErrDomainNotFound, 1},
		{"wrapped domain not found", fmt.Errorf("lookup: %w", rdap.ErrDomainNotFound), 1},
		{"other error", errors.New("network exploded"), 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer
			got := exitCode(tt.err, &stderr)
			if got != tt.want {
				t.Errorf("exitCode(%v) = %d, want %d", tt.err, got, tt.want)
			}
			if tt.err != nil && stderr.Len() == 0 {
				t.Errorf("expected an error message written to stderr")
			}
		})
	}
}

func TestRun_RejectsWrongArgCount(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no args", []string{}},
		{"two args", []string{"example.com", "example.org"}},
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

func TestRun_VersionSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"version"}, &stdout, &stderr)
	if got != 0 {
		t.Errorf("run([version]) exit code = %d, want 0", got)
	}
	if stdout.Len() == 0 {
		t.Error("expected version to be printed to stdout")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./cmd/plat/... -v`
Expected: FAIL — build error, `undefined: usageError` / `undefined: exitCode` / `undefined: run`.

- [ ] **Step 3: Write the implementation**

Overwrite `/Users/pat/codes/plat/cmd/plat/main.go`:
```go
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/patramsey/plat/internal/bootstrap"
	"github.com/patramsey/plat/internal/domain"
	"github.com/patramsey/plat/internal/rdap"
	"github.com/patramsey/plat/internal/render/plain"
)

// version is overwritten via -ldflags at release build time (M7); "dev" is
// what local builds report.
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// usageError marks input-validation failures (exit code 2), distinct from
// not-found (exit code 1) and all other lookup failures (exit code 3).
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func run(args []string, stdout, stderr io.Writer) int {
	var refreshBootstrap bool
	var timeout time.Duration

	root := &cobra.Command{
		Use:           "plat <domain>",
		Short:         "Look up domain ownership via RDAP",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args: func(cmd *cobra.Command, cliArgs []string) error {
			if len(cliArgs) != 1 {
				return usageError{fmt.Errorf("expected exactly one domain argument, got %d", len(cliArgs))}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, cliArgs []string) error {
			return lookup(cmd.Context(), stdout, cliArgs[0], refreshBootstrap, timeout)
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)
	root.Flags().BoolVar(&refreshBootstrap, "refresh-bootstrap", false, "force a fresh fetch of the IANA RDAP bootstrap file")
	root.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "per-request timeout for bootstrap and RDAP lookups")

	// Flags reserved for later milestones — intentionally not implemented
	// here: -o/--output (M4), --raw (M4), --source (M2/M3), --no-follow
	// (M3), -q/--quiet (M4), --no-color (M5), -v/--verbose (M2), plus
	// `completion`/`man` subcommands (M7).

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the plat version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(stdout, version)
			return nil
		},
	})

	err := root.Execute()
	return exitCode(err, stderr)
}

func lookup(ctx context.Context, stdout io.Writer, input string, refresh bool, timeout time.Duration) error {
	name, err := domain.Normalize(input)
	if err != nil {
		return usageError{err}
	}

	resolver, err := bootstrap.Load(ctx, bootstrap.Options{Refresh: refresh, Timeout: timeout})
	if err != nil {
		return fmt.Errorf("resolving RDAP bootstrap: %w", err)
	}

	baseURL, ok := resolver.BaseURL(name.TLD)
	if !ok {
		return fmt.Errorf("no RDAP service is known for .%s", name.TLD)
	}

	client := &rdap.Client{Timeout: timeout, UserAgent: "plat/" + version}
	result, err := client.Domain(ctx, baseURL, name.Punycode)
	if err != nil {
		return err
	}

	return plain.Render(stdout, result.Domain)
}

func exitCode(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	fmt.Fprintln(stderr, "plat:", err)

	var usageErr usageError
	switch {
	case errors.As(err, &usageErr):
		return 2
	case errors.Is(err, rdap.ErrDomainNotFound):
		return 1
	default:
		return 3
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./cmd/plat/... -v`
Expected: PASS, all subtests green.

- [ ] **Step 5: Full-program verification**

Run:
```bash
cd /Users/pat/codes/plat && go mod tidy && go build ./... && go vet ./... && go test ./...
```
Expected: all commands succeed with no diffs to `go.mod`/`go.sum` beyond what `go mod tidy` settles (cobra should now show as actually used, since Task 7 imports it), and `go test ./...` shows `ok` for every package.

- [ ] **Step 6: Commit**

```bash
cd /Users/pat/codes/plat
git add cmd/plat/main.go cmd/plat/main_test.go go.mod go.sum
git commit -m "feat: wire cobra CLI with exit-code contract"
```

---

### Task 8: CI — Lint, Test, Build Matrix

**Files:**
- Create: `/Users/pat/codes/plat/.golangci.yml`
- Create: `/Users/pat/codes/plat/.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the full module built by Tasks 1–7.
- Produces: green CI on push/PR to `main`. No other M1 task depends on this one; it's the final task.

- [ ] **Step 1: Create the golangci-lint config**

Write `/Users/pat/codes/plat/.golangci.yml` (v2 schema — the installed `golangci-lint` is 2.12.2, and v2's config format differs from v1):
```yaml
version: "2"

linters:
  default: standard
  enable:
    - errcheck
    - govet
    - ineffassign
    - staticcheck
    - unused

formatters:
  enable:
    - gofmt
    - goimports
```

- [ ] **Step 2: Run golangci-lint locally**

Run:
```bash
cd /Users/pat/codes/plat && golangci-lint run
```
Expected: no issues reported. If issues surface, fix them in the relevant file from Tasks 1–7 (do not disable the linter rule) and re-run until clean.

- [ ] **Step 3: Create the CI workflow**

Write `/Users/pat/codes/plat/.github/workflows/ci.yml`:
```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25"
      - uses: golangci/golangci-lint-action@v6
        with:
          version: v2.12.2

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25"
      - run: go test ./...

  build:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - goos: linux
            goarch: amd64
          - goos: linux
            goarch: arm64
          - goos: darwin
            goarch: amd64
          - goos: darwin
            goarch: arm64
          - goos: windows
            goarch: amd64
          - goos: windows
            goarch: arm64
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25"
      - env:
          GOOS: ${{ matrix.goos }}
          GOARCH: ${{ matrix.goarch }}
          CGO_ENABLED: "0"
        run: go build ./...
```

- [ ] **Step 4: Sanity-check the workflow YAML**

Run:
```bash
cd /Users/pat/codes/plat && python3 -c "import yaml, sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('valid YAML')"
```
Expected: `valid YAML`. (This is a syntax check only — CI itself is the real validation, exercised once this is pushed and a workflow run triggers.)

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add .golangci.yml .github/workflows/ci.yml
git commit -m "ci: add lint, test, and 6-target build matrix"
```

---

## Milestone Verification (manual, not automated)

Once all 8 tasks are complete, confirm the milestone's actual definition of done — this requires live network access and is deliberately not part of the automated test suite:

```bash
cd /Users/pat/codes/plat
go run ./cmd/plat google.com               # expect: aligned plain-text output, exit 0
echo $?

go run ./cmd/plat localhost                # expect: friendly single-label error, exit 2
echo $?

go run ./cmd/plat printer.local            # expect: friendly reserved-TLD error, exit 2
echo $?

go run ./cmd/plat this-domain-should-not-exist-xyzabc123.com  # expect: not-found message, exit 1
echo $?

go run ./cmd/plat version                  # expect: prints "dev"
```

If `google.com` doesn't resolve cleanly (e.g. Verisign changes response shape in a way the tolerant parser doesn't expect), that's a real finding — capture the raw response and feed it back into Task 4's fixture/tests rather than special-casing it in `main.go`.
