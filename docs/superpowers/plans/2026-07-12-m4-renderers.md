# M4 — Renderers, Root-Command Rewire, Exit Codes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewire `plat <domain>` from its current registry-RDAP-only path onto the full `collect.Collect` + `merge.Merge` pipeline, add a stable-schema JSON/NDJSON encoder and an unstyled plain/human renderer for the unified `model.Record`, and make exit codes 0/1/2/3 correct for the multi-source world.

**Architecture:** Two new leaf packages (`internal/render` for format selection/TTY detection, `internal/render/machine` for the JSON view-model) plus a retype of the existing `internal/render/plain`. `internal/model`, `internal/whois/parse`, and `internal/collect` get small additive extensions to carry a not-found signal end to end. `cmd/plat/main.go`'s root command is substantially rewired; the hidden `whois`/`merge` debug subcommands are untouched.

**Tech Stack:** Go 1.25 stdlib only — no new third-party dependencies this milestone (TTY detection uses `os.ModeCharDevice`, not `golang.org/x/term`).

## Global Constraints

- Root command `plat <domain>` is REWIRED to use `collect.Collect` + `merge.Merge`, replacing the current registry-RDAP-only path. `internal/render/plain` is retyped from `*rdap.DomainResponse` to `model.Record` — not kept as a fallback; the old rdap-typed `Render` and its test are deleted in the same task that replaces them.
- The hidden `whois` and `merge` subcommands (`cmd/plat/whois.go`, `cmd/plat/merge.go`) are KEPT UNCHANGED in M4. Do not modify either file.
- `--source rdap|whois|registry|registrar`: one flag, single value, filters to a row/column of the 2×2 source matrix (`rdap`→{registry-rdap,registrar-rdap}, `whois`→{registry-whois,registrar-whois}, `registry`→{registry-rdap,registry-whois}, `registrar`→{registrar-rdap,registrar-whois}). Filtering happens inside `collect.Collect` to avoid network calls for a fully-suppressed axis, EXCEPT where RDAP/WHOIS protocol structure makes that impossible: registrar RDAP can only be discovered via the registry RDAP response's `related` link, and the WHOIS registrar hop can only be reached by completing the same referral chain that visits the registry hop — in both cases the upstream fetch still happens (it's structurally required), but its `model.SourceRecord` is only added to the output when that specific source is allowed.
- JSON schema: a separate `internal/render/machine` view-model package (NOT `MarshalJSON` methods on `model` types) builds camelCase exported structs from `model.Record`. `schemaVersion` is a top-level int const `1`. Absent fields (`!Present()`) are OMITTED from the JSON entirely via `*struct` + `omitempty` — validated: a nil pointer field is skipped by `encoding/json` when tagged `omitempty`; a non-nil pointer to a populated struct is always included, and `jq .expires.value` on a record with no expires source returns `null` cleanly (missing-path access in jq is `null`, not an error).
- `human` and `plain` render IDENTICALLY in M4 (both dispatch to the same unstyled `internal/render/plain.Render`) — kept as distinct `Format` enum values now so a later milestone can reroute just `human` without touching the selection architecture. TTY detection is stdlib-only (`os.Stdout.Stat()` + `os.ModeCharDevice`) — no new dependency.
- Exit-code derivation: `model.SourceResult` gains `NotFound bool` (additive). `FromRDAP` sets it via `errors.Is(fetchErr, rdap.ErrDomainNotFound)`. `parse.Fields` gains `NotFound bool`, set via a marker-scan mirroring the existing `RateLimited` mechanism exactly. `FromWHOIS`'s `fromHop` copies `f.NotFound` to `meta.NotFound`. A new pure helper `deriveOutcome(sources []model.SourceResult) int` (validated locally before this plan was written) computes 0/1/3 from a merged record's sources.
- Multi-domain: root's `Args` validator changes from exactly-1 to at-least-1. Sequential processing — no cross-domain concurrency. `-o json` with >1 domain is a usage error (exit 2) suggesting `-o ndjson`. Overall multi-domain exit code is the worst of all per-domain codes under ordering `0 < 1 < 2 < 3`.
- In-scope flags for M4: `-o/--output`, `--raw`, `--source`, `--no-follow`, plus the pre-existing `--refresh-bootstrap`/`--timeout`. Deferred (name in a comment, do not implement): `-q/--quiet`, `-v/--verbose`, `--no-color`, `completion`/`man` subcommands.
- `--raw` with a non-machine format (`human`/`plain`) is a usage error.
- Machine-mode errors go to STDERR as `{"error": "...", "domain": "..."}` — stdout stays schema-clean, only successfully-rendered records go to stdout in machine mode. Human/plain mode errors go to stderr as a plain line.
- `docs/schema.md`: pragmatic prose + a worked JSON example for `schemaVersion: 1` — not a formal JSON-Schema file (that's M7).
- Every task in this plan that modifies a file from an earlier milestone MUST verify, and its report MUST explicitly confirm, that every pre-existing test in that file's package still passes unmodified. This plan touches more already-shipped files across more milestones (M1's `render/plain`, M2's `whois/parse`, M3's `model`/`collect`, M1-M3's `cmd/plat`) than any prior milestone — regression discipline is not optional in any single task here.

---

### Task 1: Thread a Not-Found Signal Through Model, Parse, and Adapters

**Files:**
- Modify: `internal/model/record.go` (add `NotFound bool` to `SourceResult`)
- Modify: `internal/whois/parse/parse.go` (add `NotFound bool` to `Fields`, add marker-scan)
- Create: `testdata/whois/notfound.txt`
- Modify: `internal/collect/adapt_rdap.go` (set `meta.NotFound` from the fetch error)
- Modify: `internal/collect/adapt_whois.go` (copy `f.NotFound` to `meta.NotFound`)
- Test: `internal/whois/parse/parse_test.go` (extend), `internal/collect/adapt_rdap_test.go` (extend), `internal/collect/adapt_whois_test.go` (extend)

**Interfaces:**
- Consumes: `model.SourceResult` (existing), `parse.Fields`/`Parse` (existing), `rdap.ErrDomainNotFound` (existing, M1), `FromRDAP`/`fromHop` (existing, M3).
- Produces: `model.SourceResult.NotFound bool`, `parse.Fields.NotFound bool` — consumed by Task 6's `deriveOutcome`.

- [ ] **Step 1: Write the failing tests**

Create `testdata/whois/notfound.txt`:
```
No match for "NONEXISTENT-DOMAIN-XYZ.COM".
>>> Last update of WHOIS database: 2026-07-12T09:15:00Z <<<
```

Append to `internal/whois/parse/parse_test.go` (uses the existing `loadFixture` helper already defined in that file):
```go
func TestParse_NotFoundDetection(t *testing.T) {
	raw := loadFixture(t, "notfound.txt")
	f := Parse(raw, "com")
	if !f.NotFound {
		t.Error("NotFound = false, want true")
	}
}

func TestParse_FoundDomainNotFlaggedNotFound(t *testing.T) {
	raw := loadFixture(t, "verisign-com-example.txt")
	f := Parse(raw, "com")
	if f.NotFound {
		t.Error("NotFound = true, want false for a real registered-domain response")
	}
}
```

Append to `internal/collect/adapt_rdap_test.go` (uses the existing `time` import already present in that file):
```go
func TestFromRDAP_NotFoundError(t *testing.T) {
	sr := FromRDAP(model.SourceRegistryRDAP, nil, 10*time.Millisecond, rdap.ErrDomainNotFound)
	if !sr.Meta.NotFound {
		t.Error("Meta.NotFound = false, want true for rdap.ErrDomainNotFound")
	}
}

func TestFromRDAP_OtherErrorNotFlaggedNotFound(t *testing.T) {
	sr := FromRDAP(model.SourceRegistrarRDAP, nil, 10*time.Millisecond, errors.New("connection refused"))
	if sr.Meta.NotFound {
		t.Error("Meta.NotFound = true, want false for a non-not-found error")
	}
}
```
Add `"errors"` to `adapt_rdap_test.go`'s import block if not already present.

Append to `internal/collect/adapt_whois_test.go`:
```go
func TestFromWHOIS_NotFoundHop(t *testing.T) {
	raw := loadWHOISFixture(t, "notfound.txt")
	result := &whois.Result{
		Domain: "nonexistent-domain-xyz.com",
		Hops: []whois.Hop{
			{Server: "whois.iana.org"},
			{Server: "whois.verisign-grs.com", Raw: raw, Fields: parse.Parse(raw, "com")},
		},
	}
	sources := FromWHOIS(result)
	if len(sources) != 1 {
		t.Fatalf("FromWHOIS returned %d sources, want 1", len(sources))
	}
	if !sources[0].Meta.NotFound {
		t.Error("Meta.NotFound = false, want true")
	}
}
```
(This reuses `loadWHOISFixture`, already defined in `adapt_whois_test.go` from Task 7 of the M3 plan — it reads from `../../testdata/whois/`, so `notfound.txt` from Step 1 above is directly usable here too.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/parse/... ./internal/collect/... -v -run 'NotFound'`
Expected: FAIL — build errors, `f.NotFound`/`sr.Meta.NotFound`/`sources[0].Meta.NotFound` undefined (the fields don't exist yet).

- [ ] **Step 3: Write the implementation**

Modify `internal/model/record.go` — add `NotFound bool` to the existing `SourceResult` struct:
```go
type SourceResult struct {
	Source   SourceID
	OK       bool
	NotFound bool
	Latency  time.Duration
	Err      string
	Raw      []byte
}
```

Modify `internal/whois/parse/parse.go` — add `NotFound bool` to `Fields`:
```go
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
	NotFound             bool
	Unmapped             map[string][]string
}
```

Add a `notFoundMarkers` var next to the existing `rateLimitMarkers` var:
```go
var notFoundMarkers = []string{
	"no match",
	"not found",
	"no entries found",
	"no data found",
	"status: free",
}
```

In `Parse`, immediately after the existing `rateLimitMarkers` scan loop, add an identical-shaped scan for not-found markers:
```go
	lowerRaw := strings.ToLower(raw)
	for _, marker := range rateLimitMarkers {
		if strings.Contains(lowerRaw, marker) {
			f.RateLimited = true
			break
		}
	}
	for _, marker := range notFoundMarkers {
		if strings.Contains(lowerRaw, marker) {
			f.NotFound = true
			break
		}
	}
```

Modify `internal/collect/adapt_rdap.go` — add `"errors"` to the import block, and set `meta.NotFound` in the `fetchErr != nil` branch:
```go
	if fetchErr != nil {
		meta.OK = false
		meta.Err = fetchErr.Error()
		meta.NotFound = errors.Is(fetchErr, rdap.ErrDomainNotFound)
		return model.SourceRecord{Meta: meta}
	}
```

Modify `internal/collect/adapt_whois.go` — in `fromHop`, immediately after `meta.OK = true` and `f := hop.Fields`, add:
```go
	meta.OK = true
	meta.NotFound = f.NotFound
	f := hop.Fields
```
(Reorder so `f` is assigned before or after `meta.NotFound = f.NotFound` as needed — `f` must be assigned before this line references it. The corrected order is:)
```go
	meta.OK = true
	f := hop.Fields
	meta.NotFound = f.NotFound
```

- [ ] **Step 4: Run tests to verify they pass, and confirm zero regression**

Run: `cd /Users/pat/codes/plat && go test ./internal/whois/parse/... ./internal/collect/... -v`
Expected: PASS — all new tests, AND every pre-existing test in both packages (from M1/M2/M3) still green, unmodified.

Run: `cd /Users/pat/codes/plat && go test ./...`
Expected: all 10 packages `ok` (whole-repo regression check, since `internal/model` is imported everywhere).

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/model/record.go internal/whois/parse/parse.go internal/whois/parse/parse_test.go internal/collect/adapt_rdap.go internal/collect/adapt_rdap_test.go internal/collect/adapt_whois.go internal/collect/adapt_whois_test.go testdata/whois/notfound.txt
git commit -m "feat: thread a not-found signal through model, parse, and adapters"
```

---

### Task 2: `--source` Filtering in `internal/collect`

**Files:**
- Modify: `internal/collect/collect.go` (add `Options.Sources` + `allows` + gate every branch)
- Test: `internal/collect/collect_test.go` (extend)

**Interfaces:**
- Consumes: `model.SourceID` constants (existing), `FromRDAP`/`FromWHOIS` (existing).
- Produces: `Options.Sources []model.SourceID` — consumed by Task 6's `parseSourceFilter`/root-command wiring.

- [ ] **Step 1: Write the failing tests**

Append to `internal/collect/collect_test.go` (reuses the existing `startWHOISListener` helper already defined in that file):
```go
func TestCollect_SourceFilterRDAPOnly(t *testing.T) {
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

	ianaWHOISAddr := startWHOISListener(t, func(query string) string {
		t.Error("WHOIS IANA server should never be contacted when --source rdap is set")
		return ""
	})

	name, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	sources := Collect(context.Background(), name, registrySrv.URL, ianaWHOISAddr, Options{
		Timeout: 2 * time.Second,
		Sources: []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistrarRDAP},
	})

	var gotRegistryRDAP, gotRegistrarRDAP bool
	for _, s := range sources {
		switch s.Meta.Source {
		case model.SourceRegistryRDAP:
			gotRegistryRDAP = true
		case model.SourceRegistrarRDAP:
			gotRegistrarRDAP = true
		case model.SourceRegistryWHOIS, model.SourceRegistrarWHOIS:
			t.Errorf("unexpected WHOIS source in output: %+v", s)
		}
	}
	if !gotRegistryRDAP || !gotRegistrarRDAP {
		t.Errorf("expected both RDAP sources present, got registry=%v registrar=%v", gotRegistryRDAP, gotRegistrarRDAP)
	}
}

func TestCollect_SourceFilterWHOISOnly(t *testing.T) {
	registrarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("registrar RDAP server should never be contacted when --source whois is set")
	}))
	defer registrarSrv.Close()
	registrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("registry RDAP server should never be contacted when --source whois is set")
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

	name, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	sources := Collect(context.Background(), name, registrySrv.URL, ianaWHOISAddr, Options{
		Timeout: 2 * time.Second,
		Sources: []model.SourceID{model.SourceRegistryWHOIS, model.SourceRegistrarWHOIS},
	})

	var gotRegistryWHOIS, gotRegistrarWHOIS bool
	for _, s := range sources {
		switch s.Meta.Source {
		case model.SourceRegistryWHOIS:
			gotRegistryWHOIS = true
		case model.SourceRegistrarWHOIS:
			gotRegistrarWHOIS = true
		case model.SourceRegistryRDAP, model.SourceRegistrarRDAP:
			t.Errorf("unexpected RDAP source in output: %+v", s)
		}
	}
	if !gotRegistryWHOIS || !gotRegistrarWHOIS {
		t.Errorf("expected both WHOIS sources present, got registry=%v registrar=%v", gotRegistryWHOIS, gotRegistrarWHOIS)
	}
}

func TestCollect_SourceFilterRegistryOnly(t *testing.T) {
	// registrar-rdap must be genuinely suppressed (never contacted) since
	// it depends only on the registrar-rdap allow-check, not on anything
	// structurally required.
	registrarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("registrar RDAP server should never be contacted when --source registry is set")
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

	// The registrar WHOIS hop WILL still be contacted (the referral chain
	// is structurally sequential), so this listener must respond normally
	// rather than fail the test — only its RESULT should be filtered out.
	registrarWHOISAddr := startWHOISListener(t, func(query string) string {
		return "Domain Name: example.com\nRegistrar: Example Registrar, Inc.\n"
	})
	registryWHOISAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: %s\nRegistrar: Example Registrar, Inc.\n", registrarWHOISAddr)
	})
	ianaWHOISAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("refer:        %s\ndomain:       COM\n", registryWHOISAddr)
	})

	name, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	sources := Collect(context.Background(), name, registrySrv.URL, ianaWHOISAddr, Options{
		Timeout: 2 * time.Second,
		Sources: []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistryWHOIS},
	})

	var gotRegistryRDAP, gotRegistryWHOIS bool
	for _, s := range sources {
		switch s.Meta.Source {
		case model.SourceRegistryRDAP:
			gotRegistryRDAP = true
		case model.SourceRegistryWHOIS:
			gotRegistryWHOIS = true
		case model.SourceRegistrarRDAP, model.SourceRegistrarWHOIS:
			t.Errorf("unexpected registrar-tier source in output: %+v", s)
		}
	}
	if !gotRegistryRDAP || !gotRegistryWHOIS {
		t.Errorf("expected both registry-tier sources present, got rdap=%v whois=%v", gotRegistryRDAP, gotRegistryWHOIS)
	}
}

func TestCollect_SourceFilterRegistrarOnly(t *testing.T) {
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

	// The registry RDAP server WILL still be contacted (needed to
	// discover the related link), so it must respond normally — only its
	// RESULT should be filtered out of the output.
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

	registrarWHOISAddr := startWHOISListener(t, func(query string) string {
		return "Domain Name: example.com\nRegistrar: Example Registrar, Inc.\n"
	})
	registryWHOISAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: %s\nRegistrar: Example Registrar, Inc.\n", registrarWHOISAddr)
	})
	ianaWHOISAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("refer:        %s\ndomain:       COM\n", registryWHOISAddr)
	})

	name, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	sources := Collect(context.Background(), name, registrySrv.URL, ianaWHOISAddr, Options{
		Timeout: 2 * time.Second,
		Sources: []model.SourceID{model.SourceRegistrarRDAP, model.SourceRegistrarWHOIS},
	})

	var gotRegistrarRDAP, gotRegistrarWHOIS bool
	for _, s := range sources {
		switch s.Meta.Source {
		case model.SourceRegistrarRDAP:
			gotRegistrarRDAP = true
		case model.SourceRegistrarWHOIS:
			gotRegistrarWHOIS = true
		case model.SourceRegistryRDAP, model.SourceRegistryWHOIS:
			t.Errorf("unexpected registry-tier source in output: %+v", s)
		}
	}
	if !gotRegistrarRDAP || !gotRegistrarWHOIS {
		t.Errorf("expected both registrar-tier sources present, got rdap=%v whois=%v", gotRegistrarRDAP, gotRegistrarWHOIS)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/pat/codes/plat && go test ./internal/collect/... -v -run 'SourceFilter'`
Expected: FAIL — build error, `Options.Sources` field undefined.

- [ ] **Step 3: Write the implementation**

Modify `internal/collect/collect.go`:
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
	// Sources restricts which of the four possible sources Collect
	// includes in its output. nil (the zero value) means all four are
	// allowed. This does not always suppress the underlying network
	// call: registrar RDAP can only be discovered via the registry
	// RDAP response's related link, and the WHOIS registrar hop can
	// only be reached by completing the same referral chain that
	// visits the registry hop — in both cases the upstream fetch still
	// happens when needed to reach an allowed downstream source, but
	// its own SourceRecord is only emitted if it is itself allowed.
	Sources []model.SourceID
}

func (o Options) allows(id model.SourceID) bool {
	if len(o.Sources) == 0 {
		return true
	}
	for _, s := range o.Sources {
		if s == id {
			return true
		}
	}
	return false
}

// Collect fans out to registry RDAP (and, unless NoFollow, the registrar
// RDAP hop via the registry's "related" link) and the WHOIS chain, and
// returns one model.SourceRecord per source actually attempted AND
// allowed by opts.Sources. registryBaseURL is the already-resolved RDAP
// service base for the domain's TLD (empty string means no RDAP coverage
// — Collect degrades to WHOIS-only). whoisIANAServer overrides the WHOIS
// client's IANA server (empty string uses whois.Client's own
// "whois.iana.org" default) — this parameter exists so tests can point
// the WHOIS chain at a local fake IANA server, the same way internal/whois's
// own tests do.
//
// A single source failing is normal, not fatal — Collect never returns an
// error; callers pass the (possibly partial) result straight to
// merge.Merge.
func Collect(ctx context.Context, name domain.Name, registryBaseURL string, whoisIANAServer string, opts Options) []model.SourceRecord {
	var out []model.SourceRecord

	needRDAP := registryBaseURL != "" &&
		(opts.allows(model.SourceRegistryRDAP) || (!opts.NoFollow && opts.allows(model.SourceRegistrarRDAP)))
	if needRDAP {
		rdapClient := &rdap.Client{Timeout: opts.Timeout}
		start := time.Now()
		result, err := rdapClient.Domain(ctx, registryBaseURL, name.Punycode)
		if opts.allows(model.SourceRegistryRDAP) {
			out = append(out, FromRDAP(model.SourceRegistryRDAP, result, time.Since(start), err))
		}

		if !opts.NoFollow && opts.allows(model.SourceRegistrarRDAP) && err == nil && result.Domain != nil {
			if registrarURL, ok := result.Domain.RelatedRegistrarURL(); ok && differentHost(registryBaseURL, registrarURL) {
				rStart := time.Now()
				rResult, rErr := rdapClient.DomainURL(ctx, registrarURL)
				out = append(out, FromRDAP(model.SourceRegistrarRDAP, rResult, time.Since(rStart), rErr))
			}
		}
	}

	if opts.allows(model.SourceRegistryWHOIS) || opts.allows(model.SourceRegistrarWHOIS) {
		whoisClient := &whois.Client{Timeout: opts.Timeout, IANAServer: whoisIANAServer}
		wResult, _ := whoisClient.Lookup(ctx, name)
		for _, sr := range FromWHOIS(wResult) {
			if opts.allows(sr.Meta.Source) {
				out = append(out, sr)
			}
		}
	}

	return out
}

// differentHost reports whether registrarURL points at a DIFFERENT network
// authority (host:port) than registryBaseURL — a loop guard against a
// registry advertising itself as its own registrar, or a misconfigured
// related link pointing back at the same server. Comparing the full Host
// (not just Hostname) matters for tests that run registry and registrar
// as separate local listeners sharing the loopback address on different
// ports — those are genuinely different servers, not a loop. Any URL
// parse failure is treated as "same host" (i.e. skip) — DomainURL itself
// would also reject a genuinely malformed or non-http(s) URL, but there's
// no reason to attempt a fetch this function already can't make sense of.
func differentHost(registryBaseURL, registrarURL string) bool {
	rb, err1 := url.Parse(registryBaseURL)
	ru, err2 := url.Parse(registrarURL)
	if err1 != nil || err2 != nil {
		return false
	}
	return !strings.EqualFold(rb.Host, ru.Host)
}
```

- [ ] **Step 4: Run tests to verify they pass, and confirm zero regression**

Run: `cd /Users/pat/codes/plat && go test ./internal/collect/... -v`
Expected: PASS — the 4 new filter tests, AND every pre-existing test in this package (from M3: `TestCollect_RegistryAndRegistrarRDAPPlusWHOIS`, `TestCollect_NoFollowSkipsRegistrarHop`, `TestCollect_EmptyBaseURLSkipsRDAPEntirely`, `TestCollect_WHOISOnlySources`, plus all `TestFromRDAP_*`/`TestFromWHOIS_*` adapter tests including Task 1's new ones) still green, unmodified.

Run: `cd /Users/pat/codes/plat && go test ./...`
Expected: all 10 packages `ok`.

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/collect/collect.go internal/collect/collect_test.go
git commit -m "feat: add --source filtering to the collect orchestrator"
```

---

### Task 3: Retype `internal/render/plain` to `model.Record`

**Files:**
- Modify: `internal/render/plain/plain.go` (full rewrite — delete the rdap-typed version)
- Modify: `internal/render/plain/plain_test.go` (full rewrite — delete the rdap-fixture-based tests)

**Interfaces:**
- Consumes: `model.Record`/`model.Field[T]`/`model.TimeValue`/`model.SourceResult`/`model.Conflict`/`model.RedactionNotice`/`model.Precedence` (M3, existing).
- Produces: `func Render(w io.Writer, r model.Record) error` — consumed by Task 6's root-command dispatch.

- [ ] **Step 1: Write the failing test**

Replace the entire contents of `internal/render/plain/plain_test.go`:
```go
package plain

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/model"
)

func TestRender_FullyPresentRecord(t *testing.T) {
	created, _ := time.Parse(time.RFC3339, "1995-08-14T04:00:00Z")
	expires, _ := time.Parse(time.RFC3339, "2026-08-13T04:00:00Z")

	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Handle: model.Field[string]{Value: "2336799_DOMAIN_COM-VRSN", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Registrar: model.RegistrarInfo{
			Name: model.Field[string]{Value: "Example Registrar, Inc.", Sources: []model.SourceID{model.SourceRegistrarRDAP}},
		},
		Status:  model.Field[[]string]{Value: []string{"clientTransferProhibited"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Created: model.Field[model.TimeValue]{Value: model.TimeValue{Time: created, Raw: "1995-08-14T04:00:00Z", Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Expires: model.Field[model.TimeValue]{Value: model.TimeValue{Time: expires, Raw: "2026-08-13T04:00:00Z", Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Nameservers: model.Field[[]string]{Value: []string{"a.iana-servers.net", "b.iana-servers.net"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Sources: []model.SourceResult{
			{Source: model.SourceRegistryRDAP, OK: true, Latency: 89 * time.Millisecond},
			{Source: model.SourceRegistrarRDAP, OK: true, Latency: 145 * time.Millisecond},
			{Source: model.SourceRegistryWHOIS, OK: false, Err: "timeout"},
		},
	}

	var buf bytes.Buffer
	if err := Render(&buf, rec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"Domain:", "example.com",
		"Handle:", "2336799_DOMAIN_COM-VRSN",
		"Example Registrar, Inc.",
		"clientTransferProhibited",
		"1995-08-14T04:00:00Z",
		"2026-08-13T04:00:00Z",
		"a.iana-servers.net",
		string(model.SourceRegistryRDAP),
		"89ms",
		"timeout",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, out)
		}
	}

	for _, b := range []byte(out) {
		if b == 0x1b {
			t.Fatalf("output contains ANSI escape byte, want zero ANSI:\n%s", out)
		}
	}
}

func TestRender_UnparsedTimeFallback(t *testing.T) {
	rec := model.Record{
		Domain:  model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
		Expires: model.Field[model.TimeValue]{Value: model.TimeValue{Raw: "not-a-date", Parsed: false}, Sources: []model.SourceID{model.SourceRegistryWHOIS}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "not-a-date (unparsed)") {
		t.Errorf("output missing unparsed-date fallback, got:\n%s", out)
	}
}

func TestRender_SkipsAbsentFields(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, absent := range []string{"Handle:", "Registrar:", "Status:", "Created:", "Expires:", "Nameservers:", "DNSSEC:"} {
		if strings.Contains(out, absent) {
			t.Errorf("expected %q row to be skipped when absent, got:\n%s", absent, out)
		}
	}
}

func TestRender_ConflictOrderingIsDeterministic(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Conflicts: []model.Conflict{
			{
				Field: model.FieldExpires,
				Values: map[model.SourceID]string{
					model.SourceRegistryWHOIS:  "2026-08-10",
					model.SourceRegistryRDAP:   "2026-08-13T04:00:00Z",
					model.SourceRegistrarRDAP:  "2026-08-13T04:00:00Z",
					model.SourceRegistrarWHOIS: "2026-08-11",
				},
			},
		},
	}

	var first, second bytes.Buffer
	if err := Render(&first, rec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := Render(&second, rec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if first.String() != second.String() {
		t.Fatalf("Render is non-deterministic across calls with the same input:\nfirst:\n%s\nsecond:\n%s", first.String(), second.String())
	}

	out := first.String()
	// model.Precedence order is registrar-rdap, registry-rdap,
	// registrar-whois, registry-whois — the conflict line must list
	// values in that order regardless of map iteration order.
	registrarRDAPIdx := strings.Index(out, string(model.SourceRegistrarRDAP)+"=")
	registryRDAPIdx := strings.Index(out, string(model.SourceRegistryRDAP)+"=")
	registrarWHOISIdx := strings.Index(out, string(model.SourceRegistrarWHOIS)+"=")
	registryWHOISIdx := strings.Index(out, string(model.SourceRegistryWHOIS)+"=")
	if registrarRDAPIdx < 0 || registryRDAPIdx < 0 || registrarWHOISIdx < 0 || registryWHOISIdx < 0 {
		t.Fatalf("expected all 4 source values in the conflict line, got:\n%s", out)
	}
	if !(registrarRDAPIdx < registryRDAPIdx && registryRDAPIdx < registrarWHOISIdx && registrarWHOISIdx < registryWHOISIdx) {
		t.Errorf("conflict values not rendered in model.Precedence order, got:\n%s", out)
	}
}

func TestRender_RedactedSection(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryWHOIS}},
		Redacted: []model.RedactionNotice{
			{Field: model.FieldRegistrarName, Source: model.SourceRegistrarRDAP, Reason: "redacted"},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, string(model.SourceRegistrarRDAP)) || !strings.Contains(out, "redacted") {
		t.Errorf("expected redaction notice in output, got:\n%s", out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/render/plain/... -v`
Expected: FAIL — build error, `Render(w, rec)` called with a `model.Record` argument but the current signature takes `*rdap.DomainResponse`; also `model.Field[string]{...}` composite literals fail since the current `plain.go` doesn't import `model` at all yet.

- [ ] **Step 3: Write the implementation**

Replace the entire contents of `internal/render/plain/plain.go`:
```go
package plain

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/patramsey/plat/internal/model"
)

// Render writes an unstyled, aligned key/value view of a merged domain
// record — field values with source provenance, a per-source status
// line, and any conflicts/redactions. It never emits ANSI escapes, so it
// is safe for pipes and for terminals that don't support color. This is
// the renderer both the "human" and "plain" output formats use in this
// milestone; a later milestone adds a distinct styled human renderer on
// top without changing this one.
func Render(w io.Writer, r model.Record) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)

	stringField(tw, "Domain", r.Domain)
	stringField(tw, "Handle", r.Handle)
	stringField(tw, "Registrar", r.Registrar.Name)
	stringField(tw, "Registrar IANA ID", r.Registrar.IANAID)
	stringField(tw, "Registrar URL", r.Registrar.URL)
	stringField(tw, "Abuse Email", r.Registrar.AbuseEmail)
	stringField(tw, "Abuse Phone", r.Registrar.AbusePhone)
	listField(tw, "Status", r.Status)
	timeField(tw, "Created", r.Created)
	timeField(tw, "Updated", r.Updated)
	timeField(tw, "Expires", r.Expires)
	listField(tw, "Nameservers", r.Nameservers)
	boolField(tw, "DNSSEC", r.DNSSEC)

	if len(r.Sources) > 0 {
		_, _ = fmt.Fprintln(tw, "---")
		for _, s := range r.Sources {
			status := "no data"
			switch {
			case s.OK:
				status = "ok"
			case s.NotFound:
				status = "not found"
			case s.Err != "":
				status = s.Err
			}
			_, _ = fmt.Fprintf(tw, "%s:\t%s\t%s\n", s.Source, s.Latency.Round(time.Millisecond), status)
		}
	}

	if len(r.Conflicts) > 0 {
		_, _ = fmt.Fprintln(tw, "---")
		for _, c := range r.Conflicts {
			_, _ = fmt.Fprintf(tw, "Conflict (%s):\t%s\n", c.Field, formatConflictValues(c.Values))
		}
	}

	if len(r.Redacted) > 0 {
		_, _ = fmt.Fprintln(tw, "---")
		for _, red := range r.Redacted {
			_, _ = fmt.Fprintf(tw, "Redacted (%s):\t%s (%s)\n", red.Field, red.Source, red.Reason)
		}
	}

	return tw.Flush()
}

func stringField(tw *tabwriter.Writer, label string, f model.Field[string]) {
	if !f.Present() {
		return
	}
	_, _ = fmt.Fprintf(tw, "%s:\t%s\t%s\n", label, f.Value, formatSources(f.Sources))
}

func listField(tw *tabwriter.Writer, label string, f model.Field[[]string]) {
	if !f.Present() {
		return
	}
	_, _ = fmt.Fprintf(tw, "%s:\t%s\t%s\n", label, strings.Join(f.Value, " · "), formatSources(f.Sources))
}

func boolField(tw *tabwriter.Writer, label string, f model.Field[bool]) {
	if !f.Present() {
		return
	}
	val := "false"
	if f.Value {
		val = "true"
	}
	_, _ = fmt.Fprintf(tw, "%s:\t%s\t%s\n", label, val, formatSources(f.Sources))
}

func timeField(tw *tabwriter.Writer, label string, f model.Field[model.TimeValue]) {
	if !f.Present() {
		return
	}
	if f.Value.Parsed {
		_, _ = fmt.Fprintf(tw, "%s:\t%s\t%s\n", label, f.Value.Time.Format(time.RFC3339), formatSources(f.Sources))
		return
	}
	_, _ = fmt.Fprintf(tw, "%s:\t%s (unparsed)\t%s\n", label, f.Value.Raw, formatSources(f.Sources))
}

func formatSources(sources []model.SourceID) string {
	strs := make([]string, len(sources))
	for i, s := range sources {
		strs[i] = string(s)
	}
	return strings.Join(strs, ", ")
}

// formatConflictValues renders a Conflict's map in model.Precedence order
// — Go map iteration order is randomized, and ranging over the map
// directly would make output (and any test asserting on it) flaky from
// run to run.
func formatConflictValues(values map[model.SourceID]string) string {
	var parts []string
	for _, src := range model.Precedence {
		if v, ok := values[src]; ok {
			parts = append(parts, fmt.Sprintf("%s=%s", src, v))
		}
	}
	return strings.Join(parts, ", ")
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./internal/render/plain/... -v`
Expected: PASS, all 5 test functions green.

- [ ] **Step 5: Confirm zero regression across the rest of the repo**

Run: `cd /Users/pat/codes/plat && go build ./... 2>&1 | grep -v '^$'`
Expected: this WILL fail — `cmd/plat/main.go`'s current `lookup()` function still calls `plain.Render(stdout, result.Domain)` with the OLD `*rdap.DomainResponse` signature. This is expected and will be fixed in Task 6 when `lookup()` is deleted and replaced. Do NOT attempt to fix `cmd/plat` in this task — that's out of scope here. Instead, run the narrower check:

Run: `cd /Users/pat/codes/plat && go build ./internal/... && go test ./internal/...`
Expected: PASS — everything under `internal/` builds and tests clean; only `cmd/plat` (Task 6's job) is currently broken by this retype, and that's expected at this point in the plan.

- [ ] **Step 6: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/render/plain/plain.go internal/render/plain/plain_test.go
git commit -m "feat: retype the plain renderer from rdap.DomainResponse to model.Record"
```

Note: `cmd/plat` will not compile between this commit and Task 6's commit. This is a deliberate, temporary, single-package-scoped break in a multi-commit sequence within one PR-sized unit of work — acceptable here because Task 6 (next viable task) fixes it immediately, and `go build ./internal/...`/`go test ./internal/...` fully validate everything this task actually touches.

---

### Task 4: `internal/render/machine` — JSON/NDJSON Encoder

**Files:**
- Create: `internal/render/machine/machine.go`
- Create: `internal/render/machine/machine_test.go`
- Create: `testdata/schema/full-record.json`, `testdata/schema/unparsed-time.json`, `testdata/schema/absent-fields.json`, `testdata/schema/raw-embedded.json`, `testdata/schema/conflicts-redacted.json` (golden files, generated by the test's `-update` mode in Step 4, not hand-written)

**Interfaces:**
- Consumes: `model.Record` and all its nested types (M3, existing).
- Produces: `const SchemaVersion = 1`, `type Options struct{ Raw bool }`, `func Encode(w io.Writer, r model.Record, opts Options) error`, `func EncodeNDJSON(w io.Writer, r model.Record, opts Options) error`, `func EncodeError(w io.Writer, domainName string, err error) error` — consumed by Task 6's root-command dispatch.

- [ ] **Step 1: Write the failing test**

Create `internal/render/machine/machine_test.go`:
```go
package machine

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/model"
)

var update = flag.Bool("update", false, "update golden files in testdata/schema/")

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := "../../../testdata/schema/" + name
	if !json.Valid(got) {
		t.Fatalf("output is not valid JSON:\n%s", got)
	}
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("writing golden file: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden file %s (run with -update to create it): %v", path, err)
	}
	if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(want)) {
		t.Errorf("output does not match golden file %s\ngot:\n%s\nwant:\n%s", path, got, want)
	}
}

func fullRecord() model.Record {
	created, _ := time.Parse(time.RFC3339, "1995-08-14T04:00:00Z")
	expires, _ := time.Parse(time.RFC3339, "2026-08-13T04:00:00Z")
	return model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Handle: model.Field[string]{Value: "2336799_DOMAIN_COM-VRSN", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Registrar: model.RegistrarInfo{
			Name:       model.Field[string]{Value: "Example Registrar, Inc.", Sources: []model.SourceID{model.SourceRegistrarRDAP}},
			AbuseEmail: model.Field[string]{Value: "abuse@example-registrar.example", Sources: []model.SourceID{model.SourceRegistrarRDAP}},
		},
		Status:  model.Field[[]string]{Value: []string{"clientTransferProhibited"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Created: model.Field[model.TimeValue]{Value: model.TimeValue{Time: created, Raw: "1995-08-14T04:00:00Z", Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Expires: model.Field[model.TimeValue]{Value: model.TimeValue{Time: expires, Raw: "2026-08-13T04:00:00Z", Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Nameservers: model.Field[[]string]{Value: []string{"a.iana-servers.net", "b.iana-servers.net"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Sources: []model.SourceResult{
			{Source: model.SourceRegistryRDAP, OK: true, Latency: 89 * time.Millisecond},
			{Source: model.SourceRegistrarRDAP, OK: true, Latency: 145 * time.Millisecond},
		},
	}
}

func TestEncode_FullyPresentRecord(t *testing.T) {
	var buf bytes.Buffer
	if err := Encode(&buf, fullRecord(), Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkGolden(t, "full-record.json", buf.Bytes())

	var decoded map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output did not unmarshal: %v", err)
	}
	if decoded["schemaVersion"].(float64) != 1 {
		t.Errorf("schemaVersion = %v, want 1", decoded["schemaVersion"])
	}
	expiresObj := decoded["expires"].(map[string]interface{})
	if expiresObj["value"] != "2026-08-13T04:00:00Z" {
		t.Errorf("expires.value = %v, want RFC3339 string", expiresObj["value"])
	}
}

func TestEncode_UnparsedTimeField(t *testing.T) {
	rec := model.Record{
		Expires: model.Field[model.TimeValue]{Value: model.TimeValue{Raw: "not-a-date", Parsed: false}, Sources: []model.SourceID{model.SourceRegistryWHOIS}},
	}
	var buf bytes.Buffer
	if err := Encode(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkGolden(t, "unparsed-time.json", buf.Bytes())

	var decoded map[string]interface{}
	_ = json.Unmarshal(buf.Bytes(), &decoded)
	expiresObj := decoded["expires"].(map[string]interface{})
	if expiresObj["value"] != nil {
		t.Errorf("expires.value = %v, want null for an unparsed date", expiresObj["value"])
	}
	if expiresObj["raw"] != "not-a-date" {
		t.Errorf("expires.raw = %v, want %q", expiresObj["raw"], "not-a-date")
	}
}

func TestEncode_AbsentFieldsAreOmitted(t *testing.T) {
	rec := model.Record{} // fully zero-value: nothing present
	var buf bytes.Buffer
	if err := Encode(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkGolden(t, "absent-fields.json", buf.Bytes())

	var decoded map[string]interface{}
	_ = json.Unmarshal(buf.Bytes(), &decoded)
	for _, key := range []string{"domain", "handle", "registrar", "status", "created", "updated", "expires", "nameservers", "dnssec"} {
		if _, exists := decoded[key]; exists {
			t.Errorf("expected key %q to be fully omitted when absent, but it was present: %v", key, decoded[key])
		}
	}
	if _, exists := decoded["schemaVersion"]; !exists {
		t.Error("expected schemaVersion to always be present")
	}
}

func TestEncode_RawEmbedding(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Sources: []model.SourceResult{
			{Source: model.SourceRegistryRDAP, OK: true, Latency: 89 * time.Millisecond, Raw: []byte(`{"objectClassName":"domain","ldhName":"EXAMPLE.COM"}`)},
			{Source: model.SourceRegistryWHOIS, OK: true, Latency: 30 * time.Millisecond, Raw: []byte("Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar\n")},
		},
	}

	var withRaw bytes.Buffer
	if err := Encode(&withRaw, rec, Options{Raw: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkGolden(t, "raw-embedded.json", withRaw.Bytes())

	var decoded map[string]interface{}
	_ = json.Unmarshal(withRaw.Bytes(), &decoded)
	sources := decoded["sources"].([]interface{})
	rdapSource := sources[0].(map[string]interface{})
	rawField, ok := rdapSource["raw"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected sources[0].raw to be a JSON object (embedded as-is), got %T: %v", rdapSource["raw"], rdapSource["raw"])
	}
	if rawField["ldhName"] != "EXAMPLE.COM" {
		t.Errorf("sources[0].raw.ldhName = %v, want EXAMPLE.COM (RDAP raw JSON should be embedded, not double-encoded as a string)", rawField["ldhName"])
	}
	whoisSource := sources[1].(map[string]interface{})
	whoisRaw, ok := whoisSource["raw"].(string)
	if !ok {
		t.Fatalf("expected sources[1].raw to be a JSON string (WHOIS text), got %T", whoisSource["raw"])
	}
	if whoisRaw != "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar\n" {
		t.Errorf("sources[1].raw = %q, want the WHOIS text verbatim", whoisRaw)
	}

	var withoutRaw bytes.Buffer
	if err := Encode(&withoutRaw, rec, Options{Raw: false}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded2 map[string]interface{}
	_ = json.Unmarshal(withoutRaw.Bytes(), &decoded2)
	sources2 := decoded2["sources"].([]interface{})
	if _, exists := sources2[0].(map[string]interface{})["raw"]; exists {
		t.Error("expected sources[].raw to be omitted entirely when Options.Raw is false")
	}
}

func TestEncode_ConflictsAndRedacted(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Conflicts: []model.Conflict{
			{Field: model.FieldExpires, Values: map[model.SourceID]string{model.SourceRegistryRDAP: "2026-08-13T04:00:00Z", model.SourceRegistryWHOIS: "2026-08-10"}},
		},
		Redacted: []model.RedactionNotice{
			{Field: model.FieldRegistrarName, Source: model.SourceRegistrarRDAP, Reason: "redacted"},
		},
	}
	var buf bytes.Buffer
	if err := Encode(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkGolden(t, "conflicts-redacted.json", buf.Bytes())

	var decoded map[string]interface{}
	_ = json.Unmarshal(buf.Bytes(), &decoded)
	conflicts := decoded["conflicts"].([]interface{})
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %v, want 1 entry", conflicts)
	}
	redacted := decoded["redacted"].([]interface{})
	if len(redacted) != 1 {
		t.Fatalf("redacted = %v, want 1 entry", redacted)
	}
}

func TestEncodeNDJSON_MultipleRecords(t *testing.T) {
	var buf bytes.Buffer
	rec1 := model.Record{Domain: model.Field[string]{Value: "a.com", Sources: []model.SourceID{model.SourceRegistryRDAP}}}
	rec2 := model.Record{Domain: model.Field[string]{Value: "b.com", Sources: []model.SourceID{model.SourceRegistryRDAP}}}
	if err := EncodeNDJSON(&buf, rec1, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := EncodeNDJSON(&buf, rec2, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	for i, line := range lines {
		if !json.Valid(line) {
			t.Errorf("line %d is not valid JSON: %s", i, line)
		}
	}
}

func TestEncodeError(t *testing.T) {
	var buf bytes.Buffer
	if err := EncodeError(&buf, "example.com", errDomainNotFoundForTest); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Fatalf("output is not valid JSON: %s", buf.String())
	}
	var decoded map[string]string
	_ = json.Unmarshal(buf.Bytes(), &decoded)
	if decoded["domain"] != "example.com" {
		t.Errorf("domain = %q, want %q", decoded["domain"], "example.com")
	}
	if decoded["error"] == "" {
		t.Error("expected a non-empty error field")
	}
}

var errDomainNotFoundForTest = fmtErrorf("domain not found")

func fmtErrorf(s string) error { return &simpleError{s} }

type simpleError struct{ s string }

func (e *simpleError) Error() string { return e.s }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/render/machine/... -v`
Expected: FAIL — build error, `internal/render/machine` package doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/render/machine/machine.go`:
```go
// Package machine encodes a model.Record as the stable JSON/NDJSON wire
// format described in docs/schema.md. The wire shapes here are a
// deliberately separate view-model from model.Record's Go-internal
// shapes (Field[T]'s generic {Value,Sources}, TimeValue's raw
// {Time,Raw,Parsed}) — this package owns the public API contract, and a
// breaking change to any shape below must bump SchemaVersion.
package machine

import (
	"encoding/json"
	"io"
	"time"

	"github.com/patramsey/plat/internal/model"
)

// SchemaVersion is the current machine-output schema version.
const SchemaVersion = 1

// Options controls what Encode/EncodeNDJSON include.
type Options struct {
	// Raw includes each source's raw response payload (sources[].raw).
	Raw bool
}

type fieldValue struct {
	Value   string   `json:"value"`
	Sources []string `json:"sources"`
}

type listFieldValue struct {
	Value   []string `json:"value"`
	Sources []string `json:"sources"`
}

type boolFieldValue struct {
	Value   bool     `json:"value"`
	Sources []string `json:"sources"`
}

type timeFieldValue struct {
	Value   *string  `json:"value"`
	Raw     string   `json:"raw"`
	Parsed  bool     `json:"parsed"`
	Sources []string `json:"sources"`
}

type registrarView struct {
	Name       *fieldValue `json:"name,omitempty"`
	IANAID     *fieldValue `json:"ianaId,omitempty"`
	URL        *fieldValue `json:"url,omitempty"`
	AbuseEmail *fieldValue `json:"abuseEmail,omitempty"`
	AbusePhone *fieldValue `json:"abusePhone,omitempty"`
}

type conflictView struct {
	Field  string            `json:"field"`
	Values map[string]string `json:"values"`
}

type redactionView struct {
	Field  string `json:"field"`
	Source string `json:"source"`
	Reason string `json:"reason"`
}

type sourceView struct {
	Source    string          `json:"source"`
	OK        bool            `json:"ok"`
	NotFound  bool            `json:"notFound"`
	LatencyMs int64           `json:"latencyMs"`
	Error     string          `json:"error,omitempty"`
	Raw       json.RawMessage `json:"raw,omitempty"`
}

type recordView struct {
	SchemaVersion int             `json:"schemaVersion"`
	Domain        *fieldValue     `json:"domain,omitempty"`
	Handle        *fieldValue     `json:"handle,omitempty"`
	Registrar     *registrarView  `json:"registrar,omitempty"`
	Status        *listFieldValue `json:"status,omitempty"`
	Created       *timeFieldValue `json:"created,omitempty"`
	Updated       *timeFieldValue `json:"updated,omitempty"`
	Expires       *timeFieldValue `json:"expires,omitempty"`
	Nameservers   *listFieldValue `json:"nameservers,omitempty"`
	DNSSEC        *boolFieldValue `json:"dnssec,omitempty"`
	Conflicts     []conflictView  `json:"conflicts"`
	Redacted      []redactionView `json:"redacted"`
	Sources       []sourceView    `json:"sources"`
}

func sourceIDs(ids []model.SourceID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}

func stringFieldView(f model.Field[string]) *fieldValue {
	if !f.Present() {
		return nil
	}
	return &fieldValue{Value: f.Value, Sources: sourceIDs(f.Sources)}
}

func listFieldView(f model.Field[[]string]) *listFieldValue {
	if !f.Present() {
		return nil
	}
	val := f.Value
	if val == nil {
		val = []string{}
	}
	return &listFieldValue{Value: val, Sources: sourceIDs(f.Sources)}
}

func boolFieldView(f model.Field[bool]) *boolFieldValue {
	if !f.Present() {
		return nil
	}
	return &boolFieldValue{Value: f.Value, Sources: sourceIDs(f.Sources)}
}

func timeFieldView(f model.Field[model.TimeValue]) *timeFieldValue {
	if !f.Present() {
		return nil
	}
	tv := &timeFieldValue{Raw: f.Value.Raw, Parsed: f.Value.Parsed, Sources: sourceIDs(f.Sources)}
	if f.Value.Parsed {
		s := f.Value.Time.UTC().Format(time.RFC3339)
		tv.Value = &s
	}
	return tv
}

func buildRegistrarView(r model.RegistrarInfo) *registrarView {
	name := stringFieldView(r.Name)
	ianaID := stringFieldView(r.IANAID)
	url := stringFieldView(r.URL)
	abuseEmail := stringFieldView(r.AbuseEmail)
	abusePhone := stringFieldView(r.AbusePhone)
	if name == nil && ianaID == nil && url == nil && abuseEmail == nil && abusePhone == nil {
		return nil
	}
	return &registrarView{Name: name, IANAID: ianaID, URL: url, AbuseEmail: abuseEmail, AbusePhone: abusePhone}
}

func buildView(r model.Record, opts Options) recordView {
	v := recordView{
		SchemaVersion: SchemaVersion,
		Domain:        stringFieldView(r.Domain),
		Handle:        stringFieldView(r.Handle),
		Registrar:     buildRegistrarView(r.Registrar),
		Status:        listFieldView(r.Status),
		Created:       timeFieldView(r.Created),
		Updated:       timeFieldView(r.Updated),
		Expires:       timeFieldView(r.Expires),
		Nameservers:   listFieldView(r.Nameservers),
		DNSSEC:        boolFieldView(r.DNSSEC),
		Conflicts:     []conflictView{},
		Redacted:      []redactionView{},
		Sources:       []sourceView{},
	}
	for _, c := range r.Conflicts {
		values := make(map[string]string, len(c.Values))
		for src, val := range c.Values {
			values[string(src)] = val
		}
		v.Conflicts = append(v.Conflicts, conflictView{Field: c.Field, Values: values})
	}
	for _, red := range r.Redacted {
		v.Redacted = append(v.Redacted, redactionView{Field: red.Field, Source: string(red.Source), Reason: red.Reason})
	}
	for _, s := range r.Sources {
		sv := sourceView{
			Source:    string(s.Source),
			OK:        s.OK,
			NotFound:  s.NotFound,
			LatencyMs: s.Latency.Milliseconds(),
			Error:     s.Err,
		}
		if opts.Raw && len(s.Raw) > 0 {
			if json.Valid(s.Raw) {
				sv.Raw = json.RawMessage(s.Raw)
			} else if encoded, err := json.Marshal(string(s.Raw)); err == nil {
				sv.Raw = json.RawMessage(encoded)
			}
		}
		v.Sources = append(v.Sources, sv)
	}
	return v
}

// Encode writes r as a single compact JSON object followed by a newline.
func Encode(w io.Writer, r model.Record, opts Options) error {
	v := buildView(r, opts)
	enc := json.NewEncoder(w)
	return enc.Encode(v)
}

// EncodeNDJSON writes r as one compact JSON object followed by a newline
// — the shape used for -o ndjson multi-domain output, one record per
// line. Mechanically identical to Encode; kept as a separate name so
// call sites make the multi-domain intent explicit.
func EncodeNDJSON(w io.Writer, r model.Record, opts Options) error {
	return Encode(w, r, opts)
}

// EncodeError writes a machine-mode error object to w:
// {"error": "...", "domain": "..."}. Used for stderr so stdout stays
// schema-clean even when a lookup fails in machine mode.
func EncodeError(w io.Writer, domainName string, err error) error {
	enc := json.NewEncoder(w)
	return enc.Encode(struct {
		Error  string `json:"error"`
		Domain string `json:"domain"`
	}{Error: err.Error(), Domain: domainName})
}
```

- [ ] **Step 4: Generate the golden files, then run the test to verify it passes**

Run: `cd /Users/pat/codes/plat && mkdir -p testdata/schema && go test ./internal/render/machine/... -run . -update -v`
Expected: PASS, and 5 new files appear under `testdata/schema/` (`full-record.json`, `unparsed-time.json`, `absent-fields.json`, `raw-embedded.json`, `conflicts-redacted.json`).

Run again WITHOUT `-update` to confirm the golden comparison itself works: `cd /Users/pat/codes/plat && go test ./internal/render/machine/... -v`
Expected: PASS, all 7 test functions green, comparing against the just-generated golden files.

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/render/machine/machine.go internal/render/machine/machine_test.go testdata/schema/
git commit -m "feat: add JSON/NDJSON machine-output encoder with stable schema"
```

---

### Task 5: `internal/render` — Format Selection and TTY Detection

**Files:**
- Create: `internal/render/render.go`
- Create: `internal/render/render_test.go`

**Interfaces:**
- Consumes: nothing beyond stdlib.
- Produces: `type Format int` + `FormatHuman`/`FormatPlain`/`FormatJSON`/`FormatNDJSON`, `func ParseFormat(s string) (Format, error)`, `func IsTerminal(f *os.File) bool`, `func Select(explicit string, isTTY bool) (Format, error)`, `func IsMachine(f Format) bool` — consumed by Task 6's root-command dispatch.

- [ ] **Step 1: Write the failing test**

Create `internal/render/render_test.go`:
```go
package render

import (
	"os"
	"testing"
)

func TestParseFormat(t *testing.T) {
	tests := []struct {
		in      string
		want    Format
		wantErr bool
	}{
		{"human", FormatHuman, false},
		{"plain", FormatPlain, false},
		{"json", FormatJSON, false},
		{"ndjson", FormatNDJSON, false},
		{"HUMAN", FormatHuman, false},
		{"  json  ", FormatJSON, false},
		{"yaml", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseFormat(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseFormat(%q) expected an error, got nil", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseFormat(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseFormat(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestSelect(t *testing.T) {
	tests := []struct {
		name     string
		explicit string
		isTTY    bool
		want     Format
		wantErr  bool
	}{
		{"explicit wins over TTY", "json", true, FormatJSON, false},
		{"explicit wins over pipe", "json", false, FormatJSON, false},
		{"no explicit, TTY -> human", "", true, FormatHuman, false},
		{"no explicit, pipe -> plain", "", false, FormatPlain, false},
		{"invalid explicit format", "bogus", true, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Select(tt.explicit, tt.isTTY)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Select(%q, %v) expected an error, got nil", tt.explicit, tt.isTTY)
				}
				return
			}
			if err != nil {
				t.Fatalf("Select(%q, %v) unexpected error: %v", tt.explicit, tt.isTTY, err)
			}
			if got != tt.want {
				t.Errorf("Select(%q, %v) = %v, want %v", tt.explicit, tt.isTTY, got, tt.want)
			}
		})
	}
}

func TestIsTerminal_FalseForPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	if IsTerminal(r) {
		t.Error("IsTerminal(pipe read end) = true, want false")
	}
	if IsTerminal(w) {
		t.Error("IsTerminal(pipe write end) = true, want false")
	}
}

func TestIsMachine(t *testing.T) {
	tests := []struct {
		f    Format
		want bool
	}{
		{FormatHuman, false},
		{FormatPlain, false},
		{FormatJSON, true},
		{FormatNDJSON, true},
	}
	for _, tt := range tests {
		if got := IsMachine(tt.f); got != tt.want {
			t.Errorf("IsMachine(%v) = %v, want %v", tt.f, got, tt.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/pat/codes/plat && go test ./internal/render/... -v`
Expected: FAIL — build error, `internal/render` package (the `render.go` file specifically, as opposed to its `plain`/`machine` subpackages) doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/render/render.go`:
```go
// Package render selects which output format cmd/plat uses for a lookup
// and detects whether stdout is an interactive terminal. It does not
// import internal/render/plain or internal/render/machine itself — the
// caller (cmd/plat) dispatches to the right one based on the Format this
// package returns, keeping this leaf package free of both renderers'
// dependencies.
package render

import (
	"fmt"
	"os"
	"strings"
)

// Format selects which renderer cmd/plat dispatches to. Human and Plain
// render identically in this milestone (both use internal/render/plain)
// — there is no styling difference until a later milestone adds a
// distinct styled human renderer. They are kept as separate values now
// so that milestone only has to reroute Human, not touch this selection
// logic.
type Format int

const (
	FormatHuman Format = iota
	FormatPlain
	FormatJSON
	FormatNDJSON
)

// ParseFormat validates the -o/--output flag's value.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "human":
		return FormatHuman, nil
	case "plain":
		return FormatPlain, nil
	case "json":
		return FormatJSON, nil
	case "ndjson":
		return FormatNDJSON, nil
	default:
		return 0, fmt.Errorf("invalid output format %q: must be one of human, plain, json, ndjson", s)
	}
}

// IsTerminal reports whether f is connected to an interactive terminal.
func IsTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// Select resolves the format to use: an explicit -o value always wins;
// otherwise a TTY gets Human and a pipe/file gets Plain. explicit=="" means
// no -o flag was given.
func Select(explicit string, isTTY bool) (Format, error) {
	if explicit != "" {
		return ParseFormat(explicit)
	}
	if isTTY {
		return FormatHuman, nil
	}
	return FormatPlain, nil
}

// IsMachine reports whether f is one of the JSON/NDJSON machine formats.
func IsMachine(f Format) bool {
	return f == FormatJSON || f == FormatNDJSON
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/pat/codes/plat && go test ./internal/render/... -v`
Expected: PASS, all 4 test functions green (note: `go test ./internal/render/...` also runs the `plain` and `machine` subpackage tests from Tasks 3-4 — all should be green together at this point).

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add internal/render/render.go internal/render/render_test.go
git commit -m "feat: add output-format selection and TTY detection"
```

---

### Task 6: Rewire `cmd/plat/main.go`

**Files:**
- Modify: `cmd/plat/main.go` (major rewrite: new flags, multi-domain args, new RunE flow, `deriveOutcome`, `exitSignal`, `parseSourceFilter`; delete the old `lookup` function)
- Modify: `cmd/plat/main_test.go` (extend — do not touch existing M1/M2/M3 test functions)

**Interfaces:**
- Consumes: `render.Select`/`ParseFormat`/`IsTerminal`/`IsMachine` (Task 5), `plain.Render` (Task 3), `machine.Encode`/`EncodeNDJSON`/`EncodeError` (Task 4), `collect.Collect`/`collect.Options` (Tasks 1-2), `merge.Merge` (M3, unchanged), `model.SourceResult`/`model.SourceID` (Task 1 + M3).
- Produces: nothing consumed by later tasks in this plan — this is M4's final, root-command-visible deliverable. `newWhoisCommand`/`newMergeCommand` (M2/M3, in `whois.go`/`merge.go`) are consumed unchanged.

This is the highest-risk task in the milestone: it deletes and replaces the root command's entire lookup path, which every prior milestone's manual verification exercised. Every pre-existing automated test in `cmd/plat/main_test.go` must keep passing unmodified.

- [ ] **Step 1: Write the failing tests**

Append to `cmd/plat/main_test.go` (add `"strconv"` to the import block if not already present; the existing imports already include `bytes`, `errors`, `fmt`, `strings`, `testing` from M1-M3):
```go
func TestDeriveOutcome(t *testing.T) {
	tests := []struct {
		name string
		in   []model.SourceResult
		want int
	}{
		{"all OK", []model.SourceResult{{OK: true}, {OK: true}}, 0},
		{"mixed OK and failed", []model.SourceResult{{OK: true}, {}}, 0},
		{"mixed OK and notfound", []model.SourceResult{{OK: true}, {NotFound: true}}, 0},
		{"all notfound", []model.SourceResult{{NotFound: true}, {NotFound: true}}, 1},
		{"single notfound", []model.SourceResult{{NotFound: true}}, 1},
		{"mixed notfound and failed", []model.SourceResult{{NotFound: true}, {}}, 3},
		{"all failed", []model.SourceResult{{}, {}}, 3},
		{"single failed", []model.SourceResult{{}}, 3},
		{"zero sources", []model.SourceResult{}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deriveOutcome(tt.in); got != tt.want {
				t.Errorf("deriveOutcome(%+v) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseSourceFilter(t *testing.T) {
	tests := []struct {
		in      string
		want    []model.SourceID
		wantErr bool
	}{
		{"", nil, false},
		{"rdap", []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistrarRDAP}, false},
		{"whois", []model.SourceID{model.SourceRegistryWHOIS, model.SourceRegistrarWHOIS}, false},
		{"registry", []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistryWHOIS}, false},
		{"registrar", []model.SourceID{model.SourceRegistrarRDAP, model.SourceRegistrarWHOIS}, false},
		{"bogus", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseSourceFilter(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseSourceFilter(%q) expected an error, got nil", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSourceFilter(%q) unexpected error: %v", tt.in, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("parseSourceFilter(%q) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseSourceFilter(%q)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestRun_AcceptsMultipleDomainArgs(t *testing.T) {
	// A single malformed domain among several still yields a usage-level
	// per-domain error (exit code 2 contributes to the overall worst
	// code) rather than a hard cobra arg-count usage error — multiple
	// args are now valid at the Args-validator level.
	var stdout, stderr bytes.Buffer
	got := run([]string{"localhost", "also-bad"}, &stdout, &stderr)
	if got != 2 {
		t.Errorf("run([localhost also-bad]) exit code = %d, want 2 (both are single-label, worst code across domains is 2)", got)
	}
}

func TestRun_NoArgsStillRejected(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{}, &stdout, &stderr)
	if got != 2 {
		t.Errorf("run([]) exit code = %d, want 2 (at least one domain required)", got)
	}
}

func TestRun_InvalidOutputFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"-o", "bogus", "example.com"}, &stdout, &stderr)
	if got != 2 {
		t.Errorf("run with -o bogus exit code = %d, want 2", got)
	}
}

func TestRun_RawWithoutMachineFormatIsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"--raw", "-o", "plain", "example.com"}, &stdout, &stderr)
	if got != 2 {
		t.Errorf("run with --raw -o plain exit code = %d, want 2", got)
	}
}

func TestRun_MultiDomainJSONIsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"-o", "json", "a.com", "b.com"}, &stdout, &stderr)
	if got != 2 {
		t.Errorf("run with -o json and 2 domains exit code = %d, want 2", got)
	}
}

func TestRun_InvalidSourceFilter(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"--source", "bogus", "example.com"}, &stdout, &stderr)
	if got != 2 {
		t.Errorf("run with --source bogus exit code = %d, want 2", got)
	}
}
```

Add `"github.com/patramsey/plat/internal/model"` to `cmd/plat/main_test.go`'s import block.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/pat/codes/plat && go test ./cmd/plat/... -v`
Expected: FAIL — build errors, `deriveOutcome`/`parseSourceFilter` undefined, and (pre-existing) `cmd/plat` currently doesn't compile at all because Task 3 retyped `plain.Render` out from under the old `lookup()` function still present in `main.go`.

- [ ] **Step 3: Write the implementation**

Replace the entire contents of `cmd/plat/main.go`:
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
	"github.com/patramsey/plat/internal/collect"
	"github.com/patramsey/plat/internal/domain"
	"github.com/patramsey/plat/internal/merge"
	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/rdap"
	"github.com/patramsey/plat/internal/render"
	"github.com/patramsey/plat/internal/render/machine"
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

// exitSignal carries a pre-computed final exit code (0, 1, or 3) out of
// cobra's error-only RunE contract — used by the multi-domain loop, which
// derives its own worst-of-N outcome rather than a single error. Only
// constructed for a non-zero code; a fully successful run returns nil
// normally, so exitCode never needs to special-case exitSignal{0}.
type exitSignal struct{ code int }

func (e exitSignal) Error() string { return "" }

func run(args []string, stdout, stderr io.Writer) int {
	var refreshBootstrap bool
	var timeout time.Duration
	var output string
	var raw bool
	var sourceFilter string
	var noFollow bool

	root := &cobra.Command{
		Use:           "plat <domain> [domain...]",
		Short:         "Look up domain ownership via RDAP and WHOIS",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args: func(cmd *cobra.Command, cliArgs []string) error {
			if len(cliArgs) < 1 {
				return usageError{fmt.Errorf("expected at least one domain argument, got %d", len(cliArgs))}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, cliArgs []string) error {
			return runLookup(cmd.Context(), stdout, stderr, cliArgs, lookupOptions{
				RefreshBootstrap: refreshBootstrap,
				Timeout:          timeout,
				Output:           output,
				Raw:              raw,
				SourceFilter:     sourceFilter,
				NoFollow:         noFollow,
			})
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)
	root.Flags().BoolVar(&refreshBootstrap, "refresh-bootstrap", false, "force a fresh fetch of the IANA RDAP bootstrap file")
	root.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "per-source timeout for bootstrap, RDAP, and WHOIS lookups")
	root.Flags().StringVarP(&output, "output", "o", "", "output format: human, plain, json, ndjson (default: auto-detect from terminal)")
	root.Flags().BoolVar(&raw, "raw", false, "include raw source payloads (json/ndjson only)")
	root.Flags().StringVar(&sourceFilter, "source", "", "restrict to one source: rdap, whois, registry, registrar")
	root.Flags().BoolVar(&noFollow, "no-follow", false, "skip the registrar RDAP related-link hop")
	root.CompletionOptions.DisableDefaultCmd = true

	// Flags reserved for later milestones — intentionally not implemented
	// here: -q/--quiet (condensed human view, M4 stretch/M5), -v/--verbose
	// (per-hop referral timing to stderr, needs hop-level data collect
	// currently discards), --no-color (no-op before M5's styled human
	// renderer exists), plus `completion`/`man` subcommands (M7).

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the plat version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(stdout, version)
			return err
		},
	})

	root.AddCommand(newWhoisCommand(stdout))
	root.AddCommand(newMergeCommand(stdout))

	err := root.Execute()
	return exitCode(err, stderr)
}

type lookupOptions struct {
	RefreshBootstrap bool
	Timeout          time.Duration
	Output           string
	Raw              bool
	SourceFilter     string
	NoFollow         bool
}

// runLookup validates flags/args once, resolves the output format and
// bootstrap resolver once, then loops domains sequentially — each
// domain's own outcome (0/1/2/3) is tracked and the worst wins overall.
func runLookup(ctx context.Context, stdout, stderr io.Writer, domains []string, opts lookupOptions) error {
	format, err := render.Select(opts.Output, render.IsTerminal(os.Stdout))
	if err != nil {
		return usageError{err}
	}
	if opts.Raw && !render.IsMachine(format) {
		return usageError{fmt.Errorf("--raw is only meaningful with -o json or -o ndjson")}
	}
	if format == render.FormatJSON && len(domains) > 1 {
		return usageError{fmt.Errorf("-o json supports exactly one domain; use -o ndjson for multiple")}
	}
	sources, err := parseSourceFilter(opts.SourceFilter)
	if err != nil {
		return usageError{err}
	}

	resolver, err := bootstrap.Load(ctx, bootstrap.Options{Refresh: opts.RefreshBootstrap, Timeout: opts.Timeout})
	if err != nil {
		return fmt.Errorf("resolving RDAP bootstrap: %w", err)
	}

	worst := 0
	for i, input := range domains {
		code := lookupOne(ctx, stdout, stderr, resolver, input, opts, sources, format)
		if code > worst {
			worst = code
		}
		if !render.IsMachine(format) && i < len(domains)-1 {
			_, _ = fmt.Fprintln(stdout)
		}
	}
	if worst != 0 {
		return exitSignal{worst}
	}
	return nil
}

// lookupOne performs one domain's normalize -> collect -> merge ->
// render-or-report flow and returns that domain's exit code (0/2/1/3;
// 2 only for a per-domain normalize failure).
func lookupOne(ctx context.Context, stdout, stderr io.Writer, resolver *bootstrap.Resolver, input string, opts lookupOptions, sources []model.SourceID, format render.Format) int {
	name, err := domain.Normalize(input)
	if err != nil {
		reportLookupError(stderr, format, input, err)
		return 2
	}

	baseURL, _ := resolver.BaseURL(name.TLD) // "" is fine — Collect degrades to WHOIS-only
	collectOpts := collect.Options{NoFollow: opts.NoFollow, Timeout: opts.Timeout, Sources: sources}
	records := collect.Collect(ctx, name, baseURL, "", collectOpts)
	record := merge.Merge(records)

	code := deriveOutcome(record.Sources)
	if code == 0 {
		if err := renderRecord(stdout, format, record, opts.Raw); err != nil {
			reportLookupError(stderr, format, name.Punycode, err)
			return 3
		}
		return 0
	}
	reportLookupError(stderr, format, name.Punycode, fmt.Errorf("no usable data for %s", name.Punycode))
	return code
}

func renderRecord(w io.Writer, format render.Format, record model.Record, raw bool) error {
	switch format {
	case render.FormatJSON:
		return machine.Encode(w, record, machine.Options{Raw: raw})
	case render.FormatNDJSON:
		return machine.EncodeNDJSON(w, record, machine.Options{Raw: raw})
	default: // FormatHuman, FormatPlain
		return plain.Render(w, record)
	}
}

func reportLookupError(stderr io.Writer, format render.Format, domainName string, err error) {
	if render.IsMachine(format) {
		_ = machine.EncodeError(stderr, domainName, err)
		return
	}
	_, _ = fmt.Fprintln(stderr, "plat:", domainName+":", err)
}

// deriveOutcome classifies rec's per-source results into an exit code: 0
// if any source returned usable data, 1 if every attempted source agrees
// the domain doesn't exist (and none hard-failed), 3 otherwise (total
// failure, or a source errored so non-existence can't be asserted with
// confidence).
func deriveOutcome(sources []model.SourceResult) int {
	if len(sources) == 0 {
		return 3
	}
	hasData, hasNotFound, hasFailed := false, false, false
	for _, s := range sources {
		switch {
		case s.OK:
			hasData = true
		case s.NotFound:
			hasNotFound = true
		default:
			hasFailed = true
		}
	}
	if hasData {
		return 0
	}
	if hasNotFound && !hasFailed {
		return 1
	}
	return 3
}

// parseSourceFilter translates the --source flag's friendly value into
// the 2-element model.SourceID slice collect.Options.Sources expects.
// An empty string means "no filter" (nil, allow everything).
func parseSourceFilter(s string) ([]model.SourceID, error) {
	switch s {
	case "":
		return nil, nil
	case "rdap":
		return []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistrarRDAP}, nil
	case "whois":
		return []model.SourceID{model.SourceRegistryWHOIS, model.SourceRegistrarWHOIS}, nil
	case "registry":
		return []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistryWHOIS}, nil
	case "registrar":
		return []model.SourceID{model.SourceRegistrarRDAP, model.SourceRegistrarWHOIS}, nil
	default:
		return nil, fmt.Errorf("invalid --source value %q: must be one of rdap, whois, registry, registrar", s)
	}
}

func exitCode(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	var sig exitSignal
	if errors.As(err, &sig) {
		return sig.code
	}
	_, _ = fmt.Fprintln(stderr, "plat:", err)

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

- [ ] **Step 4: Run tests to verify they pass, and confirm zero regression**

Run: `cd /Users/pat/codes/plat && go test ./cmd/plat/... -v`
Expected: PASS — all new tests (`TestDeriveOutcome`, `TestParseSourceFilter`, `TestRun_AcceptsMultipleDomainArgs`, `TestRun_NoArgsStillRejected`, `TestRun_InvalidOutputFormat`, `TestRun_RawWithoutMachineFormatIsUsageError`, `TestRun_MultiDomainJSONIsUsageError`, `TestRun_InvalidSourceFilter`) AND every pre-existing test function from M1/M2/M3 (`TestExitCode`, `TestRun_RejectsWrongArgCount`, `TestRun_VersionSubcommand`, `TestRun_WhoisSubcommandRegistered`, `TestRun_WhoisRejectsWrongArgCount`, `TestRun_WhoisHiddenFromHelp`, `TestRun_MergeSubcommandRegistered`, `TestRun_MergeRejectsWrongArgCount`, `TestRun_MergeHiddenFromHelp`) still green.

Note: `TestRun_RejectsWrongArgCount` (from M1) tested that 0 or 2 args were BOTH rejected under the old exactly-1 rule. Under M4's at-least-1 rule, 2 args is no longer inherently a usage error at the Args-validator level — but since `["example.com", "example.org"]` are both syntactically valid single-label-free domains, `TestRun_RejectsWrongArgCount`'s specific test cases need to be re-examined: if that test's table includes a 2-arg case expecting exit 2, it will now FAIL under M4's rules (2 valid domains no longer trigger a usage error) — this is a REQUIRED, INTENTIONAL behavior change from M1, not a regression to preserve. If `go test` shows this specific test failing for that reason, this is a case where the test itself must be updated to match the new, correct multi-domain-accepting behavior, NOT a case where `main.go`'s new Args validator should be reverted. Read `cmd/plat/main_test.go`'s current `TestRun_RejectsWrongArgCount` before deciding whether it needs a matching update, and if so, update the test's 2-arg case to expect the new multi-domain behavior (2 valid domains now succeed and produce output, not exit 2) or remove that specific subtest with a comment explaining why, while keeping the 0-arg case (which is still correctly rejected under "at least one").

Run: `cd /Users/pat/codes/plat && go mod tidy && go build ./... && go vet ./... && golangci-lint run && go test ./...`
Expected: all succeed, `golangci-lint run` reports 0 issues, every package `ok`.

- [ ] **Step 5: Commit**

```bash
cd /Users/pat/codes/plat
git add cmd/plat/main.go cmd/plat/main_test.go go.mod go.sum
git commit -m "feat: rewire root command onto the merge pipeline with JSON/NDJSON output and correct exit codes"
```

---

### Task 7: `docs/schema.md`

**Files:**
- Create: `docs/schema.md`

**Interfaces:**
- Consumes: the final shapes from Task 4's `internal/render/machine` (read the finished `machine.go` before writing this, to document the true wire shapes, not a guess).
- Produces: nothing consumed by later tasks — pure documentation, the final task in this milestone.

- [ ] **Step 1: Write the documentation**

Create `docs/schema.md`:
```markdown
# plat JSON output schema

`plat <domain> -o json` and `plat <domain> -o ndjson` emit the unified
domain record as JSON. This schema is a public API: a breaking change to
any field's shape bumps `schemaVersion`. The current version is **1**.

## Top-level shape

```json
{
  "schemaVersion": 1,
  "domain": { "value": "example.com", "sources": ["registry-rdap"] },
  "handle": { "value": "2336799_DOMAIN_COM-VRSN", "sources": ["registry-rdap"] },
  "registrar": {
    "name": { "value": "Example Registrar, Inc.", "sources": ["registrar-rdap"] },
    "abuseEmail": { "value": "abuse@example-registrar.example", "sources": ["registrar-rdap"] }
  },
  "status": { "value": ["clientTransferProhibited"], "sources": ["registry-rdap"] },
  "created": { "value": "1995-08-14T04:00:00Z", "raw": "1995-08-14T04:00:00Z", "parsed": true, "sources": ["registry-rdap"] },
  "expires": { "value": "2026-08-13T04:00:00Z", "raw": "2026-08-13T04:00:00Z", "parsed": true, "sources": ["registry-rdap"] },
  "nameservers": { "value": ["a.iana-servers.net", "b.iana-servers.net"], "sources": ["registry-rdap"] },
  "conflicts": [],
  "redacted": [],
  "sources": [
    { "source": "registry-rdap", "ok": true, "notFound": false, "latencyMs": 89 },
    { "source": "registrar-rdap", "ok": true, "notFound": false, "latencyMs": 145 }
  ]
}
```

## Field shapes

Every optional field (`domain`, `handle`, `registrar.*`, `status`,
`created`, `updated`, `expires`, `nameservers`, `dnssec`) is **omitted
entirely** from the output when no source contributed a value — not
`null`, not an empty object, simply absent. `jq '.expires.value'` on a
record with no expires data returns `null` (jq's normal behavior for a
missing path), so pipelines don't need to special-case absence.

- **String field** (`domain`, `handle`, `registrar.name`, `registrar.ianaId`, `registrar.url`, `registrar.abuseEmail`, `registrar.abusePhone`):
  ```json
  { "value": "<string>", "sources": ["<source-id>", ...] }
  ```
- **List field** (`status`, `nameservers`):
  ```json
  { "value": ["<string>", ...], "sources": ["<source-id>", ...] }
  ```
- **Bool field** (`dnssec`):
  ```json
  { "value": true, "sources": ["<source-id>", ...] }
  ```
- **Time field** (`created`, `updated`, `expires`):
  ```json
  { "value": "<RFC3339 string or null>", "raw": "<original string>", "parsed": true, "sources": [...] }
  ```
  `value` is `null` when the source's date string couldn't be parsed — `raw`/`parsed` always reflect the underlying source data so nothing is silently dropped.
- **`registrar`** is an object of up to 5 string fields (`name`, `ianaId`, `url`, `abuseEmail`, `abusePhone`), each following the string-field shape above and each independently omittable. The whole `registrar` key is omitted only if every one of its sub-fields is absent.
- **`conflicts[]`** — one entry per field where present sources disagreed:
  ```json
  { "field": "expires", "values": { "registry-rdap": "2026-08-13T04:00:00Z", "registry-whois": "2026-08-10" } }
  ```
- **`redacted[]`** — one entry per field where a higher-precedence source's value was withheld:
  ```json
  { "field": "registrar.name", "source": "registrar-rdap", "reason": "redacted" }
  ```
- **`sources[]`** — one entry per source actually attempted, always present (an empty array if literally nothing was attempted):
  ```json
  { "source": "registry-rdap", "ok": true, "notFound": false, "latencyMs": 89, "error": "timeout" }
  ```
  `error` is omitted when empty. `source` is one of `registry-rdap`, `registrar-rdap`, `registry-whois`, `registrar-whois`.

## `--raw`

Adding `--raw` includes each source's raw response payload as `sources[].raw`:

```json
{ "source": "registry-rdap", "ok": true, "raw": { "objectClassName": "domain", "ldhName": "EXAMPLE.COM", ... } }
```

For RDAP sources, `raw` is the actual response JSON embedded as-is (a JSON
object, not a string). For WHOIS sources, `raw` is the plaintext response
encoded as a JSON string, since WHOIS has no native JSON structure:

```json
{ "source": "registry-whois", "ok": true, "raw": "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar\n..." }
```

Without `--raw`, the `raw` key is omitted entirely from every source entry.

## NDJSON (`-o ndjson`)

For multiple domain arguments, each domain's record is written as one
compact JSON object per line (no pretty-printing, no blank lines between
records) — standard [NDJSON](http://ndjson.org/). `-o json` (the
single-object form) only accepts exactly one domain argument; use
`-o ndjson` for multiple.

## Errors in machine mode

If a domain can't be looked up at all (bad input, or no source returned
usable data), the error goes to **stderr**, not stdout, as:

```json
{ "error": "no usable data for example-nonexistent-xyz.com", "domain": "example-nonexistent-xyz.com" }
```

stdout only ever contains successfully-rendered records in machine mode —
scripts consuming stdout never need to distinguish a partial/error object
from a real record.

## Stability policy

This schema is versioned via the top-level `schemaVersion` field (currently
`1`). Any backward-incompatible change — a field renamed, removed, or its
type changed — bumps `schemaVersion`. Purely additive changes (a new
optional field) do not require a version bump.
```

- [ ] **Step 2: Verify the doc is internally consistent with the actual encoder**

Run: `cd /Users/pat/codes/plat && go test ./internal/render/machine/... -v`
Expected: still PASS (this step doesn't change any code, just confirms the doc was written after reading the real `machine.go`/golden files from Task 4 — no test changes needed here, this is a manual cross-check while writing the doc, not an automated one).

- [ ] **Step 3: Commit**

```bash
cd /Users/pat/codes/plat
git add docs/schema.md
git commit -m "docs: add JSON output schema documentation"
```

---

## Milestone Verification (manual, not automated)

Once all 7 tasks are complete, confirm the milestone's actual definition of done — this requires live network access and is deliberately not part of the automated test suite:

```bash
cd /Users/pat/codes/plat

go run ./cmd/plat google.com                        # TTY: unstyled human output, per-source status line, exit 0
echo $?

go run ./cmd/plat google.com | cat                   # pipe: plain output, zero ANSI
echo $?

go run ./cmd/plat google.com -o json | jq .           # valid JSON, schemaVersion 1
go run ./cmd/plat google.com -o json | jq .expires.value   # RFC3339 string, no ANSI garbage

go run ./cmd/plat google.com -o json --raw | jq '.sources[0].raw'   # RDAP JSON embedded as an object

go run ./cmd/plat google.com example.org -o ndjson   # 2 lines, each valid JSON
go run ./cmd/plat google.com example.org -o ndjson | while read -r line; do echo "$line" | jq -e . >/dev/null || echo "INVALID: $line"; done

go run ./cmd/plat --source whois google.com          # sources[] contains only *-whois entries
go run ./cmd/plat --no-follow google.com              # sources[] contains no registrar-rdap entry

go run ./cmd/plat this-domain-should-not-exist-xyzabc123.com; echo $?   # expect 1
go run ./cmd/plat localhost; echo $?                  # expect 2 (usage)
go run ./cmd/plat google.com -o bogus; echo $?        # expect 2 (bad format)
go run ./cmd/plat a.com b.com -o json; echo $?        # expect 2 (multi-domain + single-object json)
go run ./cmd/plat --raw google.com; echo $?           # expect 2 (--raw needs a machine format)
```

If a real-world response surfaces a genuine schema gap (a field shape that doesn't hold up, an unexpected `--raw` payload shape), that's a finding — extend `internal/render/machine`'s golden-file tests rather than special-casing it in `cmd/plat`, consistent with how M1-M3 handled real-world surprises.

---

## Self-Review

**Spec coverage:** JSON/NDJSON with stable schema (Task 4 + docs/schema.md), plain renderer (Task 3), TTY detection (Task 5), exit codes (Task 1 + Task 6's `deriveOutcome`) — all four items from the M4 milestone line are covered. `--source`/`--no-follow`/`-o`/`--raw` from plat-plan.md section 7 are wired (Task 2 + Task 6); `-q`/`-v`/`--no-color`/`completion`/`man` are explicitly deferred per the Global Constraints, named in a comment in Task 6's implementation.

**Placeholder scan:** no "TBD"/"handle appropriately"/"similar to Task N" patterns — every step has complete, runnable code, including the full JSON view-model, the full plain renderer, and the full root-command rewire.

**Type consistency:** `deriveOutcome(sources []model.SourceResult) int` — same signature used in Task 6's own test table and its call site inside `lookupOne`. `collect.Options{NoFollow, Timeout, Sources}` — the same 3-field shape used consistently across Task 2's implementation, Task 2's tests, and Task 6's `lookupOne`. `machine.Options{Raw bool}` — consistent across Task 4 and Task 6. `render.Format`/`render.Select`/`render.ParseFormat`/`render.IsTerminal`/`render.IsMachine` — consistent across Task 5 and Task 6. `plain.Render(w io.Writer, r model.Record) error` — consistent across Task 3 and Task 6.

**Regression discipline:** every task that modifies a pre-existing file (Task 1: `model/record.go`, `whois/parse/parse.go`, `collect/adapt_rdap.go`, `collect/adapt_whois.go`; Task 2: `collect/collect.go`; Task 3: `render/plain/plain.go`; Task 6: `cmd/plat/main.go`) has an explicit Step verifying that package's pre-existing tests still pass, and Task 3 explicitly flags + justifies the one deliberate, temporary cross-package build break (fixed by Task 6 in the same plan) rather than leaving it as a silent surprise.
