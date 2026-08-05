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

func TestMerge_ScalarComparisonIsCaseAndWhitespaceInsensitive(t *testing.T) {
	registrarRDAP := sr(model.SourceRegistrarRDAP, true)
	registrarRDAP.Domain = "google.com"
	registrarRDAP.Registrar.Name = "  Markmonitor Inc. "
	registryRDAP := sr(model.SourceRegistryRDAP, true)
	registryRDAP.Domain = "GOOGLE.COM"
	registryRDAP.Registrar.Name = "MarkMonitor Inc."

	rec := Merge([]model.SourceRecord{registryRDAP, registrarRDAP})

	if len(rec.Conflicts) != 0 {
		t.Errorf("Conflicts = %+v, want none (casing/whitespace-only differences should not be reported as disagreements)", rec.Conflicts)
	}
	if rec.Domain.Value != "google.com" {
		t.Errorf("Domain.Value = %q, want %q (the winning precedence source's ORIGINAL casing, not normalized)", rec.Domain.Value, "google.com")
	}
	if len(rec.Domain.Sources) != 2 {
		t.Errorf("Domain.Sources = %v, want both sources to agree", rec.Domain.Sources)
	}
	if rec.Registrar.Name.Value != "  Markmonitor Inc. " {
		t.Errorf("Registrar.Name.Value = %q, want the winning source's original value verbatim (untrimmed)", rec.Registrar.Name.Value)
	}
	if len(rec.Registrar.Name.Sources) != 2 {
		t.Errorf("Registrar.Name.Sources = %v, want both sources to agree", rec.Registrar.Name.Sources)
	}
}

func TestMerge_ScalarComparisonIgnoresTrailingPeriod(t *testing.T) {
	registrarRDAP := sr(model.SourceRegistrarRDAP, true)
	registrarRDAP.Registrar.Name = "Name.com, Inc"
	registryRDAP := sr(model.SourceRegistryRDAP, true)
	registryRDAP.Registrar.Name = "Name.com, Inc."

	rec := Merge([]model.SourceRecord{registryRDAP, registrarRDAP})

	if len(rec.Conflicts) != 0 {
		t.Errorf("Conflicts = %+v, want none (a trailing period is formatting noise, not a genuine disagreement)", rec.Conflicts)
	}
	if rec.Registrar.Name.Value != "Name.com, Inc" {
		t.Errorf("Registrar.Name.Value = %q, want %q (the winning precedence source's ORIGINAL value, not normalized)", rec.Registrar.Name.Value, "Name.com, Inc")
	}
	if len(rec.Registrar.Name.Sources) != 2 {
		t.Errorf("Registrar.Name.Sources = %v, want both sources to agree", rec.Registrar.Name.Sources)
	}
}

func TestMerge_ScalarComparisonIgnoresCommaBeforeCorporateSuffix(t *testing.T) {
	// Real-world pattern seen from two different registrars: the same
	// name reported with a comma before "Inc"/"LLC" by one source and
	// without by another (e.g. "NAMECHEAP INC" vs "NameCheap, Inc.").
	// This is formatting noise, not a genuine disagreement about who the
	// registrar is.
	registrarRDAP := sr(model.SourceRegistrarRDAP, true)
	registrarRDAP.Registrar.Name = "NAMECHEAP INC"
	registrarWHOIS := sr(model.SourceRegistrarWHOIS, true)
	registrarWHOIS.Registrar.Name = "NameCheap, Inc."

	rec := Merge([]model.SourceRecord{registrarRDAP, registrarWHOIS})

	if len(rec.Conflicts) != 0 {
		t.Errorf("Conflicts = %+v, want none (a comma before a corporate suffix is formatting noise, not a genuine disagreement)", rec.Conflicts)
	}
	if rec.Registrar.Name.Value != "NAMECHEAP INC" {
		t.Errorf("Registrar.Name.Value = %q, want %q (the winning precedence source's ORIGINAL value, not normalized)", rec.Registrar.Name.Value, "NAMECHEAP INC")
	}
	if len(rec.Registrar.Name.Sources) != 2 {
		t.Errorf("Registrar.Name.Sources = %v, want both sources to agree", rec.Registrar.Name.Sources)
	}
}

func TestMerge_ScalarComparisonStillCatchesGenuineDifferences(t *testing.T) {
	registrarRDAP := sr(model.SourceRegistrarRDAP, true)
	registrarRDAP.Registrar.Name = "Example Registrar A"
	registryRDAP := sr(model.SourceRegistryRDAP, true)
	registryRDAP.Registrar.Name = "Example Registrar B"

	rec := Merge([]model.SourceRecord{registryRDAP, registrarRDAP})

	if len(rec.Conflicts) != 1 {
		t.Fatalf("Conflicts = %+v, want exactly one conflict (a genuine value difference, not just casing/whitespace, must still be caught)", rec.Conflicts)
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

func TestMerge_ExpiresConflictPicksEarliestDate(t *testing.T) {
	// Expires is the one field where a conflict overrides the precedence
	// winner: the earliest parsed date wins, since showing more runway
	// than actually exists (a surprise lapse) is the riskier failure
	// mode. Here registry-rdap outranks registry-whois, but registry-
	// whois's earlier date should still win the conflict override.
	rdapTime, _ := time.Parse(time.RFC3339, "2026-08-13T04:00:00Z")
	whoisTime, _ := time.Parse("2006-01-02", "2026-08-10")

	registry := sr(model.SourceRegistryRDAP, true)
	registry.Expires = model.TimeValue{Time: rdapTime, Raw: "2026-08-13T04:00:00Z", Parsed: true}
	whois := sr(model.SourceRegistryWHOIS, true)
	whois.Expires = model.TimeValue{Time: whoisTime, Raw: "2026-08-10", Parsed: true}

	rec := Merge([]model.SourceRecord{registry, whois})

	if rec.Expires.Value.Raw != "2026-08-10" {
		t.Errorf("Expires.Value.Raw = %q, want the earlier date (2026-08-10) despite registry-rdap outranking registry-whois", rec.Expires.Value.Raw)
	}
	if len(rec.Conflicts) != 1 || rec.Conflicts[0].Field != model.FieldExpires {
		t.Fatalf("Conflicts = %+v, want exactly one expires conflict", rec.Conflicts)
	}
	if len(rec.Conflicts[0].Values) != 2 {
		t.Errorf("Conflict Values = %v, want both sources' raw dates listed", rec.Conflicts[0].Values)
	}
	if len(rec.Expires.Sources) != 1 || rec.Expires.Sources[0] != model.SourceRegistryWHOIS {
		t.Errorf("Expires.Sources = %v, want only registry-whois (the source that actually reported the displayed earliest date)", rec.Expires.Sources)
	}
}

func TestMerge_UpdatedConflictKeepsPrecedenceWinnerNotEarliest(t *testing.T) {
	// Unlike Expires, Updated has no "safer" direction -- an earlier
	// Updated isn't more trustworthy, just older -- so a conflict must
	// still keep the precedence winner. registrar-rdap (higher
	// precedence) reports a LATER date than registry-rdap here
	// specifically to distinguish "precedence wins" from "earliest wins":
	// if the Expires-only override leaked into Updated, this would
	// wrongly pick registry-rdap's earlier date instead.
	laterTime, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	earlierTime, _ := time.Parse(time.RFC3339, "2020-01-01T00:00:00Z")

	registrarRDAP := sr(model.SourceRegistrarRDAP, true)
	registrarRDAP.Updated = model.TimeValue{Time: laterTime, Raw: "2026-01-01T00:00:00Z", Parsed: true}
	registryRDAP := sr(model.SourceRegistryRDAP, true)
	registryRDAP.Updated = model.TimeValue{Time: earlierTime, Raw: "2020-01-01T00:00:00Z", Parsed: true}

	rec := Merge([]model.SourceRecord{registrarRDAP, registryRDAP})

	if rec.Updated.Value.Raw != "2026-01-01T00:00:00Z" {
		t.Errorf("Updated.Value.Raw = %q, want the higher-precedence (later) value kept despite the conflict", rec.Updated.Value.Raw)
	}
	if len(rec.Updated.Sources) != 1 || rec.Updated.Sources[0] != model.SourceRegistrarRDAP {
		t.Errorf("Updated.Sources = %v, want only registrar-rdap (registry-rdap disagrees and must be excluded, not counted as agreeing)", rec.Updated.Sources)
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
	if len(rec.Nameservers.Sources) != 2 {
		t.Errorf("Nameservers.Sources = %v, want both sources (their sets agree once normalized)", rec.Nameservers.Sources)
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
	if len(rec.Nameservers.Sources) != 0 {
		t.Errorf("Nameservers.Sources = %v, want empty: neither source's own set equals the 3-entry union, so crediting either as \"agreeing\" would be false consensus", rec.Nameservers.Sources)
	}
}

func TestMerge_NameserverStragglerExcludedFromSources(t *testing.T) {
	// Reproduces ycombinator.com live: registrar-rdap reports a stale
	// 3-server subset while registry-rdap and registrar-whois both report
	// the current, complete 4-server set. The merged value is still the
	// 4-server union (per the documented "union either way" policy), but
	// registrar-rdap disagrees with that union and must not be counted as
	// an agreeing source — only the two sources whose own set matches the
	// full union should appear in Sources.
	stale := sr(model.SourceRegistrarRDAP, true)
	stale.Nameservers = []string{"ns-1411.awsdns-48.org", "ns-1914.awsdns-47.co.uk", "ns-225.awsdns-28.com"}
	full1 := sr(model.SourceRegistryRDAP, true)
	full1.Nameservers = []string{"ns-1411.awsdns-48.org", "ns-1914.awsdns-47.co.uk", "ns-225.awsdns-28.com", "ns-556.awsdns-05.net"}
	full2 := sr(model.SourceRegistrarWHOIS, true)
	full2.Nameservers = []string{"ns-1411.awsdns-48.org", "ns-1914.awsdns-47.co.uk", "ns-225.awsdns-28.com", "ns-556.awsdns-05.net"}

	rec := Merge([]model.SourceRecord{stale, full1, full2})

	if len(rec.Nameservers.Value) != 4 {
		t.Errorf("Nameservers.Value = %v, want the 4-entry union", rec.Nameservers.Value)
	}
	found := false
	for _, c := range rec.Conflicts {
		if c.Field == model.FieldNameservers {
			found = true
		}
	}
	if !found {
		t.Error("expected a nameservers conflict since registrar-rdap's set is a strict subset of the union")
	}
	wantSources := map[model.SourceID]bool{model.SourceRegistryRDAP: true, model.SourceRegistrarWHOIS: true}
	if len(rec.Nameservers.Sources) != len(wantSources) {
		t.Fatalf("Nameservers.Sources = %v, want exactly %v", rec.Nameservers.Sources, wantSources)
	}
	for _, s := range rec.Nameservers.Sources {
		if !wantSources[s] {
			t.Errorf("Nameservers.Sources unexpectedly includes %v (its own set was a strict subset of the merged union, so it disagrees and should be excluded)", s)
		}
		if s == model.SourceRegistrarRDAP {
			t.Error("Nameservers.Sources includes registrar-rdap, but its 3-server set does not match the 4-server union it's credited with agreeing to")
		}
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

func TestMerge_StatusDropsBareFormWhenPrefixedVariantPresent(t *testing.T) {
	// Real GoDaddy pattern: registrar RDAP reports the ambiguous bare EPP
	// vocabulary term while registry RDAP reports the properly
	// client/server-prefixed form for the same restriction.
	registrarRDAP := sr(model.SourceRegistrarRDAP, true)
	registrarRDAP.Status = []string{"deleteProhibited", "transferProhibited", "renewProhibited", "updateProhibited"}
	registryRDAP := sr(model.SourceRegistryRDAP, true)
	registryRDAP.Status = []string{"clientDeleteProhibited", "clientRenewProhibited", "clientTransferProhibited", "clientUpdateProhibited", "serverDeleteProhibited", "serverTransferProhibited", "serverUpdateProhibited"}

	rec := Merge([]model.SourceRecord{registrarRDAP, registryRDAP})

	if len(rec.Status.Value) != 7 {
		t.Fatalf("Status.Value = %v, want only the 7 client/server-prefixed entries (bare duplicates dropped)", rec.Status.Value)
	}
	for _, bare := range []string{"deleteProhibited", "transferProhibited", "renewProhibited", "updateProhibited"} {
		for _, got := range rec.Status.Value {
			if got == bare {
				t.Errorf("Status.Value contains bare %q, want it dropped since a client/server-prefixed variant is present", bare)
			}
		}
	}
}

func TestMerge_StatusKeepsBareFormWhenNoPrefixedVariantExists(t *testing.T) {
	a := sr(model.SourceRegistrarRDAP, true)
	a.Status = []string{"ok"}

	rec := Merge([]model.SourceRecord{a})

	if len(rec.Status.Value) != 1 || rec.Status.Value[0] != "ok" {
		t.Errorf(`Status.Value = %v, want ["ok"] preserved (no client/server-prefixed variant exists to make it redundant)`, rec.Status.Value)
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

	if rec.Expires.Value.Raw != "2026-08-13T04:00:00Z" {
		t.Errorf("Expires.Value.Raw = %q, want %q (the earliest PARSED candidate -- an unparsed value can never win the conservative override, even though it's the highest-precedence present candidate)", rec.Expires.Value.Raw, "2026-08-13T04:00:00Z")
	}
	if len(rec.Conflicts) != 1 || rec.Conflicts[0].Field != model.FieldExpires {
		t.Fatalf("Conflicts = %+v, want exactly one expires conflict (the two PARSED candidates disagree by >24h, even though the winner itself didn't parse)", rec.Conflicts)
	}
	if len(rec.Conflicts[0].Values) != 3 {
		t.Errorf("Conflict.Values = %+v, want all 3 present candidates' Raw values listed (including the unparsed winner)", rec.Conflicts[0].Values)
	}
}

func TestMerge_LifecycleStageEstimates(t *testing.T) {
	updated, _ := time.Parse(time.RFC3339, "2026-08-01T00:00:00Z")

	tests := []struct {
		name         string
		status       string
		wantStage    model.LifecycleStage
		wantLabel    string
		wantAnchor   time.Time
		wantDuration time.Duration
	}{
		{"redemption grace, anchored to Updated", "redemptionPeriod", model.LifecycleRedemptionGrace, "Redemption Grace Period", updated, 30 * 24 * time.Hour},
		{"pending delete, anchored to Updated", "pendingDelete", model.LifecyclePendingDelete, "Pending Delete", updated, 5 * 24 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := sr(model.SourceRegistryRDAP, true)
			a.Domain = "example.com"
			a.Status = []string{tt.status}
			a.Updated = model.TimeValue{Time: updated, Raw: "2026-08-01T00:00:00Z", Parsed: true}

			rec := Merge([]model.SourceRecord{a})

			if rec.Lifecycle == nil {
				t.Fatal("Lifecycle = nil, want populated")
			}
			if rec.Lifecycle.Stage != tt.wantStage {
				t.Errorf("Stage = %q, want %q", rec.Lifecycle.Stage, tt.wantStage)
			}
			if rec.Lifecycle.Label != tt.wantLabel {
				t.Errorf("Label = %q, want %q", rec.Lifecycle.Label, tt.wantLabel)
			}
			if rec.Lifecycle.Description == "" {
				t.Error("Description is empty, want an explanation of the stage")
			}
			if rec.Lifecycle.EstimatedEndsBy == nil {
				t.Fatal("EstimatedEndsBy = nil, want a computed estimate")
			}
			want := tt.wantAnchor.Add(tt.wantDuration)
			if !rec.Lifecycle.EstimatedEndsBy.Equal(want) {
				t.Errorf("EstimatedEndsBy = %v, want %v", rec.Lifecycle.EstimatedEndsBy, want)
			}
			if rec.Lifecycle.EstimateBasis == "" {
				t.Error("EstimateBasis is empty, want prose explaining the estimate")
			}
		})
	}
}

func TestMerge_LifecycleAutoRenewGraceAnchoredToRegistrarExpires(t *testing.T) {
	registrarExpires, _ := time.Parse(time.RFC3339, "2026-08-03T02:51:21Z")
	registryExpires, _ := time.Parse(time.RFC3339, "2027-08-03T02:51:21Z")

	registrarWHOIS := sr(model.SourceRegistrarWHOIS, true)
	registrarWHOIS.Domain = "example.com"
	registrarWHOIS.Status = []string{"autoRenewPeriod"}
	registrarWHOIS.Expires = model.TimeValue{Time: registrarExpires, Raw: "2026-08-03T02:51:21Z", Parsed: true}

	registryWHOIS := sr(model.SourceRegistryWHOIS, true)
	registryWHOIS.Domain = "example.com"
	// The registry's own Expires reflects its already-performed
	// auto-renewal (bumped a year forward) -- it must NOT be used as the
	// anchor. This mirrors a real observed registry/registrar WHOIS pair.
	registryWHOIS.Expires = model.TimeValue{Time: registryExpires, Raw: "2027-08-03T02:51:21Z", Parsed: true}

	rec := Merge([]model.SourceRecord{registrarWHOIS, registryWHOIS})

	if rec.Lifecycle == nil {
		t.Fatal("Lifecycle = nil, want populated")
	}
	if rec.Lifecycle.Stage != model.LifecycleAutoRenewGrace {
		t.Errorf("Stage = %q, want %q", rec.Lifecycle.Stage, model.LifecycleAutoRenewGrace)
	}
	if rec.Lifecycle.EstimatedEndsBy == nil {
		t.Fatal("EstimatedEndsBy = nil, want a computed estimate anchored to the registrar's Expires")
	}
	want := registrarExpires.Add(45 * 24 * time.Hour)
	if !rec.Lifecycle.EstimatedEndsBy.Equal(want) {
		t.Errorf("EstimatedEndsBy = %v, want %v (anchored to the registrar's Expires, NOT the registry's later, already-auto-renewed date)", rec.Lifecycle.EstimatedEndsBy, want)
	}
	if rec.Lifecycle.EstimateBasis == "" {
		t.Error("EstimateBasis is empty, want prose explaining the estimate")
	}
}

func TestMerge_LifecycleAutoRenewGraceNoEstimateWithoutRegistrarSource(t *testing.T) {
	expires, _ := time.Parse(time.RFC3339, "2027-08-03T00:00:00Z")
	a := sr(model.SourceRegistryRDAP, true)
	a.Domain = "example.com"
	a.Status = []string{"autoRenewPeriod"}
	a.Expires = model.TimeValue{Time: expires, Raw: "2027-08-03T00:00:00Z", Parsed: true}

	rec := Merge([]model.SourceRecord{a})

	if rec.Lifecycle == nil {
		t.Fatal("Lifecycle = nil, want populated (Stage/Label/Description don't need the anchor)")
	}
	if rec.Lifecycle.Stage != model.LifecycleAutoRenewGrace {
		t.Errorf("Stage = %q, want %q", rec.Lifecycle.Stage, model.LifecycleAutoRenewGrace)
	}
	if rec.Lifecycle.EstimatedEndsBy != nil {
		t.Errorf("EstimatedEndsBy = %v, want nil when no registrar source is present to anchor from", rec.Lifecycle.EstimatedEndsBy)
	}
	if rec.Lifecycle.EstimateBasis != "" {
		t.Errorf("EstimateBasis = %q, want empty when no estimate was computed", rec.Lifecycle.EstimateBasis)
	}
}

func TestMerge_LifecyclePendingRestoreHasNoEstimate(t *testing.T) {
	a := sr(model.SourceRegistryRDAP, true)
	a.Domain = "example.com"
	a.Status = []string{"pendingRestore"}
	a.Updated = model.TimeValue{Time: time.Now(), Raw: "irrelevant", Parsed: true}

	rec := Merge([]model.SourceRecord{a})

	if rec.Lifecycle == nil {
		t.Fatal("Lifecycle = nil, want populated for pendingRestore")
	}
	if rec.Lifecycle.Stage != model.LifecyclePendingRestore {
		t.Errorf("Stage = %q, want %q", rec.Lifecycle.Stage, model.LifecyclePendingRestore)
	}
	if rec.Lifecycle.EstimatedEndsBy != nil {
		t.Errorf("EstimatedEndsBy = %v, want nil (no ICANN-fixed cap exists for Pending Restore)", rec.Lifecycle.EstimatedEndsBy)
	}
	if rec.Lifecycle.EstimateBasis != "" {
		t.Errorf("EstimateBasis = %q, want empty since EstimatedEndsBy is nil", rec.Lifecycle.EstimateBasis)
	}
}

func TestMerge_LifecycleNilForCCTLD(t *testing.T) {
	a := sr(model.SourceRegistryRDAP, true)
	a.Domain = "example.de"
	a.Status = []string{"redemptionPeriod"}
	a.Updated = model.TimeValue{Time: time.Now(), Raw: "irrelevant", Parsed: true}

	rec := Merge([]model.SourceRecord{a})

	if rec.Lifecycle != nil {
		t.Errorf("Lifecycle = %+v, want nil for a ccTLD regardless of status -- ccTLD registries set independent policies plat doesn't model", rec.Lifecycle)
	}
}

func TestMerge_LifecycleNilWhenNoRecognizedStatus(t *testing.T) {
	a := sr(model.SourceRegistryRDAP, true)
	a.Domain = "example.com"
	a.Status = []string{"clientTransferProhibited"}

	rec := Merge([]model.SourceRecord{a})

	if rec.Lifecycle != nil {
		t.Errorf("Lifecycle = %+v, want nil when Status carries no lifecycle-relevant EPP code", rec.Lifecycle)
	}
}

func TestMerge_LifecycleMissingAnchorLeavesEstimateEmpty(t *testing.T) {
	a := sr(model.SourceRegistryRDAP, true)
	a.Domain = "example.com"
	a.Status = []string{"redemptionPeriod"}
	// Updated deliberately left zero-value (Raw "") -- no usable anchor.

	rec := Merge([]model.SourceRecord{a})

	if rec.Lifecycle == nil {
		t.Fatal("Lifecycle = nil, want populated (Stage/Label/Description don't need the anchor)")
	}
	if rec.Lifecycle.EstimatedEndsBy != nil {
		t.Errorf("EstimatedEndsBy = %v, want nil when Updated isn't present/parsed", rec.Lifecycle.EstimatedEndsBy)
	}
	if rec.Lifecycle.EstimateBasis != "" {
		t.Errorf("EstimateBasis = %q, want empty when no estimate was computed", rec.Lifecycle.EstimateBasis)
	}
	if rec.Lifecycle.Description == "" {
		t.Error("Description is empty, want the stage explanation regardless of the missing estimate")
	}
}

func TestMerge_LifecyclePriorityPendingDeleteBeatsRedemptionGrace(t *testing.T) {
	a := sr(model.SourceRegistryRDAP, true)
	a.Domain = "example.com"
	a.Status = []string{"redemptionPeriod", "pendingDelete"}
	a.Updated = model.TimeValue{Time: time.Now(), Raw: "irrelevant", Parsed: true}

	rec := Merge([]model.SourceRecord{a})

	if rec.Lifecycle == nil {
		t.Fatal("Lifecycle = nil, want populated")
	}
	if rec.Lifecycle.Stage != model.LifecyclePendingDelete {
		t.Errorf("Stage = %q, want %q (pendingDelete is more urgent/definitive than redemptionPeriod)", rec.Lifecycle.Stage, model.LifecyclePendingDelete)
	}
}

func TestMerge_LifecyclePriorityPendingRestoreBeatsAutoRenewPeriod(t *testing.T) {
	a := sr(model.SourceRegistryRDAP, true)
	a.Domain = "example.com"
	a.Status = []string{"autoRenewPeriod", "pendingRestore"}
	a.Updated = model.TimeValue{Time: time.Now(), Raw: "irrelevant", Parsed: true}

	rec := Merge([]model.SourceRecord{a})

	if rec.Lifecycle == nil {
		t.Fatal("Lifecycle = nil, want populated")
	}
	if rec.Lifecycle.Stage != model.LifecyclePendingRestore {
		t.Errorf("Stage = %q, want %q (pendingRestore is more urgent/definitive than autoRenewPeriod)", rec.Lifecycle.Stage, model.LifecyclePendingRestore)
	}
}

func TestMerge_LifecycleNilForIDNCCTLD(t *testing.T) {
	// internal/collect/adapt_rdap.go prefers the Unicode domain form over
	// the punycode/LDH form, so both shapes need to be checked: the raw
	// Unicode ccTLD directly, and the punycode-encoded (xn--) form a
	// source might still report.
	tests := []struct {
		name   string
		domain string
	}{
		{"Unicode ccTLD", "пример.рф"},
		{"punycode-encoded IDN ccTLD", "xn--e1afmkfd.xn--p1ai"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := sr(model.SourceRegistryRDAP, true)
			a.Domain = tt.domain
			a.Status = []string{"redemptionPeriod"}
			a.Updated = model.TimeValue{Time: time.Now(), Raw: "irrelevant", Parsed: true}

			rec := Merge([]model.SourceRecord{a})

			if rec.Lifecycle != nil {
				t.Errorf("Lifecycle = %+v, want nil for IDN ccTLD %q (byte length must not be mistaken for character length, and the punycode form must be recognized too)", rec.Lifecycle, tt.domain)
			}
		})
	}
}

func TestMerge_LifecycleNilForIDNGTLD(t *testing.T) {
	// Documented limitation: IDN gTLDs (here, the real gTLD ".在线",
	// punycode "xn--3ds443g") are excluded from lifecycle interpretation
	// alongside IDN ccTLDs, since the two can't be reliably told apart
	// without a real TLD-type classification list. See isGTLD's doc
	// comment.
	tests := []struct {
		name   string
		domain string
	}{
		{"Unicode gTLD form", "example.在线"},
		{"punycode gTLD form", "xn--e1afmkfd.xn--3ds443g"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := sr(model.SourceRegistryRDAP, true)
			a.Domain = tt.domain
			a.Status = []string{"redemptionPeriod"}
			a.Updated = model.TimeValue{Time: time.Now(), Raw: "irrelevant", Parsed: true}

			rec := Merge([]model.SourceRecord{a})

			if rec.Lifecycle != nil {
				t.Errorf("Lifecycle = %+v, want nil -- IDN gTLDs are out of scope for lifecycle interpretation alongside IDN ccTLDs (documented limitation, see isGTLD)", rec.Lifecycle)
			}
		})
	}
}

func TestMerge_LifecycleNilForMalformedDomain(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{"trailing dot", "example.com."},
		{"dot-less", "localhost"},
		{"empty string", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := sr(model.SourceRegistryRDAP, true)
			a.Domain = tt.domain
			a.Status = []string{"redemptionPeriod"}
			a.Updated = model.TimeValue{Time: time.Now(), Raw: "irrelevant", Parsed: true}

			rec := Merge([]model.SourceRecord{a})

			if rec.Lifecycle != nil {
				t.Errorf("Lifecycle = %+v, want nil for malformed domain %q", rec.Lifecycle, tt.domain)
			}
		})
	}
}
