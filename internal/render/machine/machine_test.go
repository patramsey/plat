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
		if err := os.WriteFile(path, got, 0o600); err != nil {
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
		Status:      model.Field[[]string]{Value: []string{"clientTransferProhibited"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Created:     model.Field[model.TimeValue]{Value: model.TimeValue{Time: created, Raw: "1995-08-14T04:00:00Z", Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Expires:     model.Field[model.TimeValue]{Value: model.TimeValue{Time: expires, Raw: "2026-08-13T04:00:00Z", Parsed: true}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
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

// TestEncode_NameserversWithEmptySourcesStillPresent covers a real
// merge.Merge output shape: a genuine nameserver conflict leaves
// Field.Sources empty while Field.Value stays populated with the union
// (see internal/merge's nameservers() doc comment). The "nameservers" key
// must still appear in JSON, with an empty (not omitted) sources array.
func TestEncode_NameserversWithEmptySourcesStillPresent(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Nameservers: model.Field[[]string]{
			Value:   []string{"ns1.example.com", "ns2.example.com"},
			Sources: nil,
		},
	}
	var buf bytes.Buffer
	if err := Encode(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded map[string]interface{}
	_ = json.Unmarshal(buf.Bytes(), &decoded)
	ns, exists := decoded["nameservers"]
	if !exists {
		t.Fatalf("expected \"nameservers\" key to be present, got: %s", buf.String())
	}
	nsMap := ns.(map[string]interface{})
	values := nsMap["value"].([]interface{})
	if len(values) != 2 {
		t.Errorf("nameservers.value = %v, want 2 entries", values)
	}
	sources, ok := nsMap["sources"].([]interface{})
	if !ok || len(sources) != 0 {
		t.Errorf("nameservers.sources = %v, want an empty array", nsMap["sources"])
	}
}

func TestEncode_LifecycleField(t *testing.T) {
	updated, _ := time.Parse(time.RFC3339, "2026-08-01T00:00:00Z")
	endsBy := updated.Add(30 * 24 * time.Hour)
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Lifecycle: &model.LifecycleInfo{
			Stage:           model.LifecycleRedemptionGrace,
			Label:           "Redemption Grace Period",
			Description:     "This domain has expired and is no longer eligible for normal renewal.",
			EstimatedEndsBy: &endsBy,
			EstimateBasis:   "Estimate based on ICANN's fixed 30-day Redemption Grace Period policy for gTLDs.",
		},
	}
	var buf bytes.Buffer
	if err := Encode(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkGolden(t, "lifecycle.json", buf.Bytes())

	var decoded map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output did not unmarshal: %v", err)
	}
	lifecycle := decoded["lifecycle"].(map[string]interface{})
	if lifecycle["stage"] != "redemptionGrace" {
		t.Errorf("lifecycle.stage = %v, want %q", lifecycle["stage"], "redemptionGrace")
	}
	if lifecycle["estimatedEndsBy"] != "2026-08-31T00:00:00Z" {
		t.Errorf("lifecycle.estimatedEndsBy = %v, want %q", lifecycle["estimatedEndsBy"], "2026-08-31T00:00:00Z")
	}
}

func TestEncode_LifecycleAbsentWhenNil(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	var buf bytes.Buffer
	if err := Encode(&buf, rec, Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded map[string]interface{}
	_ = json.Unmarshal(buf.Bytes(), &decoded)
	if _, ok := decoded["lifecycle"]; ok {
		t.Errorf("lifecycle key present, want omitted when Record.Lifecycle is nil")
	}
}
