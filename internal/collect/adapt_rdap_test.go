package collect

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/merge"
	"github.com/patramsey/plat/internal/source"

	"github.com/patramsey/plat/internal/rdap"
	"github.com/patramsey/plat/model"
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

// A real registrar RDAP answer (MarkMonitor, google.com). Its abuse
// contact is nested inside the registrar entity, as the gTLD RDAP profile
// specifies (#133), and carries a phone and a contact URI but no email.
// Its redaction remarks sit on the registrant entity, which plat does not
// model, so there is no top-level redaction notice -- the hand-written
// fixture this replaced invented one.
func TestFromRDAP_RegistrarFixtureWithEntities(t *testing.T) {
	d := loadRDAPFixture(t, "markmonitor-registrar-google-recorded.json")
	result := &rdap.Result{Domain: d, Raw: []byte("raw bytes")}

	sr := FromRDAP(model.SourceRegistrarRDAP, result, 30*time.Millisecond, nil)

	if sr.Registrar.Name != "Markmonitor Inc." {
		t.Errorf("Registrar.Name = %q, want %q", sr.Registrar.Name, "Markmonitor Inc.")
	}
	if sr.Registrar.AbusePhone != "+1.2086851750" {
		t.Errorf("Registrar.AbusePhone = %q, want %q (nested in the registrar entity)", sr.Registrar.AbusePhone, "+1.2086851750")
	}
	if sr.Registrar.AbuseEmail != "" {
		t.Errorf("Registrar.AbuseEmail = %q, want empty (MarkMonitor's abuse contact has none)", sr.Registrar.AbuseEmail)
	}
	if len(sr.Redactions) != 0 {
		t.Errorf("Redactions = %+v, want none at the top level", sr.Redactions)
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

// RFC 9537 entries map onto the fields plat shows (#134). The handle
// paths are PIR's real ones; the registrar-field paths are synthetic --
// no sampled registry redacts them -- and follow the ICANN RDAP Response
// Profile's JSONPath shapes. Contact redactions (registrant, tech) map
// to nothing: plat deliberately does not show contacts.
func TestRedactedField(t *testing.T) {
	for _, tt := range []struct {
		name, prePath, want string
	}{
		{"Registry Domain ID", "$.handle", model.FieldHandle},
		{"", "$.handle", model.FieldHandle},
		{"Registry Domain ID", "", model.FieldHandle},
		{"Registrar Name", "$.entities[?(@.roles[0]=='registrar')].vcardArray[1][?(@[0]=='fn')][3]", model.FieldRegistrarName},                                                          // synthetic
		{"Registrar Abuse Contact Email", "$.entities[?(@.roles[0]=='registrar')].entities[?(@.roles[0]=='abuse')].vcardArray[1][?(@[0]=='email')][3]", model.FieldRegistrarAbuseEmail}, // synthetic
		{"Registrar Abuse Contact Phone", "$.entities[?(@.roles[0]=='registrar')].entities[?(@.roles[0]=='abuse')].vcardArray[1][?(@[0]=='tel')][3]", model.FieldRegistrarAbusePhone},   // synthetic
		{"Registrant Name", "$.entities[?(@.roles[0]=='registrant')].vcardArray[1][?(@[0]=='fn')][3]", ""},
		{"Tech Email", "$.entities[?(@.roles[0]=='technical')].vcardArray[1][?(@[0]=='email')][3]", ""},
		{"Registry Registrant ID", "$.entities[?(@.roles[0]=='registrant')].handle", ""},
	} {
		r := rdap.Redaction{PrePath: tt.prePath}
		r.Name.Type = tt.name
		if got := redactedField(r); got != tt.want {
			t.Errorf("redactedField(%q, %q) = %q, want %q", tt.name, tt.prePath, got, tt.want)
		}
	}
}

// PIR's real answer removes the Registry Domain ID under RFC 9537. With
// no registrar RDAP to outrank it, the record must say so rather than
// silently showing no handle.
func TestFromRDAP_RFC9537HandleRedaction(t *testing.T) {
	d := loadRDAPFixture(t, "pir-org-wikipedia-recorded.json")
	sr := FromRDAP(model.SourceRegistryRDAP, &rdap.Result{Domain: d}, 0, nil)
	if !sr.RedactedFields[model.FieldHandle] {
		t.Errorf("RedactedFields = %v, want handle marked redacted", sr.RedactedFields)
	}
	rec := merge.Merge([]source.SourceRecord{sr})
	want := model.RedactionNotice{Field: model.FieldHandle, Source: model.SourceRegistryRDAP, Reason: "redacted"}
	if !slices.Contains(rec.Redacted, want) {
		t.Errorf("Redacted = %+v, want %+v", rec.Redacted, want)
	}
}

// TestApplyRFC9537_ClearsPlaceholders covers the registrar fields no
// sampled server redacts yet: a "replacementValue" or "emptyValue"
// leaves a placeholder in the member, which must not survive as data.
// Synthetic, like the registrar rows in TestRedactedField.
func TestApplyRFC9537_ClearsPlaceholders(t *testing.T) {
	sr := source.SourceRecord{RedactedFields: map[string]bool{}}
	sr.Handle = "REDACTED"
	sr.Registrar.Name = "REDACTED"
	sr.Registrar.AbuseEmail = "redacted@example.invalid"
	sr.Registrar.AbusePhone = "+1.0000000000"

	var list rdap.RedactionList
	for _, name := range []string{
		"Registry Domain ID",
		"Registrar Name",
		"Registrar Abuse Contact Email",
		"Registrar Abuse Contact Phone",
		"Registrant Name",
	} {
		var r rdap.Redaction
		r.Name.Type = name
		r.Method = "replacementValue"
		list = append(list, r)
	}
	applyRFC9537(&sr, list)

	if sr.Handle != "" || sr.Registrar.Name != "" || sr.Registrar.AbuseEmail != "" || sr.Registrar.AbusePhone != "" {
		t.Errorf("placeholders survived: handle=%q registrar=%+v", sr.Handle, sr.Registrar)
	}
	for _, f := range []string{model.FieldHandle, model.FieldRegistrarName, model.FieldRegistrarAbuseEmail, model.FieldRegistrarAbusePhone} {
		if !sr.RedactedFields[f] {
			t.Errorf("RedactedFields[%s] = false, want true", f)
		}
	}
	if len(sr.RedactedFields) != 4 {
		t.Errorf("RedactedFields = %v, want exactly the four shown fields", sr.RedactedFields)
	}
}
