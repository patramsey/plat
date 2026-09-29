package collect

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

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
