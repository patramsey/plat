package collect

import (
	"encoding/json"
	"errors"
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
