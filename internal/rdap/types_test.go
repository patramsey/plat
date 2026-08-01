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

func TestDomainResponseEventAccessors_RegistrarExpirationVariant(t *testing.T) {
	// Namecheap's registrar-rdap response for for.ninja uses
	// "registrar expiration" rather than RFC 9083's base "expiration" —
	// an open-set eventAction variant that normalizeEventAction must
	// still recognize, or the field silently disappears from Expires().
	tests := []struct {
		name        string
		eventAction string
	}{
		{"registrar expiration", "registrar expiration"},
		{"registry expiration", "registry expiration"},
		{"case and whitespace insensitive", "  Registrar Expiration  "},
		{"soft expiration (.is, confirmed live against archive.is)", "soft expiration"},
		{"record expires (.kg, confirmed live against google.kg)", "Record expires"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := `{"objectClassName":"domain","events":[{"eventAction":"` + tt.eventAction + `","eventDate":"2026-09-27T14:13:46Z"}]}`
			var d DomainResponse
			if err := json.Unmarshal([]byte(raw), &d); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			expires, ok := d.Expires()
			if !ok || expires.Raw != "2026-09-27T14:13:46Z" {
				t.Errorf("Expires() = %v, %v, want ok with Raw 2026-09-27T14:13:46Z", expires, ok)
			}
		})
	}
}

func TestDomainResponsePort43(t *testing.T) {
	tests := []struct {
		name string
		json string
		want string
	}{
		{"populated", `{"objectClassName":"domain","port43":"whois.name.com"}`, "whois.name.com"},
		{"absent", `{"objectClassName":"domain"}`, ""},
		{"explicit null", `{"objectClassName":"domain","port43":null}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d DomainResponse
			if err := json.Unmarshal([]byte(tt.json), &d); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d.Port43 != tt.want {
				t.Errorf("Port43 = %q, want %q", d.Port43, tt.want)
			}
		})
	}
}
