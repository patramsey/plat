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
			name:   "typical registrar vcard",
			json:   `["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Registrar, Inc."]]]`,
			wantFN: "Example Registrar, Inc.",
		},
		{
			name:   "abuse vcard with email and tel",
			json:   `["vcard",[["fn",{},"text","Abuse Team"],["email",{},"text","abuse@example.example"],["tel",{},"text","+1.5555550100"]]]`,
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
			name:   "non-string property value (e.g. structured n) is skipped, not fatal",
			json:   `["vcard",[["n",{},"text",["Corp","Example",[],[],[]]],["fn",{},"text","Example Corp"]]]`,
			wantFN: "Example Corp",
		},
		{
			name:      "property array too short degrades that entry silently",
			json:      `["vcard",[["fn",{}],["email",{},"text","real@example.example"]]]`,
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

// TestASNRedactionRemarks mirrors TestRedactionRemarks -- ASNResponse's
// RedactionRemarks was added alongside DomainResponse's so the ASN
// adapters (internal/collect/adapt_asn.go) have a working signal to
// populate ASNSourceRecord.Redactions from, the same way the domain
// adapter already does.
func TestASNRedactionRemarks(t *testing.T) {
	a := ASNResponse{
		Remarks: RemarkList{
			{Title: "Terms of Use", Type: "", Description: []string{"Service subject to Terms of Use."}},
			{Title: "REDACTED FOR PRIVACY", Type: "object redacted due to authorization", Description: []string{"Some data has been removed."}},
		},
	}
	got := a.RedactionRemarks()
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
