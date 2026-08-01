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
