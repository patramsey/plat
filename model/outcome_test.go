package model

import "testing"

func TestClassify(t *testing.T) {
	tests := []struct {
		name    string
		sources []SourceResult
		want    Outcome
	}{
		{"no sources at all", nil, OutcomeFailed},
		{"one source with data", []SourceResult{{OK: true}}, OutcomeOK},
		{"data plus a failure still OK", []SourceResult{{OK: true}, {}}, OutcomeOK},
		{"data plus not-found still OK", []SourceResult{{OK: true}, {NotFound: true}}, OutcomeOK},
		{"all not-found", []SourceResult{{NotFound: true}, {NotFound: true}}, OutcomeNotFound},
		{"not-found mixed with failure is a failure", []SourceResult{{NotFound: true}, {}}, OutcomeFailed},
		{"all failed", []SourceResult{{}, {}}, OutcomeFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.sources); got != tt.want {
				t.Fatalf("Classify = %v, want %v", got, tt.want)
			}
		})
	}
}

// A source with no service for the name (retired WHOIS, unsupported TLD,
// refused queries) says nothing about the name, so it is left out: a free
// .shop name is not found on RDAP's 404 alone.
func TestClassify_UnavailableSourcesAreLeftOut(t *testing.T) {
	retired := SourceResult{Source: SourceRegistryWHOIS, Unavailable: true, Err: "WHOIS service retired"}
	for _, tt := range []struct {
		name    string
		sources []SourceResult
		want    Outcome
	}{
		{"not found, plus an unavailable WHOIS", []SourceResult{{Source: SourceRegistryRDAP, NotFound: true}, retired}, OutcomeNotFound},
		{"data, plus an unavailable WHOIS", []SourceResult{{Source: SourceRegistryRDAP, OK: true}, retired}, OutcomeOK},
		{"only an unavailable source", []SourceResult{retired}, OutcomeFailed},
		{"not found, unavailable and a real failure", []SourceResult{{Source: SourceRegistryRDAP, NotFound: true}, retired, {Source: SourceRegistrarWHOIS, Err: "timeout"}}, OutcomeFailed},
	} {
		if got := Classify(tt.sources); got != tt.want {
			t.Errorf("%s: Classify = %v, want %v", tt.name, got, tt.want)
		}
	}
}
