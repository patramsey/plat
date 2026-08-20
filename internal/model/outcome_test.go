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
