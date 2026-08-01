package model

import "testing"

func TestIsRedactedPlaceholder_CaseInsensitive(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"exact uppercase", "REDACTED FOR PRIVACY", true},
		{"exact lowercase", "redacted for privacy", true},
		{"mixed case", "Redacted For Privacy", true},
		{"data redacted", "Data Redacted", true},
		{"data protected", "DATA PROTECTED", true},
		{"not disclosed", "Not Disclosed", true},
		{"gdpr masked", "GDPR Masked", true},
		{"statutory masking enabled", "Statutory Masking Enabled", true},
		{"bare redacted", "REDACTED", true},
		{"registration private", "Registration Private", true},
		{"leading/trailing whitespace", "  REDACTED FOR PRIVACY  ", true},
		{"real organization name", "Redacted Solutions LLC", false},
		{"real name containing redact as substring", "The Redactions Group", false},
		{"empty string", "", false},
		{"unrelated value", "Example Corp", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsRedactedPlaceholder(tt.input)
			if got != tt.want {
				t.Errorf("IsRedactedPlaceholder(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
