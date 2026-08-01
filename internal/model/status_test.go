package model

import "testing"

func TestNormalizeEPPStatus(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"space separated verisign form", "client transfer prohibited", "clientTransferProhibited"},
		{"already camelCase", "clientTransferProhibited", "clientTransferProhibited"},
		{"space separated all caps", "CLIENT TRANSFER PROHIBITED", "clientTransferProhibited"},
		{"space separated, different words", "client delete prohibited", "clientDeleteProhibited"},
		{"single lowercase word", "active", "active"},
		{"single uppercase word", "ACTIVE", "active"},
		{"already camelCase, server prefix", "serverDeleteProhibited", "serverDeleteProhibited"},
		{"single word, no case ambiguity", "connect", "connect"},
		{"two-letter lowercase", "ok", "ok"},
		{"two-letter uppercase", "OK", "ok"},
		{"already camelCase, pendingDelete", "pendingDelete", "pendingDelete"},
		{"empty string", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeEPPStatus(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeEPPStatus(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
