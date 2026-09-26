package source

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
		{"single lowercase word", "published", "published"},
		{"single uppercase word", "CONNECT", "connect"},
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

func TestNormalizeEPPStatus_CanonicalisesKnownCodesCaseInsensitively(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"clientDeleteProhibited", "clientDeleteProhibited"},
		{"clientdeleteprohibited", "clientDeleteProhibited"},
		{"CLIENTDELETEPROHIBITED", "clientDeleteProhibited"},
		{"clientTransferProhibited", "clientTransferProhibited"},
		{"serverupdateprohibited", "serverUpdateProhibited"},
		{"redemptionperiod", "redemptionPeriod"},
		{"pendingdelete", "pendingDelete"},
		{"autorenewperiod", "autoRenewPeriod"},
		{"ok", "ok"},
		{"active", "ok"}, // RFC 8056: RDAP "active" is EPP "ok"
		// Not an EPP code: today's behaviour is preserved untouched.
		{"connect", "connect"},
		{"Sponsoring registrar change forbidden", "sponsoringRegistrarChangeForbidden"},
	} {
		if got := NormalizeEPPStatus(tt.in); got != tt.want {
			t.Errorf("NormalizeEPPStatus(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// RFC 8056 maps RDAP's "active" to EPP's "ok". Without the mapping, an
// unlocked domain answered by both RDAP and WHOIS showed
// "Status: active · ok" -- one status, listed twice.
func TestNormalizeEPPStatus_RDAPActiveIsEPPOk(t *testing.T) {
	for _, in := range []string{"active", "Active", "ACTIVE"} {
		if got := NormalizeEPPStatus(in); got != "ok" {
			t.Errorf("NormalizeEPPStatus(%q) = %q, want ok", in, got)
		}
	}
}
