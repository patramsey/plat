package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		wantPunycode    string
		wantTLD         string
		wantUnicode     string
		wantErr         error
		wantErrContains string
	}{
		{
			name:         "simple lowercase",
			input:        "example.com",
			wantPunycode: "example.com",
			wantTLD:      "com",
		},
		{
			name:         "uppercase normalizes to lowercase",
			input:        "EXAMPLE.COM",
			wantPunycode: "example.com",
			wantTLD:      "com",
		},
		{
			name:         "trailing dot stripped",
			input:        "example.com.",
			wantPunycode: "example.com",
			wantTLD:      "com",
		},
		{
			name:         "IDN converts to punycode",
			input:        "münchen.de",
			wantPunycode: "xn--mnchen-3ya.de",
			wantTLD:      "de",
		},
		{
			name:         "already-punycode xn-- input passes through",
			input:        "xn--mnchen-3ya.de",
			wantPunycode: "xn--mnchen-3ya.de",
			wantTLD:      "de",
		},
		{
			name:    "single-label input rejected",
			input:   "localhost",
			wantErr: ErrSingleLabel,
		},
		{
			name:         "domain whose labels are numeric is still a domain",
			input:        "123.com",
			wantPunycode: "123.com",
			wantTLD:      "com",
		},
		{
			name:            "reserved TLD .local rejected",
			input:           "printer.local",
			wantErrContains: "reserved/private TLD",
		},
		{
			name:            "reserved TLD .internal rejected",
			input:           "svc.internal",
			wantErrContains: "reserved/private TLD",
		},
		{
			name:         "uppercase IDN normalizes and converts to punycode",
			input:        "MÜNCHEN.DE",
			wantPunycode: "xn--mnchen-3ya.de",
			wantTLD:      "de",
		},
		{
			name:         "already-punycode xn-- input round-trips to Unicode display form",
			input:        "xn--mnchen-3ya.de",
			wantPunycode: "xn--mnchen-3ya.de",
			wantTLD:      "de",
			wantUnicode:  "münchen.de",
		},
		{
			name:         "IDN under a ccTLD with its own IDN suffix",
			input:        "täst.xn--p1ai",
			wantPunycode: "xn--tst-qla.xn--p1ai",
			wantTLD:      "xn--p1ai",
		},
		{
			name:         "mixed-script label still converts (idna.ToASCII does not perform confusable detection)",
			input:        "аpple.com", // Cyrillic "а" (U+0430) + Latin "pple.com" — a classic homograph
			wantPunycode: "xn--pple-43d.com",
			wantTLD:      "com",
		},
		{
			name:            "reserved TLD .test rejected",
			input:           "example.test",
			wantErrContains: "reserved/private TLD",
		},
		{
			name:            "reserved TLD .example rejected",
			input:           "foo.example",
			wantErrContains: "reserved/private TLD",
		},
		{
			name:            "reserved TLD .invalid rejected",
			input:           "foo.invalid",
			wantErrContains: "reserved/private TLD",
		},
		{
			name:         "https scheme stripped",
			input:        "https://example.com",
			wantPunycode: "example.com",
			wantTLD:      "com",
		},
		{
			name:         "http scheme, trailing slash, and path stripped",
			input:        "http://example.com/whois/lookup",
			wantPunycode: "example.com",
			wantTLD:      "com",
		},
		{
			name:         "scheme, port, path, query, and fragment all stripped",
			input:        "https://example.com:8080/foo/bar?x=1#y",
			wantPunycode: "example.com",
			wantTLD:      "com",
		},
		{
			name:         "bare host with path and no scheme still stripped",
			input:        "example.com/foo/bar",
			wantPunycode: "example.com",
			wantTLD:      "com",
		},
		{
			name:         "NFC and NFD forms of the same visible IDN normalize to the same punycode",
			input:        "café.com", // NFD: "e" + combining acute accent U+0301
			wantPunycode: "xn--caf-dma.com",
			wantTLD:      "com",
		},
		{
			name:         "ideographic full stop is treated as a label separator",
			input:        "münchen。de", // U+3002 IDEOGRAPHIC FULL STOP
			wantPunycode: "xn--mnchen-3ya.de",
			wantTLD:      "de",
		},
		{
			name:         "fullwidth full stop is treated as a label separator",
			input:        "münchen．de", // U+FF0E FULLWIDTH FULL STOP
			wantPunycode: "xn--mnchen-3ya.de",
			wantTLD:      "de",
		},
		{
			name:         "trailing ideographic full stop is stripped like a trailing ASCII dot",
			input:        "münchen.de。",
			wantPunycode: "xn--mnchen-3ya.de",
			wantTLD:      "de",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := Normalize(tt.input)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Normalize(%q) error = %v, want errors.Is match for %v", tt.input, err, tt.wantErr)
				}
				return
			}
			if tt.wantErrContains != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Fatalf("Normalize(%q) error = %v, want error containing %q", tt.input, err, tt.wantErrContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalize(%q) unexpected error: %v", tt.input, err)
			}
			if q.Name.Punycode != tt.wantPunycode {
				t.Errorf("Punycode = %q, want %q", q.Name.Punycode, tt.wantPunycode)
			}
			if q.Name.TLD != tt.wantTLD {
				t.Errorf("TLD = %q, want %q", q.Name.TLD, tt.wantTLD)
			}
			if tt.wantUnicode != "" && q.Name.Unicode != tt.wantUnicode {
				t.Errorf("Unicode = %q, want %q", q.Name.Unicode, tt.wantUnicode)
			}
		})
	}
}

func TestNormalize_ClassifiesIPInput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantKind Kind
		wantIP   string
	}{
		{"bare IPv4", "8.8.8.8", KindIPv4, "8.8.8.8"},
		{"bare IPv6", "2001:4860:4860::8888", KindIPv6, "2001:4860:4860::8888"},
		{"bracketed IPv6", "[2001:db8::1]", KindIPv6, "2001:db8::1"},
		{"IPv4 CIDR resolves to network address", "8.8.8.0/24", KindIPv4, "8.8.8.0"},
		{"IPv4 pasted as a URL", "https://8.8.8.8/whois", KindIPv4, "8.8.8.8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := Normalize(tt.input)
			if err != nil {
				t.Fatalf("Normalize(%q) unexpected error: %v", tt.input, err)
			}
			if q.Kind != tt.wantKind {
				t.Errorf("Kind = %v, want %v", q.Kind, tt.wantKind)
			}
			if q.IP.String() != tt.wantIP {
				t.Errorf("IP = %q, want %q", q.IP.String(), tt.wantIP)
			}
		})
	}
}

func TestNormalize_DomainStillClassifiesAsDomain(t *testing.T) {
	q, err := Normalize("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.Kind != KindDomain {
		t.Errorf("Kind = %v, want KindDomain", q.Kind)
	}
	if q.Name.Punycode != "example.com" || q.Name.TLD != "com" {
		t.Errorf("Name = %+v, want punycode example.com / tld com", q.Name)
	}
}

func TestNormalize_NumericLabelDomainIsNotAnIP(t *testing.T) {
	q, err := Normalize("123.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.Kind != KindDomain {
		t.Errorf("Kind = %v, want KindDomain for 123.com", q.Kind)
	}
}

// TestNormalize_RejectsReservedIPs is a regression test for a real
// defect caught during live verification: reserved/private IP input
// (10.0.0.1, 127.0.0.1, ::1, 0.0.0.0, 255.255.255.255...) sailed through
// Normalize as an ordinary KindIPv4/KindIPv6 Query, and ~5 seconds later
// plat printed "lookup failed -- no sources could be reached" at exit
// 3 -- a factually wrong message (whois.iana.org *was* reached and
// answered "organisation: IANA - Private Use"; it just had no "refer:"
// line, so nothing downstream ever surfaced that response). These must
// now be rejected up front with ErrReservedIP, mirroring how a reserved
// TLD is rejected for domains.
func TestNormalize_RejectsReservedIPs(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"IPv4 private (RFC 1918)", "10.0.0.1"},
		{"IPv4 private, 172.16/12", "172.16.5.5"},
		{"IPv4 private, 192.168/16", "192.168.1.1"},
		{"IPv4 loopback", "127.0.0.1"},
		{"IPv4 unspecified", "0.0.0.0"},
		{"IPv4 limited broadcast", "255.255.255.255"},
		{"IPv4 link-local", "169.254.1.1"},
		{"IPv4 multicast", "224.0.0.1"},
		{"IPv6 loopback", "::1"},
		{"IPv6 unspecified", "::"},
		{"IPv6 unique local (RFC 4193)", "fc00::1"},
		{"IPv6 link-local", "fe80::1"},
		{"IPv6 multicast", "ff02::1"},
		{"bracketed IPv6 loopback", "[::1]"},
		{"private IPv4 CIDR", "10.0.0.0/8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := Normalize(tt.input)
			if err == nil {
				t.Fatalf("Normalize(%q) = %+v, nil, want an ErrReservedIP error", tt.input, q)
			}
			if !errors.Is(err, ErrReservedIP) {
				t.Errorf("Normalize(%q) error = %v, want errors.Is(err, ErrReservedIP)", tt.input, err)
			}
			// The message must not claim sources were unreachable --
			// that's the exact wrong-explanation bug this guard fixes.
			if strings.Contains(err.Error(), "unreachable") || strings.Contains(err.Error(), "no sources") {
				t.Errorf("Normalize(%q) error = %q, must not claim sources were unreachable", tt.input, err.Error())
			}
		})
	}
}

// TestNormalize_OrdinaryPublicIPsStillAccepted guards against the
// reserved-IP rejection being too broad: real, publicly-allocated
// addresses across all five RIRs (used throughout this branch's live
// verification) must still classify normally.
func TestNormalize_OrdinaryPublicIPsStillAccepted(t *testing.T) {
	tests := []string{
		"8.8.8.8",              // ARIN
		"193.0.6.139",          // RIPE
		"1.1.1.1",              // APNIC
		"200.3.12.1",           // LACNIC
		"196.216.2.1",          // AFRINIC
		"2001:67c:2e8::1",      // RIPE, IPv6
		"2001:4860:4860::8888", // ARIN, IPv6
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			q, err := Normalize(input)
			if err != nil {
				t.Fatalf("Normalize(%q) unexpected error: %v", input, err)
			}
			if q.Kind != KindIPv4 && q.Kind != KindIPv6 {
				t.Errorf("Kind = %v, want an IP kind", q.Kind)
			}
		})
	}
}
