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
			got, err := Normalize(tt.input)
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
			if got.Punycode != tt.wantPunycode {
				t.Errorf("Punycode = %q, want %q", got.Punycode, tt.wantPunycode)
			}
			if got.TLD != tt.wantTLD {
				t.Errorf("TLD = %q, want %q", got.TLD, tt.wantTLD)
			}
			if tt.wantUnicode != "" && got.Unicode != tt.wantUnicode {
				t.Errorf("Unicode = %q, want %q", got.Unicode, tt.wantUnicode)
			}
		})
	}
}
