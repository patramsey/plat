package render

import (
	"os"
	"testing"
)

func TestParseFormat(t *testing.T) {
	tests := []struct {
		in      string
		want    Format
		wantErr bool
	}{
		{"human", FormatHuman, false},
		{"plain", FormatPlain, false},
		{"json", FormatJSON, false},
		{"ndjson", FormatNDJSON, false},
		{"HUMAN", FormatHuman, false},
		{"  json  ", FormatJSON, false},
		{"yaml", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseFormat(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseFormat(%q) expected an error, got nil", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseFormat(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseFormat(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestSelect(t *testing.T) {
	tests := []struct {
		name     string
		explicit string
		isTTY    bool
		noColor  bool
		want     Format
		wantErr  bool
	}{
		{"explicit wins over TTY", "json", true, false, FormatJSON, false},
		{"explicit wins over pipe", "json", false, false, FormatJSON, false},
		{"explicit human wins over NO_COLOR", "human", true, true, FormatHuman, false},
		{"no explicit, TTY, no NO_COLOR -> human", "", true, false, FormatHuman, false},
		{"no explicit, pipe -> plain", "", false, false, FormatPlain, false},
		{"no explicit, TTY, NO_COLOR set -> plain", "", true, true, FormatPlain, false},
		{"invalid explicit format", "bogus", true, false, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Select(tt.explicit, tt.isTTY, tt.noColor)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Select(%q, %v, %v) expected an error, got nil", tt.explicit, tt.isTTY, tt.noColor)
				}
				return
			}
			if err != nil {
				t.Fatalf("Select(%q, %v, %v) unexpected error: %v", tt.explicit, tt.isTTY, tt.noColor, err)
			}
			if got != tt.want {
				t.Errorf("Select(%q, %v, %v) = %v, want %v", tt.explicit, tt.isTTY, tt.noColor, got, tt.want)
			}
		})
	}
}

func TestIsTerminal_FalseForPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()
	if IsTerminal(r) {
		t.Error("IsTerminal(pipe read end) = true, want false")
	}
	if IsTerminal(w) {
		t.Error("IsTerminal(pipe write end) = true, want false")
	}
}

func TestIsMachine(t *testing.T) {
	tests := []struct {
		f    Format
		want bool
	}{
		{FormatHuman, false},
		{FormatPlain, false},
		{FormatJSON, true},
		{FormatNDJSON, true},
	}
	for _, tt := range tests {
		if got := IsMachine(tt.f); got != tt.want {
			t.Errorf("IsMachine(%v) = %v, want %v", tt.f, got, tt.want)
		}
	}
}
