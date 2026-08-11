package parse

import (
	"strings"
	"testing"
	"time"
)

func TestParseDate(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantParsed bool
		wantUTC    string
	}{
		{"RFC3339 with zone", "2026-07-12T10:00:00Z", true, "2026-07-12T10:00:00Z"},
		{"RFC3339Nano", "2026-07-12T10:00:00.123456Z", true, "2026-07-12T10:00:00Z"},
		{"no zone assumed UTC", "2026-07-12T10:00:00", true, "2026-07-12T10:00:00Z"},
		{"space instead of T with zone", "2026-07-12 10:00:00Z", true, "2026-07-12T10:00:00Z"},
		{"space no zone", "2026-07-12 10:00:00", true, "2026-07-12T10:00:00Z"},
		{"date only", "2026-07-12", true, "2026-07-12T00:00:00Z"},
		{"legacy dash-month-dash lowercase", "14-aug-1995", true, "1995-08-14T00:00:00Z"},
		{"legacy dash-month-dash titlecase", "14-Aug-1995", true, "1995-08-14T00:00:00Z"},
		{"slash form (.jp)", "2026/07/12", true, "2026-07-12T00:00:00Z"},
		{"dot form", "2026.07.12", true, "2026-07-12T00:00:00Z"},
		{"day.month.year dot form", "12.07.2026", true, "2026-07-12T00:00:00Z"},
		{"LACNIC compact unpunctuated form", "20031127", true, "2003-11-27T00:00:00Z"},
		{"verbose month name", "August 14, 1995", true, "1995-08-14T00:00:00Z"},
		{"verbose month name lowercase", "august 14, 1995", true, "1995-08-14T00:00:00Z"},
		{"weekday month day year", "Wed Aug 14 2025", true, "2025-08-14T00:00:00Z"},
		{"garbage never errors", "not-a-date", false, ""},
		{"empty string", "", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseDate(tt.input)
			wantRaw := strings.TrimSpace(tt.input)
			if got.Raw != wantRaw {
				t.Errorf("Raw = %q, want %q", got.Raw, wantRaw)
			}
			if got.Parsed != tt.wantParsed {
				t.Errorf("Parsed = %v, want %v (input %q)", got.Parsed, tt.wantParsed, tt.input)
			}
			if tt.wantParsed && got.Time.Format(time.RFC3339) != tt.wantUTC {
				t.Errorf("Time = %v, want %v", got.Time.Format(time.RFC3339), tt.wantUTC)
			}
		})
	}
}

func TestParseDate_TortureFormats(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantParsed bool
		wantUTC    string // RFC3339, only checked if wantParsed
	}{
		{
			name:       "dash-month with time, no zone",
			input:      "14-Aug-1995 04:00:00",
			wantParsed: true,
			wantUTC:    "1995-08-14T04:00:00Z",
		},
		{
			name:       "RFC1123-ish with GMT abbreviation",
			input:      "Mon, 14 Aug 1995 04:00:00 GMT",
			wantParsed: true,
			wantUTC:    "1995-08-14T04:00:00Z",
		},
		{
			name:       "RFC1123-ish with UTC abbreviation",
			input:      "Mon, 14 Aug 1995 04:00:00 UTC",
			wantParsed: true,
			wantUTC:    "1995-08-14T04:00:00Z",
		},
		{
			name:       "RFC1123-ish with an ambiguous US zone abbreviation stays unparsed",
			input:      "Mon, 14 Aug 1995 04:00:00 PST",
			wantParsed: false,
		},
		{
			name:       "RFC1123-ish with another ambiguous US zone abbreviation stays unparsed",
			input:      "Mon, 14 Aug 1995 04:00:00 EST",
			wantParsed: false,
		},
		{
			name:       "fractional seconds, already covered by RFC3339Nano",
			input:      "2026-08-13T04:00:00.500Z",
			wantParsed: true,
			wantUTC:    "2026-08-13T04:00:00.5Z",
		},
		{
			name:       "day-first DD.MM.YYYY is parsed under that assumption, not disambiguated",
			input:      "12.07.2026",
			wantParsed: true,
			wantUTC:    "2026-07-12T00:00:00Z",
		},
		{
			name:       "genuinely unrecognized format stays unparsed with Raw preserved",
			input:      "sometime next week",
			wantParsed: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := ParseDate(tt.input)
			if d.Raw != tt.input {
				t.Errorf("Raw = %q, want %q (input preserved verbatim, trimmed)", d.Raw, tt.input)
			}
			if d.Parsed != tt.wantParsed {
				t.Fatalf("Parsed = %v, want %v (Time = %v)", d.Parsed, tt.wantParsed, d.Time)
			}
			if tt.wantParsed && d.Time.UTC().Format(time.RFC3339Nano) != tt.wantUTC {
				gotFormatted := d.Time.UTC().Format(time.RFC3339)
				if gotFormatted != tt.wantUTC {
					t.Errorf("Time.UTC() = %s, want %s", d.Time.UTC().Format(time.RFC3339), tt.wantUTC)
				}
			}
		})
	}
}
