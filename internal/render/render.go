// Package render selects which output format cmd/plat uses for a lookup
// and detects whether stdout is an interactive terminal. It does not
// import internal/render/plain, internal/render/human, or
// internal/render/machine itself — the caller (cmd/plat) dispatches to
// the right one based on the Format this package returns, keeping this
// leaf package free of all three renderers' dependencies.
package render

import (
	"fmt"
	"os"
	"strings"
)

// Format selects which renderer cmd/plat dispatches to: FormatHuman to
// internal/render/human's styled output, FormatPlain to
// internal/render/plain's unstyled output, FormatJSON/FormatNDJSON to
// internal/render/machine's encoder.
type Format int

const (
	FormatHuman Format = iota
	FormatPlain
	FormatJSON
	FormatNDJSON
)

// ParseFormat validates the -o/--output flag's value.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "human":
		return FormatHuman, nil
	case "plain":
		return FormatPlain, nil
	case "json":
		return FormatJSON, nil
	case "ndjson":
		return FormatNDJSON, nil
	default:
		return 0, fmt.Errorf("invalid output format %q: must be one of human, plain, json, ndjson", s)
	}
}

// IsTerminal reports whether f is connected to an interactive terminal.
func IsTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// Select resolves the format to use: an explicit -o value always wins
// (including "human" even under NO_COLOR or a non-terminal destination —
// lipgloss.Fprint's own downsampling strips ANSI in that case, this
// function never second-guesses an explicit choice). With no explicit
// value, a TTY with no NO_COLOR gets Human; anything else (a pipe, or
// NO_COLOR set) gets Plain.
func Select(explicit string, isTTY bool, noColor bool) (Format, error) {
	if explicit != "" {
		return ParseFormat(explicit)
	}
	if isTTY && !noColor {
		return FormatHuman, nil
	}
	return FormatPlain, nil
}

// IsMachine reports whether f is one of the JSON/NDJSON machine formats.
func IsMachine(f Format) bool {
	return f == FormatJSON || f == FormatNDJSON
}
