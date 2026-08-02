package human

import (
	"strings"
	"time"

	"charm.land/lipgloss/v2"

	"github.com/patramsey/plat/internal/model"
)

// Theme holds every style the human renderer uses, resolved once at
// construction via lipgloss.LightDark so call sites never re-branch on
// dark/light per field.
type Theme struct {
	Header      lipgloss.Style // "plat · example.com" title line
	Label       lipgloss.Style // field labels ("Domain:", "Registrar:", ...)
	Value       lipgloss.Style // default field value styling
	Identity    lipgloss.Style // the Domain and Registrar values — the two "headline" fields
	SourceBadge lipgloss.Style // trailing "(registry-rdap, registrar-whois)" hint
	Muted       lipgloss.Style // unparsed dates, redaction notices
	OK          lipgloss.Style // ✓ / DNSSEC signed / source succeeded / protective status codes
	Err         lipgloss.Style // ✗ / source hard-failed / at-risk status codes
	Warn        lipgloss.Style // conflict header / source not-found / transitional status codes / diff highlight
	ExpiryOK    lipgloss.Style // expires more than 90 days out
	ExpiryWarn  lipgloss.Style // expires within 90 days
	ExpiryCrit  lipgloss.Style // expires within 30 days, or already expired
}

// NewTheme builds a Theme appropriate for the detected terminal
// background. isDark should come from lipgloss.HasDarkBackground.
func NewTheme(isDark bool) Theme {
	ld := lipgloss.LightDark(isDark)
	accent := ld(lipgloss.Color("#1D4ED8"), lipgloss.Color("#60A5FA"))
	label := ld(lipgloss.Color("#6B7280"), lipgloss.Color("#9CA3AF"))
	muted := ld(lipgloss.Color("#9CA3AF"), lipgloss.Color("#6B7280"))
	green := ld(lipgloss.Color("#15803D"), lipgloss.Color("#4ADE80"))
	yellow := ld(lipgloss.Color("#A16207"), lipgloss.Color("#FACC15"))
	red := ld(lipgloss.Color("#B91C1C"), lipgloss.Color("#F87171"))

	return Theme{
		Header:      lipgloss.NewStyle().Bold(true).Foreground(accent),
		Label:       lipgloss.NewStyle().Foreground(label),
		Value:       lipgloss.NewStyle(),
		Identity:    lipgloss.NewStyle().Foreground(accent),
		SourceBadge: lipgloss.NewStyle().Foreground(muted).Italic(true),
		Muted:       lipgloss.NewStyle().Foreground(muted),
		OK:          lipgloss.NewStyle().Foreground(green),
		Err:         lipgloss.NewStyle().Foreground(red),
		Warn:        lipgloss.NewStyle().Foreground(yellow),
		ExpiryOK:    lipgloss.NewStyle().Foreground(green),
		ExpiryWarn:  lipgloss.NewStyle().Foreground(yellow),
		ExpiryCrit:  lipgloss.NewStyle().Foreground(red).Bold(true),
	}
}

// statusGood are EPP status codes that mean the domain is locked down —
// reassuring, not alarming, so they get the same calm color as a
// successful check elsewhere in this renderer. Includes both the
// client/server-prefixed forms and the bare, unprefixed forms some
// registries report alongside them (e.g. GoDaddy's RDAP responses list
// both "transferProhibited" and "clientTransferProhibited" for the same
// domain) — bare forms aren't standard EPP, but they carry the same
// meaning wherever seen.
var statusGood = map[string]bool{
	"deleteProhibited":         true,
	"clientDeleteProhibited":   true,
	"serverDeleteProhibited":   true,
	"transferProhibited":       true,
	"clientTransferProhibited": true,
	"serverTransferProhibited": true,
	"updateProhibited":         true,
	"clientUpdateProhibited":   true,
	"serverUpdateProhibited":   true,
	"renewProhibited":          true,
	"clientRenewProhibited":    true,
	"serverRenewProhibited":    true,
}

// statusCrit are EPP status codes that mean something is actively wrong
// with the domain right now: DNS held/suspended, or mid-deletion.
var statusCrit = map[string]bool{
	"clientHold":       true,
	"serverHold":       true,
	"pendingDelete":    true,
	"redemptionPeriod": true,
	"inactive":         true,
}

// statusWarn are EPP status codes for a transitional or grace-period
// state — worth noticing, not alarming.
var statusWarn = map[string]bool{
	"pendingCreate":   true,
	"pendingRenew":    true,
	"pendingRestore":  true,
	"pendingTransfer": true,
	"pendingUpdate":   true,
	"addPeriod":       true,
	"autoRenewPeriod": true,
	"renewPeriod":     true,
	"transferPeriod":  true,
}

// statusStyle classifies an EPP status code (see internal/model.
// NormalizeEPPStatus) into a color: green for a protective/locked-down
// status, red for one meaning something is actively wrong, yellow for a
// transitional/grace-period state, and the default value style for
// anything not in any of those lists (e.g. plain "ok") rather than
// guessing at codes this table doesn't recognize.
func statusStyle(th Theme, status string) lipgloss.Style {
	switch {
	case statusGood[status]:
		return th.OK
	case statusCrit[status]:
		return th.Err
	case statusWarn[status]:
		return th.Warn
	default:
		return th.Value
	}
}

// expiryStyle picks the color-ramp style for an expiry date: green when
// comfortably far out, yellow inside 90 days, red inside 30 days or
// already expired. An unparsed value gets no ramp — writeTimeField
// already falls back to th.Muted for that case regardless of the style
// passed here.
func expiryStyle(th Theme, tv model.TimeValue) lipgloss.Style {
	if !tv.Parsed {
		return th.Muted
	}
	until := time.Until(tv.Time)
	switch {
	case until <= 30*24*time.Hour:
		return th.ExpiryCrit
	case until <= 90*24*time.Hour:
		return th.ExpiryWarn
	default:
		return th.ExpiryOK
	}
}

// sourceCode abbreviates a source ID to the fixed 2-letter code shown in
// field badges and Conflicts entries -- "registrar-rdap, registry-rdap,
// registry-whois" repeated on every field row of a well-agreed-upon
// record was the dominant source of line width (and the main reason
// rows needed wrapping at all). sourceLegend prints the one-line key
// these codes decode against; an unrecognized SourceID (shouldn't happen
// given the closed set in internal/model) falls back to the raw string
// rather than a blank code.
func sourceCode(s model.SourceID) string {
	switch s {
	case model.SourceRegistrarRDAP:
		return "RR"
	case model.SourceRegistryRDAP:
		return "GR"
	case model.SourceRegistrarWHOIS:
		return "RW"
	case model.SourceRegistryWHOIS:
		return "GW"
	default:
		return string(s)
	}
}

func formatSources(sources []model.SourceID) string {
	strs := make([]string, len(sources))
	for i, s := range sources {
		strs[i] = sourceCode(s)
	}
	return strings.Join(strs, ", ")
}
