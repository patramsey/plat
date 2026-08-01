// Package human renders a merged domain record as a styled, colorized
// view for interactive terminals — the FormatHuman counterpart to
// internal/render/plain's unstyled FormatPlain. Output goes through
// lipgloss.Fprint, which downsamples/strips ANSI automatically based on
// the destination writer and the process environment (NO_COLOR,
// CLICOLOR_FORCE, COLORTERM) — this package never hand-checks those
// itself.
package human

import (
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/charmbracelet/x/ansi"

	"github.com/patramsey/plat/internal/model"
)

// labelWidth is the fixed left-column width every field row's label is
// padded to. Values wrap at whatever width remains.
const labelWidth = 20

// defaultWidth is used when Options.Width is unset (<=0) — e.g. when the
// destination isn't a real terminal and no width could be detected.
const defaultWidth = 80

// boxOverhead is how many columns the record box's rounded border plus
// Padding(0, 1) adds beyond its content: 1 border rune + 1 padding space
// on each side.
const boxOverhead = 4

// minInnerWidth floors how narrow the box's usable content width can go,
// mirroring the floor writeStyledRow already applies to a single value
// column, so a very narrow terminal degrades gracefully instead of
// wrapping every value to almost nothing.
const minInnerWidth = 20

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

// Options controls Render's appearance and verbosity.
type Options struct {
	Theme Theme
	// Width is the target terminal width for value wrapping. <=0 falls
	// back to defaultWidth.
	Width int
	// Verbose includes the per-source diagnostic block (latency and
	// ok/not-found/error status for every source attempted). Without it,
	// Render shows the merged field values plus any Conflicts/Redacted
	// notices — genuine disagreements between sources stay visible either
	// way, since they're meaningful regardless of verbosity; the
	// per-source latency/status dump is the part that's mostly useful for
	// debugging, not everyday lookups.
	Verbose bool
	// ShowConflicts prints the full Conflicts block (every disagreeing
	// source's raw value, per field). Without it, a conflicted field still
	// gets a small ⚠ marker next to its badge -- so a conflict is never
	// invisible -- but the raw per-source breakdown is opt-in: a domain
	// with several noisy timestamp/nameserver disagreements otherwise
	// dominates the box with detail most lookups don't need.
	ShowConflicts bool
}

// Render writes a styled, colorized view of r to w: a "plat · domain"
// title above a bordered box containing the field table. The at-a-glance
// summary line (lock status, expiry, conflict count) lives INSIDE the
// box as its first section, not floating above it with the title — it's
// data about the domain, like Conflicts/Redacted/Sources below it, not a
// heading, so it belongs with the rest of the content it's summarizing.
// Field ordering and coverage inside the box matches
// internal/render/plain.Render exactly (this package styles, it does not
// add or remove fields): Domain, Handle, Registrar
// (Name/IANAID/URL/AbuseEmail/AbusePhone), Status, Created, Updated,
// Expires, Nameservers, DNSSEC, then Conflicts/Redacted always, and
// Sources only when opts.Verbose.
func Render(w io.Writer, r model.Record, opts Options) error {
	width := opts.Width
	if width <= 0 {
		width = defaultWidth
	}
	th := opts.Theme

	innerWidth := width - boxOverhead
	if innerWidth < minInnerWidth {
		innerWidth = minInnerWidth
	}

	var header strings.Builder
	if r.Domain.Present() {
		header.WriteString(th.Header.Render("plat · " + r.Domain.Value))
	}

	var b strings.Builder
	if summary := buildSummary(th, r); summary != "" {
		b.WriteString(summary + "\n\n")
	}
	writeStringField(&b, th, innerWidth, "Domain", r.Domain, th.Identity, hasConflict(r.Conflicts, model.FieldDomain))
	writeStringField(&b, th, innerWidth, "Handle", r.Handle, th.Value, hasConflict(r.Conflicts, model.FieldHandle))
	writeStringField(&b, th, innerWidth, "Registrar", r.Registrar.Name, th.Identity, hasConflict(r.Conflicts, model.FieldRegistrarName))
	writeStringField(&b, th, innerWidth, "Registrar IANA ID", r.Registrar.IANAID, th.Value, hasConflict(r.Conflicts, model.FieldRegistrarIANAID))
	writeURLField(&b, th, innerWidth, "Registrar URL", r.Registrar.URL, hasConflict(r.Conflicts, model.FieldRegistrarURL))
	writeStringField(&b, th, innerWidth, "Abuse Email", r.Registrar.AbuseEmail, th.Value, hasConflict(r.Conflicts, model.FieldRegistrarAbuseEmail))
	writeStringField(&b, th, innerWidth, "Abuse Phone", r.Registrar.AbusePhone, th.Value, hasConflict(r.Conflicts, model.FieldRegistrarAbusePhone))
	writeStatusField(&b, th, innerWidth, "Status", r.Status)
	writeTimeField(&b, th, innerWidth, "Created", r.Created, th.Value, hasConflict(r.Conflicts, model.FieldCreated))
	writeTimeField(&b, th, innerWidth, "Updated", r.Updated, th.Value, hasConflict(r.Conflicts, model.FieldUpdated))
	writeTimeField(&b, th, innerWidth, "Expires", r.Expires, expiryStyle(th, r.Expires.Value), hasConflict(r.Conflicts, model.FieldExpires))
	writeListField(&b, th, innerWidth, "Nameservers", r.Nameservers, hasConflict(r.Conflicts, model.FieldNameservers))
	writeBoolField(&b, th, innerWidth, "DNSSEC", r.DNSSEC, hasConflict(r.Conflicts, model.FieldDNSSEC))
	writeSourceLegend(&b, th, innerWidth)

	if opts.Verbose {
		writeSources(&b, th, innerWidth, r.Sources)
	}
	if opts.ShowConflicts {
		writeConflicts(&b, th, innerWidth, r.Conflicts)
	} else {
		writeConflictsHint(&b, th, r.Conflicts)
	}
	writeRedacted(&b, th, innerWidth, r.Redacted)

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderStyle(th, r.Status.Value).GetForeground()).
		Padding(0, 1).
		Render(strings.TrimRight(b.String(), "\n"))

	out := box + "\n"
	if header.Len() > 0 {
		out = header.String() + "\n\n" + out
	}

	_, err := lipgloss.Fprint(w, out)
	return err
}

// buildSummary composes the at-a-glance line under the title: a lock
// badge (if r.Status carries a recognized status), an expiry countdown
// (if r.Expires parsed), and a conflict count (only when there is at
// least one) — joined with a muted separator. Returns "" when none of
// the three have anything to say, so Render can skip the line entirely
// rather than print an empty one.
// QuietSummary composes the one-line, unstyled description --quiet
// prints instead of the full boxed/field-listing view: the same lock
// status, expiry countdown, and conflict count buildSummary's styled
// line shows, but as plain text with no ANSI codes regardless of output
// format (human or plain) -- quick to read and safe to pipe into other
// tools. Returns "" when none of the three have anything to say, same
// as buildSummary.
func QuietSummary(r model.Record) string {
	var parts []string
	switch domainVerdict(r.Status.Value) {
	case verdictCrit:
		parts = append(parts, "at risk")
	case verdictGood:
		parts = append(parts, "locked")
	}
	if r.Expires.Present() && r.Expires.Value.Parsed {
		days := int(time.Until(r.Expires.Value.Time).Hours() / 24)
		if days < 0 {
			parts = append(parts, fmt.Sprintf("expired %d days ago", -days))
		} else {
			parts = append(parts, fmt.Sprintf("expires in %d days", days))
		}
	}
	if n := len(r.Conflicts); n > 0 {
		word := "conflict"
		if n > 1 {
			word = "conflicts"
		}
		parts = append(parts, fmt.Sprintf("%d %s", n, word))
	}
	return strings.Join(parts, " · ")
}

func buildSummary(th Theme, r model.Record) string {
	var parts []string
	if lock := lockBadge(th, r.Status.Value); lock != "" {
		parts = append(parts, lock)
	}
	if expiry := expirySummary(th, r.Expires); expiry != "" {
		parts = append(parts, expiry)
	}
	if n := len(r.Conflicts); n > 0 {
		word := "conflict"
		if n > 1 {
			word = "conflicts"
		}
		parts = append(parts, th.Warn.Render(fmt.Sprintf("⚠ %d %s", n, word)))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, th.Muted.Render(" · "))
}

// verdict is the overall good/critical/neutral read on a domain's status
// set, shared by the summary line's lock badge and the record box's
// border color so the two always agree with each other.
type verdict int

const (
	verdictNeutral verdict = iota
	verdictGood
	verdictCrit
)

// domainVerdict classifies statuses into a verdict: verdictCrit wins over
// verdictGood when both a statusCrit and a statusGood code are present,
// since a hold/pending-delete matters more than a transfer-lock in the
// same set. verdictNeutral means nothing in statuses was recognized,
// rather than asserting either way about an unfamiliar status
// vocabulary.
func domainVerdict(statuses []string) verdict {
	hasGood, hasCrit := false, false
	for _, s := range statuses {
		if statusGood[s] {
			hasGood = true
		}
		if statusCrit[s] {
			hasCrit = true
		}
	}
	switch {
	case hasCrit:
		return verdictCrit
	case hasGood:
		return verdictGood
	default:
		return verdictNeutral
	}
}

// lockBadge renders domainVerdict(statuses) as the summary line's badge.
// Returns "" for verdictNeutral, so buildSummary can skip it entirely.
func lockBadge(th Theme, statuses []string) string {
	switch domainVerdict(statuses) {
	case verdictCrit:
		return th.Err.Render("⚠ at risk")
	case verdictGood:
		return th.OK.Render("🔒 locked")
	default:
		return ""
	}
}

// borderStyle picks the record box's border color from the same verdict
// as lockBadge, so an at-risk domain gets a red box and a locked one a
// green box at a glance, before the reader even reaches the summary
// line's text. verdictNeutral keeps the border a plain, unopinionated
// muted color.
func borderStyle(th Theme, statuses []string) lipgloss.Style {
	switch domainVerdict(statuses) {
	case verdictCrit:
		return th.Err
	case verdictGood:
		return th.OK
	default:
		return th.Muted
	}
}

// expirySummary renders a plain-language, ramp-colored countdown
// ("expires in 314 days" / "expired 12 days ago") matching the same
// green/yellow/red thresholds as the Expires field row itself. Returns
// "" when there's no parsed expiry to summarize.
func expirySummary(th Theme, f model.Field[model.TimeValue]) string {
	if !f.Present() || !f.Value.Parsed {
		return ""
	}
	style := expiryStyle(th, f.Value)
	days := int(time.Until(f.Value.Time).Hours() / 24)
	if days < 0 {
		return style.Render(fmt.Sprintf("expired %d days ago", -days))
	}
	return style.Render(fmt.Sprintf("expires in %d days", days))
}

// RenderSources writes just the styled per-source diagnostic block (latency
// and ok/not-found/error status for every source attempted) with no other
// record fields — used on the CLI's lookup-failure path, where -v should
// still show why every source was unusable even though there's no merged
// Record worth rendering in full. width bounds the table's columns the
// same way Render's own innerWidth does; <=0 falls back to defaultWidth.
func RenderSources(w io.Writer, th Theme, width int, sources []model.SourceResult) error {
	if width <= 0 {
		width = defaultWidth
	}
	var b strings.Builder
	writeSources(&b, th, width, sources)
	_, err := lipgloss.Fprint(w, b.String())
	return err
}

func writeStringField(b *strings.Builder, th Theme, width int, label string, f model.Field[string], style lipgloss.Style, conflicted bool) {
	if !f.Present() {
		return
	}
	writeStyledRow(b, th, width, label, f.Value, style, f.Sources, "", conflicted)
}

// writeURLField renders like writeStringField, but makes the value an
// OSC 8 hyperlink to itself — for Registrar URL, the one field that's
// actually meant to be visited, not just displayed.
func writeURLField(b *strings.Builder, th Theme, width int, label string, f model.Field[string], conflicted bool) {
	if !f.Present() {
		return
	}
	writeStyledRow(b, th, width, label, f.Value, th.Value, f.Sources, f.Value, conflicted)
}

func writeListField(b *strings.Builder, th Theme, width int, label string, f model.Field[[]string], conflicted bool) {
	// Deliberately not f.Present(): a genuine merge conflict (see
	// internal/merge's nameservers()) can leave Sources empty while Value
	// stays populated with the merged union -- the row must still print,
	// just with no per-source badge (conflictBadge already handles that).
	if len(f.Value) == 0 {
		return
	}
	writeStyledListRow(b, th, width, label, f.Value, f.Sources, conflicted)
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

func writeStatusField(b *strings.Builder, th Theme, width int, label string, f model.Field[[]string]) {
	if !f.Present() {
		return
	}
	styled := make([]string, len(f.Value))
	for i, s := range f.Value {
		styled[i] = statusStyle(th, s).Render(s)
	}
	// Status never conflicts -- differing sets are unioned, never flagged
	// (see status()'s own doc comment) -- so this row never needs a
	// conflict marker.
	writeStyledListRow(b, th, width, label, styled, f.Sources, false)
}

func writeBoolField(b *strings.Builder, th Theme, width int, label string, f model.Field[bool], conflicted bool) {
	if !f.Present() {
		return
	}
	val, style := "false ✗", th.Muted
	if f.Value {
		val, style = "true ✓", th.OK
	}
	writeStyledRow(b, th, width, label, val, style, f.Sources, "", conflicted)
}

func writeTimeField(b *strings.Builder, th Theme, width int, label string, f model.Field[model.TimeValue], style lipgloss.Style, conflicted bool) {
	if !f.Present() {
		return
	}
	if f.Value.Parsed {
		writeStyledRow(b, th, width, label, f.Value.Time.UTC().Format(time.RFC3339), style, f.Sources, "", conflicted)
		return
	}
	writeStyledRow(b, th, width, label, f.Value.Raw+" (unparsed)", th.Muted, f.Sources, "", conflicted)
}

// conflictBadge builds the trailing "(sources) ⚠" badge text shared by
// writeStyledRow and writeStyledListRow. The ⚠ marker prints whenever
// conflicted is true, even if sources is empty -- a genuine multi-way fork
// (e.g. nameservers where no single source's set matches the merged union)
// can leave a field with zero agreeing sources, and that's still worth
// flagging. Full per-source conflicting values only ever appear in the
// Conflicts block, gated by Options.ShowConflicts -- this badge is just a
// pointer to "look closer", not the detail itself.
func conflictBadge(th Theme, sources []model.SourceID, conflicted bool) string {
	badge := ""
	if len(sources) > 0 {
		badge = " " + th.SourceBadge.Render("("+formatSources(sources)+")")
	}
	if conflicted {
		badge += " " + th.Warn.Render("⚠")
	}
	return badge
}

// writeStyledRow lays out one "Label: value (sources)" row: a fixed-width
// styled label column, a wrapped+styled value column, and a trailing
// muted source-provenance badge on the row's last line only. The value
// column's wrap width reserves room for the badge on every line (even
// though the badge itself only appears on the last one) so the row as a
// whole — label, value, and badge together — never exceeds width; this
// matters now that Render places rows inside a bordered box sized to fit
// exactly width columns.
//
// hyperlinkURL, if non-empty, wraps the value in an OSC 8 hyperlink —
// but only when it fits on a single wrapped line. OSC 8's open/close
// markers have to stay on the same line as each other; applying them to
// a value that's about to line-wrap would silently split them across
// lines, so a wrapping value falls back to plain (still fully readable)
// text instead. lipgloss.Fprint already strips OSC 8 for pipes/no-color
// output the same way it strips color (confirmed empirically), so this
// never affects the plain-text/pipe-safety guarantee.
func writeStyledRow(b *strings.Builder, th Theme, width int, label, value string, valueStyle lipgloss.Style, sources []model.SourceID, hyperlinkURL string, conflicted bool) {
	labelCol := th.Label.Render(fmt.Sprintf("%-*s", labelWidth, label+":"))
	badge := conflictBadge(th, sources, conflicted)
	badgeWidth := lipgloss.Width(badge)

	// valueWidth deliberately does NOT reserve room for the badge: doing
	// so squeezed even short, unwrappable values (a 20-column date) down
	// to the 10-column floor whenever a row cited 3+ sources, wrapping
	// them character-by-character for no reason — writeBadge already
	// moves the badge to its own line whenever it doesn't fit next to
	// the actual (not artificially shrunk) last line, so reserving space
	// for it here just doubly penalizes the common case where that's
	// exactly what happens anyway.
	valueWidth := width - labelWidth
	if valueWidth < 10 {
		valueWidth = 10
	}
	lines := wrapValue(value, valueWidth)
	for i, line := range lines {
		if i == 0 {
			b.WriteString(labelCol)
		} else {
			b.WriteString(strings.Repeat(" ", labelWidth))
		}
		rendered := valueStyle.Render(line)
		if hyperlinkURL != "" && len(lines) == 1 {
			rendered = ansi.SetHyperlink(hyperlinkURL) + rendered + ansi.ResetHyperlink()
		}
		b.WriteString(rendered)
		if i == len(lines)-1 {
			writeBadge(b, line, badge, width, labelWidth, badgeWidth)
		}
		b.WriteString("\n")
	}
}

// writeBadge appends badge to b right after lastLine if label/indent +
// lastLine + badge together fit within width; otherwise badge moves to
// its own line, indented to the value column. Without this, a badge
// that alone doesn't fit — common once a row cites 3+ sources, ~50
// visible columns — would get unconditionally appended to whatever the
// last wrapped line is, including an unbreakable long token (a status
// code, a URL) that already exceeds its own share of the width budget,
// blowing far past the target width on that one line instead of
// degrading gracefully like every other wrap decision in this file.
func writeBadge(b *strings.Builder, lastLine, badge string, width, labelWidth, badgeWidth int) {
	if badge == "" {
		return
	}
	if lipgloss.Width(lastLine)+labelWidth+badgeWidth <= width {
		b.WriteString(badge)
		return
	}
	// The badge doesn't fit next to the content, so it gets its own
	// line(s) — plural, because a 4-source badge ("registrar-rdap,
	// registry-rdap, registrar-whois, registry-whois") is itself wide
	// enough to need wrapping at narrower widths, and it must degrade
	// the same way everything else in this file does rather than
	// overflow just because it's "only" a badge.
	ownLineWidth := width - labelWidth
	if ownLineWidth < 10 {
		ownLineWidth = 10
	}
	for _, bl := range wrapValue(strings.TrimPrefix(badge, " "), ownLineWidth) {
		b.WriteString("\n" + strings.Repeat(" ", labelWidth) + bl)
	}
}

// wrapValue wraps s to fit within width columns using lipgloss's own
// word-boundary wrapping. lipgloss.Style.Width right-pads every wrapped
// line to exactly width runes (confirmed locally) — each returned line
// has that trailing padding trimmed, since callers do their own layout.
func wrapValue(s string, width int) []string {
	wrapped := lipgloss.NewStyle().Width(width).Render(s)
	rawLines := strings.Split(wrapped, "\n")
	lines := make([]string, len(rawLines))
	for i, l := range rawLines {
		lines[i] = strings.TrimRight(l, " ")
	}
	return lines
}

// writeStyledListRow lays out one "Label: item · item · item (sources)"
// row like writeStyledRow, but wraps by whole item via wrapItems instead
// of generic word-wrapping — see wrapItems for why.
func writeStyledListRow(b *strings.Builder, th Theme, width int, label string, items []string, sources []model.SourceID, conflicted bool) {
	labelCol := th.Label.Render(fmt.Sprintf("%-*s", labelWidth, label+":"))
	badge := conflictBadge(th, sources, conflicted)
	badgeWidth := lipgloss.Width(badge)

	// See writeStyledRow's matching comment: valueWidth deliberately does
	// not reserve room for the badge, since writeBadge already moves it
	// to its own line whenever it doesn't fit next to the actual last
	// line.
	valueWidth := width - labelWidth
	if valueWidth < 10 {
		valueWidth = 10
	}
	// wrapItems only breaks *between* items — a single item wider than
	// valueWidth (a long nameserver or status code) still comes back as
	// its own over-wide line, which would blow the box border out past
	// width since it has no fixed .Width() of its own. A second wrapValue
	// pass over any still-too-wide line catches that, same as
	// writeWrappedEntry already does for the Conflicts block.
	var lines []string
	for _, line := range wrapItems(items, valueWidth, " · ") {
		if lipgloss.Width(line) > valueWidth {
			lines = append(lines, wrapValue(line, valueWidth)...)
		} else {
			lines = append(lines, line)
		}
	}
	for i, line := range lines {
		if i == 0 {
			b.WriteString(labelCol)
		} else {
			b.WriteString(strings.Repeat(" ", labelWidth))
		}
		b.WriteString(line)
		if i == len(lines)-1 {
			writeBadge(b, line, badge, width, labelWidth, badgeWidth)
		}
		b.WriteString("\n")
	}
}

// wrapItems greedily packs items — each already styled with its own ANSI
// codes if the caller applies any, e.g. writeStatusField's per-status
// colors — into lines joined by sep, measuring visible width via
// lipgloss.Width (ANSI-aware) rather than rune count. Unlike wrapValue's
// generic word-wrap, which treats sep as its own breakable word and can
// leave one alone at the start of a wrapped line, this only ever breaks
// between items, so a wrapped line always starts with a real item.
func wrapItems(items []string, width int, sep string) []string {
	if len(items) == 0 {
		return []string{""}
	}
	lines := make([]string, 0, 1)
	cur := items[0]
	for _, item := range items[1:] {
		candidate := cur + sep + item
		if lipgloss.Width(candidate) > width {
			lines = append(lines, cur)
			cur = item
			continue
		}
		cur = candidate
	}
	return append(lines, cur)
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

// writeSourceLegend prints the key decoding sourceCode's abbreviations --
// unconditionally, not gated by --verbose or --conflicts, since the codes
// it explains appear in the DEFAULT view; hiding the legend by default
// would make the default output undecodable, not just less detailed. The
// legend text itself is ~77 columns, wide enough to need the same
// wrap-safety every other line in this file gets rather than assuming it
// always fits.
func writeSourceLegend(b *strings.Builder, th Theme, width int) {
	const legend = "RR registrar-rdap   GR registry-rdap   RW registrar-whois   GW registry-whois"
	b.WriteString("\n")
	for _, line := range wrapValue(legend, width) {
		b.WriteString(th.Muted.Render(line) + "\n")
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

// writeSources renders the per-source diagnostic block as a borderless,
// column-aligned table (Source / Latency / Status). A table.Table replaces
// what used to be a hand-formatted "%-20s %s  %s" line: that format only
// padded the Source column, so Status drifted out of alignment whenever
// latency strings differed in length (e.g. "85ms" vs "5s"); the table
// computes every column's width from its actual (ANSI-aware) content, so
// all three stay aligned regardless of content length.
func writeSources(b *strings.Builder, th Theme, width int, sources []model.SourceResult) {
	if len(sources) == 0 {
		return
	}
	b.WriteString("\n" + th.Label.Render("Sources") + "\n")

	newSourcesTable := func() *table.Table {
		t := table.New().
			BorderTop(false).BorderBottom(false).
			BorderLeft(false).BorderRight(false).
			BorderColumn(false).BorderRow(false).BorderHeader(false).
			StyleFunc(func(_, col int) lipgloss.Style {
				if col < 2 {
					return lipgloss.NewStyle().PaddingRight(2)
				}
				return lipgloss.NewStyle()
			})
		for _, s := range sources {
			status := th.Muted.Render("no data")
			switch {
			case s.OK:
				status = th.OK.Render("✓ ok")
			case s.NotFound:
				status = th.Warn.Render("– not found")
			case s.Err != "":
				status = th.Err.Render("✗ " + s.Err)
			}
			t.Row(string(s.Source), s.Latency.Round(time.Millisecond).String(), status)
		}
		return t
	}

	// table.Width() both expands AND contracts columns to fill exactly
	// that width, so setting it unconditionally would stretch a short
	// table (the common case: short source names, short latencies) out
	// to the box's full width with ugly gaps. Render unconstrained first
	// and only fall back to a width-constrained re-render — needed when a
	// source's error message is long enough to threaten the box's border
	// — if that natural rendering would actually overflow.
	rendered := newSourcesTable().Render()
	if avail := width - 2; widestLine(rendered) > avail { // 2-col indent below
		rendered = newSourcesTable().Width(avail).Render()
	}

	for line := range strings.SplitSeq(rendered, "\n") {
		b.WriteString("  " + line + "\n")
	}
}

// widestLine returns the visible (ANSI-aware) width of s's widest line.
func widestLine(s string) int {
	widest := 0
	for line := range strings.SplitSeq(s, "\n") {
		if w := lipgloss.Width(line); w > widest {
			widest = w
		}
	}
	return widest
}

// writeConflicts renders each conflict as "  field: src=value, src=value,
// ...", wrapped to width the same item-aware way Status/Nameservers are
// (wrapItems, never breaking mid-value or leaving a bare "," starting a
// line) — this line was previously printed with NO width awareness at
// all, so a conflict citing several long values (e.g. three differently-
// formatted timestamps) could stretch the auto-sizing box's effective
// width far past its target, dragging every other, correctly-wrapped
// line in the box along with it into real terminal-side line wrapping.
func writeConflicts(b *strings.Builder, th Theme, width int, conflicts []model.Conflict) {
	if len(conflicts) == 0 {
		return
	}
	b.WriteString("\n" + th.Warn.Render("Conflicts") + "\n")
	for _, c := range conflicts {
		label := fmt.Sprintf("%s: ", c.Field)
		writeWrappedEntry(b, label, conflictValueParts(th, c.Values), width)
	}
}

// hasConflict reports whether field appears in conflicts — used to decide
// whether a field's row gets the ⚠ marker from conflictBadge.
func hasConflict(conflicts []model.Conflict, field string) bool {
	for _, c := range conflicts {
		if c.Field == field {
			return true
		}
	}
	return false
}

// writeConflictsHint prints a single muted line pointing at --conflicts
// when conflicts exist but Options.ShowConflicts is off — otherwise a
// conflict is only visible via the top summary's count and each field's ⚠
// marker, with no indication anywhere that a flag exists to see the actual
// disagreeing values.
func writeConflictsHint(b *strings.Builder, th Theme, conflicts []model.Conflict) {
	if len(conflicts) == 0 {
		return
	}
	noun := "conflict"
	if len(conflicts) != 1 {
		noun = "conflicts"
	}
	b.WriteString("\n" + th.Muted.Render(fmt.Sprintf("%d %s hidden — pass --conflicts to see details", len(conflicts), noun)) + "\n")
}

// writeRedacted renders each redaction notice wrapped to width the same
// way writeConflicts does, for the same reason — even though a single
// "source (reason)" value rarely needs it in practice, it must degrade
// the same way everything else in this file does rather than assume it
// never will.
func writeRedacted(b *strings.Builder, th Theme, width int, redacted []model.RedactionNotice) {
	if len(redacted) == 0 {
		return
	}
	b.WriteString("\n" + th.Muted.Render("Redacted") + "\n")
	for _, red := range redacted {
		label := fmt.Sprintf("%s: ", red.Field)
		value := fmt.Sprintf("%s (%s)", red.Source, red.Reason)
		// Word-wrap via wrapValue, not writeWrappedEntry/wrapItems: the
		// reason is free-form prose ("redacted for privacy per
		// applicable data protection law"), not a list of discrete
		// items to join with a separator. Passing it to wrapItems as a
		// single one-element "item" never wrapped it at all, since
		// wrapItems only ever breaks BETWEEN items -- with just one,
		// there's nothing to break between, so an unbounded line
		// through here was the actual bug behind two of the reports
		// this session, not the same accepted "unbreakable token"
		// trade-off as e.g. a single long URL.
		indent := 2 + len([]rune(label))
		valueWidth := width - indent
		if valueWidth < 10 {
			valueWidth = 10
		}
		for i, line := range wrapValue(value, valueWidth) {
			if i == 0 {
				fmt.Fprintf(b, "  %s%s\n", label, line)
			} else {
				fmt.Fprintf(b, "%s%s\n", strings.Repeat(" ", indent), line)
			}
		}
	}
}

// writeWrappedEntry writes "  label" + parts wrapped by whole item
// (wrapItems, joined with ", ") to fit within width, indenting
// continuation lines under where the value starts. A single item can
// itself exceed width — e.g. one conflict source's whole
// "registrar-whois=ns1, ns2, ns3, ns4" entry, which wrapItems treats as
// one opaque unbreakable unit — so any resulting line still wider than
// valueWidth gets a secondary word-wrap pass via wrapValue, the same
// fallback writeRedacted uses for its own single-item case. Without
// this, a multi-nameserver conflict line stretches the whole box to its
// width regardless of the target, since the box auto-sizes to its
// widest rendered line.
func writeWrappedEntry(b *strings.Builder, label string, parts []string, width int) {
	indent := 2 + len([]rune(label))
	valueWidth := width - indent
	if valueWidth < 10 {
		valueWidth = 10
	}
	var lines []string
	for _, line := range wrapItems(parts, valueWidth, ", ") {
		if lipgloss.Width(line) > valueWidth {
			lines = append(lines, wrapValue(line, valueWidth)...)
		} else {
			lines = append(lines, line)
		}
	}
	for i, line := range lines {
		if i == 0 {
			fmt.Fprintf(b, "  %s%s\n", label, line)
		} else {
			fmt.Fprintf(b, "%s%s\n", strings.Repeat(" ", indent), line)
		}
	}
}

// conflictValueParts renders a Conflict's map as "src=value" strings in
// model.Precedence order — Go map iteration order is randomized, and
// ranging over the map directly would make output (and any test
// asserting on it) flaky. Each value has its differing segment (relative
// to the group's shared prefix and suffix) highlighted, so the reader
// can spot what actually changed (e.g. one digit of a timestamp) instead
// of reading the full strings side by side.
func conflictValueParts(th Theme, values map[model.SourceID]string) []string {
	ordered := make([]string, 0, len(values))
	for _, src := range model.Precedence {
		if v, ok := values[src]; ok {
			ordered = append(ordered, v)
		}
	}
	prefix, suffix := commonAffixLen(ordered)

	var parts []string
	for _, src := range model.Precedence {
		if v, ok := values[src]; ok {
			parts = append(parts, fmt.Sprintf("%s=%s", sourceCode(src), highlightDiff(th, v, prefix, suffix)))
		}
	}
	return parts
}

// commonAffixLen returns the length (in runes) of the longest prefix and,
// separately, longest suffix shared by every string in vals. The two
// never overlap: suffix search stops once it would eat into the prefix
// already found, so a short value like "ok" shared with "ok-2" reports
// prefix=2, suffix=0 rather than double-counting the "ok".
//
// Matching is case-insensitive, mirroring internal/merge's
// normalizeScalar: a conflict like "Markmonitor Inc." vs "MarkMonitor,
// Inc." is genuinely different (the comma), but a case-sensitive affix
// match would stop at the incidental "m"/"M" difference four characters
// in and highlight nearly the whole value as "different" — comparing
// case-insensitively while still measuring/returning lengths against the
// ORIGINAL strings finds the real (much shorter) point of difference
// without altering what gets displayed.
func commonAffixLen(vals []string) (prefix, suffix int) {
	if len(vals) < 2 {
		return 0, 0
	}
	runes := make([][]rune, len(vals))
	minLen := -1
	for i, v := range vals {
		runes[i] = []rune(v)
		if minLen == -1 || len(runes[i]) < minLen {
			minLen = len(runes[i])
		}
	}
	for prefix < minLen {
		c := unicode.ToLower(runes[0][prefix])
		match := true
		for _, r := range runes[1:] {
			if unicode.ToLower(r[prefix]) != c {
				match = false
				break
			}
		}
		if !match {
			break
		}
		prefix++
	}
	for suffix < minLen-prefix {
		c := unicode.ToLower(runes[0][len(runes[0])-1-suffix])
		match := true
		for _, r := range runes[1:] {
			if unicode.ToLower(r[len(r)-1-suffix]) != c {
				match = false
				break
			}
		}
		if !match {
			break
		}
		suffix++
	}
	return prefix, suffix
}

// highlightDiff wraps the middle of v — the part after the shared prefix
// and before the shared suffix — in th.Warn, leaving the shared parts
// unstyled. If v is too short to have a distinct middle (its length
// differs enough from the group that prefix+suffix would overlap), v is
// returned unstyled rather than highlighting something misleading.
func highlightDiff(th Theme, v string, prefix, suffix int) string {
	r := []rune(v)
	if prefix+suffix >= len(r) {
		return v
	}
	head := string(r[:prefix])
	mid := string(r[prefix : len(r)-suffix])
	tail := string(r[len(r)-suffix:])
	return head + th.Warn.Render(mid) + tail
}
