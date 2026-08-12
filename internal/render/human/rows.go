package human

import (
	"fmt"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/patramsey/plat/internal/model"
)

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

// Legend text decoding sourceCode's abbreviations. Two variants, because
// which sources can exist depends on the object type: a domain is held by
// a registrar under a registry, so all four codes are reachable, while an
// IP allocation or an autonomous system is registered directly with an RIR
// and has no registrar at all. Listing RR/RW on an IP or ASN record
// explains badges that can never appear there, which reads as "plat failed
// to reach the registrar" rather than "no such source exists".
const (
	legendWithRegistrar = "RR registrar-rdap   GR registry-rdap   RW registrar-whois   GW registry-whois"
	legendRegistryOnly  = "GR registry-rdap   GW registry-whois"
)

// writeSourceLegend prints the key decoding sourceCode's abbreviations --
// unconditionally, not gated by --verbose or --conflicts, since the codes
// it explains appear in the DEFAULT view; hiding the legend by default
// would make the default output undecodable, not just less detailed. The
// widest legend is ~77 columns, wide enough to need the same wrap-safety
// every other line in this file gets rather than assuming it always fits.
//
// legend is the caller's choice of the two constants above: domain records
// pass legendWithRegistrar, IP and ASN records pass legendRegistryOnly.
func writeSourceLegend(b *strings.Builder, th Theme, width int, legend string) {
	b.WriteString("\n")
	for _, line := range wrapValue(legend, width) {
		b.WriteString(th.Muted.Render(line) + "\n")
	}
}
