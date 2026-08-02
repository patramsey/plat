package human

import (
	"fmt"
	"strings"
	"unicode"

	"charm.land/lipgloss/v2"

	"github.com/patramsey/plat/internal/model"
)

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
