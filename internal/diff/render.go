package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"charm.land/lipgloss/v2"

	"github.com/patramsey/plat/internal/render/human"
)

// DiffSchemaVersion versions the -o json diff output. It is deliberately
// independent of machine.SchemaVersion: the record schema and the diff
// schema change for different reasons, and tying them would force a bump
// of one whenever the other moved.
const DiffSchemaVersion = 1

type changeJSON struct {
	Key          string   `json:"key"`
	Label        string   `json:"label"`
	Kind         string   `json:"kind"`
	Before       string   `json:"before,omitempty"`
	After        string   `json:"after,omitempty"`
	AddedItems   []string `json:"addedItems,omitempty"`
	RemovedItems []string `json:"removedItems,omitempty"`
}

type diffJSON struct {
	DiffSchemaVersion int          `json:"diffSchemaVersion"`
	Name              string       `json:"name"`
	Changes           []changeJSON `json:"changes"`
}

// RenderJSON writes the machine-readable diff. changes==nil encodes as an
// empty array, never null.
func RenderJSON(w io.Writer, name string, changes []Change) error {
	out := diffJSON{
		DiffSchemaVersion: DiffSchemaVersion,
		Name:              name,
		Changes:           make([]changeJSON, 0, len(changes)),
	}
	for _, c := range changes {
		out.Changes = append(out.Changes, changeJSON{
			Key: c.Key, Label: c.Label, Kind: c.Kind.String(),
			Before: c.Before, After: c.After,
			AddedItems: c.AddedItems, RemovedItems: c.RemovedItems,
		})
	}
	enc := json.NewEncoder(w)
	return enc.Encode(out)
}

// describe renders one change's right-hand side, shared by the human and
// plain renderers so the two never drift in what they report.
func describe(c Change) string {
	switch c.Kind {
	case Added:
		if len(c.AddedItems) > 0 {
			return "+" + strings.Join(c.AddedItems, " +")
		}
		return "+" + c.After
	case Removed:
		if len(c.RemovedItems) > 0 {
			return "-" + strings.Join(c.RemovedItems, " -")
		}
		return "-" + c.Before
	case ListChanged:
		var parts []string
		for _, s := range c.RemovedItems {
			parts = append(parts, "-"+s)
		}
		for _, s := range c.AddedItems {
			parts = append(parts, "+"+s)
		}
		return strings.Join(parts, " ")
	default: // Changed
		return c.Before + " -> " + c.After
	}
}

// RenderPlain writes an unstyled diff with zero ANSI, for pipes and
// NO_COLOR.
func RenderPlain(w io.Writer, name string, changes []Change) error {
	if len(changes) == 0 {
		_, err := fmt.Fprintf(w, "%s: no changes\n", name)
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, name)
	for _, c := range changes {
		_, _ = fmt.Fprintf(tw, "  %s:\t%s\n", c.Label, describe(c))
	}
	_, _ = fmt.Fprintf(tw, "\n%d changed\n", len(changes))
	return tw.Flush()
}

// defaultWidth mirrors human.defaultWidth: used when the caller passes
// width<=0 for RenderHuman, e.g. when the destination isn't a real
// terminal and no width could be detected.
const defaultWidth = 80

// minWrapWidth floors how narrow a change line's value column can wrap
// to, mirroring human.minInnerWidth. Without a floor, a very narrow (or
// degenerate zero/negative) width would leave valueWidth at or below 1,
// and lipgloss.Style.Width wraps that as one character per line.
const minWrapWidth = 20

// RenderHuman writes the styled diff. It uses the same Theme the record
// renderers use so a diff looks like part of the same tool. width bounds
// each change line the same way every other multi-item line in
// internal/render/human does (see human.rows.go's writeStyledListRow and
// writeSourceLegend): without it, a ListChanged nameserver diff with
// several long hostnames would stretch the line arbitrarily wide
// regardless of the target terminal.
//
// Warn is the correct style for the changed value: theme.go documents it
// as "conflict header / source not-found / transitional status codes /
// diff highlight" -- the theme was written anticipating this.
func RenderHuman(w io.Writer, name string, changes []Change, th human.Theme, width int) error {
	if len(changes) == 0 {
		_, err := lipgloss.Fprintln(w, th.Muted.Render(name+": no changes"))
		return err
	}
	if width <= 0 {
		width = defaultWidth
	}
	var b strings.Builder
	b.WriteString(th.Header.Render(name) + "\n\n")
	for _, c := range changes {
		writeChangeLine(&b, th, width, c)
	}
	b.WriteString("\n" + th.Muted.Render(fmt.Sprintf("%d changed", len(changes))))
	_, err := lipgloss.Fprintln(w, b.String())
	return err
}

// writeChangeLine writes one "  Label: value" line, word-wrapping value
// to stay within width and indenting continuation lines under the value
// column so a wrapped entry still reads as one row.
func writeChangeLine(b *strings.Builder, th human.Theme, width int, c Change) {
	prefix := "  " + c.Label + ": "
	indent := lipgloss.Width(prefix)
	valueWidth := width - indent
	if valueWidth < minWrapWidth {
		valueWidth = minWrapWidth
	}
	lines := wrapValue(describe(c), valueWidth)
	for i, line := range lines {
		if i == 0 {
			b.WriteString("  " + th.Label.Render(c.Label+":") + " ")
		} else {
			b.WriteString(strings.Repeat(" ", indent))
		}
		b.WriteString(th.Warn.Render(line) + "\n")
	}
}

// wrapValue word-wraps s to width columns using lipgloss's own
// word-boundary wrapping, matching human.wrapValue's approach (which is
// unexported and so can't be reused directly): Style.Width right-pads
// every wrapped line to exactly width runes, so the trailing padding is
// trimmed since the caller does its own layout.
func wrapValue(s string, width int) []string {
	wrapped := lipgloss.NewStyle().Width(width).Render(s)
	rawLines := strings.Split(wrapped, "\n")
	lines := make([]string, len(rawLines))
	for i, l := range rawLines {
		lines[i] = strings.TrimRight(l, " ")
	}
	return lines
}
