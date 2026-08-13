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

// RenderHuman writes the styled diff. It uses the same Theme the record
// renderers use so a diff looks like part of the same tool. width mirrors
// human.Options.Width in the record renderer's signature but is unused
// here: diff lines (dates, short lists) are short enough that wrapping
// hasn't been needed.
//
// Warn is the correct style for the changed value: theme.go documents it
// as "conflict header / source not-found / transitional status codes /
// diff highlight" -- the theme was written anticipating this.
func RenderHuman(w io.Writer, name string, changes []Change, th human.Theme, width int) error {
	if len(changes) == 0 {
		_, err := lipgloss.Fprintln(w, th.Muted.Render(name+": no changes"))
		return err
	}
	var b strings.Builder
	b.WriteString(th.Header.Render(name) + "\n\n")
	for _, c := range changes {
		b.WriteString("  " + th.Label.Render(c.Label+":") + " " + th.Warn.Render(describe(c)) + "\n")
	}
	b.WriteString("\n" + th.Muted.Render(fmt.Sprintf("%d changed", len(changes))))
	_, err := lipgloss.Fprintln(w, b.String())
	return err
}
