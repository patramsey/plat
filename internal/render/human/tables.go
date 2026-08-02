package human

import (
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"

	"github.com/patramsey/plat/internal/model"
)

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
