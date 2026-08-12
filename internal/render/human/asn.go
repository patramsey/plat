package human

import (
	"fmt"
	"io"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/patramsey/plat/internal/model"
)

// RenderASN writes a styled, colorized view of r to w: a "plat · <handle
// or name>" title above a bordered box containing the field table — the
// model.ASNRecord counterpart to Render. An autonomous system has no lock
// status, expiry, or lifecycle to summarize, so RenderASN has no summary
// line and the box border is always th.Muted, unlike Render's
// verdict-colored border. Field ordering and coverage inside the box
// matches internal/render/plain.RenderASN exactly (this package styles, it
// does not add or remove fields) — both iterate the same
// model.ASNFieldOrder — then Conflicts/Redacted always, and Sources only
// when opts.Verbose.
func RenderASN(w io.Writer, r model.ASNRecord, opts Options) error {
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
	if title := asnTitle(r); title != "" {
		header.WriteString(th.Header.Render("plat · " + title))
	}

	var b strings.Builder
	for _, fd := range model.ASNFieldOrder {
		writeASNField(&b, th, innerWidth, r, fd)
	}
	writeSourceLegend(&b, th, innerWidth, legendRegistryOnly)

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
		BorderForeground(th.Muted.GetForeground()).
		Padding(0, 1).
		Render(strings.TrimRight(b.String(), "\n"))

	out := box + "\n"
	if header.Len() > 0 {
		out = header.String() + "\n\n" + out
	}

	_, err := lipgloss.Fprint(w, out)
	return err
}

// asnTitle picks the title-line identifier: Handle when present (an ASN's
// canonical identifier, e.g. "AS15169"), falling back to Name, and "" if
// neither is present -- mirroring RenderIP's "skip the title entirely"
// behavior when there's nothing to identify the record by.
func asnTitle(r model.ASNRecord) string {
	if r.Handle.Present() {
		return r.Handle.Value
	}
	if r.Name.Present() {
		return r.Name.Value
	}
	return ""
}

// writeASNField dispatches one model.ASNFieldOrder entry to the write*
// helper matching its ASNRecord field's type. Range is the one
// non-mechanical entry: it combines StartAutnum and EndAutnum into a
// single "start - end" row rather than mapping 1:1 to an ASNRecord field,
// reusing writeRangeField/unionSourceIDs from ip.go since the shape (two
// independently-merged Field[string]s combined into one row) is identical.
func writeASNField(b *strings.Builder, th Theme, width int, r model.ASNRecord, fd model.FieldSpec) {
	conflicted := hasConflict(r.Conflicts, fd.Key)
	switch fd.Key {
	case model.FieldASNName:
		writeStringField(b, th, width, fd.Label, r.Name, th.Identity, conflicted)
	case model.FieldASNHandle:
		writeStringField(b, th, width, fd.Label, r.Handle, th.Value, conflicted)
	case model.FieldASNStartAutnum:
		rangeConflicted := hasConflict(r.Conflicts, model.FieldASNStartAutnum) || hasConflict(r.Conflicts, model.FieldASNEndAutnum)
		writeRangeField(b, th, width, fd.Label, r.StartAutnum, r.EndAutnum, rangeConflicted)
	case model.FieldASNType:
		writeStringField(b, th, width, fd.Label, r.Type, th.Value, conflicted)
	case model.FieldOrgName:
		writeStringField(b, th, width, fd.Label, r.Org.Name, th.Identity, conflicted)
	case model.FieldOrgID:
		writeStringField(b, th, width, fd.Label, r.Org.ID, th.Value, conflicted)
	case model.FieldASNCountry:
		writeStringField(b, th, width, fd.Label, r.Country, th.Value, conflicted)
	case model.FieldOrgAbuseEmail:
		writeStringField(b, th, width, fd.Label, r.Org.AbuseEmail, th.Value, conflicted)
	case model.FieldOrgAbusePhone:
		writeStringField(b, th, width, fd.Label, r.Org.AbusePhone, th.Value, conflicted)
	case model.FieldASNStatus:
		writeStatusField(b, th, width, fd.Label, r.Status)
	case model.FieldASNRegistered:
		writeTimeField(b, th, width, fd.Label, r.Registered, th.Value, conflicted)
	case model.FieldASNUpdated:
		writeTimeField(b, th, width, fd.Label, r.Updated, th.Value, conflicted)
	default:
		panic(fmt.Sprintf("human: unhandled model.ASNFieldOrder entry %q", fd.Key))
	}
}
