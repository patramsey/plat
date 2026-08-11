package human

import (
	"fmt"
	"io"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/patramsey/plat/internal/model"
)

// RenderIP writes a styled, colorized view of r to w: a "plat · <cidr or
// handle>" title above a bordered box containing the field table — the
// model.IPRecord counterpart to Render. An IP allocation has no lock
// status, expiry, or lifecycle to summarize, so RenderIP has no summary
// line and the box border is always th.Muted, unlike Render's
// verdict-colored border. Field ordering and coverage inside the box
// matches internal/render/plain.RenderIP exactly (this package styles, it
// does not add or remove fields) — both iterate the same
// model.IPFieldOrder — then Conflicts/Redacted always, and Sources only
// when opts.Verbose.
func RenderIP(w io.Writer, r model.IPRecord, opts Options) error {
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
	if title := ipTitle(r); title != "" {
		header.WriteString(th.Header.Render("plat · " + title))
	}

	var b strings.Builder
	for _, fd := range model.IPFieldOrder {
		writeIPField(&b, th, innerWidth, r, fd)
	}
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

// ipTitle picks the title-line identifier: CIDR when present (the most
// recognizable form of a netblock), falling back to the handle, and "" if
// neither is present -- mirroring Render's own "skip the title entirely"
// behavior when there's nothing to identify the record by.
func ipTitle(r model.IPRecord) string {
	if r.CIDR.Present() {
		return r.CIDR.Value
	}
	if r.Handle.Present() {
		return r.Handle.Value
	}
	return ""
}

// writeIPField dispatches one model.IPFieldOrder entry to the write*
// helper matching its IPRecord field's type. Range is the one
// non-mechanical entry: it combines StartAddress and EndAddress into a
// single "start - end" row rather than mapping 1:1 to an IPRecord field.
func writeIPField(b *strings.Builder, th Theme, width int, r model.IPRecord, fd model.FieldSpec) {
	conflicted := hasConflict(r.Conflicts, fd.Key)
	switch fd.Key {
	case model.FieldIPName:
		writeStringField(b, th, width, fd.Label, r.Name, th.Identity, conflicted)
	case model.FieldIPHandle:
		writeStringField(b, th, width, fd.Label, r.Handle, th.Value, conflicted)
	case model.FieldIPStartAddress:
		rangeConflicted := hasConflict(r.Conflicts, model.FieldIPStartAddress) || hasConflict(r.Conflicts, model.FieldIPEndAddress)
		writeRangeField(b, th, width, fd.Label, r.StartAddress, r.EndAddress, rangeConflicted)
	case model.FieldIPCIDR:
		writeStringField(b, th, width, fd.Label, r.CIDR, th.Identity, conflicted)
	case model.FieldIPType:
		writeStringField(b, th, width, fd.Label, r.Type, th.Value, conflicted)
	case model.FieldIPVersion:
		writeStringField(b, th, width, fd.Label, r.IPVersion, th.Value, conflicted)
	case model.FieldIPParent:
		writeStringField(b, th, width, fd.Label, r.ParentHandle, th.Value, conflicted)
	case model.FieldOrgName:
		writeStringField(b, th, width, fd.Label, r.Org.Name, th.Identity, conflicted)
	case model.FieldOrgID:
		writeStringField(b, th, width, fd.Label, r.Org.ID, th.Value, conflicted)
	case model.FieldIPCountry:
		writeStringField(b, th, width, fd.Label, r.Country, th.Value, conflicted)
	case model.FieldOrgAbuseEmail:
		writeStringField(b, th, width, fd.Label, r.Org.AbuseEmail, th.Value, conflicted)
	case model.FieldOrgAbusePhone:
		writeStringField(b, th, width, fd.Label, r.Org.AbusePhone, th.Value, conflicted)
	case model.FieldIPStatus:
		writeStatusField(b, th, width, fd.Label, r.Status)
	case model.FieldIPRegistered:
		writeTimeField(b, th, width, fd.Label, r.Registered, th.Value, conflicted)
	case model.FieldIPUpdated:
		writeTimeField(b, th, width, fd.Label, r.Updated, th.Value, conflicted)
	default:
		panic(fmt.Sprintf("human: unhandled model.IPFieldOrder entry %q", fd.Key))
	}
}

// writeRangeField renders the Range row as "start - end", combining
// StartAddress and EndAddress via writeStyledRow so it gets the same
// wrapping/badge treatment as any other row. merge.MergeIP merges the two
// through independent scalar() calls keyed "startAddress"/"endAddress" --
// each can carry its own Sources and its own Conflict entry -- so the
// caller passes a conflicted flag that already ORs both fields' conflict
// state, and this function unions both fields' Sources for the row's
// badge rather than assuming they ever agree. If only one of the two
// addresses is present, that address (and just its own sources) renders
// alone rather than with a dangling " - ".
func writeRangeField(b *strings.Builder, th Theme, width int, label string, start, end model.Field[string], conflicted bool) {
	var value string
	var sources []model.SourceID
	switch {
	case start.Present() && end.Present():
		value = start.Value + " - " + end.Value
		sources = unionSourceIDs(start.Sources, end.Sources)
	case start.Present():
		value = start.Value
		sources = start.Sources
	case end.Present():
		value = end.Value
		sources = end.Sources
	default:
		return
	}
	writeStyledRow(b, th, width, label, value, th.Value, sources, "", conflicted)
}

// unionSourceIDs returns the sources appearing in a or b, deduplicated,
// preserving a's order and appending any of b's entries not already seen
// -- used by the Range row, whose two underlying fields (StartAddress,
// EndAddress) can each carry their own independently-merged Sources set.
func unionSourceIDs(a, b []model.SourceID) []model.SourceID {
	seen := make(map[model.SourceID]bool, len(a)+len(b))
	out := make([]model.SourceID, 0, len(a)+len(b))
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
