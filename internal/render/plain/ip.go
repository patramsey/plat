package plain

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/patramsey/plat/internal/model"
)

// RenderIP writes an unstyled, aligned key/value view of a merged IP
// network record — the model.IPRecord counterpart to Render. It never
// emits ANSI escapes, so it is safe for pipes and for terminals that
// don't support color.
func RenderIP(w io.Writer, r model.IPRecord, opts Options) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)

	for _, fd := range model.IPFieldOrder {
		writeIPField(tw, r, fd)
	}
	writeSourceLegend(tw)

	if opts.Verbose {
		writeSourcesBlock(tw, r.Sources)
	}

	if len(r.Conflicts) > 0 {
		if opts.ShowConflicts {
			_, _ = fmt.Fprintln(tw, "---")
			for _, c := range r.Conflicts {
				_, _ = fmt.Fprintf(tw, "Conflict (%s):\t%s\n", c.Field, formatConflictValues(c.Values))
			}
		} else {
			noun := "conflict"
			if len(r.Conflicts) != 1 {
				noun = "conflicts"
			}
			_, _ = fmt.Fprintf(tw, "%d %s hidden -- pass --conflicts to see details\n", len(r.Conflicts), noun)
		}
	}

	if len(r.Redacted) > 0 {
		_, _ = fmt.Fprintln(tw, "---")
		for _, red := range r.Redacted {
			_, _ = fmt.Fprintf(tw, "Redacted (%s):\t%s (%s)\n", red.Field, red.Source, red.Reason)
		}
	}

	return tw.Flush()
}

// writeIPField dispatches one model.IPFieldOrder entry to the write*
// helper matching its IPRecord field's type. Range is the one
// non-mechanical entry: it combines StartAddress and EndAddress into a
// single "start - end" row rather than mapping 1:1 to an IPRecord field.
func writeIPField(tw *tabwriter.Writer, r model.IPRecord, fd model.FieldSpec) {
	conflicted := hasConflict(r.Conflicts, fd.Key)
	switch fd.Key {
	case model.FieldIPName:
		stringField(tw, fd.Label, r.Name, conflicted)
	case model.FieldIPHandle:
		stringField(tw, fd.Label, r.Handle, conflicted)
	case model.FieldIPStartAddress:
		rangeConflicted := hasConflict(r.Conflicts, model.FieldIPStartAddress) || hasConflict(r.Conflicts, model.FieldIPEndAddress)
		rangeField(tw, fd.Label, r.StartAddress, r.EndAddress, rangeConflicted)
	case model.FieldIPCIDR:
		stringField(tw, fd.Label, r.CIDR, conflicted)
	case model.FieldIPType:
		stringField(tw, fd.Label, r.Type, conflicted)
	case model.FieldIPVersion:
		stringField(tw, fd.Label, r.IPVersion, conflicted)
	case model.FieldIPParent:
		stringField(tw, fd.Label, r.ParentHandle, conflicted)
	case model.FieldOrgName:
		stringField(tw, fd.Label, r.Org.Name, conflicted)
	case model.FieldOrgID:
		stringField(tw, fd.Label, r.Org.ID, conflicted)
	case model.FieldIPCountry:
		stringField(tw, fd.Label, r.Country, conflicted)
	case model.FieldOrgAbuseEmail:
		stringField(tw, fd.Label, r.Org.AbuseEmail, conflicted)
	case model.FieldOrgAbusePhone:
		stringField(tw, fd.Label, r.Org.AbusePhone, conflicted)
	case model.FieldIPStatus:
		listField(tw, fd.Label, r.Status, false)
	case model.FieldIPRegistered:
		timeField(tw, fd.Label, r.Registered, conflicted)
	case model.FieldIPUpdated:
		timeField(tw, fd.Label, r.Updated, conflicted)
	default:
		panic(fmt.Sprintf("plain: unhandled model.IPFieldOrder entry %q", fd.Key))
	}
}

// rangeField renders the Range row as "start - end", combining
// StartAddress and EndAddress. merge.MergeIP merges the two through
// independent scalar() calls keyed "startAddress"/"endAddress" -- each
// can carry its own Sources and its own Conflict entry -- so the caller
// passes a conflicted flag that already ORs both fields' conflict state,
// and this function unions both fields' Sources for the row's badge
// rather than assuming they ever agree. If only one of the two addresses
// is present, that address (and just its own sources) renders alone
// rather than with a dangling " - ".
func rangeField(tw *tabwriter.Writer, label string, start, end model.Field[string], conflicted bool) {
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
	_, _ = fmt.Fprintf(tw, "%s:\t%s\t%s\n", label, value, sourcesCol(sources, conflicted))
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
