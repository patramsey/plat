package plain

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/patramsey/plat/internal/model"
)

// RenderASN writes an unstyled, aligned key/value view of a merged ASN
// (autonomous system) record — the model.ASNRecord counterpart to Render.
// It never emits ANSI escapes, so it is safe for pipes and for terminals
// that don't support color.
func RenderASN(w io.Writer, r model.ASNRecord, opts Options) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)

	for _, fd := range model.ASNFieldOrder {
		writeASNField(tw, r, fd)
	}
	writeSourceLegend(tw, legendRegistryOnly)

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

// writeASNField dispatches one model.ASNFieldOrder entry to the write*
// helper matching its ASNRecord field's type. Range is the one
// non-mechanical entry: it combines StartAutnum and EndAutnum into a
// single "start - end" row rather than mapping 1:1 to an ASNRecord field,
// reusing rangeField/unionSourceIDs from ip.go since the shape (two
// independently-merged Field[string]s combined into one row) is identical.
func writeASNField(tw *tabwriter.Writer, r model.ASNRecord, fd model.FieldSpec) {
	conflicted := hasConflict(r.Conflicts, fd.Key)
	switch fd.Key {
	case model.FieldASNName:
		stringField(tw, fd.Label, r.Name, conflicted)
	case model.FieldASNHandle:
		stringField(tw, fd.Label, r.Handle, conflicted)
	case model.FieldASNStartAutnum:
		rangeConflicted := hasConflict(r.Conflicts, model.FieldASNStartAutnum) || hasConflict(r.Conflicts, model.FieldASNEndAutnum)
		rangeField(tw, fd.Label, r.StartAutnum, r.EndAutnum, rangeConflicted)
	case model.FieldASNType:
		stringField(tw, fd.Label, r.Type, conflicted)
	case model.FieldOrgName:
		stringField(tw, fd.Label, r.Org.Name, conflicted)
	case model.FieldOrgID:
		stringField(tw, fd.Label, r.Org.ID, conflicted)
	case model.FieldASNCountry:
		stringField(tw, fd.Label, r.Country, conflicted)
	case model.FieldOrgAbuseEmail:
		stringField(tw, fd.Label, r.Org.AbuseEmail, conflicted)
	case model.FieldOrgAbusePhone:
		stringField(tw, fd.Label, r.Org.AbusePhone, conflicted)
	case model.FieldASNStatus:
		listField(tw, fd.Label, r.Status, false)
	case model.FieldASNRegistered:
		timeField(tw, fd.Label, r.Registered, conflicted)
	case model.FieldASNUpdated:
		timeField(tw, fd.Label, r.Updated, conflicted)
	default:
		panic(fmt.Sprintf("plain: unhandled model.ASNFieldOrder entry %q", fd.Key))
	}
}
