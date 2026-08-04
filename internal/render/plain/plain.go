package plain

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/patramsey/plat/internal/model"
)

// Options controls Render's verbosity.
type Options struct {
	// Verbose includes the per-source diagnostic block (latency and
	// ok/not-found/error status for every source attempted). Without it,
	// Render shows the merged field values plus any Conflicts/Redacted
	// notices — genuine disagreements between sources stay visible either
	// way, since they're meaningful regardless of verbosity; the
	// per-source latency/status dump is the part that's mostly useful for
	// debugging, not everyday lookups.
	Verbose bool
	// ShowConflicts prints the full "Conflict (field): src=value, ..."
	// block. Without it, a conflicted field's line still gets a trailing
	// "[conflict]" marker -- so a conflict is never invisible -- but the
	// raw per-source breakdown is opt-in, matching human.Options'
	// ShowConflicts.
	ShowConflicts bool
}

// Render writes an unstyled, aligned key/value view of a merged domain
// record — field values with source provenance, any conflicts/redactions,
// and (if opts.Verbose) a per-source status line. It never emits ANSI
// escapes, so it is safe for pipes and for terminals that don't support
// color. This is the renderer both the "human" and "plain" output formats
// use when styling isn't in play; a later milestone adds a distinct
// styled human renderer on top without changing this one.
func Render(w io.Writer, r model.Record, opts Options) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)

	for _, fd := range model.FieldOrder {
		writeField(tw, r, fd)
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

	if r.Lifecycle != nil {
		_, _ = fmt.Fprintln(tw, "---")
		_, _ = fmt.Fprintf(tw, "Lifecycle (%s):\t%s\n", r.Lifecycle.Label, r.Lifecycle.Description)
		if r.Lifecycle.EstimatedEndsBy != nil {
			_, _ = fmt.Fprintf(tw, "Lifecycle estimate:\t%s (%s)\n", r.Lifecycle.EstimatedEndsBy.UTC().Format(time.RFC3339), r.Lifecycle.EstimateBasis)
		}
	}

	return tw.Flush()
}

// RenderSources writes just the per-source diagnostic block (latency and
// ok/not-found/error status for every source attempted) with no other
// record fields — used on the CLI's lookup-failure path, where -v should
// still show why every source was unusable even though there's no merged
// Record worth rendering in full.
func RenderSources(w io.Writer, sources []model.SourceResult) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	writeSourcesBlock(tw, sources)
	return tw.Flush()
}

func writeSourcesBlock(tw *tabwriter.Writer, sources []model.SourceResult) {
	if len(sources) == 0 {
		return
	}
	_, _ = fmt.Fprintln(tw, "---")
	for _, s := range sources {
		status := "no data"
		switch {
		case s.OK:
			status = "ok"
		case s.NotFound:
			status = "not found"
		case s.Err != "":
			status = s.Err
		}
		_, _ = fmt.Fprintf(tw, "%s:\t%s\t%s\n", s.Source, s.Latency.Round(time.Millisecond), status)
	}
}

// writeField dispatches one model.FieldOrder entry to the write* helper
// matching its Record field's type. Status is passed conflicted=false
// unconditionally -- differing sets are unioned, never flagged -- so it
// never needs the marker.
func writeField(tw *tabwriter.Writer, r model.Record, fd model.FieldSpec) {
	conflicted := hasConflict(r.Conflicts, fd.Key)
	switch fd.Key {
	case model.FieldDomain:
		stringField(tw, fd.Label, r.Domain, conflicted)
	case model.FieldHandle:
		stringField(tw, fd.Label, r.Handle, conflicted)
	case model.FieldRegistrarName:
		stringField(tw, fd.Label, r.Registrar.Name, conflicted)
	case model.FieldRegistrarIANAID:
		stringField(tw, fd.Label, r.Registrar.IANAID, conflicted)
	case model.FieldRegistrarURL:
		stringField(tw, fd.Label, r.Registrar.URL, conflicted)
	case model.FieldRegistrarAbuseEmail:
		stringField(tw, fd.Label, r.Registrar.AbuseEmail, conflicted)
	case model.FieldRegistrarAbusePhone:
		stringField(tw, fd.Label, r.Registrar.AbusePhone, conflicted)
	case model.FieldStatus:
		listField(tw, fd.Label, r.Status, false)
	case model.FieldCreated:
		timeField(tw, fd.Label, r.Created, conflicted)
	case model.FieldUpdated:
		timeField(tw, fd.Label, r.Updated, conflicted)
	case model.FieldExpires:
		timeField(tw, fd.Label, r.Expires, conflicted)
	case model.FieldNameservers:
		listField(tw, fd.Label, r.Nameservers, conflicted)
	case model.FieldDNSSEC:
		boolField(tw, fd.Label, r.DNSSEC, conflicted)
	default:
		panic(fmt.Sprintf("plain: unhandled model.FieldOrder entry %q", fd.Key))
	}
}

func stringField(tw *tabwriter.Writer, label string, f model.Field[string], conflicted bool) {
	if !f.Present() {
		return
	}
	_, _ = fmt.Fprintf(tw, "%s:\t%s\t%s\n", label, f.Value, sourcesCol(f.Sources, conflicted))
}

func listField(tw *tabwriter.Writer, label string, f model.Field[[]string], conflicted bool) {
	// Deliberately not f.Present(): a genuine merge conflict (see
	// internal/merge's nameservers()) can leave Sources empty while Value
	// stays populated with the merged union -- the row must still print,
	// just with an empty sources column.
	if len(f.Value) == 0 {
		return
	}
	_, _ = fmt.Fprintf(tw, "%s:\t%s\t%s\n", label, strings.Join(f.Value, " · "), sourcesCol(f.Sources, conflicted))
}

func boolField(tw *tabwriter.Writer, label string, f model.Field[bool], conflicted bool) {
	if !f.Present() {
		return
	}
	val := "false"
	if f.Value {
		val = "true"
	}
	_, _ = fmt.Fprintf(tw, "%s:\t%s\t%s\n", label, val, sourcesCol(f.Sources, conflicted))
}

func timeField(tw *tabwriter.Writer, label string, f model.Field[model.TimeValue], conflicted bool) {
	if !f.Present() {
		return
	}
	if f.Value.Parsed {
		_, _ = fmt.Fprintf(tw, "%s:\t%s\t%s\n", label, f.Value.Time.UTC().Format(time.RFC3339), sourcesCol(f.Sources, conflicted))
		return
	}
	_, _ = fmt.Fprintf(tw, "%s:\t%s (unparsed)\t%s\n", label, f.Value.Raw, sourcesCol(f.Sources, conflicted))
}

// hasConflict reports whether field appears in conflicts.
func hasConflict(conflicts []model.Conflict, field string) bool {
	for _, c := range conflicts {
		if c.Field == field {
			return true
		}
	}
	return false
}

// sourcesCol builds a field row's trailing source-provenance column, with
// a "[conflict]" marker appended when conflicted -- even if sources is
// empty, since a genuine multi-way fork (e.g. nameservers where no single
// source's set matches the merged union) can leave zero agreeing sources.
func sourcesCol(sources []model.SourceID, conflicted bool) string {
	col := formatSources(sources)
	if conflicted {
		if col != "" {
			col += " "
		}
		col += "[conflict]"
	}
	return col
}

// sourceCode abbreviates a source ID to the fixed 2-letter code shown in
// field columns and Conflict entries -- "registrar-rdap, registry-rdap,
// registry-whois" repeated on every field row of a well-agreed-upon
// record was the dominant contributor to line length. writeSourceLegend
// prints the one-line key these codes decode against; an unrecognized
// SourceID (shouldn't happen given the closed set in internal/model)
// falls back to the raw string rather than a blank code.
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
// would make the default output undecodable, not just less detailed.
func writeSourceLegend(tw *tabwriter.Writer) {
	_, _ = fmt.Fprintln(tw, "RR registrar-rdap   GR registry-rdap   RW registrar-whois   GW registry-whois")
}

// formatConflictValues renders a Conflict's map in model.Precedence order
// — Go map iteration order is randomized, and ranging over the map
// directly would make output (and any test asserting on it) flaky from
// run to run.
func formatConflictValues(values map[model.SourceID]string) string {
	var parts []string
	for _, src := range model.Precedence {
		if v, ok := values[src]; ok {
			parts = append(parts, fmt.Sprintf("%s=%s", sourceCode(src), v))
		}
	}
	return strings.Join(parts, ", ")
}
