package plain

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

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
	// NotQueried lists sources a flag excluded before the lookup ran,
	// ordered by model.Precedence. Rendered as one trailing line in the
	// Verbose source block, because a source filtered out by --source
	// produces no SourceResult at all: without this the two WHOIS rows
	// simply vanish from a block documented as showing "every source
	// attempted", which reads as a failure rather than as the filter
	// working. Empty means nothing was filtered and no line is printed.
	NotQueried []model.SourceID
	// NotQueriedReason names the flag(s) responsible, e.g. "--source rdap".
	NotQueriedReason string
	// Width is the terminal width to lay out within. Zero -- which is
	// what term.GetSize reports when stdout is not a terminal -- disables
	// wrapping entirely and keeps output byte-identical, because this
	// renderer is also what pipes get, and wrapping a nameserver list
	// would break grep and awk on it.
	Width int
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

	var rows []row
	for _, fd := range model.FieldOrder {
		writeField(&rows, r, fd)
	}
	emitRows(tw, rows, opts.Width)

	writeSourceLegend(tw, model.PresentSources(r), opts.Width)

	if opts.Verbose {
		writeSourcesBlock(tw, r.Sources, opts.NotQueried, opts.NotQueriedReason)
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
	writeSourcesBlock(tw, sources, nil, "")
	return tw.Flush()
}

func writeSourcesBlock(tw *tabwriter.Writer, sources []model.SourceResult, notQueried []model.SourceID, reason string) {
	if len(sources) == 0 && len(notQueried) == 0 {
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
	writeNotQueried(tw, notQueried, reason)
}

// writeNotQueried names the sources a flag excluded before the lookup
// ran. See Options.NotQueried for why their absence needs saying out loud.
func writeNotQueried(tw *tabwriter.Writer, notQueried []model.SourceID, reason string) {
	if len(notQueried) == 0 {
		return
	}
	names := make([]string, len(notQueried))
	for i, s := range notQueried {
		names[i] = string(s)
	}
	_, _ = fmt.Fprintf(tw, "(%s not queried: %s)\n", strings.Join(names, ", "), reason)
}

// row is one collected field line, held until every row exists so a
// width-aware emitter can size the columns from the actual content. items
// is non-nil only for list fields, where wrapping must break between whole
// items rather than mid-hostname.
type row struct {
	label string
	value string
	items []string
	src   string
}

// minValueWidth floors how narrow the value column can get, so a very
// narrow terminal degrades gracefully instead of wrapping every value to
// almost nothing. Mirrors human.minInnerWidth's reasoning.
const minValueWidth = 20

// emitRows writes the collected rows. width <= 0 takes the tabwriter path,
// byte-identical to what this renderer has always produced, keeping piped
// output safe for grep and awk.
func emitRows(tw *tabwriter.Writer, rows []row, width int) {
	if width <= 0 {
		for _, r := range rows {
			_, _ = fmt.Fprintf(tw, "%s:\t%s\t%s\n", r.label, r.value, r.src)
		}
		return
	}
	emitRowsWithin(tw, rows, width)
}

// emitRowsWithin lays the rows out by hand within width columns.
//
// tabwriter pads the value column to its widest cell, so one long Status
// value inflated EVERY row past the terminal width -- and the terminal's
// own wrap then orphaned the source column, which is the whole point of
// the tool, onto its own line for every field. Capping the value column
// fixes all rows at once.
//
// The manual layout is why this does not go through tabwriter's columns:
// tabwriter sizes columns from content, and the whole job here is to size
// them from the terminal instead. Rows are written as plain lines with no
// tabs, which tabwriter passes through untouched.
func emitRowsWithin(tw *tabwriter.Writer, rows []row, width int) {
	const gap = 2

	labelCol, srcCol := 0, 0
	for _, r := range rows {
		if n := utf8.RuneCountInString(r.label) + 1; n > labelCol { // +1 for the ':'
			labelCol = n
		}
		if n := utf8.RuneCountInString(r.src); n > srcCol {
			srcCol = n
		}
	}
	labelCol += gap

	valueBudget := width - labelCol - srcCol - gap
	if valueBudget < minValueWidth {
		valueBudget = minValueWidth
	}

	for _, r := range rows {
		chunks := []string{r.value}
		switch {
		case r.items != nil:
			chunks = wrapItems(r.items, itemSep, valueBudget)
		case utf8.RuneCountInString(r.value) > valueBudget:
			// A scalar isn't a list, but a long one (a registrant/registrar
			// business name, typically) still needs to fit the budget.
			// Splitting on spaces is safe here in a way item-wrapping
			// isn't: there's no hostname to mistake for truncated-but-
			// plausible, just prose that continues on the next line. A
			// single unbreakable token (a URL, an email) falls through
			// unwrapped -- same as before -- because there's no space to
			// break on.
			chunks = wrapItems(strings.Fields(r.value), " ", valueBudget)
		}
		for i, chunk := range chunks {
			indent := strings.Repeat(" ", labelCol)
			if i == 0 {
				indent = pad(r.label+":", labelCol)
			}
			// The source column rides the LAST line rather than the
			// first: a badge next to a value's opening fragment reads as
			// belonging to that fragment alone.
			if i == len(chunks)-1 && r.src != "" {
				_, _ = fmt.Fprintf(tw, "%s%s%s%s\n", indent, pad(chunk, valueBudget), strings.Repeat(" ", gap), r.src)
				continue
			}
			_, _ = fmt.Fprintf(tw, "%s%s\n", indent, strings.TrimRight(chunk, " "))
		}
	}
}

// itemSep joins the values of a list field ("ns1.example.com · ns2...").
const itemSep = " · "

// wrapItems packs items into lines of at most width columns, breaking only
// between whole items. Generic word wrapping would break inside a hostname
// -- and half a nameserver still looks like a nameserver, so the reader
// cannot tell it was truncated. sep is the caller's join string: itemSep
// for list values, legendSep for the legend's entries.
func wrapItems(items []string, sep string, width int) []string {
	var lines []string
	cur := ""
	for _, it := range items {
		candidate := it
		if cur != "" {
			candidate = cur + sep + it
		}
		if cur != "" && utf8.RuneCountInString(candidate) > width {
			lines = append(lines, cur)
			cur = it
			continue
		}
		cur = candidate
	}
	return append(lines, cur)
}

// pad right-pads s to w columns, counting runes. fmt's %-*s pads by BYTE
// count, which silently misaligns every row containing a multibyte rune --
// and the list separator is itself one.
func pad(s string, w int) string {
	if n := utf8.RuneCountInString(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

// writeField dispatches one model.FieldOrder entry to the write* helper
// matching its Record field's type. Status is passed conflicted=false
// unconditionally -- differing sets are unioned, never flagged -- so it
// never needs the marker.
func writeField(rows *[]row, r model.Record, fd model.FieldSpec) {
	conflicted := hasConflict(r.Conflicts, fd.Key)
	switch fd.Key {
	case model.FieldDomain:
		stringField(rows, fd.Label, r.Domain, conflicted)
	case model.FieldHandle:
		stringField(rows, fd.Label, r.Handle, conflicted)
	case model.FieldRegistrarName:
		stringField(rows, fd.Label, r.Registrar.Name, conflicted)
	case model.FieldRegistrarIANAID:
		stringField(rows, fd.Label, r.Registrar.IANAID, conflicted)
	case model.FieldRegistrarURL:
		stringField(rows, fd.Label, r.Registrar.URL, conflicted)
	case model.FieldRegistrarAbuseEmail:
		stringField(rows, fd.Label, r.Registrar.AbuseEmail, conflicted)
	case model.FieldRegistrarAbusePhone:
		stringField(rows, fd.Label, r.Registrar.AbusePhone, conflicted)
	case model.FieldStatus:
		listField(rows, fd.Label, r.Status, false)
	case model.FieldCreated:
		timeField(rows, fd.Label, r.Created, conflicted)
	case model.FieldUpdated:
		timeField(rows, fd.Label, r.Updated, conflicted)
	case model.FieldExpires:
		timeField(rows, fd.Label, r.Expires, conflicted)
	case model.FieldNameservers:
		listField(rows, fd.Label, r.Nameservers, conflicted)
	case model.FieldDNSSEC:
		boolField(rows, fd.Label, r.DNSSEC, conflicted)
	default:
		panic(fmt.Sprintf("plain: unhandled model.FieldOrder entry %q", fd.Key))
	}
}

func stringField(rows *[]row, label string, f model.Field[string], conflicted bool) {
	if !f.Present() {
		return
	}
	*rows = append(*rows, row{label: label, value: f.Value, src: sourcesCol(f.Sources, conflicted)})
}

func listField(rows *[]row, label string, f model.Field[[]string], conflicted bool) {
	// Deliberately not f.Present(): a genuine merge conflict (see
	// internal/merge's nameservers()) can leave Sources empty while Value
	// stays populated with the merged union -- the row must still print,
	// just with an empty sources column.
	if len(f.Value) == 0 {
		return
	}
	*rows = append(*rows, row{
		label: label,
		value: strings.Join(f.Value, " · "),
		items: f.Value,
		src:   sourcesCol(f.Sources, conflicted),
	})
}

func boolField(rows *[]row, label string, f model.Field[bool], conflicted bool) {
	if !f.Present() {
		return
	}
	val := "false"
	if f.Value {
		val = "true"
	}
	*rows = append(*rows, row{label: label, value: val, src: sourcesCol(f.Sources, conflicted)})
}

func timeField(rows *[]row, label string, f model.Field[model.TimeValue], conflicted bool) {
	if !f.Present() {
		return
	}
	if f.Value.Parsed {
		*rows = append(*rows, row{label: label, value: f.Value.Time.UTC().Format(time.RFC3339), src: sourcesCol(f.Sources, conflicted)})
		return
	}
	*rows = append(*rows, row{label: label, value: f.Value.Raw + " (unparsed)", src: sourcesCol(f.Sources, conflicted)})
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

// legendEntry decodes one source into its "XX source-id" legend entry. An
// unrecognized SourceID (which shouldn't happen given the closed set in
// internal/model) has no two-letter code -- sourceCode falls back to the
// raw string -- so it prints once rather than as "foo foo".
func legendEntry(s model.SourceID) string {
	code := sourceCode(s)
	if code == string(s) {
		return code
	}
	return code + " " + string(s)
}

// buildSourceLegend renders the key decoding the two-letter codes in
// sources, which callers derive from the record via model.PresentSources*
// -- so the key explains exactly the badges the reader can see and nothing
// else. A record whose only answer came from registry WHOIS used to get
// all four codes explained, which reads as "plat failed to reach the other
// three" rather than "the other three had nothing to say".
//
// Returns "" for an empty set, so a record with no provenance at all gets
// no legend line rather than an empty one.
//
// Kept in step with the same function in internal/render/human/rows.go --
// the two renderers must decode the same codes the same way.
func buildSourceLegend(sources []model.SourceID) string {
	return strings.Join(legendEntries(sources), legendSep)
}

// legendSep separates legend entries. Wide enough that "GR registry-rdap"
// reads as one unit rather than four loose words.
const legendSep = "   "

// legendEntries returns one entry per source, in the order given. Task 8
// wraps these by whole entry rather than by word, for the same reason
// nameservers wrap by whole item.
func legendEntries(sources []model.SourceID) []string {
	entries := make([]string, len(sources))
	for i, s := range sources {
		entries[i] = legendEntry(s)
	}
	return entries
}

// writeSourceLegend prints the key unconditionally, not gated by --verbose
// or --conflicts, since the codes it explains appear in the DEFAULT view;
// hiding it by default would make the default output undecodable, not just
// less detailed.
func writeSourceLegend(tw *tabwriter.Writer, sources []model.SourceID, width int) {
	if len(sources) == 0 {
		return
	}
	legend := buildSourceLegend(sources)
	if width <= 0 || utf8.RuneCountInString(legend) <= width {
		_, _ = fmt.Fprintln(tw, legend)
		return
	}
	// Wrap by whole entry: "GR registry-rdap" split across two lines
	// would read as a code with no name and a name with no code.
	for _, line := range wrapItems(legendEntries(sources), legendSep, width) {
		_, _ = fmt.Fprintln(tw, line)
	}
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
