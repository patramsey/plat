// Package human renders a merged domain record as a styled, colorized
// view for interactive terminals — the FormatHuman counterpart to
// internal/render/plain's unstyled FormatPlain. Output goes through
// lipgloss.Fprint, which downsamples/strips ANSI automatically based on
// the destination writer and the process environment (NO_COLOR,
// CLICOLOR_FORCE, COLORTERM) — this package never hand-checks those
// itself.
//
// The package is split by concern: this file holds Render's entry points
// and the lock/expiry/verdict summary logic; theme.go holds Theme and the
// color/style decisions (status classification, expiry ramp, source
// codes); rows.go holds the per-field row writers and their wrapping;
// tables.go holds the Sources diagnostic table; conflicts.go holds the
// Conflicts/Redacted blocks and the conflict value diff-highlighting;
// lifecycle.go holds the Lifecycle interpretation block.
package human

import (
	"fmt"
	"io"
	"strings"
	"time"

	"charm.land/lipgloss/v2"

	"github.com/patramsey/plat/internal/model"
)

// labelWidth is the fixed left-column width every field row's label is
// padded to. Values wrap at whatever width remains.
const labelWidth = 20

// defaultWidth is used when Options.Width is unset (<=0) — e.g. when the
// destination isn't a real terminal and no width could be detected.
const defaultWidth = 80

// boxOverhead is how many columns the record box's rounded border plus
// Padding(0, 1) adds beyond its content: 1 border rune + 1 padding space
// on each side.
const boxOverhead = 4

// minInnerWidth floors how narrow the box's usable content width can go,
// mirroring the floor writeStyledRow already applies to a single value
// column, so a very narrow terminal degrades gracefully instead of
// wrapping every value to almost nothing.
const minInnerWidth = 20

// Options controls Render's appearance and verbosity.
type Options struct {
	Theme Theme
	// Width is the target terminal width for value wrapping. <=0 falls
	// back to defaultWidth.
	Width int
	// Verbose includes the per-source diagnostic block (latency and
	// ok/not-found/error status for every source attempted). Without it,
	// Render shows the merged field values plus any Conflicts/Redacted
	// notices — genuine disagreements between sources stay visible either
	// way, since they're meaningful regardless of verbosity; the
	// per-source latency/status dump is the part that's mostly useful for
	// debugging, not everyday lookups.
	Verbose bool
	// ShowConflicts prints the full Conflicts block (every disagreeing
	// source's raw value, per field). Without it, a conflicted field still
	// gets a small ⚠ marker next to its badge -- so a conflict is never
	// invisible -- but the raw per-source breakdown is opt-in: a domain
	// with several noisy timestamp/nameserver disagreements otherwise
	// dominates the box with detail most lookups don't need.
	ShowConflicts bool
}

// Render writes a styled, colorized view of r to w: a "plat · domain"
// title above a bordered box containing the field table. The at-a-glance
// summary line (lock status, expiry, conflict count) lives INSIDE the
// box as its first section, not floating above it with the title — it's
// data about the domain, like Conflicts/Redacted/Sources below it, not a
// heading, so it belongs with the rest of the content it's summarizing.
// Field ordering and coverage inside the box matches
// internal/render/plain.Render exactly (this package styles, it does not
// add or remove fields) — both iterate the same model.FieldOrder — then
// Conflicts/Redacted always, and Sources only when opts.Verbose.
func Render(w io.Writer, r model.Record, opts Options) error {
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
	if r.Domain.Present() {
		header.WriteString(th.Header.Render("plat · " + r.Domain.Value))
	}

	var b strings.Builder
	if summary := buildSummary(th, r); summary != "" {
		b.WriteString(summary + "\n\n")
	}
	for _, fd := range model.FieldOrder {
		writeField(&b, th, innerWidth, r, fd)
	}
	writeSourceLegend(&b, th, innerWidth, legendWithRegistrar)

	if opts.Verbose {
		writeSources(&b, th, innerWidth, r.Sources)
	}
	if opts.ShowConflicts {
		writeConflicts(&b, th, innerWidth, r.Conflicts)
	} else {
		writeConflictsHint(&b, th, r.Conflicts)
	}
	writeRedacted(&b, th, innerWidth, r.Redacted)
	writeLifecycle(&b, th, innerWidth, r.Lifecycle)

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderStyle(th, r.Status.Value).GetForeground()).
		Padding(0, 1).
		Render(strings.TrimRight(b.String(), "\n"))

	out := box + "\n"
	if header.Len() > 0 {
		out = header.String() + "\n\n" + out
	}

	_, err := lipgloss.Fprint(w, out)
	return err
}

// buildSummary composes the at-a-glance line under the title: a lock
// badge (if r.Status carries a recognized status), an expiry countdown
// (if r.Expires parsed), and a conflict count (only when there is at
// least one) — joined with a muted separator. Returns "" when none of
// the three have anything to say, so Render can skip the line entirely
// rather than print an empty one.
// QuietSummary composes the one-line, unstyled description --quiet
// prints instead of the full boxed/field-listing view: the same lock
// status, expiry countdown, and conflict count buildSummary's styled
// line shows, but as plain text with no ANSI codes regardless of output
// format (human or plain) -- quick to read and safe to pipe into other
// tools. Returns "" when none of the three have anything to say, same
// as buildSummary.
func QuietSummary(r model.Record) string {
	var parts []string
	switch domainVerdict(r.Status.Value) {
	case verdictCrit:
		parts = append(parts, "at risk")
	case verdictGood:
		parts = append(parts, "locked")
	}
	if r.Expires.Present() && r.Expires.Value.Parsed {
		days := int(time.Until(r.Expires.Value.Time).Hours() / 24)
		if days < 0 {
			parts = append(parts, fmt.Sprintf("expired %d days ago", -days))
		} else {
			parts = append(parts, fmt.Sprintf("expires in %d days", days))
		}
	}
	if n := len(r.Conflicts); n > 0 {
		word := "conflict"
		if n > 1 {
			word = "conflicts"
		}
		parts = append(parts, fmt.Sprintf("%d %s", n, word))
	}
	return strings.Join(parts, " · ")
}

func buildSummary(th Theme, r model.Record) string {
	var parts []string
	if lock := lockBadge(th, r.Status.Value); lock != "" {
		parts = append(parts, lock)
	}
	if expiry := expirySummary(th, r.Expires); expiry != "" {
		parts = append(parts, expiry)
	}
	if n := len(r.Conflicts); n > 0 {
		word := "conflict"
		if n > 1 {
			word = "conflicts"
		}
		parts = append(parts, th.Warn.Render(fmt.Sprintf("⚠ %d %s", n, word)))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, th.Muted.Render(" · "))
}

// verdict is the overall good/critical/neutral read on a domain's status
// set, shared by the summary line's lock badge and the record box's
// border color so the two always agree with each other.
type verdict int

const (
	verdictNeutral verdict = iota
	verdictGood
	verdictCrit
)

// domainVerdict classifies statuses into a verdict: verdictCrit wins over
// verdictGood when both a statusCrit and a statusGood code are present,
// since a hold/pending-delete matters more than a transfer-lock in the
// same set. verdictNeutral means nothing in statuses was recognized,
// rather than asserting either way about an unfamiliar status
// vocabulary.
func domainVerdict(statuses []string) verdict {
	hasGood, hasCrit := false, false
	for _, s := range statuses {
		if statusGood[s] {
			hasGood = true
		}
		if statusCrit[s] {
			hasCrit = true
		}
	}
	switch {
	case hasCrit:
		return verdictCrit
	case hasGood:
		return verdictGood
	default:
		return verdictNeutral
	}
}

// lockBadge renders domainVerdict(statuses) as the summary line's badge.
// Returns "" for verdictNeutral, so buildSummary can skip it entirely.
func lockBadge(th Theme, statuses []string) string {
	switch domainVerdict(statuses) {
	case verdictCrit:
		return th.Err.Render("⚠ at risk")
	case verdictGood:
		return th.OK.Render("🔒 locked")
	default:
		return ""
	}
}

// borderStyle picks the record box's border color from the same verdict
// as lockBadge, so an at-risk domain gets a red box and a locked one a
// green box at a glance, before the reader even reaches the summary
// line's text. verdictNeutral keeps the border a plain, unopinionated
// muted color.
func borderStyle(th Theme, statuses []string) lipgloss.Style {
	switch domainVerdict(statuses) {
	case verdictCrit:
		return th.Err
	case verdictGood:
		return th.OK
	default:
		return th.Muted
	}
}

// expirySummary renders a plain-language, ramp-colored countdown
// ("expires in 314 days" / "expired 12 days ago") matching the same
// green/yellow/red thresholds as the Expires field row itself. Returns
// "" when there's no parsed expiry to summarize.
func expirySummary(th Theme, f model.Field[model.TimeValue]) string {
	if !f.Present() || !f.Value.Parsed {
		return ""
	}
	style := expiryStyle(th, f.Value)
	days := int(time.Until(f.Value.Time).Hours() / 24)
	if days < 0 {
		return style.Render(fmt.Sprintf("expired %d days ago", -days))
	}
	return style.Render(fmt.Sprintf("expires in %d days", days))
}

// RenderSources writes just the styled per-source diagnostic block (latency
// and ok/not-found/error status for every source attempted) with no other
// record fields — used on the CLI's lookup-failure path, where -v should
// still show why every source was unusable even though there's no merged
// Record worth rendering in full. width bounds the table's columns the
// same way Render's own innerWidth does; <=0 falls back to defaultWidth.
func RenderSources(w io.Writer, th Theme, width int, sources []model.SourceResult) error {
	if width <= 0 {
		width = defaultWidth
	}
	var b strings.Builder
	writeSources(&b, th, width, sources)
	_, err := lipgloss.Fprint(w, b.String())
	return err
}

// writeField dispatches one model.FieldOrder entry to the write* helper
// matching its Record field's type and styling (Identity for the two
// headline fields, expiryStyle for Expires, a hyperlink for the
// Registrar URL, colorized badges for Status).
func writeField(b *strings.Builder, th Theme, width int, r model.Record, fd model.FieldSpec) {
	conflicted := hasConflict(r.Conflicts, fd.Key)
	switch fd.Key {
	case model.FieldDomain:
		writeStringField(b, th, width, fd.Label, r.Domain, th.Identity, conflicted)
	case model.FieldHandle:
		writeStringField(b, th, width, fd.Label, r.Handle, th.Value, conflicted)
	case model.FieldRegistrarName:
		writeStringField(b, th, width, fd.Label, r.Registrar.Name, th.Identity, conflicted)
	case model.FieldRegistrarIANAID:
		writeStringField(b, th, width, fd.Label, r.Registrar.IANAID, th.Value, conflicted)
	case model.FieldRegistrarURL:
		writeURLField(b, th, width, fd.Label, r.Registrar.URL, conflicted)
	case model.FieldRegistrarAbuseEmail:
		writeStringField(b, th, width, fd.Label, r.Registrar.AbuseEmail, th.Value, conflicted)
	case model.FieldRegistrarAbusePhone:
		writeStringField(b, th, width, fd.Label, r.Registrar.AbusePhone, th.Value, conflicted)
	case model.FieldStatus:
		writeStatusField(b, th, width, fd.Label, r.Status)
	case model.FieldCreated:
		writeTimeField(b, th, width, fd.Label, r.Created, th.Value, conflicted)
	case model.FieldUpdated:
		writeTimeField(b, th, width, fd.Label, r.Updated, th.Value, conflicted)
	case model.FieldExpires:
		writeTimeField(b, th, width, fd.Label, r.Expires, expiryStyle(th, r.Expires.Value), conflicted)
	case model.FieldNameservers:
		writeListField(b, th, width, fd.Label, r.Nameservers, conflicted)
	case model.FieldDNSSEC:
		writeBoolField(b, th, width, fd.Label, r.DNSSEC, conflicted)
	default:
		panic(fmt.Sprintf("human: unhandled model.FieldOrder entry %q", fd.Key))
	}
}
