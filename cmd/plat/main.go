package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/patramsey/plat/internal/bootstrap"
	"github.com/patramsey/plat/internal/collect"
	"github.com/patramsey/plat/internal/domain"
	"github.com/patramsey/plat/internal/merge"
	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/rdap"
	"github.com/patramsey/plat/internal/render"
	"github.com/patramsey/plat/internal/render/human"
	"github.com/patramsey/plat/internal/render/machine"
	"github.com/patramsey/plat/internal/render/plain"
	"github.com/patramsey/plat/internal/spinner"
)

// version, commit, date, and builtBy are overwritten via -ldflags at
// release build time (M7's .goreleaser.yaml) — the defaults below are
// what a plain local `go build`/`go run` reports. The Go linker resolves
// -X main.xxx by package name, not import path, so goreleaser's
// default-shaped ldflags work against these vars unchanged even though
// this package lives at cmd/plat, not literally a directory named main.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func main() {
	ui := uiConfig{NoColor: os.Getenv("NO_COLOR") != ""}
	if render.IsTerminal(os.Stdout) {
		ui.Dark = lipgloss.HasDarkBackground(os.Stdin, os.Stdout)
		if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
			ui.Width = w
		}
	}
	ui.StderrTTY = render.IsTerminal(os.Stderr)
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, ui))
}

// usageError marks input-validation failures (exit code 2), distinct from
// not-found (exit code 1) and all other lookup failures (exit code 3).
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

// exitSignal carries a pre-computed final exit code (0, 1, 2, or 3) out of
// cobra's error-only RunE contract — used by the multi-domain loop, which
// derives its own worst-of-N outcome rather than a single error. Only
// constructed for a non-zero code; a fully successful run returns nil
// normally, so exitCode never needs to special-case exitSignal{0}.
type exitSignal struct{ code int }

func (e exitSignal) Error() string { return "" }

// uiConfig carries terminal-detection results computed once in main()
// using real file descriptors, threaded down as plain data so every
// function below main() stays a pure function of its arguments — exactly
// like stdout/stderr being injected io.Writers rather than os.Stdout
// directly, which is what has kept this whole command line testable with
// bytes.Buffers since M1. The zero value (Dark: false, Width: 0 -> 80,
// NoColor: false, StderrTTY: false) is what every existing test already
// implicitly exercises: no color forced, no spinner.
type uiConfig struct {
	Dark      bool
	Width     int
	NoColor   bool
	StderrTTY bool
}

func run(args []string, stdout, stderr io.Writer, ui uiConfig) int {
	var refreshBootstrap bool
	var timeout time.Duration
	var output string
	var raw bool
	var sourceFilter string
	var noFollow bool
	var verbose bool
	var showConflicts bool

	root := &cobra.Command{
		Use:           "plat <domain> [domain...]",
		Short:         "Look up domain ownership via RDAP and WHOIS",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args: func(cmd *cobra.Command, cliArgs []string) error {
			if len(cliArgs) < 1 {
				// A bare invocation ("plat" with nothing else) almost
				// always means someone is looking for how to use the
				// tool, not making a genuine mistake — show the same
				// help --help would, rather than a terse one-line error
				// that leaves them guessing. Other usage errors (a bad
				// flag value, an invalid domain) stay terse: those are
				// real mistakes with real context already in the
				// message, not "how do I even start" moments.
				_ = cmd.Help()
				return exitSignal{2}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, cliArgs []string) error {
			return runLookup(cmd.Context(), stdout, stderr, cliArgs, lookupOptions{
				RefreshBootstrap: refreshBootstrap,
				Timeout:          timeout,
				Output:           output,
				Raw:              raw,
				SourceFilter:     sourceFilter,
				NoFollow:         noFollow,
				Verbose:          verbose,
				ShowConflicts:    showConflicts,
			}, ui)
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)
	// cobra/pflag's own flag-parsing errors (unknown flag, wrong argument
	// type, missing flag value) happen inside Execute() itself, before
	// RunE runs — without this, they're indistinguishable from any other
	// error by the time exitCode sees them, and fall through to exit 3
	// ("total lookup failure") instead of 2 ("usage error"), even though
	// no lookup was ever attempted.
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageError{err}
	})
	root.Flags().BoolVar(&refreshBootstrap, "refresh-bootstrap", false, "force a fresh fetch of the IANA RDAP bootstrap file")
	root.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "per-source timeout for bootstrap, RDAP, and WHOIS lookups")
	root.Flags().StringVarP(&output, "output", "o", "", "output format: human, plain, json, ndjson (default: auto-detect from terminal)")
	root.Flags().BoolVar(&raw, "raw", false, "include raw source payloads (json/ndjson only)")
	root.Flags().StringVar(&sourceFilter, "source", "", "restrict to one source: rdap, whois, registry, registrar")
	root.Flags().BoolVar(&noFollow, "no-follow", false, "skip the registrar RDAP related-link hop")
	root.Flags().BoolVarP(&verbose, "verbose", "v", false, "show the per-source diagnostic block (latency and status for every source attempted)")
	root.Flags().BoolVar(&showConflicts, "conflicts", false, "show the full per-source breakdown for every conflicted field (a field with a conflict is always marked with ⚠, even without this flag)")

	// Flags reserved for later milestones — intentionally not implemented
	// here: -q/--quiet (condensed human view, M4 stretch/M5), --no-color
	// (no-op before M5's styled human renderer exists). `completion` is
	// now a real subcommand (M7, cobra's built-in generator); man pages
	// are a build-time-only artifact (M7's gendocs, not a runtime
	// subcommand).

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the plat version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(stdout, "plat %s (%s, built %s by %s)\n", version, commit, date, builtBy)
			return err
		},
	})

	root.AddCommand(newWhoisCommand(stdout))
	root.AddCommand(newMergeCommand(stdout))
	root.AddCommand(newGendocsCommand(root))

	err := root.Execute()
	return exitCode(err, stderr)
}

type lookupOptions struct {
	RefreshBootstrap bool
	Timeout          time.Duration
	Output           string
	Raw              bool
	SourceFilter     string
	NoFollow         bool
	Verbose          bool
	ShowConflicts    bool
}

// runLookup validates flags/args once, resolves the output format and
// bootstrap resolver once, then loops domains sequentially — each
// domain's own outcome (0/1/2/3) is tracked and the worst wins overall.
func runLookup(ctx context.Context, stdout, stderr io.Writer, domains []string, opts lookupOptions, ui uiConfig) error {
	format, err := render.Select(opts.Output, render.IsTerminal(os.Stdout), ui.NoColor)
	if err != nil {
		return usageError{err}
	}
	if opts.Raw && !render.IsMachine(format) {
		return usageError{fmt.Errorf("--raw is only meaningful with -o json or -o ndjson")}
	}
	if format == render.FormatJSON && len(domains) > 1 {
		return usageError{fmt.Errorf("-o json supports exactly one domain; use -o ndjson for multiple")}
	}
	sources, err := parseSourceFilter(opts.SourceFilter)
	if err != nil {
		return usageError{err}
	}

	resolver, err := bootstrap.Load(ctx, bootstrap.Options{Refresh: opts.RefreshBootstrap, Timeout: opts.Timeout})
	if err != nil {
		return fmt.Errorf("resolving RDAP bootstrap: %w", err)
	}

	worst := 0
	for i, input := range domains {
		code := lookupOne(ctx, stdout, stderr, resolver, input, opts, sources, format, ui)
		if code > worst {
			worst = code
		}
		if !render.IsMachine(format) && i < len(domains)-1 {
			_, _ = fmt.Fprintln(stdout)
		}
	}
	if worst != 0 {
		return exitSignal{worst}
	}
	return nil
}

// lookupOne performs one domain's normalize -> collect -> merge ->
// render-or-report flow and returns that domain's exit code (0/2/1/3;
// 2 only for a per-domain normalize failure). Collect runs behind a
// spinner (on stderr) only when stderr is a real terminal and the output
// format is FormatHuman — never for Plain/JSON/NDJSON, and never when
// stderr is redirected even if stdout is a terminal.
func lookupOne(ctx context.Context, stdout, stderr io.Writer, resolver *bootstrap.Resolver, input string, opts lookupOptions, sources []model.SourceID, format render.Format, ui uiConfig) int {
	name, err := domain.Normalize(input)
	if err != nil {
		reportLookupError(stderr, format, input, err, nil, opts.Verbose, ui)
		return 2
	}

	baseURL, _ := resolver.BaseURL(name.TLD) // "" is fine — Collect degrades to WHOIS-only
	collectOpts := collect.Options{NoFollow: opts.NoFollow, Timeout: opts.Timeout, Sources: sources}

	var records []model.SourceRecord
	work := func() {
		records = collect.Collect(ctx, name, baseURL, "", collectOpts)
	}
	if ui.StderrTTY && format == render.FormatHuman {
		spinner.Run(stderr, "looking up "+name.Punycode+"...", work)
	} else {
		work()
	}

	record := merge.Merge(records)

	code := deriveOutcome(record.Sources)
	if code == 0 {
		if err := renderRecord(stdout, format, record, opts.Raw, opts.Verbose, opts.ShowConflicts, ui); err != nil {
			reportLookupError(stderr, format, name.Punycode, err, record.Sources, opts.Verbose, ui)
			return 3
		}
		return 0
	}
	reportLookupError(stderr, format, name.Punycode, lookupOutcomeError(code, record.Sources), record.Sources, opts.Verbose, ui)
	return code
}

// lookupOutcomeError builds the message reported for a non-zero deriveOutcome
// code. It never repeats the domain name -- reportLookupError already
// prefixes "plat: <domain>: " ahead of it. Exit 1 (every attempted source
// agrees the domain doesn't exist) is good, actionable news for plat's most
// common use case — checking domain availability — so it reads that way
// ("is not registered") rather than the generic "no usable data" wording
// that made a confirmed-available result look identical to an actual
// failure. Exit 3 keeps a distinct, more cautious wording, since it covers
// both a total connectivity failure and a mixed result where non-existence
// can't be asserted with confidence.
func lookupOutcomeError(code int, sources []model.SourceResult) error {
	names := make([]string, len(sources))
	for i, s := range sources {
		names[i] = string(s.Source)
	}
	checked := strings.Join(names, ", ")

	if code == 1 {
		return fmt.Errorf("is not registered (checked: %s)", checked)
	}
	if len(sources) == 0 {
		return errors.New("lookup failed -- no sources could be reached")
	}
	failed := 0
	for _, s := range sources {
		if !s.OK && !s.NotFound {
			failed++
		}
	}
	return fmt.Errorf("lookup inconclusive -- %d of %d sources failed, so non-existence can't be confirmed (checked: %s)", failed, len(sources), checked)
}

func renderRecord(w io.Writer, format render.Format, record model.Record, raw, verbose, showConflicts bool, ui uiConfig) error {
	switch format {
	case render.FormatJSON:
		return machine.Encode(w, record, machine.Options{Raw: raw})
	case render.FormatNDJSON:
		return machine.EncodeNDJSON(w, record, machine.Options{Raw: raw})
	case render.FormatHuman:
		return human.Render(w, record, human.Options{Theme: human.NewTheme(ui.Dark), Width: ui.Width, Verbose: verbose, ShowConflicts: showConflicts})
	default: // FormatPlain
		return plain.Render(w, record, plain.Options{Verbose: verbose, ShowConflicts: showConflicts})
	}
}

// reportLookupError prints a lookup failure to stderr. In machine mode this
// is always the minimal, stable {"error", "domain"} shape — verbose has no
// effect there, matching -v's human/plain-only scope. Otherwise, when
// verbose is set and sources carries any per-source attempts (e.g. a
// not-found or total-failure outcome from deriveOutcome), the same
// diagnostic block -v shows on a successful lookup is printed after the
// error line, so -v still explains *why* every source came up empty
// instead of going silent exactly when that detail matters most.
//
// In human mode, a confirmed-not-registered outcome (deriveOutcome == 1)
// prints in th.OK rather than th.Err — it's the tool's most common "good"
// result (checking domain availability), not a failure, and shouldn't read
// like one. Every other outcome (usage errors, total lookup failure, a
// render error) keeps the existing error styling. Plain/JSON stay
// unstyled either way, matching how every other renderer in this package
// only colors human output.
func reportLookupError(stderr io.Writer, format render.Format, domainName string, err error, sources []model.SourceResult, verbose bool, ui uiConfig) {
	if render.IsMachine(format) {
		_ = machine.EncodeError(stderr, domainName, err)
		return
	}
	if format == render.FormatHuman {
		th := human.NewTheme(ui.Dark)
		style := th.Err
		if deriveOutcome(sources) == 1 {
			style = th.OK
		}
		_, _ = lipgloss.Fprintln(stderr, style.Render(fmt.Sprintf("plat: %s: %s", domainName, err)))
	} else {
		_, _ = fmt.Fprintln(stderr, "plat:", domainName+":", err)
	}
	if !verbose || len(sources) == 0 {
		return
	}
	if format == render.FormatHuman {
		_ = human.RenderSources(stderr, human.NewTheme(ui.Dark), ui.Width, sources)
	} else {
		_ = plain.RenderSources(stderr, sources)
	}
}

// deriveOutcome classifies rec's per-source results into an exit code: 0
// if any source returned usable data, 1 if every attempted source agrees
// the domain doesn't exist (and none hard-failed), 3 otherwise (total
// failure, or a source errored so non-existence can't be asserted with
// confidence).
func deriveOutcome(sources []model.SourceResult) int {
	if len(sources) == 0 {
		return 3
	}
	hasData, hasNotFound, hasFailed := false, false, false
	for _, s := range sources {
		switch {
		case s.OK:
			hasData = true
		case s.NotFound:
			hasNotFound = true
		default:
			hasFailed = true
		}
	}
	if hasData {
		return 0
	}
	if hasNotFound && !hasFailed {
		return 1
	}
	return 3
}

// parseSourceFilter translates the --source flag's friendly value into
// the 2-element model.SourceID slice collect.Options.Sources expects.
// An empty string means "no filter" (nil, allow everything).
func parseSourceFilter(s string) ([]model.SourceID, error) {
	switch s {
	case "":
		return nil, nil
	case "rdap":
		return []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistrarRDAP}, nil
	case "whois":
		return []model.SourceID{model.SourceRegistryWHOIS, model.SourceRegistrarWHOIS}, nil
	case "registry":
		return []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistryWHOIS}, nil
	case "registrar":
		return []model.SourceID{model.SourceRegistrarRDAP, model.SourceRegistrarWHOIS}, nil
	default:
		return nil, fmt.Errorf("invalid --source value %q: must be one of rdap, whois, registry, registrar", s)
	}
}

func exitCode(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	var sig exitSignal
	if errors.As(err, &sig) {
		return sig.code
	}
	_, _ = fmt.Fprintln(stderr, "plat:", err)

	var usageErr usageError
	switch {
	case errors.As(err, &usageErr):
		return 2
	case errors.Is(err, rdap.ErrDomainNotFound):
		return 1
	default:
		return 3
	}
}
