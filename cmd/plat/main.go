package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"golang.org/x/term"

	"github.com/patramsey/plat"
	"github.com/patramsey/plat/internal/diff"
	"github.com/patramsey/plat/internal/domain"
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

// stdin is runLookup's source for "--file -". A package-level var, not a
// direct os.Stdin reference, purely so tests can substitute a fixed
// io.Reader and drive that path through run()/runLookup like any other
// input -- production code never reassigns it.
var stdin io.Reader = os.Stdin

// versionInfo holds the build metadata plat was compiled with. Shared by
// the version subcommand and the root --version flag so their default
// (non-JSON, non-full) output can never drift out of sync with each
// other -- both ultimately call currentVersionInfo(false).humanLine().
type versionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	BuiltBy   string `json:"builtBy"`
	GoVersion string `json:"goVersion,omitempty"`
	Platform  string `json:"platform,omitempty"`
}

// currentVersionInfo builds a versionInfo from the package-level
// version/commit/date/builtBy vars (overwritten via -ldflags at release
// build time). full adds GoVersion/Platform, sourced from the standard
// library -- runtime.Version() rather than runtime/debug.ReadBuildInfo's
// GoVersion field, since it needs no error handling and reports the same
// value for a normally built binary.
func currentVersionInfo(full bool) versionInfo {
	vi := versionInfo{Version: version, Commit: commit, Date: date, BuiltBy: builtBy}
	if full {
		vi.GoVersion = runtime.Version()
		vi.Platform = runtime.GOOS + "/" + runtime.GOARCH
	}
	return vi
}

// humanLine formats v the way plat version's default output always has:
// "plat X.Y.Z (commit, built DATE by BUILTBY)". When GoVersion is set (v
// came from currentVersionInfo(true)), two extra labeled lines are
// appended.
func (v versionInfo) humanLine() string {
	line := fmt.Sprintf("plat %s (%s, built %s by %s)", v.Version, v.Commit, v.Date, v.BuiltBy)
	if v.GoVersion == "" {
		return line
	}
	return fmt.Sprintf("%s\ngo:       %s\nplatform: %s", line, v.GoVersion, v.Platform)
}

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

// exitSignal carries a pre-computed final exit code (0, 1, 2, 3, or 4) out of
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
	var showVersion bool
	var quiet bool
	var noColorFlag bool
	var diffPath string
	var filePath string
	var concurrency int

	root := &cobra.Command{
		Use:           "plat <domain|ip|asn> [domain|ip|asn...]",
		Short:         "Look up domain, IP, or ASN ownership via RDAP and WHOIS",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args: func(cmd *cobra.Command, cliArgs []string) error {
			if showVersion {
				// --version is a valid zero-arg invocation -- skip the
				// no-args-shows-help path below entirely; RunE handles
				// printing and returns before runLookup is ever reached.
				return nil
			}
			if filePath != "" {
				// --file supplies the name list in place of positional
				// args -- "plat --file names.txt" with zero cliArgs is
				// the flag's primary use case, not a bare invocation
				// asking for help. runLookup does its own validation
				// (mutual exclusivity with positional args, file-open,
				// and empty-list errors) once RunE resolves the list.
				return nil
			}
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
			if showVersion {
				_, err := fmt.Fprintln(stdout, currentVersionInfo(false).humanLine())
				return err
			}
			return runLookup(cmd.Context(), stdout, stderr, cliArgs, lookupOptions{
				RefreshBootstrap: refreshBootstrap,
				Timeout:          timeout,
				Output:           output,
				Raw:              raw,
				SourceFilter:     sourceFilter,
				NoFollow:         noFollow,
				Verbose:          verbose,
				ShowConflicts:    showConflicts,
				Quiet:            quiet,
				NoColor:          noColorFlag,
				DiffPath:         diffPath,
				FilePath:         filePath,
				Concurrency:      concurrency,
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
	root.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "per-source timeout for bootstrap, RDAP, and WHOIS lookups; bounds time spent talking to a server, not time a bulk run spends waiting its turn")
	root.Flags().StringVarP(&output, "output", "o", "", "output format: human, plain, json, ndjson (default: auto-detect from terminal)")
	root.Flags().BoolVar(&raw, "raw", false, "include raw source payloads (json/ndjson only)")
	root.Flags().StringVar(&sourceFilter, "source", "", "restrict to one source: rdap, whois, registry, registrar")
	root.Flags().BoolVar(&noFollow, "no-follow", false, "skip the registrar RDAP related-link hop")
	root.Flags().BoolVarP(&verbose, "verbose", "v", false, "show the per-source diagnostic block (latency and status for every source attempted)")
	root.Flags().BoolVar(&showConflicts, "conflicts", false, "show the full per-source breakdown for every conflicted field (a field with a conflict is always marked with ⚠, even without this flag)")
	root.Flags().BoolVar(&showVersion, "version", false, "print the plat version and exit")
	root.Flags().BoolVarP(&quiet, "quiet", "q", false, "print a one-line summary per domain (lock status, expiry, conflict count) instead of the full view -- ignored for -o json/ndjson")
	root.Flags().BoolVar(&noColorFlag, "no-color", false, "disable color output (same effect as the NO_COLOR env var)")
	root.Flags().StringVar(&diffPath, "diff", "", "compare the lookup against a saved -o json snapshot; exits 4 if anything changed")
	root.Flags().StringVar(&filePath, "file", "", "read names from a file, one per line (- for stdin); blank lines and # comments are skipped")
	root.Flags().IntVar(&concurrency, "concurrency", 4, "number of names to look up in parallel (1 = sequential)")

	// `completion` is a real subcommand (M7, cobra's built-in generator);
	// man pages are a build-time-only artifact (M7's gendocs, not a
	// runtime subcommand).

	var versionOutput string
	var versionFull bool
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the plat version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := currentVersionInfo(versionFull)
			switch versionOutput {
			case "human":
				_, err := fmt.Fprintln(stdout, info.humanLine())
				return err
			case "json":
				return json.NewEncoder(stdout).Encode(info)
			default:
				return usageError{fmt.Errorf("invalid --output value %q for version: must be human or json", versionOutput)}
			}
		},
	}
	versionCmd.Flags().StringVarP(&versionOutput, "output", "o", "human", "output format: human or json")
	versionCmd.Flags().BoolVar(&versionFull, "full", false, "include Go version and platform (human: extra lines; json: extra keys)")
	root.AddCommand(versionCmd)

	root.AddCommand(newGendocsCommand(root))

	err := root.Execute()
	return exitCode(err, stderr)
}

// lookupOptions carries every --flag value runLookup needs. Four of its
// fields -- RefreshBootstrap, Timeout, SourceFilter, and NoFollow -- are
// read only inside runLookup itself, where they are folded into the one
// plat.Options passed to plat.New (see runLookup's Timeout/NoFollow/
// RefreshBootstrap/Sources forwarding and parseSourceFilter(opts.SourceFilter)).
// Past that point the struct still travels on, unread, through
// runLookupPool, lookupOne, and each of the three lookupOne* helpers --
// nothing down there consults these four fields, because their effect is
// already baked into the shared client. A future edit that tried to read
// one of them per-name at that depth would compile and silently do
// nothing.
type lookupOptions struct {
	RefreshBootstrap bool
	Timeout          time.Duration
	Output           string
	Raw              bool
	SourceFilter     string
	NoFollow         bool
	Verbose          bool
	ShowConflicts    bool
	Quiet            bool
	NoColor          bool
	// DiffPath is the --diff flag's value: a path to a saved -o json
	// snapshot to compare the fresh lookup against. Empty means --diff
	// was not passed -- the zero value for every existing caller, so no
	// prior behavior changes when it's unset.
	DiffPath string
	// FilePath is the --file flag's value: a path to a file of names, one
	// per line ("-" for stdin), read in place of positional domain args.
	// Empty means --file was not passed -- the zero value for every
	// existing caller, so no prior behavior changes when it's unset.
	FilePath string
	// Concurrency is the --concurrency flag's value: how many names
	// runLookup looks up in parallel. Defaults to 4 via the flag
	// registration; runLookup rejects anything less than 1.
	Concurrency int
	// whoisIANAServer overrides the WHOIS server lookupOne queries first
	// to resolve a TLD's registry server (see plat.Options.WHOISIANAServer).
	// Unexported and unset by every real flag -- it's always "" (the
	// real-network default) outside of this package's own tests, which
	// construct lookupOptions directly to point it at a fake local
	// listener. runLookup forwards it into the one plat.Client it builds;
	// the per-server WHOIS pacing limiter and IANA referral cache the pool
	// used to carry here now live on that client.
	whoisIANAServer string
	// SuppressSpinner disables the three per-name spinners in lookupOne's
	// domain/IP/ASN branches. Set by runLookupPool when it is driving its
	// own progress counter over the same stderr line -- without this, a
	// per-name spinner and the bulk counter would both write \r-prefixed
	// lines to that line concurrently and produce garbage. False (every
	// existing caller's zero value) for a single-name run, which has no
	// counter and keeps its per-name spinner exactly as before.
	SuppressSpinner bool
}

// effectiveNoColor reports whether color output should be suppressed:
// the NO_COLOR env var (captured once in main() into ui.NoColor) or the
// --no-color flag, either one is sufficient — matching NO_COLOR's own
// "presence, not value" convention (https://no-color.org/).
func effectiveNoColor(ui uiConfig, noColorFlag bool) bool {
	return ui.NoColor || noColorFlag
}

// syncWriter serializes concurrent writes to a shared io.Writer. Only
// stdout gets a per-name buffer (so it can be flushed in input order);
// stderr diagnostics have no ordering requirement across names, but the
// pool's workers still write to the same underlying writer concurrently
// -- without this, that's a data race (fatal under -race, and simply
// corrupted output for anything, like *bytes.Buffer, that isn't safe for
// concurrent use on its own).
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// runLookup validates flags/args once, resolves the output format and
// bootstrap resolver once, then looks domains up through a bounded worker
// pool (opts.Concurrency workers) — each domain's own outcome (0/1/2/3)
// is tracked and the worst wins overall. Results are buffered per name
// and flushed to stdout in input order once every worker finishes, so
// output never depends on completion order.
func runLookup(ctx context.Context, stdout, stderr io.Writer, domains []string, opts lookupOptions, ui uiConfig) error {
	if opts.FilePath != "" {
		if len(domains) > 0 {
			return usageError{fmt.Errorf("--file and names on the command line are mutually exclusive")}
		}
		r := stdin
		if opts.FilePath != "-" {
			f, err := os.Open(opts.FilePath) //nolint:gosec // a user-supplied path is the point of the flag
			if err != nil {
				return usageError{fmt.Errorf("--file: %w", err)}
			}
			defer func() { _ = f.Close() }()
			r = f
		}
		names, err := readNameList(r)
		if err != nil {
			return usageError{err}
		}
		if len(names) == 0 {
			return usageError{fmt.Errorf("--file: no names found in %s", opts.FilePath)}
		}
		domains = names
	}

	format, err := render.Select(opts.Output, render.IsTerminal(os.Stdout), effectiveNoColor(ui, opts.NoColor))
	if err != nil {
		return usageError{err}
	}
	if opts.Raw && !render.IsMachine(format) {
		return usageError{fmt.Errorf("--raw is only meaningful with -o json or -o ndjson")}
	}
	if format == render.FormatJSON && len(domains) > 1 {
		return usageError{fmt.Errorf("-o json supports exactly one domain; use -o ndjson for multiple")}
	}
	if opts.DiffPath != "" && len(domains) != 1 {
		return usageError{fmt.Errorf("--diff supports exactly one name")}
	}
	if opts.Concurrency < 1 {
		return usageError{fmt.Errorf("--concurrency must be at least 1")}
	}
	sources, err := parseSourceFilter(opts.SourceFilter)
	if err != nil {
		return usageError{err}
	}

	// Exactly one Client per run, shared by every name in the pool below.
	// That is load-bearing, not incidental: the per-server WHOIS pacing
	// limiter and the IANA referral cache live on the Client, so building
	// one per name would silently un-pace a bulk run and resume hammering
	// a single registry.
	//
	// Pacing is off for a single name and on from two names up -- the
	// same rule the pool used to apply when it owned the limiter. Pacing
	// protects a bulk run from hammering one server; a lone lookup has
	// nothing to protect anyone from, and it would pay a full interval
	// whenever a registry refers the registrar query back to the host the
	// chain already used for its IANA hop (example.com does exactly
	// that), which is a wait no one is served by.
	client, err := plat.New(ctx, plat.Options{
		Timeout:            opts.Timeout,
		Sources:            sources,
		NoFollow:           opts.NoFollow,
		RefreshBootstrap:   opts.RefreshBootstrap,
		WHOISIANAServer:    opts.whoisIANAServer,
		DisableWHOISPacing: len(domains) == 1,
	})
	// plat.New's only failure mode is loading the IANA RDAP bootstrap
	// data, so naming that in the message is accurate rather than a
	// guess; if New ever grows a second one, this wrap has to be revisited.
	if err != nil {
		return fmt.Errorf("resolving RDAP bootstrap: %w", err)
	}

	return runLookupPool(ctx, stdout, stderr, domains, opts, format, ui, client)
}

// runLookupPool builds the bounded worker pool (opts.Concurrency workers)
// and flushes results to stdout in input order, never completion order.
// Split out of runLookup so tests can drive this, the actual pool/ordering
// logic, directly against an already-built *plat.Client (e.g. one built
// with plat.Options.Resolver pointed at a fake RDAP server via
// bootstrap.NewResolver, exactly like every lookupOne test in
// lookupone_test.go already does) instead of going through runLookup's
// real bootstrap fetch/cache/embedded chain, which always hits the
// network or the embedded snapshot and can't be pointed at a hermetic
// fake. This is the same "escape hatch for tests" shape as
// lookupOptions.whoisIANAServer on the WHOIS side -- runLookup's real
// behavior is unchanged, this only names the seam.
//
// The client is built once per run, by runLookup, and shared by every
// worker here: the per-server WHOIS pacing limiter and the IANA referral
// cache live on it, so one client per name would un-pace the whole run.
func runLookupPool(ctx context.Context, stdout, stderr io.Writer, domains []string, opts lookupOptions, format render.Format, ui uiConfig, client *plat.Client) error {
	// Each name renders into its own buffer; buffers are flushed in input
	// order after every worker finishes, so output never depends on
	// completion order.
	bufs := make([]bytes.Buffer, len(domains))
	codes := make([]int, len(domains))

	// Workers run concurrently but share this one stderr writer -- unlike
	// stdout, diagnostics have no input-order requirement, but concurrent
	// unsynchronized writes to it are still a data race (and, for a
	// caller-supplied *bytes.Buffer as in tests, unsafe regardless of
	// ordering). syncStderr serializes those writes without touching
	// lookupOne's signature.
	syncStderr := &syncWriter{w: stderr}

	var g errgroup.Group
	g.SetLimit(opts.Concurrency)

	// The counter is shown only under the same TTY-and-human condition the
	// per-name spinners use, and only when there is more than one name --
	// a single name gets no counter and no pool-level spinner at all,
	// exactly as before this task. When the counter is active, every
	// worker's per-name spinner must be suppressed (SuppressSpinner):
	// otherwise a per-name spinner and this counter would both write
	// \r-prefixed lines to the same stderr row concurrently and produce
	// garbage.
	showCounter := ui.StderrTTY && format == render.FormatHuman && len(domains) > 1
	opts.SuppressSpinner = showCounter

	// done is incremented by every worker after lookupOne returns and read
	// by the counter's message function, which runs from RunFunc's
	// animation goroutine -- atomic.Int64 keeps both sides race-free
	// regardless of whether the counter is actually shown.
	var done atomic.Int64
	runPool := func() {
		for i, input := range domains {
			g.Go(func() error {
				codes[i] = lookupOne(ctx, &bufs[i], syncStderr, client, input, opts, format, ui)
				done.Add(1)
				return nil
			})
		}
		_ = g.Wait() // no worker returns a non-nil error; each records its own exit code
	}
	if showCounter {
		// syncStderr, not raw stderr: every worker's diagnostics
		// (reportLookupError, reached whenever a name errors) already
		// write through syncStderr concurrently with this animation
		// goroutine. Writing to raw stderr here races with those writes
		// and, even without -race, glues error text onto the counter's
		// in-progress line with no \r reset.
		spinner.RunFunc(syncStderr, func() string {
			return fmt.Sprintf("looking up... %d/%d", done.Load(), len(domains))
		}, runPool)
	} else {
		runPool()
	}

	worst := 0
	for i := range domains {
		if _, err := stdout.Write(bufs[i].Bytes()); err != nil {
			return err
		}
		if codes[i] > worst {
			worst = codes[i]
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

// lookupOne performs one name's normalize -> look up -> render-or-report
// flow and returns that name's exit code (0/2/1/3; 2 only for a per-name
// normalize failure). The library call -- which fans out to RDAP and
// WHOIS and merges the answers -- runs behind a
// spinner (on stderr) only when stderr is a real terminal, the output
// format is FormatHuman, and opts.SuppressSpinner is false — never for
// Plain/JSON/NDJSON, never when stderr is redirected even if stdout is a
// terminal, and never when runLookupPool's own bulk-run progress counter
// is already driving that stderr line (SuppressSpinner).
func lookupOne(ctx context.Context, stdout, stderr io.Writer, client *plat.Client, input string, opts lookupOptions, format render.Format, ui uiConfig) int {
	q, err := domain.Normalize(input)
	if err != nil {
		reportLookupError(stderr, format, input, err, nil, opts.Verbose, ui)
		return 2
	}

	// The --diff snapshot is loaded and validated here -- before any
	// network call -- rather than after the lookup succeeds. The
	// object-type and name it must match are already fully known from
	// the normalized query alone, so there is nothing to gain by
	// spending a real RDAP/WHOIS round trip only to reject a snapshot
	// that could never have matched.
	var prior *machine.Snapshot
	if opts.DiffPath != "" {
		snap, err := loadSnapshot(opts.DiffPath, q)
		if err != nil {
			reportLookupError(stderr, format, input, err, nil, opts.Verbose, ui)
			return 2
		}
		prior = &snap
	}

	switch q.Kind {
	case domain.KindIPv4, domain.KindIPv6:
		return lookupOneIP(ctx, stdout, stderr, client, q, opts, format, ui, prior)
	case domain.KindASN:
		return lookupOneASN(ctx, stdout, stderr, client, q, opts, format, ui, prior)
	default:
		return lookupOneDomain(ctx, stdout, stderr, client, q, opts, format, ui, prior)
	}
}

// diffObjectType and diffQueryName report what --diff's snapshot
// guardrail expects a matching snapshot to look like, derived from the
// normalized query alone -- object type is unambiguous from Kind, and
// diffQueryName is the display form used in the guardrail's mismatch
// message. For domains this is exactly what the registry echoes back
// (case differences only, which loadSnapshot tolerates via
// strings.EqualFold). For ASNs, RIR handles are the deterministic
// "AS"+number form regardless of source, so it's known up front too.
func diffObjectType(q domain.Query) string {
	switch q.Kind {
	case domain.KindIPv4, domain.KindIPv6:
		return "ip"
	case domain.KindASN:
		return "asn"
	default:
		return "domain"
	}
}

// article returns the indefinite article for an objectType value, so the
// --diff mismatch message reads "is an ip record" / "is an asn record",
// not "is a ip record" / "is a asn record".
func article(objectType string) string {
	switch objectType {
	case "ip", "asn":
		return "an"
	default:
		return "a"
	}
}

func diffQueryName(q domain.Query) string {
	switch q.Kind {
	case domain.KindIPv4, domain.KindIPv6:
		return q.IP.String()
	case domain.KindASN:
		return fmt.Sprintf("AS%d", q.ASN)
	default:
		return q.Name.Punycode
	}
}

// loadSnapshot reads the --diff snapshot and rejects one that does not
// match what q actually looked up. Refusing beats guessing: silently
// diffing example.com against a snapshot of iana.org would report every
// field as changed and look like a real result.
//
// The name check is type-aware rather than a single string compare.
// Domain and ASN snapshots store the same identifier the query itself
// carries (a domain name; an "AS"+number RIR handle), so an exact
// case-insensitive match is correct. An IP snapshot's Name is instead
// the registry's allocated CIDR block (e.g. "8.8.8.0/24"), never the
// literal address someone typed -- requiring an exact string match
// there would reject --diff's own most common usage: querying the same
// address twice. So for an IP query, a snapshot whose Name parses as a
// CIDR containing the queried address is accepted; anything else falls
// back to the exact match every other object type uses.
func loadSnapshot(path string, q domain.Query) (machine.Snapshot, error) {
	f, err := os.Open(path) //nolint:gosec // path is a user-supplied CLI argument, which is the point
	if err != nil {
		return machine.Snapshot{}, usageError{fmt.Errorf("--diff: %w", err)}
	}
	defer func() { _ = f.Close() }()

	snap, err := machine.Decode(f)
	if err != nil {
		switch {
		case errors.Is(err, machine.ErrMultipleRecords):
			return machine.Snapshot{}, usageError{fmt.Errorf("--diff requires a single -o json snapshot, not ndjson")}
		case errors.Is(err, machine.ErrUnsupportedSchema):
			return machine.Snapshot{}, usageError{fmt.Errorf("--diff snapshot has an unsupported schemaVersion: %w", err)}
		case errors.Is(err, machine.ErrUnknownObjectType):
			return machine.Snapshot{}, usageError{fmt.Errorf("--diff snapshot has an unrecognized objectType: %w", err)}
		}
		return machine.Snapshot{}, usageError{fmt.Errorf("--diff: %w", err)}
	}

	wantObjectType := diffObjectType(q)
	if snap.ObjectType != wantObjectType {
		return machine.Snapshot{}, usageError{fmt.Errorf(
			"--diff snapshot is %s %s record, but the query is %s %s",
			article(snap.ObjectType), snap.ObjectType, article(wantObjectType), wantObjectType)}
	}
	if !diffNameMatches(snap, q) {
		return machine.Snapshot{}, usageError{fmt.Errorf(
			"--diff snapshot is for %s, but the query is %s", snap.Name, diffQueryName(q))}
	}
	return snap, nil
}

// diffNameMatches implements loadSnapshot's type-aware name check --
// see loadSnapshot's doc comment for why IP needs CIDR-containment
// rather than a literal match.
func diffNameMatches(snap machine.Snapshot, q domain.Query) bool {
	if q.Kind == domain.KindIPv4 || q.Kind == domain.KindIPv6 {
		if prefix, err := netip.ParsePrefix(snap.Name); err == nil {
			return prefix.Contains(q.IP)
		}
	}
	return strings.EqualFold(snap.Name, diffQueryName(q))
}

// diffRender is --diff's compare-and-render step, shared by the domain,
// IP, and ASN lookup paths: it round-trips the fresh record through
// encode/Decode so both sides of the comparison went through exactly
// the same transformation, compares against prior, renders in the
// active format, and reports the resulting exit code (4 if anything
// changed, 0 otherwise). encode writes the fresh record in the exact
// -o json shape Decode expects -- machine.Encode, EncodeIP, or
// EncodeASN, supplied by the caller since each object type has its own.
func diffRender(w io.Writer, format render.Format, prior machine.Snapshot, encode func(io.Writer) error, ui uiConfig) (int, error) {
	var freshBuf bytes.Buffer
	if err := encode(&freshBuf); err != nil {
		return 0, err
	}
	fresh, err := machine.Decode(&freshBuf)
	if err != nil {
		return 0, err
	}

	changes := diff.Compare(prior.Fields(), fresh.Fields())

	switch format {
	case render.FormatJSON, render.FormatNDJSON:
		err = diff.RenderJSON(w, fresh.Name, changes)
	case render.FormatHuman:
		err = diff.RenderHuman(w, fresh.Name, changes, human.NewTheme(ui.Dark), ui.Width)
	default:
		err = diff.RenderPlain(w, fresh.Name, changes)
	}
	if err != nil {
		return 0, err
	}
	if len(changes) > 0 {
		return 4, nil
	}
	return 0, nil
}

// lookupOneDomain is lookupOne's KindDomain branch — the pre-M6 lookup
// flow, unchanged apart from being split out of lookupOne so it can share
// a signature shape with lookupOneIP.
func lookupOneDomain(ctx context.Context, stdout, stderr io.Writer, client *plat.Client, q domain.Query, opts lookupOptions, format render.Format, ui uiConfig, prior *machine.Snapshot) int {
	var res plat.Result
	var lookupErr error
	work := func() {
		res, lookupErr = client.Lookup(ctx, q.Name.Punycode)
	}
	if ui.StderrTTY && format == render.FormatHuman && !opts.SuppressSpinner {
		spinner.Run(stderr, "looking up "+q.Name.Punycode+"...", work)
	} else {
		work()
	}
	if res.Domain == nil {
		reportLookupError(stderr, format, q.Name.Punycode, lookupErr, nil, opts.Verbose, ui)
		return 3
	}
	record := *res.Domain

	code := deriveOutcome(record.Sources)
	if code == 0 {
		if prior != nil {
			dcode, err := diffRender(stdout, format, *prior, func(w io.Writer) error {
				return machine.Encode(w, record, machine.Options{})
			}, ui)
			if err != nil {
				reportLookupError(stderr, format, q.Name.Punycode, err, record.Sources, opts.Verbose, ui)
				return 3
			}
			return dcode
		}
		if err := renderRecord(stdout, format, record, opts.Raw, opts.Verbose, opts.ShowConflicts, opts.Quiet, ui); err != nil {
			reportLookupError(stderr, format, q.Name.Punycode, err, record.Sources, opts.Verbose, ui)
			return 3
		}
		return 0
	}
	reportLookupError(stderr, format, q.Name.Punycode, lookupOutcomeError(code, record.Sources), record.Sources, opts.Verbose, ui)
	return code
}

// lookupOneIP is lookupOne's KindIPv4/KindIPv6 branch: the IP counterpart
// of lookupOneDomain, sharing the same look-up -> render-or-report shape.
// The kind-specific fan-out (two sources, no registrar hop) happens inside
// the library, which returns the merged record in Result.IP. deriveOutcome/
// lookupOutcomeError operate on []model.SourceResult, which model.IPRecord
// carries just like model.Record, so both are reused unchanged -- exit
// codes stay consistent between the domain and IP paths.
func lookupOneIP(ctx context.Context, stdout, stderr io.Writer, client *plat.Client, q domain.Query, opts lookupOptions, format render.Format, ui uiConfig, prior *machine.Snapshot) int {
	var res plat.Result
	var lookupErr error
	work := func() {
		res, lookupErr = client.Lookup(ctx, q.Input)
	}
	if ui.StderrTTY && format == render.FormatHuman && !opts.SuppressSpinner {
		spinner.Run(stderr, "looking up "+q.Input+"...", work)
	} else {
		work()
	}
	if res.IP == nil {
		reportLookupError(stderr, format, q.Input, lookupErr, nil, opts.Verbose, ui)
		return 3
	}
	record := *res.IP

	code := deriveOutcome(record.Sources)
	if code == 0 {
		if prior != nil {
			dcode, err := diffRender(stdout, format, *prior, func(w io.Writer) error {
				return machine.EncodeIP(w, record, machine.Options{})
			}, ui)
			if err != nil {
				reportLookupError(stderr, format, q.Input, err, record.Sources, opts.Verbose, ui)
				return 3
			}
			return dcode
		}
		if err := renderIPRecord(stdout, format, record, opts.Raw, opts.Verbose, opts.ShowConflicts, opts.Quiet, ui); err != nil {
			reportLookupError(stderr, format, q.Input, err, record.Sources, opts.Verbose, ui)
			return 3
		}
		return 0
	}
	reportLookupError(stderr, format, q.Input, lookupOutcomeError(code, record.Sources), record.Sources, opts.Verbose, ui)
	return code
}

// lookupOneASN is lookupOne's KindASN branch: the ASN counterpart of
// lookupOneIP, sharing the same look-up -> render-or-report shape. The
// kind-specific fan-out (two sources, no registrar hop) happens inside the
// library, which returns the merged record in Result.ASN.
// deriveOutcome/lookupOutcomeError
// operate on []model.SourceResult, which model.ASNRecord carries just like
// model.Record and model.IPRecord, so both are reused unchanged -- exit
// codes stay consistent across the domain, IP, and ASN paths.
func lookupOneASN(ctx context.Context, stdout, stderr io.Writer, client *plat.Client, q domain.Query, opts lookupOptions, format render.Format, ui uiConfig, prior *machine.Snapshot) int {
	var res plat.Result
	var lookupErr error
	work := func() {
		res, lookupErr = client.Lookup(ctx, q.Input)
	}
	if ui.StderrTTY && format == render.FormatHuman && !opts.SuppressSpinner {
		spinner.Run(stderr, "looking up "+q.Input+"...", work)
	} else {
		work()
	}
	if res.ASN == nil {
		reportLookupError(stderr, format, q.Input, lookupErr, nil, opts.Verbose, ui)
		return 3
	}
	record := *res.ASN

	code := deriveOutcome(record.Sources)
	if code == 0 {
		if prior != nil {
			dcode, err := diffRender(stdout, format, *prior, func(w io.Writer) error {
				return machine.EncodeASN(w, record, machine.Options{})
			}, ui)
			if err != nil {
				reportLookupError(stderr, format, q.Input, err, record.Sources, opts.Verbose, ui)
				return 3
			}
			return dcode
		}
		if err := renderASNRecord(stdout, format, record, opts.Raw, opts.Verbose, opts.ShowConflicts, opts.Quiet, ui); err != nil {
			reportLookupError(stderr, format, q.Input, err, record.Sources, opts.Verbose, ui)
			return 3
		}
		return 0
	}
	reportLookupError(stderr, format, q.Input, lookupOutcomeError(code, record.Sources), record.Sources, opts.Verbose, ui)
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

func renderRecord(w io.Writer, format render.Format, record model.Record, raw, verbose, showConflicts, quiet bool, ui uiConfig) error {
	if quiet && !render.IsMachine(format) {
		summary := human.QuietSummary(record)
		if summary == "" {
			_, err := fmt.Fprintln(w, record.Domain.Value)
			return err
		}
		_, err := fmt.Fprintf(w, "%s: %s\n", record.Domain.Value, summary)
		return err
	}
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

// renderIPRecord is renderRecord's IP counterpart. -q's one-line summary
// has no lock/expiry/lifecycle verdict to report (an IP allocation has
// none of those), so it degrades to "<cidr> · <org name>", falling back
// to whichever of the two is actually present, and finally to the record's
// handle if neither is -- mirroring renderRecord's own always-print-
// something-identifying behavior for a quiet summary with nothing to say.
func renderIPRecord(w io.Writer, format render.Format, rec model.IPRecord, raw, verbose, showConflicts, quiet bool, ui uiConfig) error {
	if quiet && !render.IsMachine(format) {
		_, err := fmt.Fprintln(w, ipQuietSummary(rec))
		return err
	}
	switch format {
	case render.FormatJSON:
		return machine.EncodeIP(w, rec, machine.Options{Raw: raw})
	case render.FormatNDJSON:
		return machine.EncodeIPNDJSON(w, rec, machine.Options{Raw: raw})
	case render.FormatHuman:
		return human.RenderIP(w, rec, human.Options{Theme: human.NewTheme(ui.Dark), Width: ui.Width, Verbose: verbose, ShowConflicts: showConflicts})
	default: // FormatPlain
		return plain.RenderIP(w, rec, plain.Options{Verbose: verbose, ShowConflicts: showConflicts})
	}
}

// ipQuietSummary builds -q's one-line "<cidr> · <org name>" summary for an
// IP lookup, degrading gracefully when either half is absent: just the
// other half alone, or the handle if neither CIDR nor org name came back
// from any source.
func ipQuietSummary(rec model.IPRecord) string {
	cidr := rec.CIDR.Value
	org := rec.Org.Name.Value
	switch {
	case cidr != "" && org != "":
		return cidr + " · " + org
	case cidr != "":
		return cidr
	case org != "":
		return org
	case rec.Handle.Value != "":
		return rec.Handle.Value
	default:
		return "no data"
	}
}

// renderASNRecord is renderRecord's ASN counterpart, mirroring
// renderIPRecord's shape. -q's one-line summary has no lock/expiry/
// lifecycle verdict to report (an autonomous system allocation has none of
// those either), so it degrades the same way ipQuietSummary does.
func renderASNRecord(w io.Writer, format render.Format, rec model.ASNRecord, raw, verbose, showConflicts, quiet bool, ui uiConfig) error {
	if quiet && !render.IsMachine(format) {
		_, err := fmt.Fprintln(w, asnQuietSummary(rec))
		return err
	}
	switch format {
	case render.FormatJSON:
		return machine.EncodeASN(w, rec, machine.Options{Raw: raw})
	case render.FormatNDJSON:
		return machine.EncodeASNNDJSON(w, rec, machine.Options{Raw: raw})
	case render.FormatHuman:
		return human.RenderASN(w, rec, human.Options{Theme: human.NewTheme(ui.Dark), Width: ui.Width, Verbose: verbose, ShowConflicts: showConflicts})
	default: // FormatPlain
		return plain.RenderASN(w, rec, plain.Options{Verbose: verbose, ShowConflicts: showConflicts})
	}
}

// asnQuietSummary builds -q's one-line "<handle> · <org name>" summary for
// an ASN lookup, degrading gracefully when either half is absent: just the
// other half alone, or the name if neither handle nor org name came back
// from any source -- mirroring ipQuietSummary's identical reasoning.
func asnQuietSummary(rec model.ASNRecord) string {
	handle := rec.Handle.Value
	org := rec.Org.Name.Value
	switch {
	case handle != "" && org != "":
		return handle + " · " + org
	case handle != "":
		return handle
	case org != "":
		return org
	case rec.Name.Value != "":
		return rec.Name.Value
	default:
		return "no data"
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
	switch model.Classify(sources) {
	case model.OutcomeOK:
		return 0
	case model.OutcomeNotFound:
		return 1
	default:
		return 3
	}
}

// parseSourceFilter translates the --source flag's friendly value into
// the 2-element model.SourceID slice plat.Options.Sources expects.
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
