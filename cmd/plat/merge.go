package main

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/patramsey/plat/internal/bootstrap"
	"github.com/patramsey/plat/internal/collect"
	"github.com/patramsey/plat/internal/domain"
	"github.com/patramsey/plat/internal/merge"
	"github.com/patramsey/plat/internal/model"
)

// newMergeCommand builds the hidden `plat merge <domain>` debug/demo
// subcommand. It is Hidden (off --help) for the same reason M2's `whois`
// subcommand is: proper --source/-o wiring into the root command is
// reserved for a later milestone (M4); this exists to prove the merge
// engine end to end during development.
func newMergeCommand(stdout io.Writer) *cobra.Command {
	var timeout time.Duration
	var noFollow bool

	cmd := &cobra.Command{
		Use:    "merge <domain|ip>",
		Short:  "Look up domain or IP ownership via merged RDAP+WHOIS sources (debug/demo command)",
		Hidden: true,
		Args: func(cmd *cobra.Command, cliArgs []string) error {
			if len(cliArgs) != 1 {
				return usageError{fmt.Errorf("expected exactly one domain argument, got %d", len(cliArgs))}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, cliArgs []string) error {
			return mergeLookup(cmd.Context(), stdout, cliArgs[0], timeout, noFollow)
		},
	}
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "per-source timeout for RDAP and WHOIS lookups")
	cmd.Flags().BoolVar(&noFollow, "no-follow", false, "skip the registrar RDAP related-link hop")
	return cmd
}

func mergeLookup(ctx context.Context, stdout io.Writer, input string, timeout time.Duration, noFollow bool) error {
	q, err := domain.Normalize(input)
	if err != nil {
		return usageError{err}
	}

	resolver, err := bootstrap.Load(ctx, bootstrap.Options{Timeout: timeout})
	if err != nil {
		return fmt.Errorf("resolving RDAP bootstrap: %w", err)
	}

	if q.Kind == domain.KindIPv4 || q.Kind == domain.KindIPv6 {
		baseURL, _ := resolver.IPBaseURL(q.IP) // "" is fine — CollectIP degrades to WHOIS-only
		sources := collect.CollectIP(ctx, q.IP, baseURL, "", collect.Options{Timeout: timeout})
		record := merge.MergeIP(sources)
		return printIPRecord(stdout, record)
	}

	baseURL, _ := resolver.BaseURL(q.Name.TLD) // "" is fine — Collect degrades to WHOIS-only

	sources := collect.Collect(ctx, q.Name, baseURL, "", collect.Options{NoFollow: noFollow, Timeout: timeout})
	record := merge.Merge(sources)

	return printRecord(stdout, record)
}

func printRecord(stdout io.Writer, r model.Record) error {
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	printField(tw, "Domain", r.Domain)
	printField(tw, "Handle", r.Handle)
	printField(tw, "Registrar", r.Registrar.Name)
	printField(tw, "Registrar IANA ID", r.Registrar.IANAID)
	printField(tw, "Abuse Email", r.Registrar.AbuseEmail)
	printField(tw, "Abuse Phone", r.Registrar.AbusePhone)
	if r.Status.Present() {
		_, _ = fmt.Fprintf(tw, "Status:\t%v\t%v\n", r.Status.Value, r.Status.Sources)
	}
	printTimeField(tw, "Created", r.Created)
	printTimeField(tw, "Updated", r.Updated)
	printTimeField(tw, "Expires", r.Expires)
	if r.Nameservers.Present() {
		_, _ = fmt.Fprintf(tw, "Nameservers:\t%v\t%v\n", r.Nameservers.Value, r.Nameservers.Sources)
	}
	_, _ = fmt.Fprintln(tw, "---")
	for _, s := range r.Sources {
		status := "ok"
		if !s.OK {
			status = s.Err
		}
		_, _ = fmt.Fprintf(tw, "Source %s:\t%s\t%s\n", s.Source, s.Latency.Round(time.Millisecond), status)
	}
	if len(r.Conflicts) > 0 {
		_, _ = fmt.Fprintln(tw, "---")
		for _, c := range r.Conflicts {
			_, _ = fmt.Fprintf(tw, "Conflict %s:\t%v\n", c.Field, c.Values)
		}
	}
	if len(r.Redacted) > 0 {
		_, _ = fmt.Fprintln(tw, "---")
		for _, red := range r.Redacted {
			_, _ = fmt.Fprintf(tw, "Redacted %s:\t%s (%s)\n", red.Field, red.Source, red.Reason)
		}
	}
	return tw.Flush()
}

// printIPRecord is printRecord's IP counterpart: same tabwriter-based
// debug dump, but over model.IPRecord's field set (no registrar,
// nameservers, or expiry -- an IP allocation has none of those).
func printIPRecord(stdout io.Writer, r model.IPRecord) error {
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	printField(tw, "Handle", r.Handle)
	printField(tw, "Name", r.Name)
	printField(tw, "Type", r.Type)
	printField(tw, "Start address", r.StartAddress)
	printField(tw, "End address", r.EndAddress)
	printField(tw, "CIDR", r.CIDR)
	printField(tw, "IP version", r.IPVersion)
	printField(tw, "Parent handle", r.ParentHandle)
	printField(tw, "Country", r.Country)
	printField(tw, "Org name", r.Org.Name)
	printField(tw, "Org ID", r.Org.ID)
	printField(tw, "Abuse email", r.Org.AbuseEmail)
	printField(tw, "Abuse phone", r.Org.AbusePhone)
	if r.Status.Present() {
		_, _ = fmt.Fprintf(tw, "Status:\t%v\t%v\n", r.Status.Value, r.Status.Sources)
	}
	printTimeField(tw, "Registered", r.Registered)
	printTimeField(tw, "Updated", r.Updated)
	_, _ = fmt.Fprintln(tw, "---")
	for _, s := range r.Sources {
		status := "ok"
		if !s.OK {
			status = s.Err
		}
		_, _ = fmt.Fprintf(tw, "Source %s:\t%s\t%s\n", s.Source, s.Latency.Round(time.Millisecond), status)
	}
	if len(r.Conflicts) > 0 {
		_, _ = fmt.Fprintln(tw, "---")
		for _, c := range r.Conflicts {
			_, _ = fmt.Fprintf(tw, "Conflict %s:\t%v\n", c.Field, c.Values)
		}
	}
	if len(r.Redacted) > 0 {
		_, _ = fmt.Fprintln(tw, "---")
		for _, red := range r.Redacted {
			_, _ = fmt.Fprintf(tw, "Redacted %s:\t%s (%s)\n", red.Field, red.Source, red.Reason)
		}
	}
	return tw.Flush()
}

func printField(tw *tabwriter.Writer, label string, f model.Field[string]) {
	if !f.Present() {
		return
	}
	_, _ = fmt.Fprintf(tw, "%s:\t%s\t%v\n", label, f.Value, f.Sources)
}

func printTimeField(tw *tabwriter.Writer, label string, f model.Field[model.TimeValue]) {
	if !f.Present() {
		return
	}
	if f.Value.Parsed {
		_, _ = fmt.Fprintf(tw, "%s:\t%s\t%v\n", label, f.Value.Time.Format(time.RFC3339), f.Sources)
	} else {
		_, _ = fmt.Fprintf(tw, "%s:\t%s (unparsed)\t%v\n", label, f.Value.Raw, f.Sources)
	}
}
