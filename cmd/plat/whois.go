package main

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/patramsey/plat/internal/domain"
	"github.com/patramsey/plat/internal/whois"
)

// newWhoisCommand builds the hidden `plat whois <domain>` debug/demo
// subcommand. It is Hidden (off --help) because proper --source whois
// wiring into the root command is reserved for a later milestone; this
// exists to prove the WHOIS engine end to end during development.
func newWhoisCommand(stdout io.Writer) *cobra.Command {
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:    "whois <domain>",
		Short:  "Look up domain ownership via WHOIS (debug/demo command)",
		Hidden: true,
		Args: func(cmd *cobra.Command, cliArgs []string) error {
			if len(cliArgs) != 1 {
				return usageError{fmt.Errorf("expected exactly one domain argument, got %d", len(cliArgs))}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, cliArgs []string) error {
			return whoisLookup(cmd.Context(), stdout, cliArgs[0], timeout)
		},
	}
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "per-hop timeout for WHOIS queries")
	return cmd
}

func whoisLookup(ctx context.Context, stdout io.Writer, input string, timeout time.Duration) error {
	q, err := domain.Normalize(input)
	if err != nil {
		return usageError{err}
	}
	if q.Kind != domain.KindDomain {
		// Replaced with a real IP lookup in the final task of this plan.
		return usageError{fmt.Errorf("plat: IP lookups are not wired up yet")}
	}

	client := &whois.Client{Timeout: timeout}
	result, err := client.Lookup(ctx, q.Name)
	if err != nil {
		return err
	}

	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	for i, h := range result.Hops {
		status := "ok"
		if h.Err != nil {
			status = h.Err.Error()
		}
		_, _ = fmt.Fprintf(tw, "Hop %d:\t%s\t%s\t%s\n", i+1, h.Server, h.Latency.Round(time.Millisecond), status)
	}
	if deepest := result.Deepest(); deepest != nil {
		_, _ = fmt.Fprintf(tw, "Registrar:\t%s\n", deepest.Fields.Registrar)
		_, _ = fmt.Fprintf(tw, "Domain status:\t%v\n", deepest.Fields.Statuses)
		_, _ = fmt.Fprintf(tw, "Nameservers:\t%v\n", deepest.Fields.Nameservers)
	}
	return tw.Flush()
}
