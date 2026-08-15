package whois

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

// Client performs port-43 WHOIS lookups with IANA -> registry -> registrar
// referral chasing.
type Client struct {
	// IANAServer is the WHOIS server queried first to resolve a TLD's
	// registry server. Defaults to "whois.iana.org".
	IANAServer string
	// Timeout bounds each individual hop. Defaults to 5s.
	Timeout time.Duration
	// Dialer is used to open each TCP connection. Defaults to &net.Dialer{}.
	Dialer *net.Dialer
	// Limiter paces outbound queries per server. nil means no pacing,
	// which is correct for a single lookup: one query to one server
	// needs no throttle. Bulk runs set it so every worker shares one.
	Limiter Limiter
	// PacingCtx, if non-nil, is used instead of the ctx passed to query()
	// when acquiring a Limiter slot. This matters because the ctx a hop
	// runs under already carries the whole-chain deadline collect.go's
	// collectWHOIS (and its IP/ASN counterparts) applies with
	// context.WithTimeout -- if Acquire also waited on that ctx, a
	// pacing wait scheduled late in a run (HostLimiter hands out slots
	// at 0s, 1s, 2s...) would be charged against the same budget as the
	// actual network hops, and could exceed it before a single byte is
	// sent. PacingCtx should carry the run's cancellation (so an
	// interrupted run still aborts a pacing wait promptly) but not that
	// per-chain timeout. nil falls back to the ctx passed to query(),
	// which is correct whenever Limiter is also nil (a single lookup)
	// since nothing ever calls Acquire in that case.
	PacingCtx context.Context
	// IANACache, if non-nil, caches the WHOIS-server-per-TLD mapping
	// resolved from the IANA hop, shared across every concurrent lookup
	// in a bulk run -- see IANACache's doc comment. nil means no
	// caching, which is correct for a single lookup.
	IANACache *IANACache
}

func (c *Client) ianaServer() string {
	if c.IANAServer != "" {
		return c.IANAServer
	}
	return "whois.iana.org"
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 5 * time.Second
}

func (c *Client) dialer() *net.Dialer {
	if c.Dialer != nil {
		return c.Dialer
	}
	return &net.Dialer{}
}

// pacingCtx returns the context a Limiter.Acquire call should wait on:
// c.PacingCtx if set (see its doc comment), otherwise the ctx a hop
// actually runs under.
func (c *Client) pacingCtx(ctx context.Context) context.Context {
	if c.PacingCtx != nil {
		return c.PacingCtx
	}
	return ctx
}

// query performs one TCP round-trip: dial server (appending the default
// port 43 if server doesn't already specify one), send the quirk-adjusted
// query for domain, and read the response to EOF. Bounded to 1 MiB to
// defend against a runaway or hostile server.
func (c *Client) query(ctx context.Context, server, domain string) (string, error) {
	if c.Limiter != nil {
		if err := c.Limiter.Acquire(c.pacingCtx(ctx), server); err != nil {
			return "", fmt.Errorf("whois: pacing %s: %w", server, err)
		}
	}

	addr := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		addr = net.JoinHostPort(server, "43")
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	conn, err := c.dialer().DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("whois: dialing %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	q := BuildQuery(server, domain) + "\r\n"
	if _, err := conn.Write([]byte(q)); err != nil {
		return "", fmt.Errorf("whois: writing query to %s: %w", addr, err)
	}

	body, err := io.ReadAll(io.LimitReader(conn, 1<<20))
	if err != nil {
		return "", fmt.Errorf("whois: reading response from %s: %w", addr, err)
	}
	return string(body), nil
}
