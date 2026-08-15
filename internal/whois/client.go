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
	// ChainTimeout, if > 0, additionally bounds the WHOLE referral chain
	// (IANA -> registry -> registrar) started by Lookup, LookupIP or
	// LookupASN -- but bounds only the time that chain spends talking to
	// servers. Deliberate idling does not count: a Limiter pacing wait,
	// and a wait on another name's in-flight IANACache fetch, are both
	// credited back to the budget rather than charged against it. Wall
	// time across the chain can therefore exceed ChainTimeout by however
	// long it sat idle waiting its turn; time on the wire cannot.
	//
	// That distinction is the whole point of the field. A bulk run's
	// shared HostLimiter hands out slots for one server at 0s, 1s, 2s...,
	// so with a plain whole-chain context.WithTimeout the Nth name to
	// want a busy server reaches its dial with an already-expired context
	// and loses that source before sending a byte -- silently, since a
	// WHOIS source failing is normal rather than fatal.
	//
	// Zero (the default) means no whole-chain bound at all: each hop is
	// bounded only by Timeout. That is the correct standalone behavior
	// for a Client used directly; internal/collect sets both fields.
	ChainTimeout time.Duration
	// Dialer is used to open each TCP connection. Defaults to &net.Dialer{}.
	Dialer *net.Dialer
	// Limiter paces outbound queries per server. nil means no pacing,
	// which is correct for a single lookup: one query to one server
	// needs no throttle. Bulk runs set it so every worker shares one.
	Limiter Limiter
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

// hopDeadline returns the instant a hop starting now must be finished
// by: its own per-hop budget (c.timeout()), shortened to whatever the
// chain budget has left when ctx carries one. Reading the chain budget
// here rather than nesting a context.WithTimeout inside a whole-chain
// context.WithTimeout is what lets pacing waits be credited back -- a
// context deadline, once set, cannot be pushed out.
func (c *Client) hopDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(c.timeout())
	if chainEnd, ok := chainDeadline(ctx); ok && chainEnd.Before(deadline) {
		return chainEnd
	}
	return deadline
}

// query performs one TCP round-trip: dial server (appending the default
// port 43 if server doesn't already specify one), send the quirk-adjusted
// query for domain, and read the response to EOF. Bounded to 1 MiB to
// defend against a runaway or hostile server.
func (c *Client) query(ctx context.Context, server, domain string) (string, error) {
	if c.Limiter != nil {
		// The wait is credited back to the chain budget before the hop
		// deadline is computed below, so a slot handed out later than
		// the budget is wide never costs this hop its dial. Crediting
		// happens whether or not Acquire succeeded: an aborted wait
		// still consumed wall clock the chain didn't spend on the wire.
		start := time.Now()
		err := c.Limiter.Acquire(ctx, server)
		creditChain(ctx, time.Since(start))
		if err != nil {
			return "", fmt.Errorf("whois: pacing %s: %w", server, err)
		}
	}

	addr := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		addr = net.JoinHostPort(server, "43")
	}

	ctx, cancel := context.WithDeadline(ctx, c.hopDeadline(ctx))
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
