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

// query performs one TCP round-trip: dial server (appending the default
// port 43 if server doesn't already specify one), send the quirk-adjusted
// query for domain, and read the response to EOF. Bounded to 1 MiB to
// defend against a runaway or hostile server.
func (c *Client) query(ctx context.Context, server, domain string) (string, error) {
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
