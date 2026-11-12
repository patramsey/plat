package whois

import (
	"context"
	"fmt"
	"net"
)

// referralKey marks a context whose connection goes to a server named by
// a WHOIS or RDAP answer rather than by the caller.
type referralKey struct{}

func withReferral(ctx context.Context) context.Context {
	return context.WithValue(ctx, referralKey{}, true)
}

func isReferral(ctx context.Context) bool {
	v, _ := ctx.Value(referralKey{}).(bool)
	return v
}

// checkReferral reports whether server, named by an answer, may be
// queried. A referral is followed only on port 43: no real one names a
// port, and one that does is an answer choosing which service on the
// caller's network plat connects to (GHSA-8q76-8r67-p8g8). Servers the
// caller configures are not checked, so a WHOIS mirror keeps its port.
func checkReferral(server string) error {
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		host, port = server, "43"
	}
	if !isWHOISHost(host) {
		return fmt.Errorf("whois: refusing referral to %q: not a host name", server)
	}
	if port != "43" {
		return fmt.Errorf("whois: refusing referral to %s: a referral is followed only on port 43", server)
	}
	return nil
}

// followReferral queries server, named by an earlier answer, through
// hop. A referral checkReferral rejects becomes a failed Hop that never
// touches the network, so -v shows why the chain stopped.
func (c *Client) followReferral(ctx context.Context, server string, hop func(context.Context, string) Hop) Hop {
	if err := checkReferral(server); err != nil {
		return Hop{Server: server, Err: err}
	}
	return hop(withReferral(ctx), server)
}
