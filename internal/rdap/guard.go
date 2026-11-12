package rdap

import (
	"context"
	"net/http"
	"sync"

	"github.com/patramsey/plat/internal/netguard"
)

// referralKey marks a request whose URL an RDAP answer chose -- the
// registrar link a registry response names -- rather than the caller or
// IANA's bootstrap data.
type referralKey struct{}

func withReferral(ctx context.Context) context.Context {
	return context.WithValue(ctx, referralKey{}, true)
}

func isReferral(ctx context.Context) bool {
	v, _ := ctx.Value(referralKey{}).(bool)
	return v
}

// guarded is the client a referral request uses in place of the default
// one: the same transport settings, but every connection -- the first
// request and each redirect it follows -- goes through netguard, which
// refuses loopback, private and link-local addresses after resolution
// (GHSA-8q76-8r67-p8g8). It is built from defaultHTTP and rebuilt only
// if that changes, which only tests do. It has its own RSA fallback state,
// so a fallback retry is guarded too.
var guarded guardedState

type guardedState struct {
	mu       sync.Mutex
	base     *http.Client
	client   *http.Client
	fallback fallbackState
}

func (g *guardedState) clientFor(base *http.Client) (*http.Client, *fallbackState) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.client == nil || g.base != base {
		t, ok := base.Transport.(*http.Transport)
		if !ok || t == nil {
			t = http.DefaultTransport.(*http.Transport)
		}
		clone := t.Clone()
		clone.DialContext = netguard.Dialer().DialContext
		// guardedFor only hands out this client for a request with no
		// proxy configured, so a proxy here could only be a surprise.
		clone.Proxy = nil
		g.base = base
		g.client = &http.Client{Transport: clone, Timeout: base.Timeout, CheckRedirect: base.CheckRedirect, Jar: base.Jar}
		g.fallback = fallbackState{}
	}
	return g.client, &g.fallback
}

// proxyFor reports the proxy a default-client request would use. A
// variable so tests can configure one: net/http reads the environment
// only once per process.
var proxyFor = http.ProxyFromEnvironment

// clientFor returns the client and RSA fallback state req should use: the
// guarded one for a referral, or for any request when GuardAll is set.
// A caller's own client is used as given: its transport is its policy,
// as with TLS. With a proxy configured for req, the proxy resolves and
// connects to the destination, so plat cannot see the address; the
// request goes through the proxy unguarded rather than being refused.
func (c *Client) clientFor(req *http.Request) (*http.Client, *fallbackState) {
	if c.HTTP != nil || (!c.GuardAll && !isReferral(req.Context())) {
		return c.httpClient(), &tlsFallback
	}
	if proxy, err := proxyFor(req); err == nil && proxy != nil {
		return c.httpClient(), &tlsFallback
	}
	return guarded.clientFor(defaultHTTP)
}
