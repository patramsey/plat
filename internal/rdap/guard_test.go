package rdap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"testing"

	"github.com/patramsey/plat/internal/netguard"
)

// rdapServer serves the recorded example.com answer and counts requests.
func rdapServer(t *testing.T, hits *int32) *httptest.Server {
	t.Helper()
	fixture, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(hits, 1)
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(fixture)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestDomainURL_DefaultClientRefusesNonPublicAddress: a registrar link
// is chosen by a registry's answer, so with plat's default client it may
// not reach a loopback address. The server never sees the request.
func TestDomainURL_DefaultClientRefusesNonPublicAddress(t *testing.T) {
	var hits int32
	srv := rdapServer(t, &hits)

	_, err := (&Client{}).DomainURL(context.Background(), srv.URL+"/domain/example.com")
	var refused *netguard.RefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("err = %v, want a netguard refusal", err)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("server saw %d request(s), want 0", n)
	}
}

// TestGuardedClient_RefusesNonPublicAddress checks the guard lives in the
// guarded client's transport rather than in DomainURL. A redirect is a
// new request on that same transport, so a registrar server cannot bounce
// plat onto a private address either. A test cannot redirect for real: a
// guarded client can never reach an httptest server to be redirected,
// since they all listen on loopback.
func TestGuardedClient_RefusesNonPublicAddress(t *testing.T) {
	var hits int32
	target := rdapServer(t, &hits)
	hc, _ := guarded.clientFor(defaultHTTP)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, target.URL+"/domain/example.com", nil)
	_, err := hc.Do(req)
	var refused *netguard.RefusedError
	if !errors.As(err, &refused) || atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("guarded client: err = %v, hits = %d; want a refusal and no request", err, hits)
	}
}

// TestDomain_ConfiguredServerIsNotGuarded: the registry query goes to a
// base URL from bootstrap data or the caller's Resolver -- a private RDAP
// mirror is allowed -- so only the registrar link is checked.
func TestDomain_ConfiguredServerIsNotGuarded(t *testing.T) {
	var hits int32
	srv := rdapServer(t, &hits)

	if _, err := (&Client{}).Domain(context.Background(), srv.URL, "example.com"); err != nil {
		t.Fatalf("registry query to a configured loopback server: %v", err)
	}
}

// TestDomainURL_ProxyBypassesGuard: with a proxy configured, the proxy
// resolves the destination, so plat sends the request through it rather
// than refusing a destination it cannot see. The test proxy is the
// server itself, which answers any URL with the fixture.
func TestDomainURL_ProxyBypassesGuard(t *testing.T) {
	var hits int32
	srv := rdapServer(t, &hits)
	proxyURL, _ := url.Parse(srv.URL)
	saved, savedProxy := defaultHTTP, proxyFor
	t.Cleanup(func() { defaultHTTP, proxyFor = saved, savedProxy })
	proxyFor = http.ProxyURL(proxyURL)
	defaultHTTP = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	if _, err := (&Client{}).DomainURL(context.Background(), "http://rdap.registrar.test/domain/example.com"); err != nil {
		t.Fatalf("DomainURL through a proxy: %v", err)
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("proxy saw %d request(s), want 1", n)
	}
}

// TestDomain_GuardAllRefusesNonPublicRegistry: with base URLs from IANA's
// bootstrap data, every RDAP server is public, so GuardAll guards the
// registry query too -- and with it any redirect the registry sends.
func TestDomain_GuardAllRefusesNonPublicRegistry(t *testing.T) {
	var hits int32
	srv := rdapServer(t, &hits)

	_, err := (&Client{GuardAll: true}).Domain(context.Background(), srv.URL, "example.com")
	var refused *netguard.RefusedError
	if !errors.As(err, &refused) || atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("err = %v, hits = %d; want a refusal and no request", err, hits)
	}
}

// TestDomain_GuardAllLeavesCallerClientAlone: a caller's client is its
// own policy, GuardAll or not.
func TestDomain_GuardAllLeavesCallerClientAlone(t *testing.T) {
	var hits int32
	srv := rdapServer(t, &hits)

	if _, err := (&Client{GuardAll: true, HTTP: srv.Client()}).Domain(context.Background(), srv.URL, "example.com"); err != nil {
		t.Fatalf("caller's client: %v", err)
	}
}
