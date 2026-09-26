package whois

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/domain"
)

// startGatedListener is startListener's sibling (see client_test.go):
// instead of responding immediately, it closes started once a connection
// arrives and then blocks until release is closed, so a test can hold a
// query open for as long as it needs another goroutine to observe and
// react to it being in flight.
func startGatedListener(t *testing.T, started, release chan struct{}, reply string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		close(started)
		<-release
		_, _ = conn.Write([]byte(reply))
	}()
	return ln.Addr().String()
}

// TestClient_IANAHopCreditsBlockedWaitToInheritingCallersBudget pins
// ianaHop's creditChain(ctx, blocked) call at referral.go:68. Deleting it
// leaves the rest of the suite green: a name that loses the IANACache
// singleflight race for a TLD still gets the winner's result, but the
// time it spent blocked waiting for that result is never credited back
// to its own chain budget, so under a busy shared limiter its later hops
// can silently run out of budget and that name loses its registry-WHOIS
// source.
//
// This does not depend on measuring how long anything actually took, or
// on racing a duration against a threshold: withChain's budget is a
// concrete time.Time stored on the chain value ctx carries, readable
// directly via chainDeadline. Crediting is "add the blocked duration to
// that time.Time"; the deleted call is "don't". So the caller that
// blocked either has a chain deadline strictly later than the one it
// started with (credited), or the exact same one it started with
// (uncredited, since nothing else in resolve/ianaHop ever touches it) --
// an equality check, not a margin.
//
// The blocked caller is forced to actually block, deterministically, by
// gating the winning fetch's WHOIS response behind a channel this test
// controls: the winner's query cannot return until the test releases it,
// and the blocked caller cannot reach that release until it has already
// joined the singleflight group, so "was it blocked at all" never
// depends on scheduling luck.
func TestClient_IANAHopCreditsBlockedWaitToInheritingCallersBudget(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	addr := startGatedListener(t, started, release, "refer: whois.example-registry.test\n")

	c := &Client{IANAServer: addr, Timeout: 2 * time.Second, IANACache: NewIANACache()}

	winnerDone := make(chan struct{})
	go func() {
		defer close(winnerDone)
		c.ianaHop(withChain(context.Background(), time.Second), "test")
	}()

	// Once the winner's query has reached the gated listener, the cache
	// is still cold (nothing is written to it until the winner's fetch
	// returns), so the call below cannot take the fast path -- it must
	// join the winner's singleflight call, making it deterministically
	// the blocked/inheriting caller. release is held closed for another
	// `held` beyond that so the join below is never racing the winner's
	// own completion -- the same shape ianacache_test.go's
	// TestIANACache_ReportsBlockedTimeOnlyForInheritedFetches uses to
	// force a real, non-zero block.
	<-started
	const held = 50 * time.Millisecond
	go func() {
		time.Sleep(held)
		close(release)
	}()

	blockedCtx := withChain(context.Background(), time.Second)
	before, ok := chainDeadline(blockedCtx)
	if !ok {
		t.Fatal("chainDeadline reported no budget for a ctx built by withChain")
	}

	hop := c.ianaHop(blockedCtx, "test")
	<-winnerDone

	if !strings.Contains(hop.Fields.Refer, "example-registry.test") {
		t.Fatalf("inherited hop.Fields.Refer = %q, want the winner's refer: target -- this caller never reached the network itself", hop.Fields.Refer)
	}

	after, _ := chainDeadline(blockedCtx)
	if !after.After(before) {
		t.Errorf("chain deadline after inheriting a blocked IANA fetch = %v, want strictly later than %v -- "+
			"the time this caller spent blocked on the winner's fetch must be credited back to its chain budget "+
			"(referral.go's creditChain(ctx, blocked) call in ianaHop), or a busy shared limiter can silently "+
			"starve this name's later hops of the budget they were promised", after, before)
	}
}

// withRegistryFallback points tld's fallback registry server at addr for
// the duration of the test, so the fallback path can be exercised against
// a local listener instead of the real registry.
func withRegistryFallback(t *testing.T, tld, addr string) {
	t.Helper()
	orig := registryFallback
	registryFallback = map[string]string{tld: addr}
	t.Cleanup(func() { registryFallback = orig })
}

// IANA's record for .uk has carried an empty "whois:" line since
// 2026-08-04, though whois.nic.uk still answers. Without a fallback the
// chain stopped at IANA and a .uk lookup had RDAP as its only source.
func TestClient_LookupFallsBackWhenIANAListsNoServer(t *testing.T) {
	registryAddr := startListener(t, func(query string) string {
		return "\n    Domain name:\n        bbc.co.uk\n"
	})
	ianaAddr := startListener(t, func(query string) string {
		return "domain:       UK\nwhois:        \nstatus:       ACTIVE\n"
	})
	withRegistryFallback(t, "uk", registryAddr)

	q, err := domain.Normalize("bbc.co.uk")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	c := &Client{IANAServer: ianaAddr, Timeout: 2 * time.Second}
	result, err := c.Lookup(context.Background(), q.Name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(result.Hops) != 2 {
		t.Fatalf("got %d hops, want 2 (IANA, then the fallback registry server)", len(result.Hops))
	}
	if got := result.Hops[1].Server; got != registryAddr {
		t.Errorf("registry hop server = %q, want fallback %q", got, registryAddr)
	}
	if got := result.Hops[1].Fields.Domain; got != "bbc.co.uk" {
		t.Errorf("registry hop Domain = %q, want bbc.co.uk", got)
	}
}

// The fallback table only fills a gap; it must never override a server
// IANA does name, or a stale entry would outlive a registry's move.
func TestClient_LookupPrefersIANAReferralOverFallback(t *testing.T) {
	registryAddr := startListener(t, func(query string) string {
		return "Domain Name: example.uk\n"
	})
	ianaAddr := startListener(t, func(query string) string {
		return "refer: " + registryAddr + "\n"
	})
	withRegistryFallback(t, "uk", "127.0.0.1:1")

	q, err := domain.Normalize("example.uk")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	c := &Client{IANAServer: ianaAddr, Timeout: 2 * time.Second}
	result, err := c.Lookup(context.Background(), q.Name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(result.Hops) != 2 || result.Hops[1].Server != registryAddr {
		t.Fatalf("hops = %+v, want registry hop to IANA's referral %q", result.Hops, registryAddr)
	}
}

// .au's registry answers with "Registrar WHOIS Server: whois.auda.org.au"
// -- itself. Following it re-queried the registry and counted its answer
// a second time, as registrar-whois, overclaiming the provenance.
func TestClient_LookupSkipsRegistrarHopToTheRegistryItself(t *testing.T) {
	var registryAddr string
	registryAddr = startListener(t, func(query string) string {
		return "Domain Name: google.com.au\nRegistrar WHOIS Server: " + registryAddr + "\n"
	})
	ianaAddr := startListener(t, func(query string) string {
		return "refer: " + registryAddr + "\n"
	})

	q, err := domain.Normalize("google.com.au")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	c := &Client{IANAServer: ianaAddr, Timeout: 2 * time.Second}
	result, err := c.Lookup(context.Background(), q.Name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(result.Hops) != 2 {
		t.Fatalf("got %d hops, want 2 (IANA, registry) -- the registrar referral names the registry itself", len(result.Hops))
	}
}

func TestSameWHOISServer(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		want bool
	}{
		{"whois.auda.org.au", "whois.auda.org.au", true},
		{"WHOIS.AUDA.ORG.AU.", "whois.auda.org.au", true},
		{"whois.auda.org.au:43", "whois.auda.org.au", true},
		{"whois.markmonitor.com", "whois.verisign-grs.com", false},
		{"127.0.0.1:1000", "127.0.0.1:2000", false},
	} {
		if got := sameWHOISServer(tt.a, tt.b); got != tt.want {
			t.Errorf("sameWHOISServer(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
