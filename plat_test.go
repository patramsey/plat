package plat

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/whois"
)

// selfReferringWHOIS starts a fake WHOIS server that answers a whole
// referral chain from ONE host: the IANA hop is referred back to itself,
// and so is the registrar hop. That is not a contrivance -- example.com's
// registry response really does name whois.iana.org as the registrar
// WHOIS server, so a real single lookup hits one host three times. It is
// also the only shape that can tell paced from un-paced apart, since a
// limiter never delays the first query to a given server.
func selfReferringWHOIS(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	var hop int
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 4096)
				n, _ := conn.Read(buf)
				_ = strings.TrimRight(string(buf[:n]), "\r\n")
				mu.Lock()
				hop++
				n = hop
				mu.Unlock()
				var reply string
				switch n {
				case 1: // IANA hop: the TLD's registry server is this host
					reply = "refer: " + ln.Addr().String() + "\n"
				case 2: // registry hop: refers the registrar query back here
					reply = "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar, Inc.\n" +
						"Registrar WHOIS Server: " + ln.Addr().String() + "\n"
				default: // registrar hop: terminal, no further referral
					reply = "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar, Inc.\n"
				}
				_, _ = conn.Write([]byte(reply))
			}()
		}
	}()
	return ln.Addr().String()
}

func TestNew_DefaultsAreApplied(t *testing.T) {
	c, err := New(context.Background(), Options{
		DisableCache: true,
		Resolver:     NewResolver(map[string]string{}),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.opts.Timeout != defaultTimeout {
		t.Errorf("Timeout = %v, want %v", c.opts.Timeout, defaultTimeout)
	}
	if c.limiter == nil {
		t.Error("limiter is nil; bulk consumers would get no WHOIS pacing")
	}
	if c.ianaCache == nil {
		t.Error("ianaCache is nil")
	}
	if c.resolver == nil {
		t.Error("resolver is nil")
	}
}

func TestNew_WHOISIntervalDefaultsToPackageDefault(t *testing.T) {
	c, err := New(context.Background(), Options{
		DisableCache: true,
		Resolver:     NewResolver(map[string]string{}),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := c.interval; got != whois.DefaultWHOISInterval {
		t.Errorf("interval = %v, want %v", got, whois.DefaultWHOISInterval)
	}
}

func TestLookup_DomainReturnsDomainKind(t *testing.T) {
	fixture, err := os.ReadFile("testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	c, err := New(context.Background(), Options{
		DisableCache:    true,
		NoFollow:        true,
		Timeout:         2 * time.Second,
		Sources:         []SourceID{SourceRegistryRDAP},
		Resolver:        NewResolver(map[string]string{"com": srv.URL}),
		WHOISIANAServer: "127.0.0.1:1",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Lookup(context.Background(), "EXAMPLE.COM")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.Kind != KindDomain {
		t.Fatalf("Kind = %v, want KindDomain", res.Kind)
	}
	if res.Domain == nil {
		t.Fatal("Domain is nil for KindDomain")
	}
	if res.IP != nil || res.ASN != nil {
		t.Error("more than one record pointer is non-nil")
	}
	if res.Input != "EXAMPLE.COM" {
		t.Errorf("Input = %q, want the original input unmodified", res.Input)
	}
	if res.Domain.Domain.Value == "" {
		t.Error("merged record carries no domain name")
	}
}

func TestLookup_InvalidInputIsErrInvalidInput(t *testing.T) {
	c, err := New(context.Background(), Options{DisableCache: true, Resolver: NewResolver(map[string]string{})})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Lookup(context.Background(), "localhost"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput", err)
	}
}

func TestLookup_AllSourcesFailIsErrLookupFailed(t *testing.T) {
	c, err := New(context.Background(), Options{
		DisableCache:    true,
		NoFollow:        true,
		Timeout:         200 * time.Millisecond,
		Resolver:        NewResolver(map[string]string{"com": "http://127.0.0.1:1/dead"}),
		WHOISIANAServer: "127.0.0.1:1",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Lookup(context.Background(), "example.com"); !errors.Is(err, ErrLookupFailed) {
		t.Fatalf("err = %v, want ErrLookupFailed", err)
	}
}

func TestLookup_PartialSuccessIsNotAnError(t *testing.T) {
	fixture, err := os.ReadFile("testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	// RDAP answers; WHOIS is pointed at a dead port and will fail.
	c, err := New(context.Background(), Options{
		DisableCache:    true,
		NoFollow:        true,
		Timeout:         500 * time.Millisecond,
		Resolver:        NewResolver(map[string]string{"com": srv.URL}),
		WHOISIANAServer: "127.0.0.1:1",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("a failing source must not fail the lookup: %v", err)
	}
	var sawFailure bool
	for _, s := range res.Domain.Sources {
		if !s.OK && !s.NotFound {
			sawFailure = true
		}
	}
	if !sawFailure {
		t.Fatal("test did not exercise a failing source; it proves nothing")
	}
}

// TestLookup_PacingDelaysRepeatQueriesToOneServer is the load-bearing half
// of the pacing pair: a default client must space repeat queries to the
// same WHOIS host by the interval. Deleting the limiter (or storing a nil
// one) makes this test fail on elapsed time -- verified by running it
// against a client built with DisableWHOISPacing, which finishes in
// milliseconds.
func TestLookup_PacingDelaysRepeatQueriesToOneServer(t *testing.T) {
	const interval = 300 * time.Millisecond
	addr := selfReferringWHOIS(t)

	c, err := New(context.Background(), Options{
		DisableCache:    true,
		Timeout:         5 * time.Second,
		WHOISInterval:   interval,
		Resolver:        NewResolver(map[string]string{}), // no RDAP: WHOIS-only
		WHOISIANAServer: addr,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	start := time.Now()
	res, err := c.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	elapsed := time.Since(start)

	if res.Domain.Registrar.Name.Value == "" {
		t.Fatal("chain produced no registrar; the test never reached the paced hops")
	}
	// Three queries to one host: the first is free, the two after it each
	// wait a full interval.
	if want := 2 * interval; elapsed < want {
		t.Errorf("elapsed = %v, want >= %v -- repeat queries to one WHOIS server were not paced", elapsed, want)
	}
}

// TestLookup_DisableWHOISPacingSkipsTheWait covers the option the plat CLI
// sets for a single-name run. Two things must hold, and the first is the
// one a type error cannot catch: a client with no limiter must not panic.
// Storing a nil *whois.HostLimiter rather than a nil whois.Limiter would
// hand collect a non-nil interface wrapping a nil pointer, sail past its
// nil check, and panic inside Acquire -- so this test drives a full
// referral chain, which is where Acquire is actually called.
func TestLookup_DisableWHOISPacingSkipsTheWait(t *testing.T) {
	const interval = 300 * time.Millisecond
	addr := selfReferringWHOIS(t)

	c, err := New(context.Background(), Options{
		DisableCache:       true,
		DisableWHOISPacing: true,
		Timeout:            5 * time.Second,
		WHOISInterval:      interval,
		Resolver:           NewResolver(map[string]string{}),
		WHOISIANAServer:    addr,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.limiter != nil {
		t.Fatal("limiter is non-nil with DisableWHOISPacing set -- a nil *HostLimiter stored in the interface would panic in Acquire")
	}

	start := time.Now()
	res, err := c.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	elapsed := time.Since(start)

	if res.Domain.Registrar.Name.Value == "" {
		t.Fatal("chain produced no registrar; the test never reached the hops that would have been paced")
	}
	if elapsed >= interval {
		t.Errorf("elapsed = %v, want < %v -- pacing was not actually disabled", elapsed, interval)
	}
}
