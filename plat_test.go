package plat

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// selfReferringWHOISTwoHops is selfReferringWHOIS's shorter sibling: it
// answers only the IANA hop and the registry hop from one host, with no
// further registrar referral, so a chain against it hits that host
// exactly twice. That is the minimum shape that can observe pacing at
// all (a limiter never delays the first query), which keeps this test's
// added wait to one interval instead of selfReferringWHOIS's two.
func selfReferringWHOISTwoHops(t *testing.T) string {
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
				if n == 1 { // IANA hop: the TLD's registry server is this host
					reply = "refer: " + ln.Addr().String() + "\n"
				} else { // registry hop: terminal, no registrar referral
					reply = "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar, Inc.\n"
				}
				_, _ = conn.Write([]byte(reply))
			}()
		}
	}()
	return ln.Addr().String()
}

// TestNew_DefaultWHOISIntervalPacesQueries proves a default-constructed
// Client (WHOISInterval left zero) actually paces WHOIS queries at
// whois.DefaultWHOISInterval, by observing elapsed time rather than
// reading an internal field -- the same technique
// TestLookup_PacingDelaysRepeatQueriesToOneServer uses for an explicit
// interval. Asserting a stored copy of the interval, as a prior version
// of this test did, cannot catch New passing a different value to
// whois.NewHostLimiter than the one it records; this can.
func TestNew_DefaultWHOISIntervalPacesQueries(t *testing.T) {
	addr := selfReferringWHOISTwoHops(t)

	c, err := New(context.Background(), Options{
		DisableCache:    true,
		Timeout:         5 * time.Second,
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
		t.Fatal("chain produced no registrar; the test never reached the paced hop")
	}
	// Two queries to one host: the first is free, the second waits a
	// full interval -- the package default since WHOISInterval was left
	// zero.
	if elapsed < whois.DefaultWHOISInterval {
		t.Errorf("elapsed = %v, want >= %v -- the default WHOIS interval was not applied", elapsed, whois.DefaultWHOISInterval)
	}
}

// TestKindString locks Kind.String's output to the values documented as
// -o json's objectType, which internal/render/machine hardcodes
// independently ("domain"/"ip"/"asn") rather than calling this method --
// nothing else in the repo enforces that the two stay in sync.
func TestKindString(t *testing.T) {
	cases := []struct {
		k    Kind
		want string
	}{
		{KindDomain, "domain"},
		{KindIP, "ip"},
		{KindASN, "asn"},
	}
	for _, tc := range cases {
		if got := tc.k.String(); got != tc.want {
			t.Errorf("Kind(%d).String() = %q, want %q", tc.k, got, tc.want)
		}
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

// countingTransport records how many round trips it served, so a test can
// prove the caller's HTTPClient was the one actually used rather than
// merely that a lookup succeeded. Mirrors internal/collect/collect_test.go's
// helper of the same name/purpose, one layer up at the plat.Client boundary.
type countingTransport struct {
	n int
}

func (t *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.n++
	return http.DefaultTransport.RoundTrip(r)
}

// TestLookup_UsesSuppliedHTTPClient proves Options.HTTPClient reaches the
// RDAP request Lookup makes, by asserting the supplied transport actually
// served a round trip -- not merely that the lookup succeeded, which
// would also be true of collect.Collect building its own client. Deleting
// the `HTTPClient: c.opts.HTTPClient,` forwarding line in Lookup's domain
// branch makes this fail with tr.n == 0; see the mutation evidence in the
// task's fix report.
func TestLookup_UsesSuppliedHTTPClient(t *testing.T) {
	fixture, err := os.ReadFile("testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	tr := &countingTransport{}
	c, err := New(context.Background(), Options{
		DisableCache:    true,
		NoFollow:        true,
		Timeout:         2 * time.Second,
		Sources:         []SourceID{SourceRegistryRDAP},
		Resolver:        NewResolver(map[string]string{"com": srv.URL}),
		WHOISIANAServer: "127.0.0.1:1",
		HTTPClient:      &http.Client{Transport: tr},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := c.Lookup(context.Background(), "example.com"); err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	if tr.n == 0 {
		t.Fatal("supplied HTTPClient was never used; Lookup built its own")
	}
}

// failingTransport counts requests and fails them all, so a test can prove
// a client was consulted without any request leaving the machine.
type failingTransport struct{ n int }

func (t *failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.n++
	return nil, errors.New("failingTransport: no network in tests")
}

func TestNew_HTTPClientReachesBootstrapFetch(t *testing.T) {
	tr := &failingTransport{}
	// No Resolver: New must actually run bootstrap.Load, which fetches
	// four registries. The transport fails every request immediately, so
	// Load falls through to the embedded snapshot without touching the
	// network -- but it must have gone through OUR client to do so.
	_, err := New(context.Background(), Options{
		DisableCache: true,
		Timeout:      2 * time.Second,
		HTTPClient:   &http.Client{Transport: tr},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if tr.n == 0 {
		t.Fatal("supplied HTTPClient was never used for the bootstrap fetch")
	}
}

// bootstrapJSONWith builds a minimal, valid IANA dns.json-shaped bootstrap
// document mapping tld to baseURL -- enough for bootstrap.parseResolver
// (unexported, so exercised only through Load) to accept it.
func bootstrapJSONWith(tld, baseURL string) string {
	return `{"services": [[["` + tld + `"], ["` + baseURL + `"]]]}`
}

// TestNew_CacheOptionsAreForwarded is deliberately built so it cannot
// pass by accident: it plants a real, fresh cache file in a temp
// directory naming a TLD ("faketld") that cannot appear in IANA's real
// bootstrap data (embedded or fetched), then checks whether that planted
// entry shows up in the resulting Resolver.
//
//   - With CacheDir pointed at that directory and DisableCache false,
//     bootstrap.Load must read the planted file (readFreshCache short-
//     circuits before any network attempt), so "faketld" resolves.
//   - With the same CacheDir but DisableCache true, Load must ignore that
//     directory entirely and fall through to the embedded snapshot
//     instead, so "faketld" does NOT resolve.
//
// A test that passed either way -- e.g. just checking New succeeds, or
// only ever exercising DisableCache true -- would not have caught the
// reviewer's mutation (deleting both CacheDir: and DisableCache: from
// New's bootstrap.Options literal); this one does, see the fix report's
// mutation evidence.
//
// Every New call here uses an already-canceled context so any fetch
// attempt New/Load does make (for ipv4.json/ipv6.json/asn.json, which
// are never planted, or for bootstrap.json itself when DisableCache is
// true) fails in microseconds on ctx.Err() rather than ever dialing out
// -- confirmed empirically: a canceled-context http.Client.Do returns
// "context canceled" without a network round trip. Resolver.Resolver is
// not exported to this package's tests any other offline way: New never
// takes a Resolver here (that would bypass bootstrap.Load, the exact
// path under test), and Options has no field to point the fetch at a
// fake server (Important 3 -- HTTPClient does not cover the bootstrap
// fetch).
func TestNew_CacheOptionsAreForwarded(t *testing.T) {
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	dir := t.TempDir()
	planted := bootstrapJSONWith("faketld", "https://example.test/rdap/")
	if err := os.WriteFile(filepath.Join(dir, "bootstrap.json"), []byte(planted), 0o600); err != nil {
		t.Fatalf("planting cache file: %v", err)
	}

	t.Run("CacheDir is read when caching is enabled", func(t *testing.T) {
		c, err := New(canceledCtx, Options{
			CacheDir:     dir,
			DisableCache: false,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, ok := c.resolver.BaseURL("faketld"); !ok {
			t.Error(`BaseURL("faketld") not found -- the planted CacheDir file was not read`)
		}
	})

	t.Run("DisableCache overrides a populated CacheDir", func(t *testing.T) {
		c, err := New(canceledCtx, Options{
			CacheDir:     dir,
			DisableCache: true,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, ok := c.resolver.BaseURL("faketld"); ok {
			t.Error(`BaseURL("faketld") found -- DisableCache did not stop the planted CacheDir file from being read`)
		}
	})
}
