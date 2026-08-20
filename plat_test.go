package plat

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/whois"
)

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
