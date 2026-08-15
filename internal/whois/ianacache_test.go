package whois

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestIANACache_CachesAfterFirstResolve pins the basic contract: a second
// resolve for the same tld reuses the first result instead of calling
// query again.
func TestIANACache_CachesAfterFirstResolve(t *testing.T) {
	c := NewIANACache()
	var calls int32
	query := func() Hop {
		atomic.AddInt32(&calls, 1)
		return Hop{Server: "whois.verisign-grs.com"}
	}

	first := c.resolve("com", query)
	second := c.resolve("com", query)

	if calls != 1 {
		t.Errorf("query called %d times, want 1 -- the second resolve should have hit the cache", calls)
	}
	if first.Server != second.Server {
		t.Errorf("resolve returned different hops for the same tld: %+v vs %+v", first, second)
	}
}

// TestIANACache_DifferentTLDsResolveIndependently proves the cache is
// keyed by tld, not global -- a global cache would return .com's server
// for a .org lookup.
func TestIANACache_DifferentTLDsResolveIndependently(t *testing.T) {
	c := NewIANACache()
	com := c.resolve("com", func() Hop { return Hop{Server: "whois.verisign-grs.com"} })
	org := c.resolve("org", func() Hop { return Hop{Server: "whois.pir.org"} })

	if com.Server == org.Server {
		t.Fatalf("com and org resolved to the same server %q -- cache is not keyed per tld", com.Server)
	}
	if com.Server != "whois.verisign-grs.com" {
		t.Errorf("com resolved to %q, want whois.verisign-grs.com", com.Server)
	}
	if org.Server != "whois.pir.org" {
		t.Errorf("org resolved to %q, want whois.pir.org", org.Server)
	}
}

// TestIANACache_SingleFlightsConcurrentSameTLD is the test that actually
// distinguishes a real cache from "checked the map, still empty, queried
// anyway" -- without single-flight, N concurrent callers racing a cold
// cache for the same tld would all miss and all call query, exactly
// recreating the per-name IANA bottleneck C1b exists to remove. Run under
// -race since the cache is shared across a bulk run's workers.
func TestIANACache_SingleFlightsConcurrentSameTLD(t *testing.T) {
	c := NewIANACache()
	var calls int32
	release := make(chan struct{})
	query := func() Hop {
		atomic.AddInt32(&calls, 1)
		<-release // hold every racing caller here until they've all arrived
		return Hop{Server: "whois.verisign-grs.com"}
	}

	const workers = 20
	var wg sync.WaitGroup
	results := make([]Hop, workers)
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = c.resolve("com", query)
		}(i)
	}

	// Give every goroutine a chance to reach query() and block on release
	// before letting any of them proceed -- if single-flight isn't
	// working, this window is exactly when duplicate query calls would
	// happen.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if calls != 1 {
		t.Errorf("query called %d times across %d concurrent callers for the same tld, want 1", calls, workers)
	}
	for i, hop := range results {
		if hop.Server != "whois.verisign-grs.com" {
			t.Errorf("results[%d].Server = %q, want whois.verisign-grs.com", i, hop.Server)
		}
	}
}

// TestIANACache_CachesFailureToo pins a deliberate design choice: a hop
// that came back with an error is cached too, not just a successful one.
// Re-querying an already-failing IANA server for every subsequent
// same-TLD name in the run would recreate the bottleneck the cache exists
// to remove, and a repeated failure is itself useful information for the
// rest of the run.
func TestIANACache_CachesFailureToo(t *testing.T) {
	c := NewIANACache()
	var calls int32
	sentinel := errors.New("dial failed")
	query := func() Hop {
		atomic.AddInt32(&calls, 1)
		return Hop{Err: sentinel}
	}

	first := c.resolve("net", query)
	second := c.resolve("net", query)

	if calls != 1 {
		t.Errorf("query called %d times, want 1 -- a failed hop should still be cached", calls)
	}
	if first.Err == nil || second.Err == nil {
		t.Fatalf("expected both resolves to return the cached error, got first.Err=%v second.Err=%v", first.Err, second.Err)
	}
}
