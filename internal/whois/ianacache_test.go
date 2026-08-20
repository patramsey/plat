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

	first, _ := c.resolve("com", query)
	second, _ := c.resolve("com", query)

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
	com, _ := c.resolve("com", func() Hop { return Hop{Server: "whois.verisign-grs.com"} })
	org, _ := c.resolve("org", func() Hop { return Hop{Server: "whois.pir.org"} })

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
			results[i], _ = c.resolve("com", query)
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

// TestIANACache_DoesNotCacheFailures pins the deliberate design choice
// that only a SUCCESSFUL hop is cached. Caching a failure would let one
// transient IANA error poison that TLD for every remaining name in the
// run: a single dropped connection would cost the whole run its .com
// WHOIS chains rather than costing one name. Before the cache existed
// each name retried independently, and not caching failures keeps that.
func TestIANACache_DoesNotCacheFailures(t *testing.T) {
	c := NewIANACache()
	var calls int32
	sentinel := errors.New("dial failed")
	query := func() Hop {
		atomic.AddInt32(&calls, 1)
		return Hop{Err: sentinel}
	}

	first, _ := c.resolve("net", query)
	second, _ := c.resolve("net", query)

	if calls != 2 {
		t.Errorf("query called %d times, want 2 -- a failed hop must not be cached, so the next name retries", calls)
	}
	if first.Err == nil || second.Err == nil {
		t.Fatalf("expected both resolves to return the error, got first.Err=%v second.Err=%v", first.Err, second.Err)
	}

	// And a later success still populates the cache normally.
	c.resolve("net", func() Hop { return Hop{Server: "whois.verisign-grs.com"} }) //nolint:errcheck // return value is asserted via the next resolve
	hop, _ := c.resolve("net", func() Hop {
		t.Error("resolve queried again after a successful hop was cached")
		return Hop{}
	})
	if hop.Server != "whois.verisign-grs.com" {
		t.Errorf("hop.Server = %q, want the cached success", hop.Server)
	}
}

// TestIANACache_ReportsBlockedTimeOnlyForInheritedFetches pins the
// duration resolve reports alongside the hop. A caller that ran the fetch
// itself did the network work and is told it blocked for zero; a caller
// that merely waited for someone else's in-flight fetch did no network
// work at all and is told how long it waited, so ianaHop can credit that
// time back to its chain budget instead of letting another name's pacing
// slot eat this name's network budget.
func TestIANACache_ReportsBlockedTimeOnlyForInheritedFetches(t *testing.T) {
	c := NewIANACache()

	started := make(chan struct{})
	release := make(chan struct{})

	var winnerBlocked time.Duration
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, winnerBlocked = c.resolve("com", func() Hop {
			close(started)
			<-release
			return Hop{Server: "whois.verisign-grs.com"}
		})
	}()

	// Once the fetch is under way the cache is still cold, so this
	// caller cannot take the fast path and must join the singleflight --
	// making it deterministically the one that inherits the result.
	<-started
	const held = 50 * time.Millisecond
	go func() {
		time.Sleep(held)
		close(release)
	}()
	hop, blocked := c.resolve("com", func() Hop {
		t.Error("the inheriting caller ran its own fetch")
		return Hop{}
	})
	<-done

	if hop.Server != "whois.verisign-grs.com" {
		t.Errorf("inherited hop.Server = %q, want whois.verisign-grs.com", hop.Server)
	}
	if blocked < held {
		t.Errorf("inheriting caller reported blocked=%v, want at least %v -- that wait is what ianaHop credits back", blocked, held)
	}
	if winnerBlocked != 0 {
		t.Errorf("fetching caller reported blocked=%v, want 0 -- it spent that time on the wire, not waiting", winnerBlocked)
	}
}
