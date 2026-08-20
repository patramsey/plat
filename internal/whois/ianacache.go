package whois

import (
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// IANACache caches the WHOIS-server-per-TLD mapping learned from the IANA
// referral hop (the "refer:" line in whois.iana.org's reply), shared
// across every concurrent lookup that uses it. Every name's first hop
// resolves its TLD's registry WHOIS server this way, and asking IANA once
// per name buys no politeness and just recreates, one name at a time, the
// exact bottleneck a shared HostLimiter is meant to relieve.
//
// Entries never expire -- there is no TTL or invalidation. That was a
// reasonable simplification when the only production caller was the CLI,
// which builds one Client and exits at the end of a single run. It no
// longer is: a plat.Client always builds an IANACache (see plat.New), and
// a library consumer that keeps one Client alive across a long-running
// process -- exactly what New's own doc recommends for a program doing
// many lookups -- gets a mapping that is cached for that process's entire
// lifetime, not "a run". If IANA ever changes a TLD's registry WHOIS
// server, a long-lived Client will not notice. nil (the zero value) means
// no caching, which is still correct for a use that builds no Client at
// all.
//
// The cache is shared by every worker in a bulk run, so it must be
// race-safe -- see IANACache's own -race-covered tests.
type IANACache struct {
	group singleflight.Group

	mu   sync.RWMutex
	hops map[string]Hop
}

// NewIANACache returns an empty cache ready to be shared across a run's
// workers.
func NewIANACache() *IANACache {
	return &IANACache{hops: make(map[string]Hop)}
}

// resolve returns the cached IANA hop for tld, calling query to populate
// it on the first request for that tld. Concurrent callers racing on a
// cold cache for the same tld single-flight down to one call to query --
// without that, N concurrent same-TLD names would all miss the empty
// cache at once and all query IANA, which is no better than not caching
// at all. Every later caller, including ones that lost the singleflight
// race, is served the cached result without touching the network again.
//
// Only a SUCCESSFUL hop is cached. Caching a failure would let one
// transient IANA error -- a dropped connection, a rate-limit, a truncated
// reply -- poison that TLD for every remaining name in the run, turning a
// blip that used to cost one name its WHOIS chain into one that costs
// every same-TLD name theirs. Before this cache existed each name
// retried independently; not caching failures keeps that. The
// singleflight still applies to a failing fetch, so concurrent callers
// share one attempt rather than stampeding; it is only later names that
// get a fresh try.
//
// resolve also reports how long the caller spent BLOCKED on another
// caller's in-flight fetch: zero for a cache hit and zero for the caller
// that ran the fetch itself, and the full wait for one that merely
// inherited the result. A blocked caller did no network work of its own,
// so ianaHop credits that time back to its chain budget -- see ianaHop.
func (c *IANACache) resolve(tld string, query func() Hop) (Hop, time.Duration) {
	c.mu.RLock()
	hop, ok := c.hops[tld]
	c.mu.RUnlock()
	if ok {
		return hop, 0
	}

	start := time.Now()
	// Set inside the closure below, which singleflight runs synchronously
	// on the winning caller's own goroutine -- so this stays a plain
	// local read/written by one goroutine, never shared.
	var ranFetch bool
	v, _, _ := c.group.Do(tld, func() (any, error) {
		c.mu.RLock()
		hop, ok := c.hops[tld]
		c.mu.RUnlock()
		if ok {
			return hop, nil
		}

		ranFetch = true
		h := query()

		if h.Err == nil {
			c.mu.Lock()
			c.hops[tld] = h
			c.mu.Unlock()
		}
		return h, nil
	})
	hop = v.(Hop) //nolint:errcheck // the Do closure above never returns an error
	if ranFetch {
		return hop, 0
	}
	return hop, time.Since(start)
}
