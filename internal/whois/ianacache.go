package whois

import (
	"sync"

	"golang.org/x/sync/singleflight"
)

// IANACache caches the WHOIS-server-per-TLD mapping learned from the IANA
// referral hop (the "refer:" line in whois.iana.org's reply), shared
// across every concurrent lookup in a bulk run. Every name's first hop
// resolves its TLD's registry WHOIS server this way, and that mapping is
// constant per TLD for the lifetime of a run -- asking IANA once per name
// buys no politeness and just recreates, one name at a time, the exact
// bottleneck a shared HostLimiter is meant to relieve. nil (Client's zero
// value) means no caching, which is correct for a single lookup: one
// query to IANA needs no cache.
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
// Both a successful and a failed hop are cached. A repeated IANA failure
// is itself useful information for the rest of the run, and re-querying
// an already-failing IANA server for every subsequent same-TLD name would
// recreate the very bottleneck this cache exists to remove.
func (c *IANACache) resolve(tld string, query func() Hop) Hop {
	c.mu.RLock()
	hop, ok := c.hops[tld]
	c.mu.RUnlock()
	if ok {
		return hop
	}

	v, _, _ := c.group.Do(tld, func() (any, error) {
		c.mu.RLock()
		hop, ok := c.hops[tld]
		c.mu.RUnlock()
		if ok {
			return hop, nil
		}

		h := query()

		c.mu.Lock()
		c.hops[tld] = h
		c.mu.Unlock()
		return h, nil
	})
	return v.(Hop) //nolint:errcheck // the Do closure above never returns an error
}
