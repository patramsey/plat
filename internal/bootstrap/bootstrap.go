package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// bootstrapURL is a var (not a const) so tests can point it at an
// unreachable address to deterministically exercise fetch-failure
// fallback paths without touching the network.
var bootstrapURL = "https://data.iana.org/rdap/dns.json"

var (
	ipv4URL = "https://data.iana.org/rdap/ipv4.json"
	ipv6URL = "https://data.iana.org/rdap/ipv6.json"
)

const (
	cacheTTL      = 7 * 24 * time.Hour
	cacheDirName  = "plat"
	cacheFileName = "bootstrap.json"
)

// Resolver maps a TLD to its RDAP service base URL, and an IP address to
// its RIR's RDAP service base URL, as published by IANA's RDAP bootstrap
// registries (RFC 9224).
type Resolver struct {
	byTLD    map[string]string
	byPrefix map[netip.Prefix]string
}

// NewResolver builds a Resolver directly from a TLD -> RDAP base URL map,
// bypassing Load's fetch/cache/embedded-fallback chain entirely. Load
// remains the only production entry point; this exists so other packages'
// tests can point a Resolver at a fake RDAP server without hitting the
// real network or the real IANA bootstrap file.
func NewResolver(byTLD map[string]string) *Resolver {
	return &Resolver{byTLD: byTLD}
}

// NewIPResolver builds a Resolver from an IP-prefix -> RDAP base URL map,
// bypassing Load's fetch/cache/embedded-fallback chain. Load remains the
// only production entry point; this exists so other packages' tests can
// point a Resolver at a fake RDAP server without touching the network.
func NewIPResolver(prefixes map[netip.Prefix]string) *Resolver {
	return &Resolver{byPrefix: prefixes}
}

// BaseURL returns the RDAP base URL for tld and whether the TLD has RDAP
// coverage at all. tld should not include a leading dot.
func (r *Resolver) BaseURL(tld string) (string, bool) {
	u, ok := r.byTLD[strings.ToLower(tld)]
	return u, ok
}

// IPBaseURL returns the RDAP base URL for the RIR holding addr, and
// whether any delegated range covers it. When delegations overlap (a /8
// held by one RIR with a /24 sub-delegated to another), the most specific
// prefix wins -- matching how the IANA registry is meant to be read.
func (r *Resolver) IPBaseURL(addr netip.Addr) (string, bool) {
	best, bestBits := "", -1
	for prefix, url := range r.byPrefix {
		if prefix.Addr().Is4() != addr.Is4() {
			continue
		}
		if prefix.Contains(addr) && prefix.Bits() > bestBits {
			best, bestBits = url, prefix.Bits()
		}
	}
	return best, bestBits >= 0
}

type bootstrapDoc struct {
	Services [][][]string `json:"services"`
}

func parseResolver(data []byte) (*Resolver, error) {
	var doc bootstrapDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("bootstrap: parsing dns.json: %w", err)
	}
	byTLD := make(map[string]string)
	for _, service := range doc.Services {
		if len(service) < 2 || len(service[1]) == 0 {
			continue
		}
		base := strings.TrimRight(service[1][0], "/") + "/"
		for _, tld := range service[0] {
			byTLD[strings.ToLower(tld)] = base
		}
	}
	return &Resolver{byTLD: byTLD}, nil
}

// parsePrefixes reads an IANA ipv4.json/ipv6.json bootstrap document.
// It shares dns.json's services structure; only the keys differ (CIDR
// blocks rather than TLD strings). An unparseable prefix is skipped
// rather than failing the whole document -- one malformed entry must not
// cost every other delegation.
func parsePrefixes(data []byte, into map[netip.Prefix]string) error {
	var doc bootstrapDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("bootstrap: parsing IP registry: %w", err)
	}
	for _, service := range doc.Services {
		if len(service) < 2 || len(service[1]) == 0 {
			continue
		}
		base := strings.TrimRight(service[1][0], "/") + "/"
		for _, cidr := range service[0] {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				continue
			}
			into[prefix] = base
		}
	}
	return nil
}

// Options controls Load's behavior.
type Options struct {
	// Refresh forces a fetch attempt even if a fresh cache entry exists.
	// A failed fetch still falls back to a stale cache or the embedded
	// snapshot rather than erroring.
	Refresh bool
	// Timeout bounds the network fetch. Defaults to 5s.
	Timeout time.Duration
}

// path returns the cache file path for the named bootstrap document (e.g.
// "bootstrap.json", "ipv4.json"), or "" if the user cache directory can't
// be determined.
func path(name string) string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, cacheDirName, name)
}

func cachePath() (string, bool) {
	p := path(cacheFileName)
	return p, p != ""
}

// fetchOrEmbedded resolves one bootstrap document using, in order of
// preference: a fresh local cache, a freshly fetched copy (which it then
// caches), a stale local cache, or the embedded fallback snapshot. Each
// candidate other than the embedded snapshot is validated as parseable
// bootstrap JSON before being accepted; an invalid candidate falls
// through to the next. The embedded snapshot is returned unconditionally
// as the last resort -- callers parse it themselves and surface any
// error, which should not happen in practice since it ships with the
// binary.
func fetchOrEmbedded(ctx context.Context, cachePath, url string, embedded []byte, opts Options) ([]byte, error) {
	haveCachePath := cachePath != ""

	if !opts.Refresh && haveCachePath {
		if data, ok := readFreshCache(cachePath); ok && validBootstrapJSON(data) {
			return data, nil
		}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if data, err := fetchURL(ctx, url, timeout); err == nil && validBootstrapJSON(data) {
		if haveCachePath {
			writeCache(cachePath, data)
		}
		return data, nil
	}

	if haveCachePath {
		if data, err := os.ReadFile(cachePath); err == nil && validBootstrapJSON(data) { //nolint:gosec // cachePath is derived from os.UserCacheDir() + fixed constants, never user input
			return data, nil
		}
	}

	return embedded, nil
}

func validBootstrapJSON(data []byte) bool {
	var doc bootstrapDoc
	return json.Unmarshal(data, &doc) == nil
}

// Load resolves a Resolver using, in order of preference: a fresh local
// cache, a freshly fetched copy of the IANA bootstrap file (which it then
// caches), a stale local cache, or the embedded fallback snapshot. It only
// returns an error if the embedded snapshot itself fails to parse, which
// should not happen in practice — Load never fails startup purely because
// the network is unavailable.
//
// The TLD registry (dns.json) is required: a failure to parse it, even
// from the embedded fallback, fails Load. The IP registries (ipv4.json,
// ipv6.json) are populated best-effort afterward -- each falls back
// independently, and a failure to fetch or parse either one leaves IP
// lookups unavailable without affecting domain lookups.
func Load(ctx context.Context, opts Options) (*Resolver, error) {
	data, err := fetchOrEmbedded(ctx, path(cacheFileName), bootstrapURL, embedded, opts)
	if err != nil {
		return nil, err
	}
	r, err := parseResolver(data)
	if err != nil {
		return nil, err
	}

	r.byPrefix = make(map[netip.Prefix]string)
	for _, reg := range []struct {
		name     string
		url      string
		embedded []byte
	}{
		{"ipv4.json", ipv4URL, embeddedIPv4},
		{"ipv6.json", ipv6URL, embeddedIPv6},
	} {
		data, err := fetchOrEmbedded(ctx, path(reg.name), reg.url, reg.embedded, opts)
		if err != nil {
			continue
		}
		_ = parsePrefixes(data, r.byPrefix)
	}

	return r, nil
}

func readFreshCache(path string) ([]byte, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, false
	}
	if time.Since(info.ModTime()) >= cacheTTL {
		return nil, false
	}
	data, err := os.ReadFile(path) //nolint:gosec // path is cachePath(), derived from os.UserCacheDir() + fixed constants, never user input
	if err != nil {
		return nil, false
	}
	return data, true
}

func writeCache(path string, data []byte) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o600)
}

func fetch(ctx context.Context, timeout time.Duration) ([]byte, error) {
	return fetchURL(ctx, bootstrapURL, timeout)
}

func fetchURL(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bootstrap: fetching %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 5<<20))
}
