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
	"strconv"
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
	asnURL  = "https://data.iana.org/rdap/asn.json"
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
	byTLD      map[string]string
	byPrefix   map[netip.Prefix]string
	byASNRange map[[2]uint32]string
}

// NewResolver builds a Resolver directly from a TLD -> RDAP base URL map,
// bypassing Load's fetch/cache/embedded-fallback chain entirely. It is
// re-exported as public API (plat.NewResolver) for production use, in
// addition to letting other packages' tests point a Resolver at a fake
// RDAP server without hitting the real network or the real IANA
// bootstrap file.
//
// The Resolver this returns covers domain lookups ONLY: byPrefix and
// byASNRange are left nil, so IPBaseURL and ASNBaseURL always report "no
// coverage" on it. A lookup made with it for an IP address or ASN falls
// back to WHOIS-only, silently -- there is no combining constructor that
// covers more than one object kind. See NewIPResolver and NewASNResolver
// for the other two.
func NewResolver(byTLD map[string]string) *Resolver {
	return &Resolver{byTLD: byTLD}
}

// NewIPResolver builds a Resolver from an IP-prefix -> RDAP base URL map,
// bypassing Load's fetch/cache/embedded-fallback chain. It is re-exported
// as public API (plat.NewIPResolver) for production use, in addition to
// letting other packages' tests point a Resolver at a fake RDAP server
// without touching the network.
//
// The Resolver this returns covers IP lookups ONLY: byTLD and
// byASNRange are left nil, so BaseURL and ASNBaseURL always report "no
// coverage" on it. A domain or ASN lookup made with it falls back to
// WHOIS-only, silently.
func NewIPResolver(prefixes map[netip.Prefix]string) *Resolver {
	return &Resolver{byPrefix: prefixes}
}

// NewASNResolver builds a Resolver from an ASN-range -> RDAP base URL
// map, bypassing Load's fetch/cache/embedded-fallback chain. It is
// re-exported as public API (plat.NewASNResolver) for production use, in
// addition to letting other packages' tests point a Resolver at a fake
// RDAP server without touching the network.
//
// The Resolver this returns covers ASN lookups ONLY: byTLD and byPrefix
// are left nil, so BaseURL and IPBaseURL always report "no coverage" on
// it. A domain or IP lookup made with it falls back to WHOIS-only,
// silently.
func NewASNResolver(ranges map[[2]uint32]string) *Resolver {
	return &Resolver{byASNRange: ranges}
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

// ASNBaseURL returns the RDAP base URL for the RIR holding asn, and
// whether any delegated range contains it. Unlike IP delegations, IANA's
// ASN ranges do not overlap, so the first containing range wins -- there
// is no most-specific-match rule to apply.
func (r *Resolver) ASNBaseURL(asn uint32) (string, bool) {
	for span, url := range r.byASNRange {
		if asn >= span[0] && asn <= span[1] {
			return url, true
		}
	}
	return "", false
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

// parseASNRanges reads an IANA asn.json bootstrap document. It shares
// dns.json's services structure; only the keys differ (ASN numbers or
// "start-end" ranges rather than TLD strings). An unparseable entry is
// skipped rather than failing the whole document.
func parseASNRanges(data []byte, into map[[2]uint32]string) error {
	var doc bootstrapDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("bootstrap: parsing ASN registry: %w", err)
	}
	for _, service := range doc.Services {
		if len(service) < 2 || len(service[1]) == 0 {
			continue
		}
		base := strings.TrimRight(service[1][0], "/") + "/"
		for _, entry := range service[0] {
			start, end, ok := parseASNSpan(entry)
			if !ok {
				continue
			}
			into[[2]uint32{start, end}] = base
		}
	}
	return nil
}

// parseASNSpan parses "15169" or "36864-37887". A single number yields an
// inclusive one-element span.
func parseASNSpan(entry string) (uint32, uint32, bool) {
	entry = strings.TrimSpace(entry)
	lo, hi, found := strings.Cut(entry, "-")
	start, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 32)
	if err != nil {
		return 0, 0, false
	}
	if !found {
		return uint32(start), uint32(start), true
	}
	end, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 32)
	if err != nil || end < start {
		return 0, 0, false
	}
	return uint32(start), uint32(end), true
}

// Options controls Load's behavior.
type Options struct {
	// Refresh forces a fetch attempt even if a fresh cache entry exists.
	// A failed fetch still falls back to a stale cache or the embedded
	// snapshot rather than erroring.
	Refresh bool
	// Timeout bounds the network fetch. Defaults to 5s.
	Timeout time.Duration
	// CacheDir overrides where bootstrap documents are cached. Empty
	// means the OS user cache directory plus a "plat" subdirectory --
	// the location the CLI uses. A caller-supplied directory is used
	// verbatim, without that subdirectory.
	CacheDir string
	// DisableCache stops plat touching the filesystem at all: nothing is
	// read from or written to a cache, and every load falls through to
	// the network and then the embedded snapshot. Intended for library
	// consumers who do not want an embedded dependency writing to their
	// user's home directory.
	DisableCache bool
}

// path returns the cache file path for the named bootstrap document (e.g.
// "bootstrap.json", "ipv4.json"), or "" if caching is disabled or the
// user cache directory can't be determined. An empty return is the single
// signal that disables all cache reads and writes in fetchOrEmbedded.
func path(opts Options, name string) string {
	if opts.DisableCache {
		return ""
	}
	if opts.CacheDir != "" {
		return filepath.Join(opts.CacheDir, name)
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, cacheDirName, name)
}

func cachePath(opts Options) (string, bool) {
	p := path(opts, cacheFileName)
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
		if data, err := os.ReadFile(cachePath); err == nil && validBootstrapJSON(data) { //nolint:gosec // cachePath is a directory (Options.CacheDir, which may be caller-supplied) joined with a fixed filename constant, never a full caller-supplied path
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
// ipv6.json) and the ASN registry (asn.json) are populated best-effort
// afterward -- each falls back independently, and a failure to fetch or
// parse any one of them leaves that lookup kind unavailable without
// affecting the others.
func Load(ctx context.Context, opts Options) (*Resolver, error) {
	data, err := fetchOrEmbedded(ctx, path(opts, cacheFileName), bootstrapURL, embedded, opts)
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
		data, err := fetchOrEmbedded(ctx, path(opts, reg.name), reg.url, reg.embedded, opts)
		if err != nil {
			continue
		}
		_ = parsePrefixes(data, r.byPrefix)
	}

	r.byASNRange = make(map[[2]uint32]string)
	if data, err := fetchOrEmbedded(ctx, path(opts, "asn.json"), asnURL, embeddedASN, opts); err == nil {
		_ = parseASNRanges(data, r.byASNRange)
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
	data, err := os.ReadFile(path) //nolint:gosec // path is cachePath(): a directory (Options.CacheDir, which may be caller-supplied) joined with a fixed filename constant, never a full caller-supplied path
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
