package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// bootstrapURL is a var (not a const) so tests can point it at an
// unreachable address to deterministically exercise fetch-failure
// fallback paths without touching the network.
var bootstrapURL = "https://data.iana.org/rdap/dns.json"

const (
	cacheTTL      = 7 * 24 * time.Hour
	cacheDirName  = "plat"
	cacheFileName = "bootstrap.json"
)

// Resolver maps a TLD to its RDAP service base URL, as published by IANA's
// RDAP bootstrap registry (RFC 9224).
type Resolver struct {
	byTLD map[string]string
}

// NewResolver builds a Resolver directly from a TLD -> RDAP base URL map,
// bypassing Load's fetch/cache/embedded-fallback chain entirely. Load
// remains the only production entry point; this exists so other packages'
// tests can point a Resolver at a fake RDAP server without hitting the
// real network or the real IANA bootstrap file.
func NewResolver(byTLD map[string]string) *Resolver {
	return &Resolver{byTLD: byTLD}
}

// BaseURL returns the RDAP base URL for tld and whether the TLD has RDAP
// coverage at all. tld should not include a leading dot.
func (r *Resolver) BaseURL(tld string) (string, bool) {
	u, ok := r.byTLD[strings.ToLower(tld)]
	return u, ok
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

// Options controls Load's behavior.
type Options struct {
	// Refresh forces a fetch attempt even if a fresh cache entry exists.
	// A failed fetch still falls back to a stale cache or the embedded
	// snapshot rather than erroring.
	Refresh bool
	// Timeout bounds the network fetch. Defaults to 5s.
	Timeout time.Duration
}

func cachePath() (string, bool) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", false
	}
	return filepath.Join(dir, cacheDirName, cacheFileName), true
}

// Load resolves a Resolver using, in order of preference: a fresh local
// cache, a freshly fetched copy of the IANA bootstrap file (which it then
// caches), a stale local cache, or the embedded fallback snapshot. It only
// returns an error if the embedded snapshot itself fails to parse, which
// should not happen in practice — Load never fails startup purely because
// the network is unavailable.
func Load(ctx context.Context, opts Options) (*Resolver, error) {
	path, haveCachePath := cachePath()

	if !opts.Refresh && haveCachePath {
		if data, ok := readFreshCache(path); ok {
			if r, err := parseResolver(data); err == nil {
				return r, nil
			}
		}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if data, err := fetch(ctx, timeout); err == nil {
		if r, perr := parseResolver(data); perr == nil {
			if haveCachePath {
				writeCache(path, data)
			}
			return r, nil
		}
	}

	if haveCachePath {
		if data, err := os.ReadFile(path); err == nil { //nolint:gosec // path is cachePath(), derived from os.UserCacheDir() + fixed constants, never user input
			if r, err := parseResolver(data); err == nil {
				return r, nil
			}
		}
	}

	return parseResolver(embedded)
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
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bootstrapURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bootstrap: fetching %s: status %d", bootstrapURL, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 5<<20))
}
