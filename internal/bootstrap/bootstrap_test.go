package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withIsolatedCacheDir(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("HOME", tmp)
}

// unreachableURL is a loopback address nothing listens on, used to make a
// registry fetch fail fast and deterministically without touching the real
// network.
const unreachableURL = "http://127.0.0.1:1/unreachable"

// redirectRegistries points all four bootstrap registry URLs (dns, ipv4,
// ipv6, asn) at the given URLs for the duration of the test, restoring the
// originals on cleanup. Load always fetches all four, so a test that only
// cares about one registry's behavior must still redirect the other three —
// typically to unreachableURL — or it would silently depend on the real
// network.
func redirectRegistries(t *testing.T, dns, ipv4, ipv6, asn string) {
	t.Helper()
	origDNS, origV4, origV6, origASN := bootstrapURL, ipv4URL, ipv6URL, asnURL
	bootstrapURL, ipv4URL, ipv6URL, asnURL = dns, ipv4, ipv6, asn
	t.Cleanup(func() { bootstrapURL, ipv4URL, ipv6URL, asnURL = origDNS, origV4, origV6, origASN })
}

func TestEmbeddedSnapshotParses(t *testing.T) {
	r, err := parseResolver(embedded)
	if err != nil {
		t.Fatalf("parsing embedded snapshot: %v", err)
	}
	if _, ok := r.BaseURL("com"); !ok {
		t.Error(`BaseURL("com") not found in embedded snapshot`)
	}
	if _, ok := r.BaseURL("org"); !ok {
		t.Error(`BaseURL("org") not found in embedded snapshot`)
	}
}

func TestNewResolver(t *testing.T) {
	r := NewResolver(map[string]string{"com": "https://rdap.example.test/"})

	u, ok := r.BaseURL("com")
	if !ok || u != "https://rdap.example.test/" {
		t.Errorf(`BaseURL("com") = %q, %v, want "https://rdap.example.test/", true`, u, ok)
	}

	if _, ok := r.BaseURL("xyz"); ok {
		t.Error(`BaseURL("xyz") ok = true, want false for a TLD not in the map`)
	}
}

func TestLoad_UsesFreshCache(t *testing.T) {
	withIsolatedCacheDir(t)
	path, ok := cachePath(Options{})
	if !ok {
		t.Fatal("cachePath() unexpectedly unavailable")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	fakeDoc := []byte(`{"services":[[["test"],["https://rdap.example.test/"]]]}`)
	if err := os.WriteFile(path, fakeDoc, 0o600); err != nil {
		t.Fatal(err)
	}

	redirectRegistries(t, unreachableURL, unreachableURL, unreachableURL, unreachableURL)

	r, err := Load(context.Background(), Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	base, ok := r.BaseURL("test")
	if !ok || base != "https://rdap.example.test/" {
		t.Errorf(`BaseURL("test") = %q, %v, want "https://rdap.example.test/", true (fresh cache should win without a fetch)`, base, ok)
	}
}

func TestLoad_StaleCacheTriggersFetchFallback(t *testing.T) {
	withIsolatedCacheDir(t)
	path, ok := cachePath(Options{})
	if !ok {
		t.Fatal("cachePath() unexpectedly unavailable")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	staleDoc := []byte(`{"services":[[["stale"],["https://stale.example.test/"]]]}`)
	if err := os.WriteFile(path, staleDoc, 0o600); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(path, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	redirectRegistries(t, unreachableURL, unreachableURL, unreachableURL, unreachableURL) // fetch will fail

	r, err := Load(context.Background(), Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := r.BaseURL("stale"); !ok {
		t.Error(`BaseURL("stale") not found — stale cache should still be used when fetch fails`)
	}
}

func TestLoad_RefreshFailsFallsBackToEmbedded(t *testing.T) {
	withIsolatedCacheDir(t)

	redirectRegistries(t, unreachableURL, unreachableURL, unreachableURL, unreachableURL)

	r, err := Load(context.Background(), Options{Refresh: true, Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := r.BaseURL("com"); !ok {
		t.Error(`BaseURL("com") not found — should have fallen back to embedded snapshot`)
	}
}

func TestLoad_FetchSuccessWritesCache(t *testing.T) {
	withIsolatedCacheDir(t)

	fakeDoc := []byte(`{"services":[[["freshfetch"],["https://rdap.example.test/"]]]}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fakeDoc)
	}))
	defer srv.Close()

	redirectRegistries(t, srv.URL, unreachableURL, unreachableURL, unreachableURL)

	r, err := Load(context.Background(), Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	base, ok := r.BaseURL("freshfetch")
	if !ok || base != "https://rdap.example.test/" {
		t.Errorf(`BaseURL("freshfetch") = %q, %v, want "https://rdap.example.test/", true`, base, ok)
	}

	// Every other Load test in this file forces the fetch to fail (an
	// unreachable bootstrapURL), so fetch's success path — and writeCache,
	// which only ever runs after a successful fetch — have never actually
	// executed until this test. Confirm the fetched doc was written to the
	// cache file.
	path, ok := cachePath(Options{})
	if !ok {
		t.Fatal("cachePath() unexpectedly unavailable")
	}
	cached, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected a successful fetch to have written a cache file, reading it failed: %v", err)
	}
	if string(cached) != string(fakeDoc) {
		t.Errorf("cache file content = %q, want %q", cached, fakeDoc)
	}
}

func TestFetch_NonOKStatusReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	orig := bootstrapURL
	bootstrapURL = srv.URL
	defer func() { bootstrapURL = orig }()

	_, err := fetchURL(context.Background(), bootstrapURL, 2*time.Second, nil)
	if err == nil {
		t.Fatal("expected an error for a non-200 status, got nil")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("error = %v, want it to mention status 500", err)
	}
}

func TestParseResolver_NormalizesTrailingSlash(t *testing.T) {
	doc := []byte(`{"services":[[["xn--test"],["https://rdap.example.test"]]]}`)
	r, err := parseResolver(doc)
	if err != nil {
		t.Fatalf("parseResolver: %v", err)
	}
	base, ok := r.BaseURL("xn--test")
	if !ok || base != "https://rdap.example.test/" {
		t.Errorf("BaseURL = %q, %v, want trailing-slash-normalized URL", base, ok)
	}
}

func TestParseResolver_ValidJSONShape(t *testing.T) {
	var doc bootstrapDoc
	raw := []byte(`{"services":[[["a","b"],["https://x/"]]]}`)
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(doc.Services) != 1 || len(doc.Services[0][0]) != 2 {
		t.Fatalf("unexpected shape: %+v", doc)
	}
}

func TestNewIPResolver_LongestPrefixWins(t *testing.T) {
	// A /8 delegated to one RIR with a /24 sub-delegated elsewhere: the
	// most specific match must win, not the first or the widest.
	r := NewIPResolver(map[netip.Prefix]string{
		netip.MustParsePrefix("8.0.0.0/8"):  "https://wide.example/",
		netip.MustParsePrefix("8.8.8.0/24"): "https://narrow.example/",
	})
	got, ok := r.IPBaseURL(netip.MustParseAddr("8.8.8.8"))
	if !ok {
		t.Fatal("IPBaseURL returned ok=false, want a match")
	}
	if got != "https://narrow.example/" {
		t.Errorf("IPBaseURL = %q, want the /24 (most specific), not the /8", got)
	}
}

func TestNewIPResolver_NoMatch(t *testing.T) {
	r := NewIPResolver(map[netip.Prefix]string{
		netip.MustParsePrefix("8.0.0.0/8"): "https://wide.example/",
	})
	if got, ok := r.IPBaseURL(netip.MustParseAddr("9.9.9.9")); ok {
		t.Errorf("IPBaseURL = %q, ok=true; want ok=false for an address in no delegated range", got)
	}
}

func TestNewIPResolver_IPv6(t *testing.T) {
	r := NewIPResolver(map[netip.Prefix]string{
		netip.MustParsePrefix("2001:4860::/32"): "https://v6.example/",
	})
	if got, ok := r.IPBaseURL(netip.MustParseAddr("2001:4860:4860::8888")); !ok || got != "https://v6.example/" {
		t.Errorf("IPBaseURL = %q, ok=%v; want the /32 match", got, ok)
	}
}

func TestLoad_EmbeddedIPRegistriesParse(t *testing.T) {
	// The embedded snapshots must parse and cover a well-known address,
	// so an offline/first-run lookup still resolves. Redirect all four
	// registries to an unreachable address (and use an isolated, empty
	// cache dir) so this genuinely exercises the no-network, no-cache,
	// embedded-only path rather than incidentally succeeding via a real
	// fetch or a leftover cache file.
	withIsolatedCacheDir(t)
	redirectRegistries(t, unreachableURL, unreachableURL, unreachableURL, unreachableURL)

	r, err := Load(context.Background(), Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := r.IPBaseURL(netip.MustParseAddr("8.8.8.8")); !ok {
		t.Error("IPBaseURL(8.8.8.8) ok=false, want a RIR match from the embedded ipv4 registry")
	}
	if _, ok := r.IPBaseURL(netip.MustParseAddr("2001:4860:4860::8888")); !ok {
		t.Error("IPBaseURL(2001:4860:4860::8888) ok=false, want a RIR match from the embedded ipv6 registry")
	}
}

func TestNewASNResolver_RangeContainment(t *testing.T) {
	r := NewASNResolver(map[[2]uint32]string{
		{36864, 37887}: "https://afrinic.example/",
		{15169, 15169}: "https://arin.example/",
	})
	for _, tt := range []struct {
		name string
		asn  uint32
		want string
		ok   bool
	}{
		{"single-value range", 15169, "https://arin.example/", true},
		{"first autnum in range", 36864, "https://afrinic.example/", true},
		{"last autnum in range", 37887, "https://afrinic.example/", true},
		{"just below range", 36863, "", false},
		{"just above range", 37888, "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := r.ASNBaseURL(tt.asn)
			if ok != tt.ok || got != tt.want {
				t.Errorf("ASNBaseURL(%d) = %q,%v; want %q,%v", tt.asn, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestLoad_EmbeddedASNRegistryParses(t *testing.T) {
	withIsolatedCacheDir(t)
	redirectRegistries(t, unreachableURL, unreachableURL, unreachableURL, unreachableURL)
	r, err := Load(context.Background(), Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := r.ASNBaseURL(15169); !ok {
		t.Error("ASNBaseURL(15169) ok=false, want a RIR match from the embedded asn registry")
	}
}

// TestParseASNSpan exercises parseASNSpan's defensive parsing directly --
// it exists specifically to survive malformed IANA asn.json entries without
// wrapping or silently mis-parsing a span, so its non-numeric, reversed,
// empty, whitespace, and overflow branches need direct coverage rather than
// only being reached incidentally through parseASNRanges/Load.
func TestParseASNSpan(t *testing.T) {
	for _, tt := range []struct {
		name      string
		entry     string
		wantStart uint32
		wantEnd   uint32
		wantOK    bool
	}{
		{"bare single number", "15169", 15169, 15169, true},
		{"valid range", "36864-37887", 36864, 37887, true},
		{"non-numeric start", "abc-100", 0, 0, false},
		{"non-numeric end", "100-xyz", 0, 0, false},
		{"reversed range", "500-100", 0, 0, false},
		{"empty string", "", 0, 0, false},
		{"whitespace-padded range", " 100 - 200 ", 100, 200, true},
		{"whitespace-only", "   ", 0, 0, false},
		{"start exceeds uint32 must not wrap", "4294967296", 0, 0, false},
		{"end exceeds uint32 must not wrap", "1-4294967296", 0, 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			start, end, ok := parseASNSpan(tt.entry)
			if ok != tt.wantOK || start != tt.wantStart || end != tt.wantEnd {
				t.Errorf("parseASNSpan(%q) = %d, %d, %v; want %d, %d, %v",
					tt.entry, start, end, ok, tt.wantStart, tt.wantEnd, tt.wantOK)
			}
		})
	}
}

// TestParseASNRanges covers parseASNRanges' document-level defensive
// branches: invalid top-level JSON, a malformed services entry, and --
// the important case -- one unparseable span inside a service alongside a
// valid one, proving a single bad delegation doesn't cost every other
// entry in that service.
func TestParseASNRanges(t *testing.T) {
	t.Run("malformed JSON returns an error", func(t *testing.T) {
		into := map[[2]uint32]string{}
		err := parseASNRanges([]byte("{not valid json"), into)
		if err == nil {
			t.Fatal("parseASNRanges with malformed JSON: got nil error, want non-nil")
		}
		if len(into) != 0 {
			t.Errorf("into = %v, want empty on parse error", into)
		}
	})

	t.Run("service entry with fewer than 2 elements is skipped", func(t *testing.T) {
		doc := `{"services": [ [["100-200"]] ]}`
		into := map[[2]uint32]string{}
		if err := parseASNRanges([]byte(doc), into); err != nil {
			t.Fatalf("parseASNRanges: %v", err)
		}
		if len(into) != 0 {
			t.Errorf("into = %v, want empty when a service has no URL element", into)
		}
	})

	t.Run("service entry with empty URL list is skipped", func(t *testing.T) {
		doc := `{"services": [ [["100-200"], []] ]}`
		into := map[[2]uint32]string{}
		if err := parseASNRanges([]byte(doc), into); err != nil {
			t.Fatalf("parseASNRanges: %v", err)
		}
		if len(into) != 0 {
			t.Errorf("into = %v, want empty when a service's URL list is empty", into)
		}
	})

	t.Run("one unparseable span does not cost the rest of the service", func(t *testing.T) {
		doc := `{"services": [ [["abc-def", "200-300"], ["https://rir.example/"]] ]}`
		into := map[[2]uint32]string{}
		if err := parseASNRanges([]byte(doc), into); err != nil {
			t.Fatalf("parseASNRanges: %v", err)
		}
		if len(into) != 1 {
			t.Fatalf("into has %d entries, want exactly 1 (the malformed span skipped, the valid one kept): %v", len(into), into)
		}
		url, ok := into[[2]uint32{200, 300}]
		if !ok || url != "https://rir.example/" {
			t.Errorf("into[{200,300}] = %q, %v; want %q, true", url, ok, "https://rir.example/")
		}
	})
}

func TestLoad_DisableCacheWritesNothing(t *testing.T) {
	redirectRegistries(t, unreachableURL, unreachableURL, unreachableURL, unreachableURL)
	dir := t.TempDir()
	_, err := Load(context.Background(), Options{
		CacheDir:     dir,
		DisableCache: true,
		Timeout:      50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("DisableCache still wrote %d entries: %v", len(entries), entries)
	}
}

func TestPath_CacheDirOverridesUserCacheDir(t *testing.T) {
	got := path(Options{CacheDir: "/tmp/example"}, "bootstrap.json")
	want := filepath.Join("/tmp/example", "bootstrap.json")
	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
}

func TestPath_DisableCacheYieldsEmptyPath(t *testing.T) {
	if got := path(Options{DisableCache: true}, "bootstrap.json"); got != "" {
		t.Fatalf("path = %q, want \"\" when caching is disabled", got)
	}
}

func TestLoad_CacheDirWritesCacheWhenNotDisabled(t *testing.T) {
	dir := t.TempDir()
	fakeDoc := []byte(`{"services":[[["testcache"],["https://rdap.example.test/"]]]}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fakeDoc)
	}))
	defer srv.Close()

	redirectRegistries(t, srv.URL, unreachableURL, unreachableURL, unreachableURL)

	r, err := Load(context.Background(), Options{
		CacheDir:     dir,
		DisableCache: false,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := r.BaseURL("testcache"); !ok {
		t.Error(`BaseURL("testcache") not found`)
	}

	// Verify cache file was written to the specified CacheDir.
	cachePath := filepath.Join(dir, cacheFileName)
	cached, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("expected cache file to be written to %s, reading it failed: %v", cachePath, err)
	}
	if string(cached) != string(fakeDoc) {
		t.Errorf("cache file content = %q, want %q", cached, fakeDoc)
	}
}

func TestLoad_DisableCachePreventsWriteToDir(t *testing.T) {
	dir := t.TempDir()
	fakeDoc := []byte(`{"services":[[["testdisable"],["https://rdap.example.test/"]]]}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fakeDoc)
	}))
	defer srv.Close()

	redirectRegistries(t, srv.URL, unreachableURL, unreachableURL, unreachableURL)

	r, err := Load(context.Background(), Options{
		CacheDir:     dir,
		DisableCache: true,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := r.BaseURL("testdisable"); !ok {
		t.Error(`BaseURL("testdisable") not found`)
	}

	// Verify no cache file was written despite successful fetch.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("DisableCache=true still wrote %d entries to directory: %v", len(entries), entries)
	}
}
