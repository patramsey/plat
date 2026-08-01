package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestLoad_UsesFreshCache(t *testing.T) {
	withIsolatedCacheDir(t)
	path, ok := cachePath()
	if !ok {
		t.Fatal("cachePath() unexpectedly unavailable")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	fakeDoc := []byte(`{"services":[[["test"],["https://rdap.example.test/"]]]}`)
	if err := os.WriteFile(path, fakeDoc, 0o644); err != nil {
		t.Fatal(err)
	}

	orig := bootstrapURL
	bootstrapURL = "http://127.0.0.1:1/unreachable"
	defer func() { bootstrapURL = orig }()

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
	path, ok := cachePath()
	if !ok {
		t.Fatal("cachePath() unexpectedly unavailable")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	staleDoc := []byte(`{"services":[[["stale"],["https://stale.example.test/"]]]}`)
	if err := os.WriteFile(path, staleDoc, 0o644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(path, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	orig := bootstrapURL
	bootstrapURL = "http://127.0.0.1:1/unreachable" // fetch will fail
	defer func() { bootstrapURL = orig }()

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

	orig := bootstrapURL
	bootstrapURL = "http://127.0.0.1:1/unreachable"
	defer func() { bootstrapURL = orig }()

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

	orig := bootstrapURL
	bootstrapURL = srv.URL
	defer func() { bootstrapURL = orig }()

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
	path, ok := cachePath()
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

	_, err := fetch(context.Background(), 2*time.Second)
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
