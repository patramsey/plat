package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/patramsey/plat"
	"github.com/patramsey/plat/internal/bootstrap"
	"github.com/patramsey/plat/internal/render"
)

func startFakeWHOISListener(t *testing.T, respond func(query string) string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 4096)
				n, _ := conn.Read(buf)
				query := strings.TrimRight(string(buf[:n]), "\r\n")
				_, _ = conn.Write([]byte(respond(query)))
			}()
		}
	}()
	return ln.Addr().String()
}

// newTestClient builds the single *plat.Client lookupOne now takes,
// wiring it the way runLookup wires the real one: the fake resolver
// stands in for the IANA bootstrap fetch, and the timeout, source
// filter, --no-follow and WHOIS-IANA test hook the call's lookupOptions
// carry go onto the client, since that is where the lookup itself now
// reads them from. Passing the same lookupOptions value to both keeps
// the two from drifting apart.
func newTestClient(t *testing.T, resolver *plat.Resolver, opts lookupOptions, sources []plat.SourceID) *plat.Client {
	t.Helper()
	client, err := plat.New(context.Background(), plat.Options{
		Resolver:        resolver,
		Timeout:         opts.Timeout,
		Sources:         sources,
		NoFollow:        opts.NoFollow,
		WHOISIANAServer: opts.whoisIANAServer,
	})
	if err != nil {
		t.Fatalf("plat.New: %v", err)
	}
	return client
}

func TestLookupOne_HappyPath_RDAPAndWHOIS(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer rdapSrv.Close()

	registryWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		return "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar, Inc.\n"
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + registryWHOISAddr + "\n"
	})

	resolver := bootstrap.NewResolver(map[string]string{"com": rdapSrv.URL})

	var stdout, stderr bytes.Buffer
	opts := lookupOptions{whoisIANAServer: ianaAddr, NoFollow: true}
	client := newTestClient(t, resolver, opts, nil)
	code := lookupOne(
		context.Background(), &stdout, &stderr, client, "example.com",
		opts,
		nil, render.FormatJSON, uiConfig{},
	)

	if code != 0 {
		t.Errorf("exit code = %d, want 0\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "example.com") {
		t.Errorf("stdout missing domain, got:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Example Registrar") {
		t.Errorf("stdout missing WHOIS-sourced registrar name, got:\n%s", stdout.String())
	}
}

func TestLookupOne_WHOISOnlyDegradedMode(t *testing.T) {
	// An empty resolver map means BaseURL always returns ("", false) --
	// no TLD has RDAP coverage, so collect.Collect degrades to
	// WHOIS-only (its needRDAP check requires a non-empty base URL).
	resolver := bootstrap.NewResolver(map[string]string{})

	registryWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		return "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar, Inc.\n"
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + registryWHOISAddr + "\n"
	})

	var stdout, stderr bytes.Buffer
	opts := lookupOptions{whoisIANAServer: ianaAddr, NoFollow: true}
	client := newTestClient(t, resolver, opts, nil)
	code := lookupOne(
		context.Background(), &stdout, &stderr, client, "example.com",
		opts,
		nil, render.FormatJSON, uiConfig{},
	)

	if code != 0 {
		t.Errorf("exit code = %d, want 0\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "Example Registrar") {
		t.Errorf("stdout missing WHOIS-sourced registrar name, got:\n%s", stdout.String())
	}
	// RDAP was never queried -- the RDAP-only Handle field from
	// testdata/rdap/com-example.json must be absent, confirming this
	// really is WHOIS-only rather than RDAP silently having succeeded.
	if strings.Contains(stdout.String(), "2336799_DOMAIN_COM-VRSN") {
		t.Errorf("stdout contains the RDAP-only Handle value -- RDAP should never have been queried, got:\n%s", stdout.String())
	}
}

func TestLookupOne_NotFound_ExitCode1(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer rdapSrv.Close()

	registryWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		// "no match" is one of internal/whois/parse's notFoundMarkers
		// (case-insensitive substring match).
		return "No match for domain.\n"
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + registryWHOISAddr + "\n"
	})

	resolver := bootstrap.NewResolver(map[string]string{"com": rdapSrv.URL})

	var stdout, stderr bytes.Buffer
	opts := lookupOptions{whoisIANAServer: ianaAddr, NoFollow: true}
	client := newTestClient(t, resolver, opts, nil)
	code := lookupOne(
		context.Background(), &stdout, &stderr, client, "example.com",
		opts,
		nil, render.FormatPlain, uiConfig{},
	)

	if code != 1 {
		t.Errorf("exit code = %d, want 1\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "is not registered") {
		t.Errorf("stderr missing not-registered message, got:\n%s", stderr.String())
	}
}

func TestLookupOne_FailurePath_ExitCode3(t *testing.T) {
	// The "http://127.0.0.1:1/unreachable" / "127.0.0.1:1" convention
	// (also used in internal/bootstrap/bootstrap_test.go) forces a fast,
	// hermetic connection-refused failure -- no real network needed.
	resolver := bootstrap.NewResolver(map[string]string{"com": "http://127.0.0.1:1/unreachable"})

	var stdout, stderr bytes.Buffer
	opts := lookupOptions{whoisIANAServer: "127.0.0.1:1", NoFollow: true, Timeout: time.Second}
	client := newTestClient(t, resolver, opts, nil)
	code := lookupOne(
		context.Background(), &stdout, &stderr, client, "example.com",
		opts,
		nil, render.FormatPlain, uiConfig{},
	)

	if code != 3 {
		t.Errorf("exit code = %d, want 3\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "example.com") {
		t.Errorf("stderr missing domain in failure message, got:\n%s", stderr.String())
	}
}

// TestLookupOne_Diff exercises --diff's whole success path end to end:
// encode -> Decode -> Compare -> render -> exit code, none of which any
// other test in this file touches. It reuses this file's fake-WHOIS/
// httptest-RDAP harness to produce a real -o json snapshot from one
// lookup, then feeds that snapshot back in as opts.DiffPath for a second
// lookup against the same (unchanged) sources, and a third against a
// hand-mutated copy -- pinning both halves of the contract: unchanged
// sources must exit 0, and a real difference must exit 4 and be reported
// in the rendered output.
func TestLookupOne_Diff(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer rdapSrv.Close()

	registryWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		return "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar, Inc.\n"
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + registryWHOISAddr + "\n"
	})

	resolver := bootstrap.NewResolver(map[string]string{"com": rdapSrv.URL})
	baseOpts := lookupOptions{whoisIANAServer: ianaAddr, NoFollow: true}

	// Produce a baseline -o json snapshot from a fresh lookup -- this is
	// exactly what a user would have saved via `plat example.com -o json
	// > before.json`.
	var baseline, baselineErr bytes.Buffer
	client := newTestClient(t, resolver, baseOpts, nil)
	code := lookupOne(
		context.Background(), &baseline, &baselineErr, client, "example.com",
		baseOpts, nil, render.FormatJSON, uiConfig{},
	)
	if code != 0 {
		t.Fatalf("baseline lookup exit code = %d, want 0\nstderr: %s", code, baselineErr.String())
	}

	snapPath := filepath.Join(t.TempDir(), "before.json")
	if err := os.WriteFile(snapPath, baseline.Bytes(), 0o600); err != nil {
		t.Fatalf("writing snapshot: %v", err)
	}

	t.Run("unchanged sources exit 0", func(t *testing.T) {
		opts := baseOpts
		opts.DiffPath = snapPath
		var stdout, stderr bytes.Buffer
		client := newTestClient(t, resolver, opts, nil)
		code := lookupOne(
			context.Background(), &stdout, &stderr, client, "example.com",
			opts, nil, render.FormatPlain, uiConfig{},
		)
		if code != 0 {
			t.Errorf("exit code = %d, want 0\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "no changes") {
			t.Errorf(`stdout missing "no changes", got:\n%s`, stdout.String())
		}
	})

	t.Run("mutated field exits 4 and is reported", func(t *testing.T) {
		mutated := strings.Replace(baseline.String(), "Example Registrar, Inc.", "Mutated Registrar, LLC", 1)
		if mutated == baseline.String() {
			t.Fatal("mutation left the snapshot unchanged -- the registrar name text moved in the fixture")
		}
		mutatedPath := filepath.Join(t.TempDir(), "mutated.json")
		if err := os.WriteFile(mutatedPath, []byte(mutated), 0o600); err != nil {
			t.Fatalf("writing mutated snapshot: %v", err)
		}

		opts := baseOpts
		opts.DiffPath = mutatedPath
		var stdout, stderr bytes.Buffer
		client := newTestClient(t, resolver, opts, nil)
		code := lookupOne(
			context.Background(), &stdout, &stderr, client, "example.com",
			opts, nil, render.FormatPlain, uiConfig{},
		)
		if code != 4 {
			t.Errorf("exit code = %d, want 4\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "Mutated Registrar, LLC") {
			t.Errorf("stdout missing the diffed-away value, got:\n%s", stdout.String())
		}
		if !strings.Contains(stdout.String(), "1 changed") {
			t.Errorf("stdout missing change count, got:\n%s", stdout.String())
		}
	})
}

// TestLookupOne_Diff_RenderErrorPath_ExitCode3 covers lookupOneDomain's
// --diff render-error branch (the `if err := diffRender(...); err != nil`
// block, distinct from the no-prior renderRecord error branch every other
// *_RenderErrorPath_ExitCode3 test in this file covers): a successful
// lookup (code == 0) with a --diff snapshot whose comparison-and-render
// step fails must report the error and return exit 3, not silently
// succeed or panic. errWriter (defined below, reused here since this is
// the same package) forces diff.RenderPlain's write to fail deterministically,
// without depending on any renderer's internals.
func TestLookupOne_Diff_RenderErrorPath_ExitCode3(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer rdapSrv.Close()

	registryWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		return "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar, Inc.\n"
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + registryWHOISAddr + "\n"
	})

	resolver := bootstrap.NewResolver(map[string]string{"com": rdapSrv.URL})
	baseOpts := lookupOptions{whoisIANAServer: ianaAddr, NoFollow: true}

	var baseline, baselineErr bytes.Buffer
	client := newTestClient(t, resolver, baseOpts, nil)
	code := lookupOne(
		context.Background(), &baseline, &baselineErr, client, "example.com",
		baseOpts, nil, render.FormatJSON, uiConfig{},
	)
	if code != 0 {
		t.Fatalf("baseline lookup exit code = %d, want 0\nstderr: %s", code, baselineErr.String())
	}
	snapPath := filepath.Join(t.TempDir(), "before.json")
	if err := os.WriteFile(snapPath, baseline.Bytes(), 0o600); err != nil {
		t.Fatalf("writing snapshot: %v", err)
	}

	opts := baseOpts
	opts.DiffPath = snapPath
	var stderr bytes.Buffer
	client = newTestClient(t, resolver, opts, nil)
	code = lookupOne(
		context.Background(), errWriter{}, &stderr, client, "example.com",
		opts, nil, render.FormatPlain, uiConfig{},
	)
	if code != 3 {
		t.Errorf("exit code = %d, want 3\nstderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "example.com") {
		t.Errorf("stderr missing domain in render-failure message, got:\n%s", stderr.String())
	}
}

func TestLookupOne_SpinnerBranch_HumanFormat(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer rdapSrv.Close()

	registryWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		return "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar, Inc.\n"
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + registryWHOISAddr + "\n"
	})

	resolver := bootstrap.NewResolver(map[string]string{"com": rdapSrv.URL})

	var stdout, stderr bytes.Buffer
	// StderrTTY: true + FormatHuman is exactly the condition lookupOne
	// checks to route work() through spinner.Run instead of calling it
	// directly -- this is the one branch none of the other tests in this
	// file exercise.
	opts := lookupOptions{whoisIANAServer: ianaAddr, NoFollow: true}
	client := newTestClient(t, resolver, opts, nil)
	code := lookupOne(
		context.Background(), &stdout, &stderr, client, "example.com",
		opts,
		nil, render.FormatHuman, uiConfig{StderrTTY: true},
	)

	if code != 0 {
		t.Errorf("exit code = %d, want 0\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "example.com") {
		t.Errorf("stdout missing domain -- spinner.Run may have interfered with the result, got:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Example Registrar") {
		t.Errorf("stdout missing WHOIS-sourced registrar name, got:\n%s", stdout.String())
	}
}

const ipTestRDAPBody = `{
  "objectClassName": "ip network",
  "handle": "NET-8-8-8-0-2",
  "startAddress": "8.8.8.0",
  "endAddress": "8.8.8.255",
  "ipVersion": "v4",
  "name": "GOGL",
  "type": "DIRECT ALLOCATION",
  "parentHandle": "NET-8-0-0-0-0",
  "status": ["active"],
  "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
  "events": [{"eventAction": "registration", "eventDate": "2023-12-28T17:24:33-05:00"}],
  "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]]}]
}`

const ipTestWHOISText = "NetRange:       8.8.8.0 - 8.8.8.255\nCIDR:           8.8.8.0/24\nNetName:        GOGL\nNetHandle:      NET-8-8-8-0-2\nOrgName:        Google LLC\nCountry:        US\n"

func TestLookupOne_IP_HappyPath_RDAPAndWHOIS(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(ipTestRDAPBody))
	}))
	defer rdapSrv.Close()

	rirWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		return ipTestWHOISText
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + rirWHOISAddr + "\n"
	})

	resolver := bootstrap.NewIPResolver(map[netip.Prefix]string{
		netip.MustParsePrefix("8.8.8.0/24"): rdapSrv.URL,
	})

	var stdout, stderr bytes.Buffer
	opts := lookupOptions{whoisIANAServer: ianaAddr}
	client := newTestClient(t, resolver, opts, nil)
	code := lookupOne(
		context.Background(), &stdout, &stderr, client, "8.8.8.8",
		opts,
		nil, render.FormatPlain, uiConfig{},
	)

	if code != 0 {
		t.Errorf("exit code = %d, want 0\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "8.8.8.0/24") {
		t.Errorf("stdout missing CIDR, got:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Google LLC") {
		t.Errorf("stdout missing org name, got:\n%s", stdout.String())
	}
}

func TestLookupOne_IP_WHOISOnlyDegradedMode(t *testing.T) {
	// An empty resolver (no prefixes registered) means IPBaseURL always
	// returns ("", false) -- no RDAP coverage for the address, so
	// collect.CollectIP degrades to WHOIS-only (its needRDAP check
	// requires a non-empty base URL).
	resolver := bootstrap.NewIPResolver(map[netip.Prefix]string{})

	rirWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		return ipTestWHOISText
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + rirWHOISAddr + "\n"
	})

	var stdout, stderr bytes.Buffer
	opts := lookupOptions{whoisIANAServer: ianaAddr}
	client := newTestClient(t, resolver, opts, nil)
	code := lookupOne(
		context.Background(), &stdout, &stderr, client, "8.8.8.8",
		opts,
		nil, render.FormatPlain, uiConfig{},
	)

	if code != 0 {
		t.Errorf("exit code = %d, want 0\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "Google LLC") {
		t.Errorf("stdout missing WHOIS-sourced org name, got:\n%s", stdout.String())
	}
	// RDAP was never queried -- the RDAP-only Type value must be absent,
	// confirming this really is WHOIS-only rather than RDAP silently
	// having succeeded.
	if strings.Contains(stdout.String(), "DIRECT ALLOCATION") {
		t.Errorf("stdout contains the RDAP-only Type value -- RDAP should never have been queried, got:\n%s", stdout.String())
	}
}

func TestLookupOne_IP_NotFound_ExitCode1(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer rdapSrv.Close()

	rirWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		// "no match" is one of internal/whois/parse's notFoundMarkers
		// (case-insensitive substring match).
		return "No match found for 8.8.8.8.\n"
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + rirWHOISAddr + "\n"
	})

	resolver := bootstrap.NewIPResolver(map[netip.Prefix]string{
		netip.MustParsePrefix("8.8.8.0/24"): rdapSrv.URL,
	})

	var stdout, stderr bytes.Buffer
	opts := lookupOptions{whoisIANAServer: ianaAddr}
	client := newTestClient(t, resolver, opts, nil)
	code := lookupOne(
		context.Background(), &stdout, &stderr, client, "8.8.8.8",
		opts,
		nil, render.FormatPlain, uiConfig{},
	)

	if code != 1 {
		t.Errorf("exit code = %d, want 1\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "is not registered") {
		t.Errorf("stderr missing not-registered message, got:\n%s", stderr.String())
	}
}

func TestLookupOne_IP_FailurePath_ExitCode3(t *testing.T) {
	// Same "unreachable loopback" convention TestLookupOne_FailurePath_ExitCode3
	// uses for the domain path -- a fast, hermetic connection-refused
	// failure, no real network needed.
	resolver := bootstrap.NewIPResolver(map[netip.Prefix]string{
		netip.MustParsePrefix("8.8.8.0/24"): "http://127.0.0.1:1/unreachable",
	})

	var stdout, stderr bytes.Buffer
	opts := lookupOptions{whoisIANAServer: "127.0.0.1:1", Timeout: time.Second}
	client := newTestClient(t, resolver, opts, nil)
	code := lookupOne(
		context.Background(), &stdout, &stderr, client, "8.8.8.8",
		opts,
		nil, render.FormatPlain, uiConfig{},
	)

	if code != 3 {
		t.Errorf("exit code = %d, want 3\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "8.8.8.8") {
		t.Errorf("stderr missing address in failure message, got:\n%s", stderr.String())
	}
}

func TestLookupOne_IP_JSONOutput_ObjectTypeIsIP(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(ipTestRDAPBody))
	}))
	defer rdapSrv.Close()

	rirWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		return ipTestWHOISText
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + rirWHOISAddr + "\n"
	})

	resolver := bootstrap.NewIPResolver(map[netip.Prefix]string{
		netip.MustParsePrefix("8.8.8.0/24"): rdapSrv.URL,
	})

	var stdout, stderr bytes.Buffer
	opts := lookupOptions{whoisIANAServer: ianaAddr}
	client := newTestClient(t, resolver, opts, nil)
	code := lookupOne(
		context.Background(), &stdout, &stderr, client, "8.8.8.8",
		opts,
		nil, render.FormatJSON, uiConfig{},
	)

	if code != 0 {
		t.Errorf("exit code = %d, want 0\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"objectType":"ip"`) {
		t.Errorf(`stdout missing "objectType":"ip", got:%s`, stdout.String())
	}
}

// TestLookupOne_IP_Diff is TestLookupOne_Diff's IP counterpart: the IP
// path shares diffRender/loadSnapshot with the domain path (see
// lookupOneIP in main.go), but nothing before this test drove --diff
// through lookupOneIP end to end -- only the domain path was ever
// exercised, so a bug wiring IP into diffRender (wrong encode func, wrong
// prior plumbing) could compile and pass every other test here
// undetected. Same technique as TestLookupOne_Diff: take a real -o json
// snapshot from a fresh lookup, feed it back as opts.DiffPath against the
// same (unchanged) sources for the exit-0 case, and a text-mutated copy
// for the exit-4 case.
func TestLookupOne_IP_Diff(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(ipTestRDAPBody))
	}))
	defer rdapSrv.Close()

	rirWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		return ipTestWHOISText
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + rirWHOISAddr + "\n"
	})

	resolver := bootstrap.NewIPResolver(map[netip.Prefix]string{
		netip.MustParsePrefix("8.8.8.0/24"): rdapSrv.URL,
	})
	baseOpts := lookupOptions{whoisIANAServer: ianaAddr}

	// Produce a baseline -o json snapshot from a fresh lookup, exactly
	// what a user would have saved via `plat 8.8.8.8 -o json > before.json`.
	var baseline, baselineErr bytes.Buffer
	client := newTestClient(t, resolver, baseOpts, nil)
	code := lookupOne(
		context.Background(), &baseline, &baselineErr, client, "8.8.8.8",
		baseOpts, nil, render.FormatJSON, uiConfig{},
	)
	if code != 0 {
		t.Fatalf("baseline lookup exit code = %d, want 0\nstderr: %s", code, baselineErr.String())
	}

	snapPath := filepath.Join(t.TempDir(), "before.json")
	if err := os.WriteFile(snapPath, baseline.Bytes(), 0o600); err != nil {
		t.Fatalf("writing snapshot: %v", err)
	}

	t.Run("unchanged sources exit 0", func(t *testing.T) {
		opts := baseOpts
		opts.DiffPath = snapPath
		var stdout, stderr bytes.Buffer
		client := newTestClient(t, resolver, opts, nil)
		code := lookupOne(
			context.Background(), &stdout, &stderr, client, "8.8.8.8",
			opts, nil, render.FormatPlain, uiConfig{},
		)
		if code != 0 {
			t.Errorf("exit code = %d, want 0\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "no changes") {
			t.Errorf(`stdout missing "no changes", got:\n%s`, stdout.String())
		}
	})

	t.Run("mutated field exits 4 and is reported", func(t *testing.T) {
		mutated := strings.Replace(baseline.String(), "Google LLC", "Mutated Org LLC", 1)
		if mutated == baseline.String() {
			t.Fatal("mutation left the snapshot unchanged -- the org name text moved in the fixture")
		}
		mutatedPath := filepath.Join(t.TempDir(), "mutated.json")
		if err := os.WriteFile(mutatedPath, []byte(mutated), 0o600); err != nil {
			t.Fatalf("writing mutated snapshot: %v", err)
		}

		opts := baseOpts
		opts.DiffPath = mutatedPath
		var stdout, stderr bytes.Buffer
		client := newTestClient(t, resolver, opts, nil)
		code := lookupOne(
			context.Background(), &stdout, &stderr, client, "8.8.8.8",
			opts, nil, render.FormatPlain, uiConfig{},
		)
		if code != 4 {
			t.Errorf("exit code = %d, want 4\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "Mutated Org LLC") {
			t.Errorf("stdout missing the diffed-away value, got:\n%s", stdout.String())
		}
		if !strings.Contains(stdout.String(), "1 changed") {
			t.Errorf("stdout missing change count, got:\n%s", stdout.String())
		}
	})
}

// TestLookupOne_IP_SpinnerBranch_HumanFormat is lookupOneIP's counterpart
// to TestLookupOne_SpinnerBranch_HumanFormat/
// TestLookupOne_ASN_SpinnerBranch_HumanFormat: StderrTTY: true + FormatHuman
// is exactly the condition lookupOneIP checks to route work() through
// spinner.Run instead of calling it directly, and no other IP test in this
// file exercises it.
func TestLookupOne_IP_SpinnerBranch_HumanFormat(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(ipTestRDAPBody))
	}))
	defer rdapSrv.Close()

	rirWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		return ipTestWHOISText
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + rirWHOISAddr + "\n"
	})

	resolver := bootstrap.NewIPResolver(map[netip.Prefix]string{
		netip.MustParsePrefix("8.8.8.0/24"): rdapSrv.URL,
	})

	var stdout, stderr bytes.Buffer
	opts := lookupOptions{whoisIANAServer: ianaAddr}
	client := newTestClient(t, resolver, opts, nil)
	code := lookupOne(
		context.Background(), &stdout, &stderr, client, "8.8.8.8",
		opts,
		nil, render.FormatHuman, uiConfig{StderrTTY: true},
	)

	if code != 0 {
		t.Errorf("exit code = %d, want 0\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "8.8.8.0/24") {
		t.Errorf("stdout missing CIDR -- spinner.Run may have interfered with the result, got:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Google LLC") {
		t.Errorf("stdout missing org name, got:\n%s", stdout.String())
	}
}

// TestLookupOne_IP_Diff_RenderErrorPath_ExitCode3 is
// TestLookupOne_Diff_RenderErrorPath_ExitCode3's IP counterpart, covering
// lookupOneIP's --diff render-error branch.
func TestLookupOne_IP_Diff_RenderErrorPath_ExitCode3(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(ipTestRDAPBody))
	}))
	defer rdapSrv.Close()

	rirWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		return ipTestWHOISText
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + rirWHOISAddr + "\n"
	})

	resolver := bootstrap.NewIPResolver(map[netip.Prefix]string{
		netip.MustParsePrefix("8.8.8.0/24"): rdapSrv.URL,
	})
	baseOpts := lookupOptions{whoisIANAServer: ianaAddr}

	var baseline, baselineErr bytes.Buffer
	client := newTestClient(t, resolver, baseOpts, nil)
	code := lookupOne(
		context.Background(), &baseline, &baselineErr, client, "8.8.8.8",
		baseOpts, nil, render.FormatJSON, uiConfig{},
	)
	if code != 0 {
		t.Fatalf("baseline lookup exit code = %d, want 0\nstderr: %s", code, baselineErr.String())
	}
	snapPath := filepath.Join(t.TempDir(), "before.json")
	if err := os.WriteFile(snapPath, baseline.Bytes(), 0o600); err != nil {
		t.Fatalf("writing snapshot: %v", err)
	}

	opts := baseOpts
	opts.DiffPath = snapPath
	var stderr bytes.Buffer
	client = newTestClient(t, resolver, opts, nil)
	code = lookupOne(
		context.Background(), errWriter{}, &stderr, client, "8.8.8.8",
		opts, nil, render.FormatPlain, uiConfig{},
	)
	if code != 3 {
		t.Errorf("exit code = %d, want 3\nstderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "8.8.8.8") {
		t.Errorf("stderr missing address in render-failure message, got:\n%s", stderr.String())
	}
}

const asnTestRDAPBody = `{
  "objectClassName": "autnum",
  "handle": "AS15169",
  "startAutnum": 15169,
  "endAutnum": 15169,
  "name": "GOOGLE",
  "type": "DIRECT ALLOCATION",
  "status": ["active"],
  "events": [{"eventAction": "registration", "eventDate": "2000-03-30T00:00:00Z"}],
  "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]]}]
}`

const asnTestWHOISText = "ASNumber:       15169\nASName:         GOOGLE\nASHandle:       AS15169\nOrgName:        Google LLC\nOrgId:          GOGL\nRegDate:        2000-03-30\nUpdated:        2012-02-24\n"

func TestLookupOne_ASN_HappyPath_RDAPAndWHOIS(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(asnTestRDAPBody))
	}))
	defer rdapSrv.Close()

	rirWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		return asnTestWHOISText
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + rirWHOISAddr + "\n"
	})

	resolver := bootstrap.NewASNResolver(map[[2]uint32]string{
		{15169, 15169}: rdapSrv.URL,
	})

	var stdout, stderr bytes.Buffer
	opts := lookupOptions{whoisIANAServer: ianaAddr}
	client := newTestClient(t, resolver, opts, nil)
	code := lookupOne(
		context.Background(), &stdout, &stderr, client, "AS15169",
		opts,
		nil, render.FormatPlain, uiConfig{},
	)

	if code != 0 {
		t.Errorf("exit code = %d, want 0\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "AS15169") {
		t.Errorf("stdout missing handle, got:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Google LLC") {
		t.Errorf("stdout missing org name, got:\n%s", stdout.String())
	}
}

func TestLookupOne_ASN_WHOISOnlyDegradedMode(t *testing.T) {
	// An empty resolver (no ranges registered) means ASNBaseURL always
	// returns ("", false) -- no RDAP coverage for the ASN, so
	// collect.CollectASN degrades to WHOIS-only (its needRDAP check
	// requires a non-empty base URL).
	resolver := bootstrap.NewASNResolver(map[[2]uint32]string{})

	rirWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		return asnTestWHOISText
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + rirWHOISAddr + "\n"
	})

	var stdout, stderr bytes.Buffer
	opts := lookupOptions{whoisIANAServer: ianaAddr}
	client := newTestClient(t, resolver, opts, nil)
	code := lookupOne(
		context.Background(), &stdout, &stderr, client, "AS15169",
		opts,
		nil, render.FormatPlain, uiConfig{},
	)

	if code != 0 {
		t.Errorf("exit code = %d, want 0\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "Google LLC") {
		t.Errorf("stdout missing WHOIS-sourced org name, got:\n%s", stdout.String())
	}
	// RDAP was never queried -- the RDAP-only Type value must be absent,
	// confirming this really is WHOIS-only rather than RDAP silently
	// having succeeded.
	if strings.Contains(stdout.String(), "DIRECT ALLOCATION") {
		t.Errorf("stdout contains the RDAP-only Type value -- RDAP should never have been queried, got:\n%s", stdout.String())
	}
}

func TestLookupOne_ASN_NotFound_ExitCode1(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer rdapSrv.Close()

	rirWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		// "no match" is one of internal/whois/parse's notFoundMarkers
		// (case-insensitive substring match).
		return "No match found for AS15169.\n"
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + rirWHOISAddr + "\n"
	})

	resolver := bootstrap.NewASNResolver(map[[2]uint32]string{
		{15169, 15169}: rdapSrv.URL,
	})

	var stdout, stderr bytes.Buffer
	opts := lookupOptions{whoisIANAServer: ianaAddr}
	client := newTestClient(t, resolver, opts, nil)
	code := lookupOne(
		context.Background(), &stdout, &stderr, client, "AS15169",
		opts,
		nil, render.FormatPlain, uiConfig{},
	)

	if code != 1 {
		t.Errorf("exit code = %d, want 1\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "is not registered") {
		t.Errorf("stderr missing not-registered message, got:\n%s", stderr.String())
	}
}

func TestLookupOne_ASN_FailurePath_ExitCode3(t *testing.T) {
	// Same "unreachable loopback" convention TestLookupOne_FailurePath_ExitCode3
	// uses for the domain path -- a fast, hermetic connection-refused
	// failure, no real network needed.
	resolver := bootstrap.NewASNResolver(map[[2]uint32]string{
		{15169, 15169}: "http://127.0.0.1:1/unreachable",
	})

	var stdout, stderr bytes.Buffer
	opts := lookupOptions{whoisIANAServer: "127.0.0.1:1", Timeout: time.Second}
	client := newTestClient(t, resolver, opts, nil)
	code := lookupOne(
		context.Background(), &stdout, &stderr, client, "AS15169",
		opts,
		nil, render.FormatPlain, uiConfig{},
	)

	if code != 3 {
		t.Errorf("exit code = %d, want 3\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "AS15169") {
		t.Errorf("stderr missing ASN in failure message, got:\n%s", stderr.String())
	}
}

func TestLookupOne_ASN_JSONOutput_ObjectTypeIsASN(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(asnTestRDAPBody))
	}))
	defer rdapSrv.Close()

	rirWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		return asnTestWHOISText
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + rirWHOISAddr + "\n"
	})

	resolver := bootstrap.NewASNResolver(map[[2]uint32]string{
		{15169, 15169}: rdapSrv.URL,
	})

	var stdout, stderr bytes.Buffer
	opts := lookupOptions{whoisIANAServer: ianaAddr}
	client := newTestClient(t, resolver, opts, nil)
	code := lookupOne(
		context.Background(), &stdout, &stderr, client, "AS15169",
		opts,
		nil, render.FormatJSON, uiConfig{},
	)

	if code != 0 {
		t.Errorf("exit code = %d, want 0\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"objectType":"asn"`) {
		t.Errorf(`stdout missing "objectType":"asn", got:%s`, stdout.String())
	}
}

// TestLookupOne_ASN_Diff is TestLookupOne_Diff's ASN counterpart, mirroring
// TestLookupOne_IP_Diff: the ASN path shares diffRender/loadSnapshot with
// the domain and IP paths (see lookupOneASN in main.go), but nothing
// before this test drove --diff through lookupOneASN end to end. Same
// snapshot-then-mutate technique: a real -o json snapshot from a fresh
// lookup feeds back as opts.DiffPath, unchanged for the exit-0 case and
// text-mutated for the exit-4 case.
func TestLookupOne_ASN_Diff(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(asnTestRDAPBody))
	}))
	defer rdapSrv.Close()

	rirWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		return asnTestWHOISText
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + rirWHOISAddr + "\n"
	})

	resolver := bootstrap.NewASNResolver(map[[2]uint32]string{
		{15169, 15169}: rdapSrv.URL,
	})
	baseOpts := lookupOptions{whoisIANAServer: ianaAddr}

	// Produce a baseline -o json snapshot from a fresh lookup, exactly
	// what a user would have saved via `plat AS15169 -o json > before.json`.
	var baseline, baselineErr bytes.Buffer
	client := newTestClient(t, resolver, baseOpts, nil)
	code := lookupOne(
		context.Background(), &baseline, &baselineErr, client, "AS15169",
		baseOpts, nil, render.FormatJSON, uiConfig{},
	)
	if code != 0 {
		t.Fatalf("baseline lookup exit code = %d, want 0\nstderr: %s", code, baselineErr.String())
	}

	snapPath := filepath.Join(t.TempDir(), "before.json")
	if err := os.WriteFile(snapPath, baseline.Bytes(), 0o600); err != nil {
		t.Fatalf("writing snapshot: %v", err)
	}

	t.Run("unchanged sources exit 0", func(t *testing.T) {
		opts := baseOpts
		opts.DiffPath = snapPath
		var stdout, stderr bytes.Buffer
		client := newTestClient(t, resolver, opts, nil)
		code := lookupOne(
			context.Background(), &stdout, &stderr, client, "AS15169",
			opts, nil, render.FormatPlain, uiConfig{},
		)
		if code != 0 {
			t.Errorf("exit code = %d, want 0\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "no changes") {
			t.Errorf(`stdout missing "no changes", got:\n%s`, stdout.String())
		}
	})

	t.Run("mutated field exits 4 and is reported", func(t *testing.T) {
		mutated := strings.Replace(baseline.String(), "Google LLC", "Mutated Org LLC", 1)
		if mutated == baseline.String() {
			t.Fatal("mutation left the snapshot unchanged -- the org name text moved in the fixture")
		}
		mutatedPath := filepath.Join(t.TempDir(), "mutated.json")
		if err := os.WriteFile(mutatedPath, []byte(mutated), 0o600); err != nil {
			t.Fatalf("writing mutated snapshot: %v", err)
		}

		opts := baseOpts
		opts.DiffPath = mutatedPath
		var stdout, stderr bytes.Buffer
		client := newTestClient(t, resolver, opts, nil)
		code := lookupOne(
			context.Background(), &stdout, &stderr, client, "AS15169",
			opts, nil, render.FormatPlain, uiConfig{},
		)
		if code != 4 {
			t.Errorf("exit code = %d, want 4\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "Mutated Org LLC") {
			t.Errorf("stdout missing the diffed-away value, got:\n%s", stdout.String())
		}
		if !strings.Contains(stdout.String(), "1 changed") {
			t.Errorf("stdout missing change count, got:\n%s", stdout.String())
		}
	})
}

// TestLookupOne_ASN_Diff_RenderErrorPath_ExitCode3 is
// TestLookupOne_Diff_RenderErrorPath_ExitCode3's ASN counterpart, covering
// lookupOneASN's --diff render-error branch.
func TestLookupOne_ASN_Diff_RenderErrorPath_ExitCode3(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(asnTestRDAPBody))
	}))
	defer rdapSrv.Close()

	rirWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		return asnTestWHOISText
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + rirWHOISAddr + "\n"
	})

	resolver := bootstrap.NewASNResolver(map[[2]uint32]string{
		{15169, 15169}: rdapSrv.URL,
	})
	baseOpts := lookupOptions{whoisIANAServer: ianaAddr}

	var baseline, baselineErr bytes.Buffer
	client := newTestClient(t, resolver, baseOpts, nil)
	code := lookupOne(
		context.Background(), &baseline, &baselineErr, client, "AS15169",
		baseOpts, nil, render.FormatJSON, uiConfig{},
	)
	if code != 0 {
		t.Fatalf("baseline lookup exit code = %d, want 0\nstderr: %s", code, baselineErr.String())
	}
	snapPath := filepath.Join(t.TempDir(), "before.json")
	if err := os.WriteFile(snapPath, baseline.Bytes(), 0o600); err != nil {
		t.Fatalf("writing snapshot: %v", err)
	}

	opts := baseOpts
	opts.DiffPath = snapPath
	var stderr bytes.Buffer
	client = newTestClient(t, resolver, opts, nil)
	code = lookupOne(
		context.Background(), errWriter{}, &stderr, client, "AS15169",
		opts, nil, render.FormatPlain, uiConfig{},
	)
	if code != 3 {
		t.Errorf("exit code = %d, want 3\nstderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "AS15169") {
		t.Errorf("stderr missing ASN in render-failure message, got:\n%s", stderr.String())
	}
}

// TestLookupOne_ASN_SpinnerBranch_HumanFormat is lookupOneASN's counterpart
// to TestLookupOne_SpinnerBranch_HumanFormat: StderrTTY: true + FormatHuman
// is exactly the condition lookupOneASN checks to route work() through
// spinner.Run instead of calling it directly, and no other ASN test in this
// file exercises it.
func TestLookupOne_ASN_SpinnerBranch_HumanFormat(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(asnTestRDAPBody))
	}))
	defer rdapSrv.Close()

	rirWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		return asnTestWHOISText
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + rirWHOISAddr + "\n"
	})

	resolver := bootstrap.NewASNResolver(map[[2]uint32]string{
		{15169, 15169}: rdapSrv.URL,
	})

	var stdout, stderr bytes.Buffer
	opts := lookupOptions{whoisIANAServer: ianaAddr}
	client := newTestClient(t, resolver, opts, nil)
	code := lookupOne(
		context.Background(), &stdout, &stderr, client, "AS15169",
		opts,
		nil, render.FormatHuman, uiConfig{StderrTTY: true},
	)

	if code != 0 {
		t.Errorf("exit code = %d, want 0\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "AS15169") {
		t.Errorf("stdout missing handle -- spinner.Run may have interfered with the result, got:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Google LLC") {
		t.Errorf("stdout missing WHOIS-sourced org name, got:\n%s", stdout.String())
	}
}

// errWriter is an io.Writer that always fails, used below to force
// lookupOneASN's render-error branch (cmd/plat/main.go, the `if err :=
// renderASNRecord(...); err != nil` block): with a successful collect/merge
// (code == 0), the only way renderASNRecord returns a non-nil error is a
// write failure on stdout, since its own format-dispatch branches are
// already covered directly in main_test.go against valid writers.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) {
	return 0, errors.New("errWriter: forced write failure")
}

// TestLookupOne_ASN_RenderErrorPath_ExitCode3 covers lookupOneASN's
// render-error branch: a successful lookup (code == 0) whose render step
// fails must report the error and return exit 3, not 0. Quiet mode's
// renderASNRecord path is a single fmt.Fprintln, the simplest way to force
// that failure deterministically without depending on any renderer's
// internals.
func TestLookupOne_ASN_RenderErrorPath_ExitCode3(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(asnTestRDAPBody))
	}))
	defer rdapSrv.Close()

	rirWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		return asnTestWHOISText
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + rirWHOISAddr + "\n"
	})

	resolver := bootstrap.NewASNResolver(map[[2]uint32]string{
		{15169, 15169}: rdapSrv.URL,
	})

	var stderr bytes.Buffer
	opts := lookupOptions{whoisIANAServer: ianaAddr, Quiet: true}
	client := newTestClient(t, resolver, opts, nil)
	code := lookupOne(
		context.Background(), errWriter{}, &stderr, client, "AS15169",
		opts,
		nil, render.FormatPlain, uiConfig{},
	)

	if code != 3 {
		t.Errorf("exit code = %d, want 3\nstderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "AS15169") {
		t.Errorf("stderr missing ASN in render-failure message, got:\n%s", stderr.String())
	}
}
