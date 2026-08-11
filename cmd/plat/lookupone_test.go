package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

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
	code := lookupOne(
		context.Background(), &stdout, &stderr, resolver, "example.com",
		lookupOptions{whoisIANAServer: ianaAddr, NoFollow: true},
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
	code := lookupOne(
		context.Background(), &stdout, &stderr, resolver, "example.com",
		lookupOptions{whoisIANAServer: ianaAddr, NoFollow: true},
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
	code := lookupOne(
		context.Background(), &stdout, &stderr, resolver, "example.com",
		lookupOptions{whoisIANAServer: ianaAddr, NoFollow: true},
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
	code := lookupOne(
		context.Background(), &stdout, &stderr, resolver, "example.com",
		lookupOptions{whoisIANAServer: "127.0.0.1:1", NoFollow: true, Timeout: time.Second},
		nil, render.FormatPlain, uiConfig{},
	)

	if code != 3 {
		t.Errorf("exit code = %d, want 3\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "example.com") {
		t.Errorf("stderr missing domain in failure message, got:\n%s", stderr.String())
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
	code := lookupOne(
		context.Background(), &stdout, &stderr, resolver, "example.com",
		lookupOptions{whoisIANAServer: ianaAddr, NoFollow: true},
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
	code := lookupOne(
		context.Background(), &stdout, &stderr, resolver, "8.8.8.8",
		lookupOptions{whoisIANAServer: ianaAddr},
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
	code := lookupOne(
		context.Background(), &stdout, &stderr, resolver, "8.8.8.8",
		lookupOptions{whoisIANAServer: ianaAddr},
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
	code := lookupOne(
		context.Background(), &stdout, &stderr, resolver, "8.8.8.8",
		lookupOptions{whoisIANAServer: ianaAddr},
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
	code := lookupOne(
		context.Background(), &stdout, &stderr, resolver, "8.8.8.8",
		lookupOptions{whoisIANAServer: "127.0.0.1:1", Timeout: time.Second},
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
	code := lookupOne(
		context.Background(), &stdout, &stderr, resolver, "8.8.8.8",
		lookupOptions{whoisIANAServer: ianaAddr},
		nil, render.FormatJSON, uiConfig{},
	)

	if code != 0 {
		t.Errorf("exit code = %d, want 0\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"objectType":"ip"`) {
		t.Errorf(`stdout missing "objectType":"ip", got:%s`, stdout.String())
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
	code := lookupOne(
		context.Background(), &stdout, &stderr, resolver, "AS15169",
		lookupOptions{whoisIANAServer: ianaAddr},
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
	code := lookupOne(
		context.Background(), &stdout, &stderr, resolver, "AS15169",
		lookupOptions{whoisIANAServer: ianaAddr},
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
	code := lookupOne(
		context.Background(), &stdout, &stderr, resolver, "AS15169",
		lookupOptions{whoisIANAServer: ianaAddr},
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
	code := lookupOne(
		context.Background(), &stdout, &stderr, resolver, "AS15169",
		lookupOptions{whoisIANAServer: "127.0.0.1:1", Timeout: time.Second},
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
	code := lookupOne(
		context.Background(), &stdout, &stderr, resolver, "AS15169",
		lookupOptions{whoisIANAServer: ianaAddr},
		nil, render.FormatJSON, uiConfig{},
	)

	if code != 0 {
		t.Errorf("exit code = %d, want 0\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"objectType":"asn"`) {
		t.Errorf(`stdout missing "objectType":"asn", got:%s`, stdout.String())
	}
}
