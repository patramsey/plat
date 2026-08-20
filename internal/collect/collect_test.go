package collect

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/domain"
	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/whois"
)

func startWHOISListener(t *testing.T, respond func(query string) string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		query := strings.TrimRight(string(buf[:n]), "\r\n")
		_, _ = conn.Write([]byte(respond(query)))
	}()
	return ln.Addr().String()
}

func TestCollect_RegistryAndRegistrarRDAPPlusWHOIS(t *testing.T) {
	registryFixture, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	registrarFixture, err := os.ReadFile("../../testdata/rdap/registrar-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	registrarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(registrarFixture)
	}))
	defer registrarSrv.Close()

	registrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve the registry fixture, but with a "related" link injected
		// pointing at the registrar test server (whose address is only
		// known once it's started, so we can't bake this into a static
		// fixture file).
		body := strings.Replace(
			string(registryFixture),
			`"rdapConformance"`,
			fmt.Sprintf(`"links":[{"rel":"related","href":%q,"type":"application/rdap+json"}],"rdapConformance"`, registrarSrv.URL+"/rdap/domain/EXAMPLE.COM"),
			1,
		)
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer registrySrv.Close()

	registrarWHOISAddr := startWHOISListener(t, func(query string) string {
		return "Domain Name: example.com\nRegistrar: Example Registrar, Inc.\n"
	})
	registryWHOISAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: %s\nRegistrar: Example Registrar, Inc.\n", registrarWHOISAddr)
	})
	ianaWHOISAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("refer:        %s\ndomain:       COM\n", registryWHOISAddr)
	})

	q, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	name := q.Name

	sources := Collect(context.Background(), name, registrySrv.URL, ianaWHOISAddr, Options{Timeout: 2 * time.Second})

	var gotRegistryRDAP, gotRegistrarRDAP bool
	for _, s := range sources {
		if s.Meta.Source == "registry-rdap" && s.Present {
			gotRegistryRDAP = true
		}
		if s.Meta.Source == "registrar-rdap" && s.Present {
			gotRegistrarRDAP = true
			if s.Registrar.Name != "Example Registrar, Inc." {
				t.Errorf("registrar-rdap Registrar.Name = %q, want %q", s.Registrar.Name, "Example Registrar, Inc.")
			}
		}
	}
	if !gotRegistryRDAP {
		t.Error("expected a present registry-rdap source")
	}
	if !gotRegistrarRDAP {
		t.Error("expected a present registrar-rdap source (related link should have been followed)")
	}
}

func TestCollect_NoFollowSkipsRegistrarHop(t *testing.T) {
	registrarFixture, err := os.ReadFile("../../testdata/rdap/registrar-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	registrarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("registrar server should not have been contacted when NoFollow is set")
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(registrarFixture)
	}))
	defer registrarSrv.Close()

	registryFixture, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	registrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := strings.Replace(
			string(registryFixture),
			`"rdapConformance"`,
			fmt.Sprintf(`"links":[{"rel":"related","href":%q,"type":"application/rdap+json"}],"rdapConformance"`, registrarSrv.URL+"/rdap/domain/EXAMPLE.COM"),
			1,
		)
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer registrySrv.Close()

	registrarWHOISAddr := startWHOISListener(t, func(query string) string {
		return "Domain Name: example.com\nRegistrar: Example Registrar, Inc.\n"
	})
	registryWHOISAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: %s\nRegistrar: Example Registrar, Inc.\n", registrarWHOISAddr)
	})
	ianaWHOISAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("refer:        %s\ndomain:       COM\n", registryWHOISAddr)
	})

	q, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	name := q.Name

	sources := Collect(context.Background(), name, registrySrv.URL, ianaWHOISAddr, Options{NoFollow: true, Timeout: 2 * time.Second})

	for _, s := range sources {
		if s.Meta.Source == "registrar-rdap" {
			t.Errorf("expected no registrar-rdap source when NoFollow is set, got %+v", s)
		}
	}
}

func TestCollect_EmptyBaseURLSkipsRDAPEntirely(t *testing.T) {
	registrarAddr := startWHOISListener(t, func(query string) string {
		return "Domain Name: example.zz\nRegistrar: Example Registrar\n"
	})
	registryAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("Domain Name: EXAMPLE.ZZ\nRegistrar WHOIS Server: %s\nRegistrar: Example Registrar\n", registrarAddr)
	})
	ianaAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("refer:        %s\ndomain:       ZZ\n", registryAddr)
	})

	q, err := domain.Normalize("example.zz")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	name := q.Name

	sources := Collect(context.Background(), name, "", ianaAddr, Options{Timeout: 2 * time.Second})

	for _, s := range sources {
		if s.Meta.Source == "registry-rdap" || s.Meta.Source == "registrar-rdap" {
			t.Errorf("expected no RDAP sources when registryBaseURL is empty, got %+v", s)
		}
	}
}

func TestCollect_WHOISOnlySources(t *testing.T) {
	registrarAddr := startWHOISListener(t, func(query string) string {
		return "Domain Name: example.com\nRegistrant Organization: Example Corp\nRegistrar: Example Registrar, Inc.\n"
	})
	registryAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: %s\nRegistrar: Example Registrar, Inc.\n", registrarAddr)
	})
	ianaAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("refer:        %s\ndomain:       COM\n", registryAddr)
	})

	q, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	name := q.Name

	sources := Collect(context.Background(), name, "", ianaAddr, Options{Timeout: 2 * time.Second})

	var gotRegistryWHOIS, gotRegistrarWHOIS bool
	for _, s := range sources {
		if s.Meta.Source == "registry-whois" && s.Present {
			gotRegistryWHOIS = true
		}
		if s.Meta.Source == "registrar-whois" && s.Present {
			gotRegistrarWHOIS = true
		}
	}
	if !gotRegistryWHOIS || !gotRegistrarWHOIS {
		t.Errorf("expected both WHOIS sources present, got registry=%v registrar=%v", gotRegistryWHOIS, gotRegistrarWHOIS)
	}
}

func TestCollect_SourceFilterRDAPOnly(t *testing.T) {
	registrarFixture, err := os.ReadFile("../../testdata/rdap/registrar-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	registrarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(registrarFixture)
	}))
	defer registrarSrv.Close()

	registryFixture, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	registrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := strings.Replace(
			string(registryFixture),
			`"rdapConformance"`,
			fmt.Sprintf(`"links":[{"rel":"related","href":%q,"type":"application/rdap+json"}],"rdapConformance"`, registrarSrv.URL+"/rdap/domain/EXAMPLE.COM"),
			1,
		)
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer registrySrv.Close()

	ianaWHOISAddr := startWHOISListener(t, func(query string) string {
		t.Error("WHOIS IANA server should never be contacted when --source rdap is set")
		return ""
	})

	q, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	name := q.Name

	sources := Collect(context.Background(), name, registrySrv.URL, ianaWHOISAddr, Options{
		Timeout: 2 * time.Second,
		Sources: []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistrarRDAP},
	})

	var gotRegistryRDAP, gotRegistrarRDAP bool
	for _, s := range sources {
		switch s.Meta.Source {
		case model.SourceRegistryRDAP:
			gotRegistryRDAP = true
		case model.SourceRegistrarRDAP:
			gotRegistrarRDAP = true
		case model.SourceRegistryWHOIS, model.SourceRegistrarWHOIS:
			t.Errorf("unexpected WHOIS source in output: %+v", s)
		}
	}
	if !gotRegistryRDAP || !gotRegistrarRDAP {
		t.Errorf("expected both RDAP sources present, got registry=%v registrar=%v", gotRegistryRDAP, gotRegistrarRDAP)
	}
}

func TestCollect_SourceFilterWHOISOnly(t *testing.T) {
	registrarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("registrar RDAP server should never be contacted when --source whois is set")
	}))
	defer registrarSrv.Close()
	registrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("registry RDAP server should never be contacted when --source whois is set")
	}))
	defer registrySrv.Close()

	registrarWHOISAddr := startWHOISListener(t, func(query string) string {
		return "Domain Name: example.com\nRegistrar: Example Registrar, Inc.\n"
	})
	registryWHOISAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: %s\nRegistrar: Example Registrar, Inc.\n", registrarWHOISAddr)
	})
	ianaWHOISAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("refer:        %s\ndomain:       COM\n", registryWHOISAddr)
	})

	q, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	name := q.Name

	sources := Collect(context.Background(), name, registrySrv.URL, ianaWHOISAddr, Options{
		Timeout: 2 * time.Second,
		Sources: []model.SourceID{model.SourceRegistryWHOIS, model.SourceRegistrarWHOIS},
	})

	var gotRegistryWHOIS, gotRegistrarWHOIS bool
	for _, s := range sources {
		switch s.Meta.Source {
		case model.SourceRegistryWHOIS:
			gotRegistryWHOIS = true
		case model.SourceRegistrarWHOIS:
			gotRegistrarWHOIS = true
		case model.SourceRegistryRDAP, model.SourceRegistrarRDAP:
			t.Errorf("unexpected RDAP source in output: %+v", s)
		}
	}
	if !gotRegistryWHOIS || !gotRegistrarWHOIS {
		t.Errorf("expected both WHOIS sources present, got registry=%v registrar=%v", gotRegistryWHOIS, gotRegistrarWHOIS)
	}
}

func TestCollect_SourceFilterRegistryOnly(t *testing.T) {
	// registrar-rdap must be genuinely suppressed (never contacted) since
	// it depends only on the registrar-rdap allow-check, not on anything
	// structurally required.
	registrarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("registrar RDAP server should never be contacted when --source registry is set")
	}))
	defer registrarSrv.Close()

	registryFixture, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	registrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := strings.Replace(
			string(registryFixture),
			`"rdapConformance"`,
			fmt.Sprintf(`"links":[{"rel":"related","href":%q,"type":"application/rdap+json"}],"rdapConformance"`, registrarSrv.URL+"/rdap/domain/EXAMPLE.COM"),
			1,
		)
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer registrySrv.Close()

	// The registrar WHOIS hop WILL still be contacted (the referral chain
	// is structurally sequential), so this listener must respond normally
	// rather than fail the test — only its RESULT should be filtered out.
	registrarWHOISAddr := startWHOISListener(t, func(query string) string {
		return "Domain Name: example.com\nRegistrar: Example Registrar, Inc.\n"
	})
	registryWHOISAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: %s\nRegistrar: Example Registrar, Inc.\n", registrarWHOISAddr)
	})
	ianaWHOISAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("refer:        %s\ndomain:       COM\n", registryWHOISAddr)
	})

	q, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	name := q.Name

	sources := Collect(context.Background(), name, registrySrv.URL, ianaWHOISAddr, Options{
		Timeout: 2 * time.Second,
		Sources: []model.SourceID{model.SourceRegistryRDAP, model.SourceRegistryWHOIS},
	})

	var gotRegistryRDAP, gotRegistryWHOIS bool
	for _, s := range sources {
		switch s.Meta.Source {
		case model.SourceRegistryRDAP:
			gotRegistryRDAP = true
		case model.SourceRegistryWHOIS:
			gotRegistryWHOIS = true
		case model.SourceRegistrarRDAP, model.SourceRegistrarWHOIS:
			t.Errorf("unexpected registrar-tier source in output: %+v", s)
		}
	}
	if !gotRegistryRDAP || !gotRegistryWHOIS {
		t.Errorf("expected both registry-tier sources present, got rdap=%v whois=%v", gotRegistryRDAP, gotRegistryWHOIS)
	}
}

func TestCollect_SourceFilterRegistrarOnly(t *testing.T) {
	registrarFixture, err := os.ReadFile("../../testdata/rdap/registrar-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	registrarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(registrarFixture)
	}))
	defer registrarSrv.Close()

	// The registry RDAP server WILL still be contacted (needed to
	// discover the related link), so it must respond normally — only its
	// RESULT should be filtered out of the output.
	registryFixture, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	registrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := strings.Replace(
			string(registryFixture),
			`"rdapConformance"`,
			fmt.Sprintf(`"links":[{"rel":"related","href":%q,"type":"application/rdap+json"}],"rdapConformance"`, registrarSrv.URL+"/rdap/domain/EXAMPLE.COM"),
			1,
		)
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer registrySrv.Close()

	registrarWHOISAddr := startWHOISListener(t, func(query string) string {
		return "Domain Name: example.com\nRegistrar: Example Registrar, Inc.\n"
	})
	registryWHOISAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: %s\nRegistrar: Example Registrar, Inc.\n", registrarWHOISAddr)
	})
	ianaWHOISAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("refer:        %s\ndomain:       COM\n", registryWHOISAddr)
	})

	q, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	name := q.Name

	sources := Collect(context.Background(), name, registrySrv.URL, ianaWHOISAddr, Options{
		Timeout: 2 * time.Second,
		Sources: []model.SourceID{model.SourceRegistrarRDAP, model.SourceRegistrarWHOIS},
	})

	var gotRegistrarRDAP, gotRegistrarWHOIS bool
	for _, s := range sources {
		switch s.Meta.Source {
		case model.SourceRegistrarRDAP:
			gotRegistrarRDAP = true
		case model.SourceRegistrarWHOIS:
			gotRegistrarWHOIS = true
		case model.SourceRegistryRDAP, model.SourceRegistryWHOIS:
			t.Errorf("unexpected registry-tier source in output: %+v", s)
		}
	}
	if !gotRegistrarRDAP || !gotRegistrarWHOIS {
		t.Errorf("expected both registrar-tier sources present, got rdap=%v whois=%v", gotRegistrarRDAP, gotRegistrarWHOIS)
	}
}

func TestCollect_RDAPAndWHOISRunConcurrently(t *testing.T) {
	// Regression test: Collect's RDAP and WHOIS branches must run in
	// parallel goroutines, not one after the other. Each branch here is
	// made to take ~branchDelay on its own (an artificial sleep on the
	// first hop of each), so a sequential implementation would take
	// roughly 2x branchDelay wall-clock, while a concurrent one takes
	// roughly 1x. The assertion checks for well under 2x, with plenty of
	// margin for scheduler/test-runner jitter, rather than pinning to 1x
	// exactly. branchDelay is 400ms, not a tighter value, so that margin
	// stays an absolute ~250ms-plus even under -race's added scheduling
	// overhead combined with other packages' tests running concurrently
	// (`go test ./...` runs packages in parallel by default) -- confirmed
	// flaky at 150ms under that combination (elapsed 344ms vs. a 300ms
	// threshold) despite passing 5/5 in isolation, i.e. contention
	// jitter, not a real concurrency regression.
	const branchDelay = 400 * time.Millisecond

	registryFixture, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	registrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(branchDelay)
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(registryFixture)
	}))
	defer registrySrv.Close()

	registryWHOISAddr := startWHOISListener(t, func(query string) string {
		return "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar, Inc.\n"
	})
	ianaWHOISAddr := startWHOISListener(t, func(query string) string {
		time.Sleep(branchDelay)
		return fmt.Sprintf("refer:        %s\ndomain:       COM\n", registryWHOISAddr)
	})

	q, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	name := q.Name

	start := time.Now()
	sources := Collect(context.Background(), name, registrySrv.URL, ianaWHOISAddr, Options{
		NoFollow: true,
		Timeout:  2 * time.Second,
	})
	elapsed := time.Since(start)

	if elapsed >= 2*branchDelay {
		t.Errorf("Collect took %v, want well under %v (2x branchDelay) — RDAP and WHOIS appear to be running sequentially, not concurrently", elapsed, 2*branchDelay)
	}

	var gotRegistryRDAP, gotRegistryWHOIS bool
	for _, s := range sources {
		if s.Meta.Source == model.SourceRegistryRDAP && s.Present {
			gotRegistryRDAP = true
		}
		if s.Meta.Source == model.SourceRegistryWHOIS && s.Present {
			gotRegistryWHOIS = true
		}
	}
	if !gotRegistryRDAP || !gotRegistryWHOIS {
		t.Errorf("expected both registry-tier sources present despite the delays, got rdap=%v whois=%v", gotRegistryRDAP, gotRegistryWHOIS)
	}
}

func TestCollect_Port43FallbackWhenRegistryWHOISGivesNoReferral(t *testing.T) {
	// Reproduces Identity Digital's .ninja: the registry's own WHOIS
	// refuses the query outright (no "Registrar WHOIS Server:" line to
	// follow), but the registrar-RDAP hop's response — already fetched
	// via the existing "related" link-following — carries RFC 9083's
	// optional port43 field pointing at the registrar's real WHOIS
	// server. Collect must recover registrar-whois data via that
	// fallback rather than giving up.
	registryFixture, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	registrarFixture, err := os.ReadFile("../../testdata/rdap/registrar-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	registrarWHOISAddr := startWHOISListener(t, func(query string) string {
		return "Domain Name: example.com\nRegistrar: Example Registrar, Inc.\n"
	})

	registrarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := strings.Replace(
			string(registrarFixture),
			`"objectClassName"`,
			fmt.Sprintf(`"port43":%q,"objectClassName"`, registrarWHOISAddr),
			1,
		)
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer registrarSrv.Close()

	registrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := strings.Replace(
			string(registryFixture),
			`"rdapConformance"`,
			fmt.Sprintf(`"links":[{"rel":"related","href":%q,"type":"application/rdap+json"}],"rdapConformance"`, registrarSrv.URL+"/rdap/domain/EXAMPLE.COM"),
			1,
		)
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer registrySrv.Close()

	registryWHOISAddr := startWHOISListener(t, func(query string) string {
		return "TLD is not supported.\n" // no "Registrar WHOIS Server:" to follow
	})
	ianaWHOISAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("refer:        %s\ndomain:       COM\n", registryWHOISAddr)
	})

	q, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	name := q.Name

	sources := Collect(context.Background(), name, registrySrv.URL, ianaWHOISAddr, Options{Timeout: 2 * time.Second})

	var registrarWHOIS *model.SourceRecord
	for i, s := range sources {
		if s.Meta.Source == model.SourceRegistrarWHOIS {
			registrarWHOIS = &sources[i]
		}
	}
	if registrarWHOIS == nil {
		t.Fatalf("expected a registrar-whois source in the output, got: %+v", sources)
	}
	if !registrarWHOIS.Present || !registrarWHOIS.Meta.OK {
		t.Errorf("expected the port43 fallback query to succeed, got Present=%v OK=%v Err=%q", registrarWHOIS.Present, registrarWHOIS.Meta.OK, registrarWHOIS.Meta.Err)
	}
	if registrarWHOIS.Registrar.Name != "Example Registrar, Inc." {
		t.Errorf("registrar-whois Registrar.Name = %q, want %q", registrarWHOIS.Registrar.Name, "Example Registrar, Inc.")
	}
}

func TestCollect_Port43FallbackSkippedWhenReferralAlreadyFound(t *testing.T) {
	// The normal registry -> registrar WHOIS referral chain working as
	// usual must NOT also trigger the port43 fallback (which would
	// double-query the registrar's WHOIS server).
	registryFixture, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	registrarFixture, err := os.ReadFile("../../testdata/rdap/registrar-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	var fallbackQueried bool
	fallbackAddr := startWHOISListener(t, func(query string) string {
		fallbackQueried = true
		return "Domain Name: example.com\nRegistrar: Should Not Be Used\n"
	})

	registrarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := strings.Replace(
			string(registrarFixture),
			`"objectClassName"`,
			fmt.Sprintf(`"port43":%q,"objectClassName"`, fallbackAddr),
			1,
		)
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer registrarSrv.Close()

	registrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := strings.Replace(
			string(registryFixture),
			`"rdapConformance"`,
			fmt.Sprintf(`"links":[{"rel":"related","href":%q,"type":"application/rdap+json"}],"rdapConformance"`, registrarSrv.URL+"/rdap/domain/EXAMPLE.COM"),
			1,
		)
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer registrySrv.Close()

	registrarWHOISAddr := startWHOISListener(t, func(query string) string {
		return "Domain Name: example.com\nRegistrar: Example Registrar, Inc.\n"
	})
	registryWHOISAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: %s\nRegistrar: Example Registrar, Inc.\n", registrarWHOISAddr)
	})
	ianaWHOISAddr := startWHOISListener(t, func(query string) string {
		return fmt.Sprintf("refer:        %s\ndomain:       COM\n", registryWHOISAddr)
	})

	q, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	name := q.Name

	sources := Collect(context.Background(), name, registrySrv.URL, ianaWHOISAddr, Options{Timeout: 2 * time.Second})

	if fallbackQueried {
		t.Error("port43 fallback server was queried even though the normal referral chain already found a registrar-whois server")
	}
	for _, s := range sources {
		if s.Meta.Source == model.SourceRegistrarWHOIS && s.Registrar.Name != "Example Registrar, Inc." {
			t.Errorf("registrar-whois Registrar.Name = %q, want the normal-chain value, not the fallback's", s.Registrar.Name)
		}
	}
}

// TestCollect_WHOISTimeoutBoundsWholeChainNotEachHop confirms
// Options.Timeout's doc comment: it must bound the whole WHOIS chain
// (IANA + registry [+ registrar]), not hand each hop its own fresh
// budget. Without that, a chain of hops each individually well under
// Timeout can still take up to N x Timeout in total.
func TestCollect_WHOISTimeoutBoundsWholeChainNotEachHop(t *testing.T) {
	const hopDelay = 200 * time.Millisecond
	const timeout = 300 * time.Millisecond

	registryAddr := startWHOISListener(t, func(query string) string {
		time.Sleep(hopDelay)
		return "Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: whois.example-registrar.example\n"
	})
	ianaAddr := startWHOISListener(t, func(query string) string {
		time.Sleep(hopDelay)
		return fmt.Sprintf("refer:        %s\ndomain:       COM\n", registryAddr)
	})

	q, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	name := q.Name

	start := time.Now()
	sources := Collect(context.Background(), name, "", ianaAddr, Options{Timeout: timeout})
	elapsed := time.Since(start)

	// Each hop's own delay (200ms) fits comfortably under Timeout (300ms)
	// individually, so if each hop got its own fresh Timeout budget (the
	// bug), the IANA and registry hops would both succeed and the chain
	// would take ~2x hopDelay = 400ms. If Timeout genuinely bounds the
	// whole chain, the registry hop only has ~100ms of shared budget left
	// after the IANA hop's 200ms, so it fails partway through its own
	// 200ms sleep instead of completing.
	if elapsed >= 2*hopDelay {
		t.Errorf("Collect took %v, want well under %v (2x hopDelay) -- each hop appears to get its own fresh Timeout budget instead of sharing one for the whole chain", elapsed, 2*hopDelay)
	}

	var found bool
	for _, s := range sources {
		if s.Meta.Source == model.SourceRegistryWHOIS {
			found = true
			if s.Meta.OK {
				t.Errorf("registry-whois succeeded despite exhausting the chain's shared timeout budget: %+v", s)
			}
		}
	}
	if !found {
		t.Fatal("expected a registry-whois SourceRecord (even a failed one) in the results")
	}
}

// startLoopingWHOISListener is startWHOISListener plus an Accept loop (so
// it can serve more than one connection, needed by tests that share one
// fake server across several concurrent Collect calls) and an optional
// atomic hit counter.
func startLoopingWHOISListener(t *testing.T, hits *int32, respond func(query string) string) string {
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
			if hits != nil {
				atomic.AddInt32(hits, 1)
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

// TestCollect_BulkSharedLimiterAndIANACacheAllRetainRegistryWHOIS is C1's
// end-to-end regression test at the collect level: four names split
// across two TLDs run Collect concurrently, sharing one whois.HostLimiter
// and one whois.IANACache exactly the way runLookupPool wires a real bulk
// run (main.go). Before this fix (C1a: pacing waits charged against the
// per-name chain deadline; C1b: every name re-querying IANA even though
// the TLD->server mapping is constant for the run), the shared IANA host
// alone would pace four names to slots 0/200/400/600ms against a 600ms
// chain deadline, timing at least one of them out before it sent a byte
// -- silently losing registry-whois with exit code still 0, exactly the
// live defect this review caught. With both fixes: IANACache means at
// most one real IANA query per TLD (two here), so pacing on that shared
// host tops out at 200ms; per-TLD registry-host pacing (two names each)
// also tops out at 200ms; both fit comfortably inside the 600ms budget.
func TestCollect_BulkSharedLimiterAndIANACacheAllRetainRegistryWHOIS(t *testing.T) {
	const interval = 200 * time.Millisecond
	const timeout = 600 * time.Millisecond

	comRegistry := startLoopingWHOISListener(t, nil, func(query string) string {
		return "Domain Name: " + strings.ToUpper(query) + "\nRegistrar: Example Registrar, Inc.\n"
	})
	orgRegistry := startLoopingWHOISListener(t, nil, func(query string) string {
		return "Domain Name: " + strings.ToUpper(query) + "\nRegistrar: Example Registrar, Inc.\n"
	})

	var ianaHits int32
	ianaAddr := startLoopingWHOISListener(t, &ianaHits, func(query string) string {
		switch strings.TrimSpace(query) {
		case "com":
			return "refer: " + comRegistry + "\n"
		case "org":
			return "refer: " + orgRegistry + "\n"
		default:
			t.Errorf("unexpected IANA query %q", query)
			return ""
		}
	})

	names := []string{"one.com", "two.com", "three.org", "four.org"}
	opts := Options{
		Timeout:   timeout,
		Limiter:   whois.NewHostLimiter(interval),
		IANACache: whois.NewIANACache(),
	}

	results := make([][]model.SourceRecord, len(names))
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(1)
		go func(i int, n string) {
			defer wg.Done()
			q, err := domain.Normalize(n)
			if err != nil {
				t.Errorf("normalize %s: %v", n, err)
				return
			}
			results[i] = Collect(context.Background(), q.Name, "", ianaAddr, opts)
		}(i, n)
	}
	wg.Wait()

	if got := atomic.LoadInt32(&ianaHits); got > 2 {
		t.Errorf("IANA listener hit %d times for 4 names across 2 TLDs, want <= 2 (one per TLD, thanks to IANACache) -- caching isn't sharing hits across names", got)
	}

	for i, n := range names {
		var found bool
		for _, s := range results[i] {
			if s.Meta.Source == model.SourceRegistryWHOIS {
				found = true
				if !s.Meta.OK {
					t.Errorf("%s: registry-whois failed: %s -- a pacing wait must have been charged against this name's own chain deadline", n, s.Meta.Err)
				}
			}
		}
		if !found {
			t.Errorf("%s: no registry-whois source in results", n)
		}
	}
}

// TestCollect_BulkPacingIsNotChargedAgainstTheChainDeadline is the
// deterministic, hermetic gate for C1: a pacing wait must never be spent
// out of the same budget as the network hops it precedes.
//
// The sibling test above deliberately sizes its run to FIT inside the
// chain budget (two TLDs, so IANA pacing tops out at 200ms against a
// 600ms timeout), which means it passes whether or not pacing is charged
// against that budget. This one is sized so it cannot fit: eight names on
// eight distinct TLDs, each with its own registry listener, all resolving
// through the ONE shared IANA host. IANACache collapses nothing here (the
// eight TLDs are eight distinct cache keys), so the shared HostLimiter
// hands out IANA slots at 0/200/400/.../1400ms while each name's chain
// deadline is only 600ms wide. Every name whose slot falls at or past
// 600ms therefore reaches its dial with an already-expired context and
// loses registry-whois -- five of eight, with the process never touching
// the network and the exit code still 0.
//
// The assertion counts RETAINED registry-whois sources rather than
// matching an error string on purpose: the failure has already been
// "fixed" once by moving where the deadline killed the hop (from
// Limiter.Acquire to the dial), which changed the message from
// "whois: pacing ...: context deadline exceeded" to a generic
// "dial tcp: i/o timeout" while losing exactly the same five names. Only
// the count is evidence.
func TestCollect_BulkPacingIsNotChargedAgainstTheChainDeadline(t *testing.T) {
	const interval = 200 * time.Millisecond
	const timeout = 600 * time.Millisecond

	// Eight names, eight TLDs, one registry listener each -- so no two
	// names ever pace against each other on a REGISTRY host and the only
	// contended server in the run is IANA itself.
	names := []string{
		"one.com", "two.org", "three.net", "four.info",
		"five.biz", "six.dev", "seven.app", "eight.io",
	}

	registryFor := make(map[string]string, len(names))
	for _, n := range names {
		tld := n[strings.LastIndex(n, ".")+1:]
		registryFor[tld] = startLoopingWHOISListener(t, nil, func(query string) string {
			return "Domain Name: " + strings.ToUpper(query) + "\nRegistrar: Example Registrar, Inc.\n"
		})
	}

	ianaAddr := startLoopingWHOISListener(t, nil, func(query string) string {
		addr, ok := registryFor[strings.TrimSpace(query)]
		if !ok {
			t.Errorf("unexpected IANA query %q", query)
			return ""
		}
		return "refer: " + addr + "\n"
	})

	opts := Options{
		Timeout:   timeout,
		Limiter:   whois.NewHostLimiter(interval),
		IANACache: whois.NewIANACache(),
	}

	results := make([][]model.SourceRecord, len(names))
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(1)
		go func(i int, n string) {
			defer wg.Done()
			q, err := domain.Normalize(n)
			if err != nil {
				t.Errorf("normalize %s: %v", n, err)
				return
			}
			results[i] = Collect(context.Background(), q.Name, "", ianaAddr, opts)
		}(i, n)
	}
	wg.Wait()

	var retained int
	for i, n := range names {
		for _, s := range results[i] {
			if s.Meta.Source != model.SourceRegistryWHOIS {
				continue
			}
			if s.Meta.OK {
				retained++
			} else {
				t.Logf("%s: registry-whois failed: %s", n, s.Meta.Err)
			}
		}
	}
	if retained != len(names) {
		t.Errorf("registry-whois retained for %d/%d names, want %d/%d -- a pacing wait is still being charged against the chain deadline", retained, len(names), len(names), len(names))
	}
}

// countingTransport records how many round trips it served so the test
// can prove the caller's client was the one actually used, rather than
// merely that the lookup succeeded.
type countingTransport struct {
	n int
}

func (t *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.n++
	return http.DefaultTransport.RoundTrip(r)
}

func TestCollect_UsesSuppliedHTTPClient(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	tr := &countingTransport{}
	name := domain.Name{Punycode: "example.com", Unicode: "example.com", TLD: "com"}

	Collect(context.Background(), name, srv.URL, "127.0.0.1:1", Options{
		Timeout:    2 * time.Second,
		NoFollow:   true,
		Sources:    []model.SourceID{model.SourceRegistryRDAP},
		HTTPClient: &http.Client{Transport: tr},
	})

	if tr.n == 0 {
		t.Fatal("supplied HTTPClient was never used; collect built its own")
	}
}
