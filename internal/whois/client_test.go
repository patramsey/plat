package whois

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/domain"
)

func TestClient_EchoesExactQuery(t *testing.T) {
	var received string
	done := make(chan struct{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		received = string(buf[:n])
		_, _ = conn.Write([]byte("domain: TEST\n"))
	}()

	c := &Client{Timeout: 2 * time.Second}
	_, err = c.query(context.Background(), ln.Addr().String(), "example.com")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	<-done

	if received != "example.com\r\n" {
		t.Errorf("received query = %q, want %q (127.0.0.1 address matches no quirk, so bare domain + CRLF)", received, "example.com\r\n")
	}
}

func TestClient_HopTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		time.Sleep(2 * time.Second)
	}()

	c := &Client{Timeout: 200 * time.Millisecond}
	start := time.Now()
	_, err = c.query(context.Background(), ln.Addr().String(), "example.com")
	elapsed := time.Since(start)

	if elapsed > 1*time.Second {
		t.Fatalf("query took %v, want well under the listener's 2s stall (timeout should have fired around 200ms)", elapsed)
	}
	if err == nil {
		t.Fatal("expected a timeout error")
	}
}

func startListener(t *testing.T, respond func(query string) string) string {
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

func TestClient_ReferralChasing(t *testing.T) {
	registrarAddr := startListener(t, func(query string) string {
		return "Domain Name: example.com\nRegistrant Organization: Example Corp\nRegistrar: Example Registrar, Inc.\n"
	})

	registryAddr := startListener(t, func(query string) string {
		return fmt.Sprintf("Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: %s\nRegistrar: Example Registrar, Inc.\n", registrarAddr)
	})

	ianaAddr := startListener(t, func(query string) string {
		// Real whois.iana.org responses use "whois:", never "refer:" --
		// confirmed live for every TLD checked (.com, .org, .net, .jp,
		// .de, .edu). This fixture previously used "refer:", which never
		// once matched reality: the registry/registrar hops below were
		// silently unreachable for every live domain until parse.go
		// learned "whois" as a synonym for the same Refer field.
		return fmt.Sprintf("whois:        %s\ndomain:       COM\n", registryAddr)
	})

	c := &Client{IANAServer: ianaAddr, Timeout: 2 * time.Second}
	q, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	name := q.Name
	result, err := c.Lookup(context.Background(), name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(result.Hops) != 3 {
		t.Fatalf("Hops = %d, want 3", len(result.Hops))
	}
	if result.Hops[0].Server != ianaAddr {
		t.Errorf("hop 0 server = %q, want %q", result.Hops[0].Server, ianaAddr)
	}
	if result.Hops[1].Server != registryAddr {
		t.Errorf("hop 1 server = %q, want %q", result.Hops[1].Server, registryAddr)
	}
	if result.Hops[2].Server != registrarAddr {
		t.Errorf("hop 2 server = %q, want %q", result.Hops[2].Server, registrarAddr)
	}
	if result.Hops[2].Fields.Registrar != "Example Registrar, Inc." {
		t.Errorf("registrar = %q, want %q", result.Hops[2].Fields.Registrar, "Example Registrar, Inc.")
	}
}

func TestClient_LookupTimeoutReturnsPartialResult(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		time.Sleep(2 * time.Second)
	}()

	c := &Client{IANAServer: ln.Addr().String(), Timeout: 200 * time.Millisecond}
	q, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	name := q.Name

	start := time.Now()
	result, err := c.Lookup(context.Background(), name)
	elapsed := time.Since(start)

	if elapsed > 1*time.Second {
		t.Fatalf("Lookup took %v, want well under the listener's 2s stall", elapsed)
	}
	if err == nil {
		t.Fatal("expected an error since the only hop timed out")
	}
	if len(result.Hops) != 1 {
		t.Fatalf("Hops = %d, want 1 (partial result should still be returned)", len(result.Hops))
	}
	if result.Hops[0].Err == nil {
		t.Error("expected hop 0 to have a timeout error")
	}
}

func TestClient_ReferralChasing_BracketsDialectTLD(t *testing.T) {
	registrarAddr := startListener(t, func(query string) string {
		return "[Domain Name]                  EXAMPLE.JP\n[Registrant]                   Example Corp\n"
	})

	registryAddr := startListener(t, func(query string) string {
		return "[Domain Name]                  EXAMPLE.JP\n[Name Server]                  a.dns.jp\n[Status]                       Active\n"
	})

	ianaAddr := startListener(t, func(query string) string {
		// See TestClient_ReferralChasing's comment: real whois.iana.org
		// responses use "whois:", not "refer:".
		return fmt.Sprintf("whois:        %s\ndomain:       JP\n", registryAddr)
	})
	_ = registrarAddr // the registry response above has no "Registrar WHOIS Server" field, so the chain stops at 2 hops — that's fine, this test's purpose is proving the IANA hop's whois: line parses correctly for a brackets-dialect TLD, not exercising a full 3-hop chain

	c := &Client{IANAServer: ianaAddr, Timeout: 2 * time.Second}
	q, err := domain.Normalize("example.jp")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	name := q.Name
	result, err := c.Lookup(context.Background(), name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(result.Hops) != 2 {
		t.Fatalf("Hops = %d, want 2 (IANA + registry; the IANA hop's whois: line must parse correctly even though .jp's own template is brackets-dialect)", len(result.Hops))
	}
	if result.Hops[0].Fields.Refer != registryAddr {
		t.Errorf("IANA hop Refer = %q, want %q (this is the regression this test guards: the IANA hop must be parsed with the default kv dialect, not .jp's brackets dialect, since IANA's own response format is always plain kv text regardless of the queried TLD)", result.Hops[0].Fields.Refer, registryAddr)
	}
	if result.Hops[1].Server != registryAddr {
		t.Errorf("hop 1 server = %q, want %q", result.Hops[1].Server, registryAddr)
	}
	wantNS := []string{"a.dns.jp"}
	if len(result.Hops[1].Fields.Nameservers) != len(wantNS) || result.Hops[1].Fields.Nameservers[0] != wantNS[0] {
		t.Errorf("registry hop Nameservers = %v, want %v (proves the registry hop DID use the .jp brackets template correctly)", result.Hops[1].Fields.Nameservers, wantNS)
	}
}

func TestClient_ReferralChasing_LegacyReferFieldStillSupported(t *testing.T) {
	// "refer:" is the conventional WHOIS-referral field name and stays
	// recognized as a synonym for the same field "whois:" maps to, even
	// though no real whois.iana.org response observed live actually uses
	// it -- defense in depth in case some other, non-IANA referral server
	// does.
	registryAddr := startListener(t, func(query string) string {
		return "Domain Name: EXAMPLE.COM\n"
	})
	ianaAddr := startListener(t, func(query string) string {
		return fmt.Sprintf("refer:        %s\ndomain:       COM\n", registryAddr)
	})

	c := &Client{IANAServer: ianaAddr, Timeout: 2 * time.Second}
	q, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	name := q.Name
	result, err := c.Lookup(context.Background(), name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(result.Hops) != 2 {
		t.Fatalf("Hops = %d, want 2 (IANA + registry, reached via the legacy refer: field)", len(result.Hops))
	}
}

func TestClient_RateLimitDetected(t *testing.T) {
	ianaAddr := startListener(t, func(query string) string {
		return "% Query rate limit exceeded. Please wait and try again later.\n"
	})

	c := &Client{IANAServer: ianaAddr, Timeout: 2 * time.Second}
	q, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	name := q.Name
	result, err := c.Lookup(context.Background(), name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(result.Hops) != 1 {
		t.Fatalf("Hops = %d, want 1 (no refer: line means no further hops)", len(result.Hops))
	}
	if !result.Hops[0].Fields.RateLimited {
		t.Error("expected RateLimited = true on the IANA hop")
	}
}

func TestClient_QueryServerSkipsReferralChasing(t *testing.T) {
	var received string
	done := make(chan struct{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		received = string(buf[:n])
		_, _ = conn.Write([]byte("Domain Name: EXAMPLE.COM\nRegistrar: Direct Registrar, Inc.\n"))
	}()

	q, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	name := q.Name

	c := &Client{Timeout: 2 * time.Second}
	hop := c.QueryServer(context.Background(), ln.Addr().String(), name)
	<-done

	if hop.Err != nil {
		t.Fatalf("unexpected error: %v", hop.Err)
	}
	if received != "example.com\r\n" {
		t.Errorf("received query = %q, want a bare domain query with no referral-chasing overhead", received)
	}
	if hop.Fields.Registrar != "Direct Registrar, Inc." {
		t.Errorf("Fields.Registrar = %q, want %q", hop.Fields.Registrar, "Direct Registrar, Inc.")
	}
}

func TestClient_ReferralChasing_RegistrarHopUsesGenericTemplateNotDomainTLD(t *testing.T) {
	// Mirrors TestClient_ReferralChasing_BracketsDialectTLD's reasoning,
	// but for the registrar hop instead of the IANA hop: a registrar's
	// WHOIS server generally replies in plain key:value text regardless
	// of the queried domain's own TLD dialect (.jp is brackets-format in
	// templates.yaml). Parsing the registrar hop with name.TLD applies
	// the wrong tokenizer and silently extracts zero fields.
	registrarAddr := startListener(t, func(query string) string {
		return "Registrar: Example JP Registrar\nRegistrant: Example Corp\n"
	})

	registryAddr := startListener(t, func(query string) string {
		return fmt.Sprintf("[Domain Name]                  EXAMPLE.JP\n[Registrar WHOIS Server]       %s\n", registrarAddr)
	})

	ianaAddr := startListener(t, func(query string) string {
		return fmt.Sprintf("whois:        %s\ndomain:       JP\n", registryAddr)
	})

	c := &Client{IANAServer: ianaAddr, Timeout: 2 * time.Second}
	q, err := domain.Normalize("example.jp")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	name := q.Name
	result, err := c.Lookup(context.Background(), name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(result.Hops) != 3 {
		t.Fatalf("Hops = %d, want 3 (IANA + registry + registrar)", len(result.Hops))
	}
	if result.Hops[2].Fields.Registrar != "Example JP Registrar" {
		t.Errorf("registrar hop Registrar = %q, want %q (this is the regression this test guards: the registrar hop must be parsed with the default kv dialect, not the domain's own .jp brackets dialect, since a registrar WHOIS server's reply format doesn't depend on the queried domain's TLD)", result.Hops[2].Fields.Registrar, "Example JP Registrar")
	}
}

func TestLookupIP_FollowsIANAReferral(t *testing.T) {
	rirAddr := startListener(t, func(q string) string {
		return "NetRange:       8.8.8.0 - 8.8.8.255\nNetName:        GOGL\nOrgName:        Google LLC\n"
	})
	ianaAddr := startListener(t, func(q string) string {
		return "refer:          " + rirAddr + "\n"
	})

	c := &Client{IANAServer: ianaAddr, Timeout: 5 * time.Second}
	res, err := c.LookupIP(context.Background(), netip.MustParseAddr("8.8.8.8"))
	if err != nil {
		t.Fatalf("LookupIP: %v", err)
	}
	if len(res.Hops) != 2 {
		t.Fatalf("hops = %d, want 2 (IANA then RIR)", len(res.Hops))
	}
	last := res.Hops[len(res.Hops)-1]
	if last.IPFields == nil {
		t.Fatal("final hop IPFields = nil, want parsed IP fields")
	}
	if last.IPFields.NetName != "GOGL" {
		t.Errorf("NetName = %q, want GOGL", last.IPFields.NetName)
	}
}

// fakeLimiter records the servers it was asked to pace, in order.
type fakeLimiter struct {
	mu      sync.Mutex
	servers []string
}

func (f *fakeLimiter) Acquire(_ context.Context, server string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.servers = append(f.servers, server)
	return nil
}

// TestClient_QueryAcquiresLimiterForEveryServer pins that pacing happens
// at the query choke point, so every WHOIS contact is covered -- including
// referral hops to a registrar's server, which nothing at the call site
// has to remember to request.
func TestClient_QueryAcquiresLimiterForEveryServer(t *testing.T) {
	addr := startListener(t, func(string) string { return "Domain Name: EXAMPLE.COM\r\n" })

	f := &fakeLimiter{}
	c := &Client{Timeout: 2 * time.Second, Limiter: f}

	if _, err := c.query(context.Background(), addr, "example.com"); err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(f.servers) != 1 {
		t.Fatalf("limiter acquired %d times, want 1", len(f.servers))
	}
	if f.servers[0] != addr {
		t.Errorf("limiter acquired for %q, want %q", f.servers[0], addr)
	}
}

// TestClient_NilLimiterIsSafe pins that a single lookup -- which passes no
// limiter -- still works. A nil Limiter must mean "no pacing", not a panic.
func TestClient_NilLimiterIsSafe(t *testing.T) {
	addr := startListener(t, func(string) string { return "Domain Name: EXAMPLE.COM\r\n" })

	c := &Client{Timeout: 2 * time.Second} // Limiter deliberately unset
	if _, err := c.query(context.Background(), addr, "example.com"); err != nil {
		t.Fatalf("query with nil Limiter: %v", err)
	}
}

// TestClient_LookupAcquiresLimiterForEveryHop drives a full three-hop
// IANA -> registry -> registrar referral chain (mirroring
// TestClient_ReferralChasing's setup) with a Limiter set, and proves the
// choke-point placement inside query -- not just a single direct call to
// it -- actually covers every hop Lookup makes. Asserting only the count
// would also pass if the same server were paced three times instead of
// three distinct servers once each, so this checks the recorded servers
// slice itself, in order.
func TestClient_LookupAcquiresLimiterForEveryHop(t *testing.T) {
	registrarAddr := startListener(t, func(query string) string {
		return "Domain Name: example.com\nRegistrant Organization: Example Corp\nRegistrar: Example Registrar, Inc.\n"
	})

	registryAddr := startListener(t, func(query string) string {
		return fmt.Sprintf("Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: %s\nRegistrar: Example Registrar, Inc.\n", registrarAddr)
	})

	ianaAddr := startListener(t, func(query string) string {
		return fmt.Sprintf("whois:        %s\ndomain:       COM\n", registryAddr)
	})

	f := &fakeLimiter{}
	c := &Client{IANAServer: ianaAddr, Timeout: 2 * time.Second, Limiter: f}
	q, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	result, err := c.Lookup(context.Background(), q.Name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(result.Hops) != 3 {
		t.Fatalf("Hops = %d, want 3", len(result.Hops))
	}

	want := []string{ianaAddr, registryAddr, registrarAddr}
	if len(f.servers) != len(want) {
		t.Fatalf("limiter acquired %d times, want %d (one per hop): got %v", len(f.servers), len(want), f.servers)
	}
	for i, server := range want {
		if f.servers[i] != server {
			t.Errorf("limiter acquisition %d = %q, want %q (distinct server per hop, in order)", i, f.servers[i], server)
		}
	}
}

func TestLookupASN_FollowsIANAReferral(t *testing.T) {
	var rirReceived string
	rirAddr := startListener(t, func(q string) string {
		rirReceived = q
		return "ASNumber:       15169\nASName:         GOOGLE\nOrgName:        Google LLC\n"
	})
	var ianaReceived string
	ianaAddr := startListener(t, func(q string) string {
		ianaReceived = q
		return "whois:          " + rirAddr + "\n"
	})

	c := &Client{IANAServer: ianaAddr, Timeout: 5 * time.Second}
	res, err := c.LookupASN(context.Background(), 15169)
	if err != nil {
		t.Fatalf("LookupASN: %v", err)
	}
	if len(res.Hops) != 2 {
		t.Fatalf("hops = %d, want 2 (IANA then RIR)", len(res.Hops))
	}
	if ianaReceived != "AS15169" {
		t.Errorf("IANA query = %q, want %q (bare number with AS prefix, verified live against whois.iana.org)", ianaReceived, "AS15169")
	}
	if rirReceived != "AS15169" {
		t.Errorf("RIR query = %q, want %q (same query string reused at the RIR hop, verified live against whois.arin.net)", rirReceived, "AS15169")
	}
	last := res.Hops[len(res.Hops)-1]
	if last.ASNFields == nil {
		t.Fatal("final hop ASNFields = nil, want parsed ASN fields")
	}
	if last.ASNFields.Name != "GOOGLE" {
		t.Errorf("Name = %q, want GOOGLE", last.ASNFields.Name)
	}
	if last.IPFields != nil {
		t.Error("IPFields should stay nil on an ASN hop")
	}
}
