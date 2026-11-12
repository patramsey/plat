package whois

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/domain"
	"github.com/patramsey/plat/internal/netguard"
	"github.com/patramsey/plat/internal/testnet"
)

func TestCheckReferral(t *testing.T) {
	tests := []struct {
		server string
		ok     bool
	}{
		{"whois.verisign-grs.com", true},
		{"whois.verisign-grs.com:43", true},
		{"2001:db8::43", true}, // a bare IPv6 literal has no port
		{"[2001:db8::43]:43", true},
		{"whois.example.com:4343", false},
		{"10.0.0.5:6379", false},
		{"[::1]:11211", false},
		{"169.254.169.254:80", false},
		{"http://www.dns.net.za/whois", false},
		{"whois example", false},
		{":43", false},
		{"", false},
	}
	for _, tt := range tests {
		err := checkReferral(tt.server)
		if (err == nil) != tt.ok {
			t.Errorf("checkReferral(%q) = %v, want ok=%v", tt.server, err, tt.ok)
		}
	}
}

// startTrapListener is a stand-in for a service on the caller's network
// that a hostile answer points plat at. hits counts connections.
func startTrapListener(t *testing.T, hits *int32) string {
	t.Helper()
	return startListener(t, func(string) string {
		atomic.AddInt32(hits, 1)
		return "Registrar: Reply From Internal Service\r\n"
	})
}

// TestLookup_RefusesReferralWithPort covers every referral a WHOIS chain
// follows: the registry named by IANA, the registrar named by the
// registry, and the RIR named by IANA for IPs and ASNs. Each names the
// trap by host:port. The caller's Dial would reach it -- it maps every
// address straight through -- so only the port rule stands in the way.
func TestLookup_RefusesReferralWithPort(t *testing.T) {
	name := func(s string) domain.Name {
		q, err := domain.Normalize(s)
		if err != nil {
			t.Fatal(err)
		}
		return q.Name
	}
	tests := []struct {
		label  string
		answer func(trap string) (iana, registry string)
		run    func(c *Client) (*Result, error)
	}{
		{
			label:  "IANA names the registry",
			answer: func(trap string) (string, string) { return "whois: " + trap + "\n", "" },
			run:    func(c *Client) (*Result, error) { return c.Lookup(context.Background(), name("example.com")) },
		},
		{
			label: "registry names the registrar",
			answer: func(trap string) (string, string) {
				return "whois: registry.test\n", "Domain Name: EXAMPLE.COM\r\nRegistrar WHOIS Server: " + trap + "\r\n"
			},
			run: func(c *Client) (*Result, error) { return c.Lookup(context.Background(), name("example.com")) },
		},
		{
			label:  "IANA names the RIR for an IP",
			answer: func(trap string) (string, string) { return "refer: " + trap + "\n", "" },
			run: func(c *Client) (*Result, error) {
				return c.LookupIP(context.Background(), netip.MustParseAddr("8.8.8.8"))
			},
		},
		{
			label:  "IANA names the RIR for an ASN",
			answer: func(trap string) (string, string) { return "whois: " + trap + "\n", "" },
			run:    func(c *Client) (*Result, error) { return c.LookupASN(context.Background(), 15169) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			var hits int32
			trap := startTrapListener(t, &hits)
			ianaAnswer, registryAnswer := tt.answer(trap)
			registry := startListener(t, func(string) string { return registryAnswer })
			iana := startListener(t, func(string) string { return ianaAnswer })
			c := &Client{IANAServer: iana, Timeout: 2 * time.Second, Dial: testnet.Net{"registry.test": registry}.Dial}

			res, _ := tt.run(c)
			if n := atomic.LoadInt32(&hits); n != 0 {
				t.Fatalf("the trap at %s was contacted %d time(s)", trap, n)
			}
			last := res.Hops[len(res.Hops)-1]
			if last.Server != trap || last.Err == nil || !strings.Contains(last.Err.Error(), "only on port 43") {
				t.Errorf("last hop = {Server: %q, Err: %v}, want a refused hop to %s", last.Server, last.Err, trap)
			}
		})
	}
}

// TestLookup_DefaultDialerRefusesNonPublicReferral: with plat's own
// dialer, a referral on port 43 to a loopback address is refused after
// resolution, whether named by IP or by a host name that resolves to it.
// The configured IANA server is itself on loopback and is still reached.
func TestLookup_DefaultDialerRefusesNonPublicReferral(t *testing.T) {
	for _, target := range []string{"127.0.0.1", "localhost"} {
		t.Run(target, func(t *testing.T) {
			iana := startListener(t, func(string) string { return "whois: " + target + "\n" })
			c := &Client{IANAServer: iana, Timeout: 2 * time.Second}
			q, _ := domain.Normalize("example.com")

			res, _ := c.Lookup(context.Background(), q.Name)
			if len(res.Hops) != 2 || res.Hops[0].Err != nil {
				t.Fatalf("hops = %+v, want the IANA hop to succeed and a registry hop", res.Hops)
			}
			var refused *netguard.RefusedError
			if !errors.As(res.Hops[1].Err, &refused) {
				t.Errorf("registry hop err = %v, want a netguard refusal", res.Hops[1].Err)
			}
		})
	}
}

// TestQueryServer_RefusesPort: QueryServer serves RDAP's port43 field,
// which an RDAP answer names, so the port rule applies there too.
func TestQueryServer_RefusesPort(t *testing.T) {
	var hits int32
	trap := startTrapListener(t, &hits)
	c := &Client{Timeout: 2 * time.Second, Dial: testnet.Net{}.Dial}
	q, _ := domain.Normalize("example.com")

	hop := c.QueryServer(context.Background(), trap, q.Name)
	if hop.Err == nil || atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("hop err = %v, hits = %d; want a refusal before any connection", hop.Err, hits)
	}
}
