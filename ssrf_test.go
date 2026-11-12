package plat

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/testnet"
)

// startServer answers every connection with reply and counts them.
func startServer(t *testing.T, hits *int32, reply string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(hits, 1)
			_, _ = bufio.NewReader(c).ReadString('\n')
			_, _ = c.Write([]byte(reply))
			_ = c.Close()
		}
	}()
	return ln.Addr().String()
}

// TestLookup_WHOISReferralCannotReachInternalService is the scenario of
// GHSA-8q76-8r67-p8g8: IANA refers to a registry, and the registry names
// as its registrar's WHOIS server a service on the caller's network, on a
// port that isn't 43. plat must not connect to it, and nothing it sends
// back may reach the result.
//
// With a caller's Dial, which reaches any address it is given, the chain
// gets as far as the registry, and the port rule refuses the registrar
// referral: the report's exact case. With plat's own dialer no test
// registry is reachable at all -- every listener is on loopback, and a
// referral by port is refused -- so IANA refers to the registry by
// host:port and that first referral is the one refused.
func TestLookup_WHOISReferralCannotReachInternalService(t *testing.T) {
	for _, withDial := range []bool{false, true} {
		name := "default dialer"
		if withDial {
			name = "caller's Dial"
		}
		t.Run(name, func(t *testing.T) {
			var internalHits, registryHits, ianaHits int32
			internal := startServer(t, &internalHits, "Registrar: Reply From Internal Service\r\n")
			registry := startServer(t, &registryHits, "Domain Name: EXAMPLE.COM\r\nRegistrar WHOIS Server: "+internal+"\r\n")
			ianaRefer := registry
			if withDial {
				ianaRefer = "registry.test"
			}
			iana := startServer(t, &ianaHits, "refer: "+ianaRefer+"\r\n")

			opts := Options{
				WHOISIANAServer:    iana,
				Resolver:           NewResolver(ResolverConfig{}),
				DisableCache:       true,
				DisableWHOISPacing: true,
				Timeout:            5 * time.Second,
			}
			if withDial {
				opts.Dial = testnet.Net{"registry.test": registry}.Dial
			}
			c, err := New(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			res, _ := c.Lookup(context.Background(), "example.com")

			if n := atomic.LoadInt32(&internalHits); n != 0 {
				t.Errorf("plat connected to the internal service %d time(s)", n)
			}
			if res.Domain != nil && strings.Contains(res.Domain.Registrar.Name.Value, "Internal Service") {
				t.Errorf("registrar = %q: the internal service's reply reached the result", res.Domain.Registrar.Name.Value)
			}
			if withDial && atomic.LoadInt32(&registryHits) != 1 {
				t.Errorf("registry was queried %d time(s), want 1: the chain should reach it", registryHits)
			}
			if atomic.LoadInt32(&ianaHits) != 1 {
				t.Errorf("IANA, a server the caller configured, was queried %d time(s), want 1", ianaHits)
			}
		})
	}
}

// TestNew_GuardsRDAPOnlyForBootstrapData: base URLs from IANA's bootstrap
// data name only public servers, so every default-client RDAP request is
// guarded; a caller's Resolver may name a private mirror, so only the
// registrar link is.
func TestNew_GuardsRDAPOnlyForBootstrapData(t *testing.T) {
	boot, err := New(context.Background(), Options{DisableCache: true, HTTPClient: &http.Client{Transport: &failingTransport{}}})
	if err != nil {
		t.Fatal(err)
	}
	if !boot.bootstrapped {
		t.Error("Client built from bootstrap data: bootstrapped = false, want true")
	}
	own, err := New(context.Background(), Options{DisableCache: true, Resolver: NewResolver(ResolverConfig{})})
	if err != nil {
		t.Fatal(err)
	}
	if own.bootstrapped {
		t.Error("Client with a caller's Resolver: bootstrapped = true, want false")
	}
}
