package whois

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/domain"
)

// limiterFunc adapts a plain function to the Limiter interface, for tests
// that need to inspect or control exactly what Acquire is called with.
type limiterFunc func(ctx context.Context, server string) error

func (f limiterFunc) Acquire(ctx context.Context, server string) error { return f(ctx, server) }

// TestClient_QueryCreditsThePacingWaitBackToTheChainBudget is the core
// mechanism test for C1: a hop must not lose its dial because it spent
// longer waiting its turn at the Limiter than the whole-chain budget is
// wide. Here the wait (150ms) already outlasts the budget (100ms) by the
// time Acquire returns, so an uncredited budget leaves the dial with a
// deadline in the past and the hop fails without sending a byte -- the
// live defect, reproduced in miniature. Crediting the wait back leaves a
// full 100ms for a loopback round trip, which is ample.
func TestClient_QueryCreditsThePacingWaitBackToTheChainBudget(t *testing.T) {
	addr := startListener(t, func(string) string { return "Domain Name: EXAMPLE.COM\r\n" })

	lim := limiterFunc(func(context.Context, string) error {
		time.Sleep(150 * time.Millisecond)
		return nil
	})

	c := &Client{Timeout: 2 * time.Second, Limiter: lim}
	ctx := withChain(context.Background(), 100*time.Millisecond)

	raw, err := c.query(ctx, addr, "example.com")
	if err != nil {
		t.Fatalf("query: %v -- the pacing wait was charged against the chain budget", err)
	}
	if !strings.Contains(raw, "EXAMPLE.COM") {
		t.Errorf("query returned %q, want the listener's reply", raw)
	}
}

// TestClient_QueryPacingWaitIsNotCutShortByAnExhaustedChainBudget pins
// the other half of the same property: an exhausted budget must not
// ABORT the wait either. The first failed attempt at this defect waited
// on the chain deadline and turned a late slot into
// "whois: pacing ...: context deadline exceeded"; keeping the budget out
// of the context the Limiter waits on is what prevents that.
func TestClient_QueryPacingWaitIsNotCutShortByAnExhaustedChainBudget(t *testing.T) {
	waited := make(chan struct{})
	lim := limiterFunc(func(ctx context.Context, _ string) error {
		select {
		case <-time.After(30 * time.Millisecond):
			close(waited)
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	// A budget that ran out before query() was even called.
	ctx := withChain(context.Background(), -time.Second)

	c := &Client{Timeout: 2 * time.Second, Limiter: lim}
	// The query itself is expected to fail: 127.0.0.1:1 has nothing
	// listening, and that is not what this test is about. What it pins is
	// that the WAIT completed rather than being cut short, visible via
	// the waited channel.
	_, _ = c.query(ctx, "127.0.0.1:1", "example.com")

	select {
	case <-waited:
	default:
		t.Error("pacing wait did not run to completion -- an exhausted chain budget must not abort a Limiter wait")
	}
}

// TestClient_QueryPacingWaitStillObservesCancellation is the guard on the
// other side of that: taking the chain budget out of the Limiter's
// context must not also take real cancellation out of it. A user who
// interrupts a bulk run should not have to wait out every remaining
// pacing slot.
func TestClient_QueryPacingWaitStillObservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already canceled before query() is called

	lim := limiterFunc(func(ctx context.Context, _ string) error {
		select {
		case <-time.After(10 * time.Second):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	c := &Client{Timeout: 2 * time.Second, Limiter: lim}
	start := time.Now()
	_, err := c.query(ctx, "127.0.0.1:1", "example.com")
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("query blocked for %v on a canceled ctx -- the pacing wait must still observe cancellation", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), "pacing") {
		t.Errorf("query error = %v, want a whois: pacing ... error from the aborted wait", err)
	}
}

// TestClient_ChainTimeoutStillBoundsNetworkTimeAcrossHops proves the
// budget is still a budget: crediting deliberate idling back must not
// turn the whole-chain bound into a per-hop bound. The IANA hop here
// burns 250ms of real network time out of a 400ms chain budget, so the
// registry hop that follows must be cut off by what remains (~150ms) and
// not by the far larger per-hop Timeout -- the registry listener never
// replies at all, so a per-hop bound would hold the chain for 5s.
func TestClient_ChainTimeoutStillBoundsNetworkTimeAcrossHops(t *testing.T) {
	registryAddr := startSilentListener(t)

	ianaAddr := startListener(t, func(string) string {
		time.Sleep(250 * time.Millisecond)
		return "refer: " + registryAddr + "\n"
	})

	q, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	c := &Client{IANAServer: ianaAddr, Timeout: 5 * time.Second, ChainTimeout: 400 * time.Millisecond}
	start := time.Now()
	result, _ := c.Lookup(context.Background(), q.Name)
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("Lookup took %v -- the registry hop was bounded by Timeout, not by what was left of ChainTimeout", elapsed)
	}
	if len(result.Hops) != 2 {
		t.Fatalf("got %d hops, want 2 (IANA then registry)", len(result.Hops))
	}
	if result.Hops[1].Err == nil {
		t.Error("registry hop succeeded against a listener that never replies")
	}
}

// startSilentListener accepts connections and then never writes anything
// back, so a hop against it can only ever end by deadline.
func startSilentListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	return ln.Addr().String()
}

// TestClient_LookupUsesIANACache drives Lookup twice for the same tld
// through a shared IANACache and proves the second Lookup never touches
// the network for its IANA hop -- the counting listener sees exactly one
// connection, and the cached hop comes back even though the second call's
// own ctx is already canceled, because a cache hit neither acquires a
// pacing slot nor dials.
func TestClient_LookupUsesIANACache(t *testing.T) {
	registryAddr := startListener(t, func(query string) string {
		return "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar, Inc.\n"
	})

	var ianaHits int32
	ianaAddr := startCountingListener(t, &ianaHits, func(query string) string {
		return fmt.Sprintf("refer: %s\ndomain: %s\n", registryAddr, query)
	})

	cache := NewIANACache()
	q, err := domain.Normalize("example.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	c := &Client{IANAServer: ianaAddr, Timeout: 2 * time.Second, IANACache: cache}
	if _, err := c.Lookup(context.Background(), q.Name); err != nil {
		t.Fatalf("first Lookup: %v", err)
	}

	q2, err := domain.Normalize("example2.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	// A canceled ctx for the second call still succeeds for the IANA hop
	// specifically, because it's served from cache -- no Acquire, no
	// dial, so nothing in that hop observes ctx at all. (The registry hop
	// that follows does use ctx normally, will fail because ctx is
	// already canceled, and isn't the thing under test here -- Lookup
	// itself still returns a nil error since the IANA hop succeeded.)
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	result2, err := c.Lookup(canceledCtx, q2.Name)
	if err != nil {
		t.Fatalf("second Lookup: %v", err)
	}

	if got := atomic.LoadInt32(&ianaHits); got != 1 {
		t.Errorf("IANA listener hit %d times across two same-TLD Lookups, want 1 -- IANACache should have served the second from cache", got)
	}
	if len(result2.Hops) == 0 || result2.Hops[0].Err != nil {
		t.Fatalf("second Lookup's IANA hop = %+v, want the cached success", result2.Hops[0])
	}
}

// startCountingListener is startListener plus an Accept loop (so it can
// serve more than one connection) and an atomic hit counter, for tests
// that need to prove a server was -- or wasn't -- contacted a specific
// number of times.
func startCountingListener(t *testing.T, hits *int32, respond func(query string) string) string {
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
			atomic.AddInt32(hits, 1)
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
