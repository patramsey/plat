package whois

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/domain"
)

// limiterFunc adapts a plain function to the Limiter interface, for tests
// that need to inspect or control exactly what Acquire is called with.
type limiterFunc func(ctx context.Context, server string) error

func (f limiterFunc) Acquire(ctx context.Context, server string) error { return f(ctx, server) }

type pacingCtxKey struct{}

// TestClient_QueryAcquiresUsingPacingCtxNotChainCtx is C1a's core
// mechanism test: query must hand Acquire c.PacingCtx, not the ctx it was
// itself called with. In production, that ctx is the per-name chain
// deadline collect.go's collectWHOIS applies with context.WithTimeout --
// if Acquire waited on it instead, a pacing wait scheduled late in a bulk
// run could be cut short by that same deadline before a single byte is
// sent (the exact defect this fixes). Distinguishing which ctx Acquire
// actually saw is done with a context.Value marker rather than by timing,
// since a pointer-identity or timing check would be indirect and, for
// timing, flaky.
func TestClient_QueryAcquiresUsingPacingCtxNotChainCtx(t *testing.T) {
	addr := startListener(t, func(string) string { return "Domain Name: EXAMPLE.COM\r\n" })

	pacingCtx := context.WithValue(context.Background(), pacingCtxKey{}, "pacing")
	chainCtx := context.WithValue(context.Background(), pacingCtxKey{}, "chain")

	var gotMarker any
	lim := limiterFunc(func(ctx context.Context, _ string) error {
		gotMarker = ctx.Value(pacingCtxKey{})
		return nil
	})

	c := &Client{Timeout: 2 * time.Second, Limiter: lim, PacingCtx: pacingCtx}
	if _, err := c.query(chainCtx, addr, "example.com"); err != nil {
		t.Fatalf("query: %v", err)
	}
	if gotMarker != "pacing" {
		t.Errorf("Acquire was called with ctx marker %v, want %q (PacingCtx) -- pacing must not wait on the chain-bound ctx", gotMarker, "pacing")
	}
}

// TestClient_QueryFallsBackToCtxWhenPacingCtxUnset pins the other half:
// a Client that never sets PacingCtx (every non-bulk caller, and any
// pre-existing test) must keep pacing on the ctx it was given -- nil
// must mean "no override", not "no pacing context at all".
func TestClient_QueryFallsBackToCtxWhenPacingCtxUnset(t *testing.T) {
	addr := startListener(t, func(string) string { return "Domain Name: EXAMPLE.COM\r\n" })

	marker := context.WithValue(context.Background(), pacingCtxKey{}, "only-ctx")
	var gotMarker any
	lim := limiterFunc(func(ctx context.Context, _ string) error {
		gotMarker = ctx.Value(pacingCtxKey{})
		return nil
	})

	c := &Client{Timeout: 2 * time.Second, Limiter: lim} // PacingCtx deliberately unset
	if _, err := c.query(marker, addr, "example.com"); err != nil {
		t.Fatalf("query: %v", err)
	}
	if gotMarker != "only-ctx" {
		t.Errorf("Acquire was called with ctx marker %v, want %q (the plain ctx argument)", gotMarker, "only-ctx")
	}
}

// TestClient_QueryPacingWaitSurvivesAnAlreadyCanceledChainCtx is the
// regression shape for the live defect: a pacing wait that would have
// been killed by the caller's own already-expired ctx must instead run
// to completion when PacingCtx is a separate, live context. This isolates
// exactly the mechanism C1a fixes (Acquire's own context) rather than the
// downstream dial, which legitimately still depends on ctx's remaining
// budget -- see TestClient_LookupUsesIANACacheAndPacingCtxTogether below,
// and collect_test.go's bulk-run test, for the end-to-end shape where
// C1a and C1b together keep the whole hop alive, not just the wait.
func TestClient_QueryPacingWaitSurvivesAnAlreadyCanceledChainCtx(t *testing.T) {
	chainCtx, cancel := context.WithCancel(context.Background())
	cancel() // already done before query() is even called

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

	c := &Client{Timeout: 2 * time.Second, Limiter: lim, PacingCtx: context.Background()}
	// query itself still fails past the Acquire step -- chainCtx is
	// already canceled, so the subsequent dial correctly errors. What
	// this test pins is that the *wait* completed rather than being cut
	// short, which is visible via the waited channel closing.
	_, _ = c.query(chainCtx, "127.0.0.1:1", "example.com")

	select {
	case <-waited:
	default:
		t.Error("pacing wait did not run to completion -- Acquire must have waited on the canceled chain ctx instead of PacingCtx")
	}
}

// TestClient_LookupUsesIANACacheAndPacingCtxTogether drives Lookup twice
// for the same tld through a shared IANACache and proves both C1b (the
// second Lookup never touches the network for its IANA hop -- the
// counting listener sees exactly one connection) and the cached fetch's
// use of PacingCtx (the second Lookup still gets the cached hop back even
// though its own ctx is already canceled by the time it calls Lookup,
// because a cache hit never even calls Acquire or dials).
func TestClient_LookupUsesIANACacheAndPacingCtxTogether(t *testing.T) {
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

	c := &Client{IANAServer: ianaAddr, Timeout: 2 * time.Second, IANACache: cache, PacingCtx: context.Background()}
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
