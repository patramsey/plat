package whois

import (
	"context"
	"sync"
	"testing"
	"time"
)

// recordSleeps swaps in a sleep that records the delay it was asked for
// and returns immediately, so these tests assert on the schedule the
// limiter computes rather than on wall-clock time. A timing-based test
// here would be slow and flaky, and would not actually distinguish
// per-server pacing from a global throttle.
//
// l.now is frozen alongside l.sleep: since the stubbed sleep never
// actually blocks, real wall-clock time still advances (by a few
// microseconds of loop overhead) between successive Acquire calls if
// l.now is left as time.Now. That's enough for the reserved slot to
// land a few microseconds short of a full interval away from "now",
// making the schedule assertions below flaky by a hair every run.
// Freezing now removes that leak so the test is fully deterministic.
func recordSleeps(l *HostLimiter) *[]time.Duration {
	var mu sync.Mutex
	var got []time.Duration
	frozen := time.Now()
	l.now = func() time.Time {
		return frozen
	}
	l.sleep = func(_ context.Context, d time.Duration) error {
		mu.Lock()
		got = append(got, d)
		mu.Unlock()
		return nil
	}
	return &got
}

// TestHostLimiter_SameServerIsPaced pins the first half of the contract:
// two queries to one server are spaced by at least the interval.
func TestHostLimiter_SameServerIsPaced(t *testing.T) {
	l := NewHostLimiter(time.Second)
	got := recordSleeps(l)

	for range 3 {
		if err := l.Acquire(context.Background(), "whois.verisign-grs.com"); err != nil {
			t.Fatalf("Acquire: %v", err)
		}
	}

	if len(*got) != 3 {
		t.Fatalf("recorded %d sleeps, want 3", len(*got))
	}
	if (*got)[0] != 0 {
		t.Errorf("first Acquire slept %v, want 0 -- the first query to a server must not wait", (*got)[0])
	}
	if (*got)[1] < time.Second {
		t.Errorf("second Acquire slept %v, want >= 1s", (*got)[1])
	}
	if (*got)[2] < 2*time.Second {
		t.Errorf("third Acquire slept %v, want >= 2s (pacing must accumulate)", (*got)[2])
	}
}

// TestHostLimiter_DifferentServersDoNotBlockEachOther is the other half,
// and the one that actually distinguishes per-server pacing from a global
// throttle. Without it, a single global limiter would pass the test above
// and still be wrong.
func TestHostLimiter_DifferentServersDoNotBlockEachOther(t *testing.T) {
	l := NewHostLimiter(time.Second)
	got := recordSleeps(l)

	for _, server := range []string{"whois.verisign-grs.com", "whois.nic.uk", "whois.dk-hostmaster.dk"} {
		if err := l.Acquire(context.Background(), server); err != nil {
			t.Fatalf("Acquire(%s): %v", server, err)
		}
	}

	if len(*got) != 3 {
		t.Fatalf("recorded %d sleeps, want 3", len(*got))
	}
	for i, d := range *got {
		if d != 0 {
			t.Errorf("Acquire %d on a distinct server slept %v, want 0 -- servers must not pace each other", i, d)
		}
	}
}

// TestHostLimiter_RespectsContextCancellation pins that a cancelled
// context aborts the wait rather than sleeping out the full interval.
func TestHostLimiter_RespectsContextCancellation(t *testing.T) {
	l := NewHostLimiter(time.Hour)
	if err := l.Acquire(context.Background(), "whois.example.com"); err != nil {
		t.Fatalf("first Acquire: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Acquire(ctx, "whois.example.com"); err == nil {
		t.Error("Acquire with a cancelled context returned nil, want the context error")
	}
}

// TestHostLimiter_ConcurrentAcquireIsSafe runs under -race; the limiter
// is shared by every worker in the pool, so a data race here would be a
// production bug reachable on any multi-name run.
func TestHostLimiter_ConcurrentAcquireIsSafe(t *testing.T) {
	l := NewHostLimiter(time.Nanosecond)
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			server := "whois.example.com"
			if i%2 == 0 {
				server = "whois.other.com"
			}
			_ = l.Acquire(context.Background(), server)
		}(i)
	}
	wg.Wait()
}
