package whois

import (
	"context"
	"sync"
	"time"
)

// DefaultWHOISInterval is the minimum gap between two queries to the same
// WHOIS server, used whenever a caller doesn't set one explicitly. The
// limit exists to keep the caller's IP from being blocked, and the
// failure mode of setting it too high is invisible until it happens and
// painful to undo -- which is why the default deliberately doesn't
// require tuning to be safe. It is tunable, though: plat.Options.WHOISInterval
// lets a library consumer override it in either direction, with no floor
// enforced, so a consumer that lowers it takes on the ban risk this
// default is sized to avoid.
const DefaultWHOISInterval = time.Second

// Limiter paces outbound WHOIS queries. Acquire blocks until a query to
// server may proceed, or returns ctx.Err() if the context ends first.
//
// It is an interface so tests can substitute a deterministic recorder
// instead of sleeping, and so a caller that wants no pacing can pass nil.
type Limiter interface {
	Acquire(ctx context.Context, server string) error
}

// HostLimiter paces per server hostname: two queries to the same server
// are spaced by at least interval, while queries to different servers
// never wait on each other. That distinction is the whole point -- a
// global throttle would needlessly serialize a mixed-TLD list, and a
// per-server one is what actually prevents a ban.
type HostLimiter struct {
	interval time.Duration

	mu   sync.Mutex
	next map[string]time.Time

	// now and sleep are indirected for tests. Production uses time.Now
	// and a context-aware sleep.
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

func NewHostLimiter(interval time.Duration) *HostLimiter {
	return &HostLimiter{
		interval: interval,
		next:     make(map[string]time.Time),
		now:      time.Now,
		sleep:    sleepCtx,
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Acquire reserves the next slot for server and waits for it. The
// reservation is taken under the lock and the wait happens outside it, so
// concurrent callers for different servers never contend.
func (l *HostLimiter) Acquire(ctx context.Context, server string) error {
	l.mu.Lock()
	now := l.now()
	slot := l.next[server]
	if slot.Before(now) {
		slot = now
	}
	l.next[server] = slot.Add(l.interval)
	l.mu.Unlock()

	return l.sleep(ctx, slot.Sub(now))
}
