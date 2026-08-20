package whois

import (
	"context"
	"sync"
	"time"
)

// chainKey is the private context key a referral chain's budget travels
// under, from Lookup/LookupIP/LookupASN down to every hop's query.
type chainKey struct{}

// chain is one referral chain's budget for time spent TALKING TO SERVERS
// (IANA -> registry -> registrar). It exists because a plain
// context.WithTimeout cannot express that budget correctly once pacing is
// in play: a context deadline is pure wall clock and cannot be pushed
// out, while a bulk run's Limiter deliberately idles a hop for up to
// several seconds before it dials. Charging that idling against the same
// budget as the network hops means a name whose pacing slot falls past
// the deadline dies before sending a byte -- and, because a WHOIS source
// failing is normal rather than fatal, does so silently with the run's
// exit code still 0.
//
// So the budget lives here instead, as a deadline each hop reads (and
// shortens its own per-hop timeout to) and each pacing wait credits back.
// Wall time may therefore exceed the configured timeout by however long
// the chain sat idle waiting its turn; time actually spent on the wire
// may not.
//
// The deadline is mutex-guarded rather than left as a plain field: hops
// within one Lookup are sequential today, but an IANACache fetch is
// shared with (and credited by) other names' chains, and a budget that
// silently raced would reintroduce exactly the class of bug it exists to
// prevent.
type chain struct {
	mu       sync.Mutex
	deadline time.Time
}

// withChain returns ctx carrying a fresh budget of timeout for the
// network time a referral chain may spend.
func withChain(ctx context.Context, timeout time.Duration) context.Context {
	return context.WithValue(ctx, chainKey{}, &chain{deadline: time.Now().Add(timeout)})
}

// chainFrom returns the budget ctx carries, or nil when it carries none
// (a Client with no ChainTimeout -- every hop is then bounded only by its
// own Timeout, which is the whois package's standalone behavior).
func chainFrom(ctx context.Context) *chain {
	ch, _ := ctx.Value(chainKey{}).(*chain)
	return ch
}

// creditChain gives d back to ctx's budget: the chain spent d not talking
// to a server (waiting for a pacing slot, or waiting on another name's
// in-flight IANA fetch), so d must not count against what remains. A nil
// budget or a non-positive d is a no-op.
func creditChain(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	ch := chainFrom(ctx)
	if ch == nil {
		return
	}
	ch.mu.Lock()
	ch.deadline = ch.deadline.Add(d)
	ch.mu.Unlock()
}

// chainDeadline reports the instant ctx's budget runs out, and whether
// ctx carries a budget at all.
func chainDeadline(ctx context.Context) (time.Time, bool) {
	ch := chainFrom(ctx)
	if ch == nil {
		return time.Time{}, false
	}
	ch.mu.Lock()
	defer ch.mu.Unlock()
	return ch.deadline, true
}
