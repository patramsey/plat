package whois

import (
	"time"

	"github.com/patramsey/plat/internal/whois/parse"
)

// Hop is one WHOIS server queried during a lookup: the exact query sent,
// the raw response, the parsed view of that response, and how long it
// took (or the error that stopped it).
type Hop struct {
	Server string
	Query  string
	Raw    string
	Fields parse.Fields
	// IPFields is populated instead of Fields when the hop was an IP
	// query. Nil for domain hops.
	IPFields *parse.IPFields
	Latency  time.Duration
	Err      error
}

// Result is the standalone, package-scoped outcome of a WHOIS lookup: an
// ordered chain of hops (IANA, then registry, then registrar if
// discovered). It intentionally performs no cross-hop reconciliation —
// picking a winning value across hops is the shared merge engine's job in
// a later milestone.
type Result struct {
	Domain string
	Hops   []Hop
}

// Deepest returns the last hop that succeeded (Err == nil), walking from
// the end of the chain. This is a "last hop present" convenience for
// simple callers (like the demo CLI command) — it is explicitly not a
// provenance/precedence merge; an earlier hop in the chain may hold a
// field this one lacks.
func (r *Result) Deepest() *Hop {
	for i := len(r.Hops) - 1; i >= 0; i-- {
		if r.Hops[i].Err == nil {
			return &r.Hops[i]
		}
	}
	return nil
}
