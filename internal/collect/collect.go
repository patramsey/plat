package collect

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/patramsey/plat/internal/domain"
	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/rdap"
	"github.com/patramsey/plat/internal/whois"
)

// Options controls Collect's behavior.
type Options struct {
	// NoFollow skips the registrar RDAP related-link hop even if the
	// registry response advertises one.
	NoFollow bool
	// Timeout bounds each individual fetch (registry RDAP, registrar
	// RDAP) and, for the WHOIS chain, the total time that chain spends
	// TALKING TO SERVERS across its IANA -> registry -> registrar hops.
	//
	// Time the WHOIS chain spends deliberately idle is excluded from that
	// budget: when Limiter is set, a pacing wait is credited back, as is
	// a wait on another name's in-flight IANACache fetch. A bulk run's
	// limiter spaces queries to one server by a full second, so with a
	// plain wall-clock budget the Nth name to want a busy server would
	// reach its dial already out of time and lose that source silently.
	// Wall time across the chain can therefore exceed Timeout by however
	// long it sat waiting its turn; time on the wire cannot. With neither
	// a Limiter nor an IANACache there is nothing to credit and the two
	// readings coincide exactly. The plat CLI turns pacing off for a
	// single-name run (it has no one to be polite to and would otherwise
	// pay a full interval when a registry refers the registrar query back
	// to the IANA host), so a lone lookup arrives here with an IANACache
	// but no Limiter -- nothing waits, so nothing is credited either.
	Timeout time.Duration
	// Sources restricts which of the four possible sources Collect
	// includes in its output. nil (the zero value) means all four are
	// allowed. This does not always suppress the underlying network
	// call: registrar RDAP can only be discovered via the registry
	// RDAP response's related link, and the WHOIS registrar hop can
	// only be reached by completing the same referral chain that
	// visits the registry hop — in both cases the upstream fetch still
	// happens when needed to reach an allowed downstream source, but
	// its own SourceRecord is only emitted if it is itself allowed.
	Sources []model.SourceID
	// Limiter paces outbound WHOIS queries per server, shared across
	// every concurrent lookup in a bulk run. nil means no pacing.
	Limiter whois.Limiter
	// IANACache caches the WHOIS-server-per-TLD mapping resolved from
	// the IANA hop, shared across every concurrent lookup in a bulk run
	// (see whois.IANACache's doc comment). nil means no caching, which
	// is correct for a single lookup.
	IANACache *whois.IANACache
	// HTTPClient is the client used for RDAP requests. nil means
	// http.DefaultClient. Exposed so a library consumer can supply their
	// own transport -- for a proxy, custom timeouts, or instrumentation
	// -- without plat owning a second HTTP stack.
	HTTPClient *http.Client
}

func (o Options) allows(id model.SourceID) bool {
	return len(o.Sources) == 0 || slices.Contains(o.Sources, id)
}

// Collect fans out to registry RDAP (and, unless NoFollow, the registrar
// RDAP hop via the registry's "related" link) and the WHOIS chain
// concurrently — the two branches share no state (separate rdap.Client and
// whois.Client instances) and neither depends on the other's result, so
// they run in parallel goroutines rather than one after the other; only
// the registrar RDAP hop within the RDAP branch, and the registry ->
// registrar chasing within the WHOIS branch, are genuinely sequential
// (each depends on its predecessor's response to find the next hop).
// Collect returns one model.SourceRecord per source actually attempted AND
// allowed by opts.Sources, always in a fixed registry-rdap,
// registrar-rdap, registry-whois, registrar-whois order regardless of
// which goroutine finished first, so callers (e.g. the CLI's -v output)
// see a stable order across runs. registryBaseURL is the already-resolved
// RDAP service base for the domain's TLD (empty string means no RDAP
// coverage — Collect degrades to WHOIS-only). whoisIANAServer overrides
// the WHOIS client's IANA server (empty string uses whois.Client's own
// "whois.iana.org" default) — this parameter exists so tests can point
// the WHOIS chain at a local fake IANA server, the same way internal/whois's
// own tests do.
//
// After both branches finish, if the WHOIS chain didn't discover a
// registrar-whois server itself (the registry hop gave no "Registrar
// WHOIS Server:" referral — e.g. because the registry doesn't run WHOIS
// for this TLD at all, as several of Identity Digital's newer gTLDs
// don't) but the registrar-RDAP hop's response carries RFC 9083's
// optional port43 field, Collect makes one direct fallback WHOIS query
// to that server. This is a genuinely sequential extra step (it needs
// both branches' results to decide whether it's even needed), not part
// of the concurrent fan-out above, and only fires when registrar-whois
// is actually a wanted source.
//
// A single source failing is normal, not fatal — Collect never returns an
// error; callers pass the (possibly partial) result straight to
// merge.Merge.
func Collect(ctx context.Context, name domain.Name, registryBaseURL string, whoisIANAServer string, opts Options) []model.SourceRecord {
	var rdapOut, whoisOut []model.SourceRecord
	var registrarPort43 string

	needRDAP := registryBaseURL != "" &&
		(opts.allows(model.SourceRegistryRDAP) || (!opts.NoFollow && opts.allows(model.SourceRegistrarRDAP)))
	needWHOIS := opts.allows(model.SourceRegistryWHOIS) || opts.allows(model.SourceRegistrarWHOIS)

	var wg sync.WaitGroup
	if needRDAP {
		wg.Go(func() {
			rdapOut, registrarPort43 = collectRDAP(ctx, name, registryBaseURL, opts)
		})
	}
	if needWHOIS {
		wg.Go(func() {
			whoisOut = collectWHOIS(ctx, name, whoisIANAServer, opts)
		})
	}
	wg.Wait()

	if opts.allows(model.SourceRegistrarWHOIS) && registrarPort43 != "" && !hasSource(whoisOut, model.SourceRegistrarWHOIS) {
		// No ChainTimeout: this is a single direct query, not a referral
		// chain, so opts.Timeout as the per-hop bound is the whole story.
		// Any pacing wait ahead of it happens before that per-hop
		// deadline is taken, so it costs this query nothing either.
		whoisClient := &whois.Client{Timeout: opts.Timeout, Limiter: opts.Limiter}
		hop := whoisClient.QueryServer(ctx, registrarPort43, name)
		whoisOut = append(whoisOut, fromHop(model.SourceRegistrarWHOIS, hop))
	}

	out := make([]model.SourceRecord, 0, len(rdapOut)+len(whoisOut))
	out = append(out, rdapOut...)
	out = append(out, whoisOut...)
	return out
}

func hasSource(records []model.SourceRecord, id model.SourceID) bool {
	for _, r := range records {
		if r.Meta.Source == id {
			return true
		}
	}
	return false
}

// collectRDAP returns the RDAP source records plus, separately, the
// registrar-RDAP hop's port43 value (if any) — kept out-of-band from
// []model.SourceRecord since it isn't itself a per-field provenance
// value, just a hint Collect may use for the registrar-WHOIS fallback.
func collectRDAP(ctx context.Context, name domain.Name, registryBaseURL string, opts Options) ([]model.SourceRecord, string) {
	var out []model.SourceRecord
	var registrarPort43 string

	rdapClient := &rdap.Client{Timeout: opts.Timeout, HTTP: opts.HTTPClient}
	start := time.Now()
	result, err := rdapClient.Domain(ctx, registryBaseURL, name.Punycode)
	if opts.allows(model.SourceRegistryRDAP) {
		out = append(out, FromRDAP(model.SourceRegistryRDAP, result, time.Since(start), err))
	}

	if !opts.NoFollow && opts.allows(model.SourceRegistrarRDAP) && err == nil && result.Domain != nil {
		if registrarURL, ok := result.Domain.RelatedRegistrarURL(); ok && differentHost(registryBaseURL, registrarURL) {
			rStart := time.Now()
			rResult, rErr := rdapClient.DomainURL(ctx, registrarURL)
			out = append(out, FromRDAP(model.SourceRegistrarRDAP, rResult, time.Since(rStart), rErr))
			if rErr == nil && rResult.Domain != nil {
				registrarPort43 = rResult.Domain.Port43
			}
		}
	}

	return out, registrarPort43
}

func collectWHOIS(ctx context.Context, name domain.Name, whoisIANAServer string, opts Options) []model.SourceRecord {
	var out []model.SourceRecord

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second // matches whois.Client.timeout()'s own default
	}
	// Bound the WHOIS chain as a whole, not just each hop — see
	// Options.Timeout's doc comment. ChainTimeout, rather than wrapping
	// ctx here in a context.WithTimeout: a context deadline is pure wall
	// clock and cannot be pushed out once set, so an outer deadline would
	// charge the chain for the seconds a bulk run's Limiter deliberately
	// idles it before each dial. whois.Client carries the budget itself
	// instead, shortening each hop's own timeout to what remains and
	// crediting deliberate idling back — so the timeout bounds the time
	// the chain spends on the wire, which is the thing it exists to
	// bound. With no Limiter nothing is ever paced, so the only thing
	// left to credit is a wait on another name's in-flight IANACache
	// fetch -- and with neither (a lone lookup through the library's
	// defaults) this behaves exactly like the outer deadline it replaces.
	whoisClient := &whois.Client{Timeout: timeout, ChainTimeout: timeout, IANAServer: whoisIANAServer, Limiter: opts.Limiter, IANACache: opts.IANACache}
	wResult, _ := whoisClient.Lookup(ctx, name)
	for _, sr := range FromWHOIS(wResult) {
		if opts.allows(sr.Meta.Source) {
			out = append(out, sr)
		}
	}

	return out
}

// differentHost reports whether registrarURL points at a DIFFERENT network
// authority (host:port) than registryBaseURL — a loop guard against a
// registry advertising itself as its own registrar, or a misconfigured
// related link pointing back at the same server. Comparing the full Host
// (not just Hostname) matters for tests that run registry and registrar
// as separate local listeners sharing the loopback address on different
// ports — those are genuinely different servers, not a loop. Any URL
// parse failure is treated as "same host" (i.e. skip) — DomainURL itself
// would also reject a genuinely malformed or non-http(s) URL, but there's
// no reason to attempt a fetch this function already can't make sense of.
func differentHost(registryBaseURL, registrarURL string) bool {
	rb, err1 := url.Parse(registryBaseURL)
	ru, err2 := url.Parse(registrarURL)
	if err1 != nil || err2 != nil {
		return false
	}
	return !strings.EqualFold(rb.Host, ru.Host)
}
