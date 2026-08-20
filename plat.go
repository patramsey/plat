package plat

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/patramsey/plat/internal/bootstrap"
	"github.com/patramsey/plat/internal/collect"
	"github.com/patramsey/plat/internal/domain"
	"github.com/patramsey/plat/internal/merge"
	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/whois"
)

// defaultTimeout matches the CLI's default --timeout.
const defaultTimeout = 5 * time.Second

// Options configures a Client. The zero value is valid and gives the same
// defaults the plat CLI uses.
type Options struct {
	// Timeout bounds the time one lookup spends talking to servers.
	// Deliberate idling -- waiting a turn behind another name's paced
	// WHOIS query -- is not charged against it. Zero means 5s.
	Timeout time.Duration
	// Sources restricts which sources are consulted. nil means all.
	Sources []SourceID
	// NoFollow skips the second hop to the registrar's RDAP server.
	// Domain lookups only; IPs and ASNs have no registrar.
	NoFollow bool
	// CacheDir overrides where the IANA bootstrap file is cached. Empty
	// means the OS user cache directory, the same place the CLI uses.
	CacheDir string
	// DisableCache stops plat reading or writing the filesystem at all.
	DisableCache bool
	// RefreshBootstrap forces a bootstrap fetch even when a fresh cached
	// copy exists.
	RefreshBootstrap bool
	// WHOISInterval is the minimum spacing between WHOIS queries to any
	// one server. Zero means whois.DefaultWHOISInterval. Pacing is
	// always on, but costs a single lookup nothing: the first query to a
	// given server is never delayed.
	WHOISInterval time.Duration
	// DisableWHOISPacing turns off per-server WHOIS pacing for this
	// client. Pacing exists to stop a bulk run hammering one server, so
	// leaving it on is right for almost every caller. A single lookup
	// whose referral chain happens to hit one server twice -- a registry
	// that refers the registrar query back to the same host -- would
	// otherwise pay the full interval for the second hop, which is a
	// wait no one is served by.
	DisableWHOISPacing bool
	// HTTPClient is used for RDAP requests only. nil means
	// http.DefaultClient. It does NOT cover the IANA bootstrap fetch New
	// performs to load RDAP base URLs: that fetch always uses the default
	// HTTP client, regardless of this field. A caller behind a proxy who
	// needs the bootstrap fetch to go through it as well gets no error --
	// New falls back silently to a cached or embedded snapshot instead.
	HTTPClient *http.Client
	// Resolver supplies RDAP base URLs. nil means load IANA's published
	// bootstrap data, which is what almost every caller wants. Set it to
	// query a private or mirrored RDAP deployment instead.
	//
	// Each of NewResolver, NewIPResolver, and NewASNResolver builds a
	// Resolver that covers exactly ONE object kind -- there is no
	// constructor that combines all three. A Resolver from NewResolver,
	// for example, supplies RDAP base URLs for domains only; IP and ASN
	// lookups made with it fall back to WHOIS-only, silently, because it
	// reports no coverage for those kinds.
	Resolver *Resolver
	// WHOISIANAServer is the WHOIS server consulted first to discover a
	// TLD's registry WHOIS server. Empty means whois.iana.org. Set it to
	// use an internal mirror.
	WHOISIANAServer string
}

// Client performs lookups. It holds the IANA bootstrap resolver, a
// per-server WHOIS pacing limiter, and a cache of IANA WHOIS referrals,
// all of which are worth reusing across lookups -- so a program looking
// up many names should create one Client and keep it.
//
// A Client is safe for concurrent use.
type Client struct {
	opts     Options
	resolver *bootstrap.Resolver
	// limiter is the whois.Limiter interface, not *whois.HostLimiter, so
	// that "no pacing" is a true nil interface. A nil *HostLimiter stored
	// here would arrive at collect.Options.Limiter as a non-nil interface
	// wrapping a nil pointer, sail past collect's nil check, and panic
	// inside Acquire on the nil receiver.
	limiter   whois.Limiter
	ianaCache *whois.IANACache
}

// New builds a Client, loading the IANA RDAP bootstrap data once.
//
// It rarely fails: a failed fetch falls back to a cached copy and then to
// a snapshot embedded in the binary, so a caller with no network still
// gets a usable Client. The error return exists so that a future failure
// mode is not a breaking signature change.
func New(ctx context.Context, opts Options) (*Client, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	interval := opts.WHOISInterval
	if interval <= 0 {
		interval = whois.DefaultWHOISInterval
	}

	resolver := opts.Resolver
	if resolver == nil {
		var err error
		resolver, err = bootstrap.Load(ctx, bootstrap.Options{
			Refresh:      opts.RefreshBootstrap,
			Timeout:      opts.Timeout,
			CacheDir:     opts.CacheDir,
			DisableCache: opts.DisableCache,
		})
		if err != nil {
			return nil, err
		}
	}

	// Left nil -- a true nil interface, see the field's comment -- when
	// pacing is off, which is what collect reads as "do not pace".
	var limiter whois.Limiter
	if !opts.DisableWHOISPacing {
		limiter = whois.NewHostLimiter(interval)
	}

	return &Client{
		opts:      opts,
		resolver:  resolver,
		limiter:   limiter,
		ianaCache: whois.NewIANACache(),
	}, nil
}

// Kind is the sort of object a Result describes.
type Kind int

const (
	// KindDomain is a domain name.
	KindDomain Kind = iota
	// KindIP is an IP address allocation. IPv4 and IPv6 are not
	// distinguished here; IPRecord.IPVersion carries that.
	KindIP
	// KindASN is an autonomous system.
	KindASN
)

// String returns the kind's name, as used in -o json's objectType.
func (k Kind) String() string {
	switch k {
	case KindDomain:
		return "domain"
	case KindIP:
		return "ip"
	case KindASN:
		return "asn"
	}
	return "unknown"
}

// Result is one lookup's outcome. Exactly one of Domain, IP, and ASN is
// non-nil, matching Kind. The three stay separate types because the
// objects genuinely differ: an IP allocation has no registrar,
// nameservers, or expiry, and a domain has no address range.
type Result struct {
	// Kind says which record pointer below is populated.
	Kind Kind
	// Input is the caller's original string, unmodified.
	Input string
	// Domain is set when Kind is KindDomain.
	Domain *Record
	// IP is set when Kind is KindIP.
	IP *IPRecord
	// ASN is set when Kind is KindASN.
	ASN *ASNRecord
}

// Lookup classifies input as a domain, IP address, or ASN, queries the
// relevant RDAP and WHOIS sources concurrently, and merges the answers.
//
// A source failing is normal and is not an error: as long as one source
// returned data, Lookup returns a Result with nil error, and the
// per-source detail is in the record's Sources field. Lookup returns
// ErrInvalidInput, ErrNotFound, or ErrLookupFailed for the three cases
// where there is no usable answer at all.
func (c *Client) Lookup(ctx context.Context, input string) (Result, error) {
	q, err := domain.Normalize(input)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	res := Result{Input: input}
	var sources []model.SourceResult

	switch q.Kind {
	case domain.KindDomain:
		baseURL, _ := c.resolver.BaseURL(q.Name.TLD) // "" is fine -- WHOIS-only
		records := collect.Collect(ctx, q.Name, baseURL, c.opts.WHOISIANAServer, collect.Options{
			NoFollow:   c.opts.NoFollow,
			Timeout:    c.opts.Timeout,
			Sources:    c.opts.Sources,
			Limiter:    c.limiter,
			IANACache:  c.ianaCache,
			HTTPClient: c.opts.HTTPClient,
		})
		rec := merge.Merge(records)
		res.Kind, res.Domain, sources = KindDomain, &rec, rec.Sources

	case domain.KindIPv4, domain.KindIPv6:
		baseURL, _ := c.resolver.IPBaseURL(q.IP)
		records := collect.CollectIP(ctx, q.IP, baseURL, c.opts.WHOISIANAServer, collect.Options{
			Timeout:    c.opts.Timeout,
			Sources:    c.opts.Sources,
			Limiter:    c.limiter,
			HTTPClient: c.opts.HTTPClient,
		})
		rec := merge.MergeIP(records)
		res.Kind, res.IP, sources = KindIP, &rec, rec.Sources

	case domain.KindASN:
		baseURL, _ := c.resolver.ASNBaseURL(q.ASN)
		records := collect.CollectASN(ctx, q.ASN, baseURL, c.opts.WHOISIANAServer, collect.Options{
			Timeout:    c.opts.Timeout,
			Sources:    c.opts.Sources,
			Limiter:    c.limiter,
			HTTPClient: c.opts.HTTPClient,
		})
		rec := merge.MergeASN(records)
		res.Kind, res.ASN, sources = KindASN, &rec, rec.Sources
	}

	switch model.Classify(sources) {
	case model.OutcomeNotFound:
		return res, ErrNotFound
	case model.OutcomeFailed:
		return res, ErrLookupFailed
	}
	return res, nil
}
