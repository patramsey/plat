package whois

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/patramsey/plat/internal/domain"
	"github.com/patramsey/plat/internal/whois/parse"
)

func (c *Client) hop(ctx context.Context, server, queryDomain, tld string) Hop {
	start := time.Now()
	raw, err := c.query(ctx, server, queryDomain)
	h := Hop{
		Server:  server,
		Query:   BuildQuery(server, queryDomain),
		Raw:     raw,
		Latency: time.Since(start),
		Err:     err,
	}
	if err == nil {
		h.Fields = parse.Parse(raw, tld)
	}
	return h
}

// beginChain returns ctx carrying a fresh whole-chain network budget when
// c.ChainTimeout is set, and ctx untouched otherwise (the standalone
// case, where each hop is bounded only by c.Timeout). Every entry point
// that chases a referral chain calls this exactly once, so the budget is
// per-Lookup rather than per-Client -- a Client stays reentrant and safe
// to share.
func (c *Client) beginChain(ctx context.Context) context.Context {
	if c.ChainTimeout <= 0 {
		return ctx
	}
	return withChain(ctx, c.ChainTimeout)
}

// ianaHop resolves tld's registry WHOIS server via the IANA hop, going
// through c.IANACache when set so a run's concurrent same-TLD lookups
// share one IANA query instead of one each (see IANACache's doc comment).
//
// A caller that loses the race to another name's in-flight fetch blocks
// until that fetch returns and then inherits its result, having done no
// network work of its own -- so that block, exactly like a pacing wait,
// is credited back to this caller's chain budget rather than charged
// against it. Without that, an unlucky same-TLD name could spend its
// entire budget waiting on the winner's pacing slot and then fail its
// registry hop, which is the same defect as charging pacing directly,
// one indirection removed.
//
// The winning caller runs the fetch under its own ctx, budget included.
// Every caller reaches its IANA hop as the FIRST hop of its own chain, so
// the winner always has the full ChainTimeout available here -- being
// bound by its own budget is therefore no tighter than the plain per-hop
// Timeout it would otherwise get.
func (c *Client) ianaHop(ctx context.Context, tld string) Hop {
	if c.IANACache == nil {
		return c.hop(ctx, c.ianaServer(), tld, "")
	}
	hop, blocked := c.IANACache.resolve(tld, func() Hop {
		return c.hop(ctx, c.ianaServer(), tld, "")
	})
	creditChain(ctx, blocked)
	return hop
}

// QueryServer performs a single WHOIS query against server for name, with
// no IANA/registry referral chasing — for a caller that already knows
// which server to query directly (e.g. a registrar WHOIS server
// discovered via RDAP's port43 field when the normal registry ->
// registrar WHOIS referral chain didn't yield one). Like the registrar
// hop inside Lookup, this always targets a registrar's own WHOIS server,
// so it's parsed with the default/kv template ("" below), not name.TLD —
// see Lookup's registrar-hop comment for why a registrar server's reply
// format doesn't depend on the queried domain's TLD dialect.
func (c *Client) QueryServer(ctx context.Context, server string, name domain.Name) Hop {
	return c.hop(ctx, server, name.Punycode, "")
}

// Lookup performs IANA -> registry -> registrar referral chasing for
// name. A hop erroring is normal, not fatal: Lookup always records the
// IANA hop, proceeds to the registry hop only if IANA yielded a `refer:`
// server, and proceeds to the registrar hop only if the registry yielded
// a `Registrar WHOIS Server:` line. It returns a non-nil error only if
// every attempted hop failed.
func (c *Client) Lookup(ctx context.Context, name domain.Name) (*Result, error) {
	ctx = c.beginChain(ctx)
	result := &Result{Domain: name.Punycode}

	// IANA's whois.iana.org response is always plain key: value text,
	// regardless of the queried TLD's own template dialect (e.g. brackets
	// for .jp). Parse it with the default/kv template, not name.TLD, or
	// the refer: line can go unmatched and truncate the referral chain.
	ianaHop := c.ianaHop(ctx, name.TLD)
	result.Hops = append(result.Hops, ianaHop)

	if ianaHop.Err == nil && ianaHop.Fields.Refer != "" {
		registryHop := c.hop(ctx, ianaHop.Fields.Refer, name.Punycode, name.TLD)
		result.Hops = append(result.Hops, registryHop)

		if registryHop.Err == nil && registryHop.Fields.RegistrarWHOISServer != "" {
			// Same reasoning as the IANA hop above: the registrar's own
			// WHOIS server generally replies in plain key:value text
			// regardless of the queried domain's TLD dialect (e.g.
			// brackets for .jp, indent for .uk), so it's parsed with the
			// default/kv template ("") rather than name.TLD.
			registrarHop := c.hop(ctx, registryHop.Fields.RegistrarWHOISServer, name.Punycode, "")
			result.Hops = append(result.Hops, registrarHop)
		}
	}

	for _, h := range result.Hops {
		if h.Err == nil {
			return result, nil
		}
	}
	return result, fmt.Errorf("whois: all hops failed for %s", name.Punycode)
}

// LookupIP performs IANA -> RIR referral chasing for addr. There is no
// third hop: IP allocations have no registrar, so the chain stops at the
// RIR. Verified against live infrastructure -- whois.iana.org answers an
// IP query with a "refer:" line pointing at the holding RIR.
func (c *Client) LookupIP(ctx context.Context, addr netip.Addr) (*Result, error) {
	ctx = c.beginChain(ctx)
	q := addr.String()
	result := &Result{Domain: q}

	ianaHop := c.ipHop(ctx, c.ianaServer(), q)
	result.Hops = append(result.Hops, ianaHop)

	if ianaHop.Err == nil && ianaHop.Fields.Refer != "" {
		result.Hops = append(result.Hops, c.ipHop(ctx, ianaHop.Fields.Refer, q))
	}

	for _, h := range result.Hops {
		if h.Err == nil {
			return result, nil
		}
	}
	return result, fmt.Errorf("whois: all hops failed for %s", q)
}

// ipHop is hop's IP counterpart: it fills both Fields (so the referral
// chain can still read "refer:") and IPFields (the actual payload).
func (c *Client) ipHop(ctx context.Context, server, query string) Hop {
	start := time.Now()
	raw, err := c.query(ctx, server, query)
	h := Hop{
		Server:  server,
		Query:   BuildQuery(server, query),
		Raw:     raw,
		Latency: time.Since(start),
		Err:     err,
	}
	if err == nil {
		h.Fields = parse.Parse(raw, "")
		ipf := parse.ParseIP(raw)
		h.IPFields = &ipf
	}
	return h
}

// LookupASN performs IANA -> RIR referral chasing for asn. Like
// LookupIP, there is no third hop: an autonomous system has no
// registrar, so the chain stops at the RIR. The query string sent at
// both hops is the bare number with its "AS" prefix (e.g. "AS15169") --
// verified live against both whois.iana.org and whois.arin.net, which
// each answer that form directly (ARIN's plain numeric form without the
// prefix, e.g. "15169", returns no match at all).
func (c *Client) LookupASN(ctx context.Context, asn uint32) (*Result, error) {
	ctx = c.beginChain(ctx)
	q := "AS" + strconv.FormatUint(uint64(asn), 10)
	result := &Result{Domain: q}

	ianaHop := c.asnHop(ctx, c.ianaServer(), q)
	result.Hops = append(result.Hops, ianaHop)

	if ianaHop.Err == nil && ianaHop.Fields.Refer != "" {
		result.Hops = append(result.Hops, c.asnHop(ctx, ianaHop.Fields.Refer, q))
	}

	for _, h := range result.Hops {
		if h.Err == nil {
			return result, nil
		}
	}
	return result, fmt.Errorf("whois: all hops failed for %s", q)
}

// asnHop is hop's ASN counterpart: it fills both Fields (so the referral
// chain can still read "refer:"/"whois:") and ASNFields (the actual
// payload), mirroring ipHop.
func (c *Client) asnHop(ctx context.Context, server, query string) Hop {
	start := time.Now()
	raw, err := c.query(ctx, server, query)
	h := Hop{
		Server:  server,
		Query:   BuildQuery(server, query),
		Raw:     raw,
		Latency: time.Since(start),
		Err:     err,
	}
	if err == nil {
		h.Fields = parse.Parse(raw, "")
		asnf := parse.ParseASN(raw)
		h.ASNFields = &asnf
	}
	return h
}
