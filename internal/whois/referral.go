package whois

import (
	"context"
	"fmt"
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
	result := &Result{Domain: name.Punycode}

	// IANA's whois.iana.org response is always plain key: value text,
	// regardless of the queried TLD's own template dialect (e.g. brackets
	// for .jp). Parse it with the default/kv template, not name.TLD, or
	// the refer: line can go unmatched and truncate the referral chain.
	ianaHop := c.hop(ctx, c.ianaServer(), name.TLD, "")
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
