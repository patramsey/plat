package collect

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/rdap"
	"github.com/patramsey/plat/internal/whois"
)

// CollectASN fans out to the RIR's RDAP service and the WHOIS chain
// concurrently, mirroring CollectIP's structure -- an autonomous system
// has no registrar hop either, so this is a two-source fan-out rather
// than four. An empty baseURL (no RDAP coverage for the ASN) degrades to
// WHOIS-only. A single source failing is normal, not fatal -- CollectASN
// never returns an error.
//
// Like CollectIP, records come back in a fixed order (registry-rdap,
// registry-whois) regardless of which goroutine finished first, so
// callers see a stable order across runs.
func CollectASN(ctx context.Context, asn uint32, baseURL, whoisIANAServer string, opts Options) []model.ASNSourceRecord {
	var rdapOut, whoisOut []model.ASNSourceRecord

	needRDAP := baseURL != "" && opts.allows(model.SourceRegistryRDAP)
	needWHOIS := opts.allows(model.SourceRegistryWHOIS)

	var wg sync.WaitGroup
	if needRDAP {
		wg.Go(func() {
			rdapOut = collectASNRDAP(ctx, asn, baseURL, opts)
		})
	}
	if needWHOIS {
		wg.Go(func() {
			whoisOut = collectASNWHOIS(ctx, asn, whoisIANAServer, opts)
		})
	}
	wg.Wait()

	out := make([]model.ASNSourceRecord, 0, len(rdapOut)+len(whoisOut))
	out = append(out, rdapOut...)
	out = append(out, whoisOut...)
	return out
}

func collectASNRDAP(ctx context.Context, asn uint32, baseURL string, opts Options) []model.ASNSourceRecord {
	rdapClient := &rdap.Client{Timeout: opts.Timeout}
	start := time.Now()
	result, err := rdapClient.ASN(ctx, baseURL, asn)

	meta := model.SourceResult{Source: model.SourceRegistryRDAP, Latency: time.Since(start)}
	if result != nil {
		meta.Raw = result.Raw
	}
	if err != nil {
		meta.OK = false
		meta.Err = err.Error()
		meta.NotFound = errors.Is(err, rdap.ErrDomainNotFound)
		return []model.ASNSourceRecord{fromASNRDAP(meta, nil)}
	}
	meta.OK = true

	var resp *rdap.ASNResponse
	if result != nil {
		resp = result.ASN
	}
	return []model.ASNSourceRecord{fromASNRDAP(meta, resp)}
}

func collectASNWHOIS(ctx context.Context, asn uint32, whoisIANAServer string, opts Options) []model.ASNSourceRecord {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second // matches whois.Client.timeout()'s own default
	}
	// See collect.go's collectWHOIS for why the whole-chain bound is
	// ChainTimeout rather than a context.WithTimeout wrap here: a pacing
	// wait must not be charged against the same budget as the actual
	// network hops.
	whoisClient := &whois.Client{Timeout: timeout, ChainTimeout: timeout, IANAServer: whoisIANAServer, Limiter: opts.Limiter}
	result, _ := whoisClient.LookupASN(ctx, asn)
	return fromASNWHOIS(result)
}

// fromASNWHOIS adapts a LookupASN result's hop chain into a single
// SourceRegistryWHOIS model.ASNSourceRecord, mirroring fromIPWHOIS's
// hop-selection logic. LookupASN's chain has at most two hops (IANA, then
// the RIR) -- there is no third, registrar hop for ASN lookups either.
// Hops[0] (IANA) is never itself a data source; if it failed outright,
// that's surfaced as its own failed record rather than returning nothing,
// so a genuine network failure isn't indistinguishable from an ASN with
// no WHOIS referral at all.
//
// fromASNHop itself only handles the RateLimited/Unsupported refusal
// signals -- it has no NotFound signal of its own to check, since
// parse.ASNFields carries none, unlike parse.Fields, whose NotFound is
// set by scanning the raw response for markers like "no match". That
// scan does run for ASN hops too (asnHop populates Fields alongside
// ASNFields, so the referral chain can read "refer:"), so its result is
// available via hop.Fields.NotFound; this function applies it after the
// fromASNHop call to correct Meta.OK/NotFound/Present for a "no
// match"-style response, the same outcome fromHop reaches directly for
// domains.
func fromASNWHOIS(result *whois.Result) []model.ASNSourceRecord {
	if result == nil || len(result.Hops) == 0 {
		return nil
	}
	if ianaHop := result.Hops[0]; ianaHop.Err != nil {
		return []model.ASNSourceRecord{{Meta: model.SourceResult{
			Source:  model.SourceRegistryWHOIS,
			Latency: ianaHop.Latency,
			OK:      false,
			Err:     ianaHop.Err.Error(),
		}}}
	}
	if len(result.Hops) < 2 {
		return nil
	}

	hop := result.Hops[1]
	meta := model.SourceResult{Source: model.SourceRegistryWHOIS, Latency: hop.Latency, Raw: []byte(hop.Raw)}
	sr := fromASNHop(meta, hop)
	if hop.Err == nil && hop.Fields.NotFound {
		sr.Meta.OK = false
		sr.Meta.NotFound = true
		sr.Present = false
	}
	return []model.ASNSourceRecord{sr}
}
