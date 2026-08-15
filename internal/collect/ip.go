package collect

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/rdap"
	"github.com/patramsey/plat/internal/whois"
)

// CollectIP fans out to the RIR's RDAP service and the WHOIS chain
// concurrently, mirroring Collect's structure for domains. There is no
// registrar hop in either branch: an IP allocation has no registrar, so
// this is a two-source fan-out rather than four. An empty baseURL (no
// RDAP coverage for the address) degrades to WHOIS-only. A single source
// failing is normal, not fatal -- CollectIP never returns an error.
//
// Like Collect, records come back in a fixed order (registry-rdap,
// registry-whois) regardless of which goroutine finished first, so
// callers see a stable order across runs.
func CollectIP(ctx context.Context, addr netip.Addr, baseURL, whoisIANAServer string, opts Options) []model.IPSourceRecord {
	var rdapOut, whoisOut []model.IPSourceRecord

	needRDAP := baseURL != "" && opts.allows(model.SourceRegistryRDAP)
	needWHOIS := opts.allows(model.SourceRegistryWHOIS)

	var wg sync.WaitGroup
	if needRDAP {
		wg.Go(func() {
			rdapOut = collectIPRDAP(ctx, addr, baseURL, opts)
		})
	}
	if needWHOIS {
		wg.Go(func() {
			whoisOut = collectIPWHOIS(ctx, addr, whoisIANAServer, opts)
		})
	}
	wg.Wait()

	out := make([]model.IPSourceRecord, 0, len(rdapOut)+len(whoisOut))
	out = append(out, rdapOut...)
	out = append(out, whoisOut...)
	return out
}

func collectIPRDAP(ctx context.Context, addr netip.Addr, baseURL string, opts Options) []model.IPSourceRecord {
	rdapClient := &rdap.Client{Timeout: opts.Timeout}
	start := time.Now()
	result, err := rdapClient.IP(ctx, baseURL, addr)

	meta := model.SourceResult{Source: model.SourceRegistryRDAP, Latency: time.Since(start)}
	if result != nil {
		meta.Raw = result.Raw
	}
	if err != nil {
		meta.OK = false
		meta.Err = err.Error()
		meta.NotFound = errors.Is(err, rdap.ErrDomainNotFound)
		return []model.IPSourceRecord{fromIPRDAP(meta, nil)}
	}
	meta.OK = true

	var resp *rdap.IPNetworkResponse
	if result != nil {
		resp = result.IPNetwork
	}
	return []model.IPSourceRecord{fromIPRDAP(meta, resp)}
}

func collectIPWHOIS(ctx context.Context, addr netip.Addr, whoisIANAServer string, opts Options) []model.IPSourceRecord {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second // matches whois.Client.timeout()'s own default
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	whoisClient := &whois.Client{Timeout: timeout, IANAServer: whoisIANAServer, Limiter: opts.Limiter}
	result, _ := whoisClient.LookupIP(ctx, addr)
	return fromIPWHOIS(result)
}

// fromIPWHOIS adapts a LookupIP result's hop chain into a single
// SourceRegistryWHOIS model.IPSourceRecord, mirroring FromWHOIS's
// domain-side hop-selection logic. LookupIP's chain has at most two hops
// (IANA, then the RIR) -- there is no third, registrar hop for IP
// lookups, unlike the domain chain FromWHOIS handles. Hops[0] (IANA) is
// never itself a data source; if it failed outright, that's surfaced as
// its own failed record rather than returning nothing, so a genuine
// network failure isn't indistinguishable from an address with no WHOIS
// referral at all.
//
// fromIPHop itself only handles the RateLimited/Unsupported refusal
// signals (see its own doc comment) -- it has no NotFound signal of its
// own to check, since parse.IPFields carries none, unlike parse.Fields,
// whose NotFound is set by scanning the raw response for markers like
// "no match". That scan does run for IP hops too (ipHop populates Fields
// alongside IPFields, so the referral chain can read "refer:"), so its
// result is available via hop.Fields.NotFound; this function applies it
// after the fromIPHop call to correct Meta.OK/NotFound/Present for a
// "no match"-style response, the same outcome fromHop reaches directly
// for domains.
func fromIPWHOIS(result *whois.Result) []model.IPSourceRecord {
	if result == nil || len(result.Hops) == 0 {
		return nil
	}
	if ianaHop := result.Hops[0]; ianaHop.Err != nil {
		return []model.IPSourceRecord{{Meta: model.SourceResult{
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
	sr := fromIPHop(meta, hop)
	if hop.Err == nil && hop.Fields.NotFound {
		sr.Meta.OK = false
		sr.Meta.NotFound = true
		sr.Present = false
	}
	return []model.IPSourceRecord{sr}
}
