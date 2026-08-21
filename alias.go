package plat

import (
	"net/netip"

	"github.com/patramsey/plat/internal/bootstrap"
	"github.com/patramsey/plat/internal/model"
)

// The record types are aliases rather than defined types: an alias is the
// same type, so no conversion happens at the boundary and the
// implementation stays in internal/, free to change without breaking
// consumers of anything not named here.
//
// "Free to change" is narrower than it sounds for the aliased types
// themselves, though: because the alias is the same type, not a copy,
// their shapes are now part of this package's public API too. Renaming
// or removing an exported field on model.Record, model.IPRecord,
// model.ASNRecord (or the other aliased types below), or changing an
// aliased method's signature, is a breaking change for every consumer --
// exactly as if the field or method lived here directly. Adding a field
// is additive and safe, same as anywhere else. TestPublicAPISurface does
// NOT catch any of this: it parses only this package's own declarations,
// so it is blind to everything inside internal/model. Review changes to
// those types with that in mind.

// Record is a merged, provenance-annotated domain lookup result.
type Record = model.Record

// IPRecord is a merged, provenance-annotated IP network lookup result.
type IPRecord = model.IPRecord

// ASNRecord is a merged, provenance-annotated autonomous system result.
type ASNRecord = model.ASNRecord

// Field is a single merged value together with the sources that supplied
// it. Per-field provenance is plat's central idea, not a decoration.
type Field[T any] = model.Field[T]

// RegistrarInfo is a domain's registrar identity.
type RegistrarInfo = model.RegistrarInfo

// OrgInfo is the organization holding an IP allocation or ASN.
type OrgInfo = model.OrgInfo

// SourceResult is the per-source outcome behind a record.
type SourceResult = model.SourceResult

// SourceID names one of the four sources plat can consult.
type SourceID = model.SourceID

// Conflict records a field where sources disagreed.
type Conflict = model.Conflict

// TimeValue is a timestamp with the raw string it was parsed from.
type TimeValue = model.TimeValue

// RedactionNotice records that a value was withheld, typically for GDPR.
type RedactionNotice = model.RedactionNotice

// LifecycleInfo explains where an expired gTLD domain sits in ICANN's
// deletion timeline.
type LifecycleInfo = model.LifecycleInfo

// LifecycleStage is a stage of that timeline.
type LifecycleStage = model.LifecycleStage

// The four sources plat merges, in precedence order.
const (
	SourceRegistrarRDAP  = model.SourceRegistrarRDAP
	SourceRegistryRDAP   = model.SourceRegistryRDAP
	SourceRegistrarWHOIS = model.SourceRegistrarWHOIS
	SourceRegistryWHOIS  = model.SourceRegistryWHOIS
)

// The stages of ICANN's Expired Registration Recovery Policy (ERRP)
// timeline that LifecycleInfo.Stage can report.
const (
	LifecycleAutoRenewGrace  = model.LifecycleAutoRenewGrace
	LifecycleRedemptionGrace = model.LifecycleRedemptionGrace
	LifecyclePendingRestore  = model.LifecyclePendingRestore
	LifecyclePendingDelete   = model.LifecyclePendingDelete
)

// Resolver maps a TLD, IP address, or ASN to the RDAP base URL that
// serves it. New builds one from IANA's published bootstrap data; supply
// your own through Options.Resolver to query a private or mirrored RDAP
// deployment instead.
//
// Build one with NewResolver, passing a ResolverConfig. A field left nil
// means plat has no RDAP endpoint for that object kind, and lookups of it
// fall back to WHOIS-only -- that is not an error, just reduced coverage.
type Resolver = bootstrap.Resolver

// ResolverConfig describes which RDAP base URLs a Resolver should serve.
// Any field may be nil, meaning plat has no RDAP endpoint for that object
// kind and lookups of it fall back to WHOIS-only.
//
// One config covers all three kinds deliberately. The predecessor API had a
// separate constructor per kind, which made it easy to point plat at a
// private RDAP deployment for domains and, without noticing, lose RDAP for
// every IP and ASN lookup.
type ResolverConfig struct {
	// Domains maps a TLD (no leading dot, e.g. "com") to its RDAP base URL.
	Domains map[string]string
	// Prefixes maps an IP prefix to the RDAP base URL serving it. The
	// most specific matching prefix wins.
	Prefixes map[netip.Prefix]string
	// ASNs maps an inclusive [start, end] autonomous-system number range
	// to its RDAP base URL.
	ASNs map[[2]uint32]string
}

// NewResolver builds a Resolver from an explicit set of RDAP endpoints,
// for querying a private or mirrored RDAP deployment instead of the ones
// IANA publishes. Pass it as Options.Resolver.
func NewResolver(cfg ResolverConfig) *Resolver {
	return bootstrap.NewCombinedResolver(cfg.Domains, cfg.Prefixes, cfg.ASNs)
}
