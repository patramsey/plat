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
type Resolver = bootstrap.Resolver

// NewResolver builds a Resolver from an explicit TLD-to-RDAP-base-URL
// map, for domain lookups.
func NewResolver(byTLD map[string]string) *Resolver {
	return bootstrap.NewResolver(byTLD)
}

// NewIPResolver builds a Resolver from an explicit
// prefix-to-RDAP-base-URL map, for IP lookups.
func NewIPResolver(prefixes map[netip.Prefix]string) *Resolver {
	return bootstrap.NewIPResolver(prefixes)
}

// NewASNResolver builds a Resolver from an explicit ASN-range-to-
// RDAP-base-URL map, for ASN lookups. Each key is an inclusive
// [start, end] autonomous-system number range.
func NewASNResolver(ranges map[[2]uint32]string) *Resolver {
	return bootstrap.NewASNResolver(ranges)
}
