// Package model defines plat's data model: Record, IPRecord, and
// ASNRecord, the provenance-carrying Field[T] that composes them, and
// the supporting types -- Conflict, RedactionNotice, SourceResult,
// LifecycleInfo -- that describe how a merged value came to be what it
// is. Per-field provenance (which source(s) supplied each value) is
// plat's central idea, not an afterthought bolted onto these types.
//
// model is a separate package from plat, the top-level CLI/library
// package, so this data model can be documented on its own pkg.go.dev
// page rather than buried under Client and Lookup. plat aliases every
// exported name here (see plat's alias.go), so a caller using only
// plat.New and Client.Lookup rarely needs to import model directly --
// but the shapes, and their documentation, live in this package.
package model

import "time"

// Field-name constants used as Conflict.Field / RedactionNotice.Field
// values, so callers never hand-type a field name string more than once.
// Several of these share a value with an IP- or ASN-record constant
// (e.g. FieldHandle == FieldIPHandle == "handle") -- harmless in
// practice since Record, IPRecord, and ASNRecord are disjoint, but worth
// knowing before writing one switch over Conflict.Field that spans more
// than one record kind, where it produces a duplicate-case compile error.
const (
	FieldDomain              = "domain"
	FieldHandle              = "handle"
	FieldRegistrarName       = "registrar.name"
	FieldRegistrarIANAID     = "registrar.ianaId"
	FieldRegistrarURL        = "registrar.url"
	FieldRegistrarAbuseEmail = "registrar.abuseEmail"
	FieldRegistrarAbusePhone = "registrar.abusePhone"
	FieldStatus              = "status"
	FieldCreated             = "created"
	FieldUpdated             = "updated"
	FieldExpires             = "expires"
	FieldNameservers         = "nameservers"
	FieldDNSSEC              = "dnssec"
)

// FieldSpec names one Record field's display label and Conflict/
// RedactionNotice key.
type FieldSpec struct {
	Label string
	Key   string
}

// FieldOrder is the canonical field sequence and label for any renderer
// that shows every populated Record field — human and plain both iterate
// this instead of hand-listing the fields themselves, so a field added
// here can't be wired into one renderer and silently forgotten in the
// other: each renderer's Render function panics on an entry it doesn't
// recognize, which fails that renderer's own tests immediately rather
// than drifting unnoticed.
var FieldOrder = []FieldSpec{
	{"Domain", FieldDomain},
	{"Handle", FieldHandle},
	{"Registrar", FieldRegistrarName},
	{"Registrar IANA ID", FieldRegistrarIANAID},
	{"Registrar URL", FieldRegistrarURL},
	{"Abuse Email", FieldRegistrarAbuseEmail},
	{"Abuse Phone", FieldRegistrarAbusePhone},
	{"Status", FieldStatus},
	{"Created", FieldCreated},
	{"Updated", FieldUpdated},
	{"Expires", FieldExpires},
	{"Nameservers", FieldNameservers},
	{"DNSSEC", FieldDNSSEC},
}

// Field carries a merged value plus the sources that agree on it.
type Field[T any] struct {
	Value   T
	Sources []SourceID
}

// Present reports whether any source contributed to this field.
func (f Field[T]) Present() bool { return len(f.Sources) > 0 }

// TimeValue is a timestamp together with the raw string a source
// reported it as. When parsing failed, Time is the zero value but Raw
// still holds what the source sent -- check Parsed before trusting Time.
type TimeValue struct {
	Time   time.Time
	Raw    string
	Parsed bool
}

// RegistrarInfo is the registrar's own identity. Registrant/admin/tech/
// billing contact details are deliberately not modeled — see the
// "Redaction and contacts" section of README.md for why.
type RegistrarInfo struct {
	Name       Field[string]
	IANAID     Field[string]
	URL        Field[string]
	AbuseEmail Field[string]
	AbusePhone Field[string]
}

// Conflict records a field where present sources disagree. Values maps
// each disagreeing source (including the winner) to its rendered value,
// so the conflict is self-describing without cross-referencing Record.
type Conflict struct {
	Field  string
	Values map[SourceID]string
}

// RedactionNotice records that a higher-precedence source's value for
// Field was withheld (matched a known redaction placeholder), and a
// lower-precedence source's value was used instead — or no value was
// available at all if every source was redacted.
type RedactionNotice struct {
	Field  string
	Source SourceID
	Reason string
}

// SourceResult is the per-source metadata that ends up in Record.Sources
// — one row per source actually attempted, regardless of whether it
// yielded usable data.
type SourceResult struct {
	Source   SourceID
	OK       bool
	NotFound bool
	Latency  time.Duration
	Err      string
	Raw      []byte
}

// Record is a domain lookup's unified, provenance-annotated result:
// registry and registrar RDAP and WHOIS merged into one set of fields,
// each recording which source(s) supplied it.
type Record struct {
	// Domain is the normalized (lowercase, punycode) domain name.
	Domain Field[string]
	// Handle is the registry's unique identifier for the domain (RDAP's
	// "handle" / WHOIS's "Registry Domain ID").
	Handle    Field[string]
	Registrar RegistrarInfo
	// Status holds EPP status codes (RFC 8056), already normalized from
	// both RDAP's and WHOIS's differing vocabularies -- e.g. WHOIS's
	// "clientTransferProhibited" and RDAP's "client transfer prohibited"
	// both arrive here as "clientTransferProhibited".
	Status Field[[]string]
	// Created, Updated, and Expires are UTC. When a source's timestamp
	// could not be parsed, TimeValue.Time is the zero value but
	// TimeValue.Raw still carries the source's original string --
	// check TimeValue.Parsed before trusting Time.
	Created Field[TimeValue]
	Updated Field[TimeValue]
	Expires Field[TimeValue]
	// Nameservers are lowercased with any trailing dot stripped, then
	// unioned across sources; genuinely differing sets (not just casing
	// or a trailing dot) surface as a Conflict instead of being merged.
	Nameservers Field[[]string]
	// DNSSEC reports whether the domain is signed. A zero Field (check
	// Present, not just the bool) means no source expressed an opinion
	// either way -- it does not mean DNSSEC is known to be off.
	DNSSEC Field[bool]
	// Lifecycle is non-nil only for a gTLD domain whose Status places it
	// in ICANN's Expired Registration Recovery Policy timeline.
	Lifecycle *LifecycleInfo
	Redacted  []RedactionNotice
	Sources   []SourceResult
	Conflicts []Conflict
}
