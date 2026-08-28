package model

// ASN-record field-name constants, used as Conflict.Field /
// RedactionNotice.Field values. Org-related fields (FieldOrgName,
// FieldOrgID, FieldOrgAbuseEmail, FieldOrgAbusePhone) are reused verbatim
// from ip.go rather than duplicated here, since ASNRecord.Org is the same
// OrgInfo type as IPRecord.Org. Several of these also share a value with
// a Record or IPRecord constant (e.g. FieldASNHandle == FieldHandle ==
// "handle"); see the comment on Record's own field-name constants for
// why that's harmless.
const (
	FieldASNHandle      = "handle"
	FieldASNName        = "name"
	FieldASNType        = "type"
	FieldASNStartAutnum = "startAutnum"
	FieldASNEndAutnum   = "endAutnum"
	FieldASNCountry     = "country"
	FieldASNStatus      = "status"
	FieldASNRegistered  = "registered"
	FieldASNUpdated     = "updated"
)

// ASNFieldOrder is the canonical field sequence and label for renderers,
// mirroring IPFieldOrder's role for IP networks: each renderer iterates it
// and panics on an unrecognized entry, so a field added here cannot be
// wired into one renderer and silently forgotten in another.
//
// FieldASNEndAutnum deliberately has no entry of its own here, mirroring
// IPFieldOrder's omission of FieldIPEndAddress: the renderer combines
// StartAutnum and EndAutnum into a single "Range" row keyed off the
// FieldASNStartAutnum entry, while the two remain independently merged
// Fields (and independent Conflict.Field keys) under the hood.
var ASNFieldOrder = []FieldSpec{
	{"AS Name", FieldASNName},
	{"Handle", FieldASNHandle},
	{"Range", FieldASNStartAutnum},
	{"Type", FieldASNType},
	{"Organization", FieldOrgName},
	{"Org ID", FieldOrgID},
	{"Country", FieldASNCountry},
	{"Abuse Email", FieldOrgAbuseEmail},
	{"Abuse Phone", FieldOrgAbusePhone},
	{"Status", FieldASNStatus},
	{"Registered", FieldASNRegistered},
	{"Updated", FieldASNUpdated},
}

// ASNRecord is an autonomous system lookup's unified, provenance-annotated
// result: the responsible RIR's RDAP and WHOIS merged into one set of
// fields, each recording which source(s) supplied it. It is a sibling of
// IPRecord, not a variant of it: an ASN has a start/end autnum range
// instead of an address range or CIDR, and has no IP version or parent
// handle.
//
// StartAutnum and EndAutnum are Field[string], not Field[uint32], even
// though an autnum is numeric -- parse them yourself if you need to
// compare ranges numerically. This mirrors IPRecord.StartAddress and
// EndAddress, which are Field[string] for the same reason: it lets both
// record types share the same merge machinery internally, and it avoids
// committing this package to a numeric field-view a consumer might not
// want anyway (a CIDR or address range isn't naturally a single number).
type ASNRecord struct {
	// Handle is the RIR's unique identifier for this AS registration.
	Handle Field[string]
	Name   Field[string]
	// Type is the RIR's registration type (e.g. "DIRECT ALLOCATION").
	Type Field[string]
	// StartAutnum and EndAutnum bound the AS number range (a single ASN
	// has StartAutnum == EndAutnum). Both are decimal strings -- see the
	// type's own doc comment for why they aren't uint32.
	StartAutnum Field[string]
	EndAutnum   Field[string]
	Country     Field[string]
	Org         OrgInfo
	// Status is passed through as each RIR reports it; there is no
	// EPP-equivalent shared vocabulary across RIRs, so unlike Record's
	// domain Status, no normalization is applied here.
	Status Field[[]string]
	// Registered and Updated are UTC. When a source's timestamp could not
	// be parsed, TimeValue.Time is the zero value but TimeValue.Raw still
	// carries the source's original string -- check TimeValue.Parsed
	// before trusting Time.
	Registered Field[TimeValue]
	Updated    Field[TimeValue]
	Redacted   []RedactionNotice
	Sources    []SourceResult
	Conflicts  []Conflict
}
