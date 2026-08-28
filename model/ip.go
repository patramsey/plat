package model

// IP-record field-name constants, used as Conflict.Field /
// RedactionNotice.Field values. Several share a value with a Record or
// ASNRecord constant (e.g. FieldIPHandle == FieldHandle == "handle");
// see the comment on Record's own field-name constants for why that's
// harmless.
const (
	FieldIPHandle       = "handle"
	FieldIPName         = "name"
	FieldIPType         = "type"
	FieldIPStartAddress = "startAddress"
	FieldIPEndAddress   = "endAddress"
	FieldIPCIDR         = "cidr"
	FieldIPVersion      = "ipVersion"
	FieldIPParent       = "parentHandle"
	FieldIPCountry      = "country"
	FieldOrgName        = "org.name"
	FieldOrgID          = "org.id"
	FieldOrgAbuseEmail  = "org.abuseEmail"
	FieldOrgAbusePhone  = "org.abusePhone"
	FieldIPStatus       = "status"
	FieldIPRegistered   = "registered"
	FieldIPUpdated      = "updated"
)

// IPFieldOrder is the canonical field sequence and label for renderers,
// mirroring FieldOrder's role for domains: each renderer iterates it and
// panics on an unrecognized entry, so a field added here cannot be wired
// into one renderer and silently forgotten in another.
var IPFieldOrder = []FieldSpec{
	{"Network", FieldIPName},
	{"Handle", FieldIPHandle},
	{"Range", FieldIPStartAddress},
	{"CIDR", FieldIPCIDR},
	{"Type", FieldIPType},
	{"IP Version", FieldIPVersion},
	{"Parent", FieldIPParent},
	{"Organization", FieldOrgName},
	{"Org ID", FieldOrgID},
	{"Country", FieldIPCountry},
	{"Abuse Email", FieldOrgAbuseEmail},
	{"Abuse Phone", FieldOrgAbusePhone},
	{"Status", FieldIPStatus},
	{"Registered", FieldIPRegistered},
	{"Updated", FieldIPUpdated},
}

// OrgInfo is the organization holding a resource. Named generically
// rather than IPOrgInfo because the ASN follow-on reuses it unchanged.
type OrgInfo struct {
	Name       Field[string]
	ID         Field[string]
	AbuseEmail Field[string]
	AbusePhone Field[string]
}

// IPRecord is an IP network lookup's unified, provenance-annotated
// result: the responsible RIR's RDAP and WHOIS merged into one set of
// fields, each recording which source(s) supplied it. It is a sibling of
// Record, not a variant of it: an IP allocation has no registrar,
// nameservers, expiry, DNSSEC, or lifecycle, and Record has no netblock
// range.
type IPRecord struct {
	// Handle is the RIR's unique identifier for this network allocation.
	Handle Field[string]
	Name   Field[string]
	// Type is the RIR's allocation type (e.g. "ALLOCATED PA", "ASSIGNED").
	Type         Field[string]
	StartAddress Field[string]
	EndAddress   Field[string]
	CIDR         Field[string]
	// IPVersion is "4" or "6".
	IPVersion Field[string]
	// ParentHandle is the enclosing allocation's Handle, if any.
	ParentHandle Field[string]
	Country      Field[string]
	Org          OrgInfo
	// Status is passed through as each RIR reports it, unlike Record's
	// domain Status: there is no EPP-equivalent shared vocabulary across
	// RIRs, so no normalization is applied here.
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
