package model

// IP-record field-name constants, used as Conflict.Field /
// RedactionNotice.Field values.
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

// IPRecord is the unified, provenance-annotated IP network lookup result
// -- the output of merge.MergeIP. It is a sibling of Record, not a
// variant of it: an IP allocation has no registrar, nameservers, expiry,
// DNSSEC, or lifecycle, and Record has no netblock range.
type IPRecord struct {
	Handle       Field[string]
	Name         Field[string]
	Type         Field[string]
	StartAddress Field[string]
	EndAddress   Field[string]
	CIDR         Field[string]
	IPVersion    Field[string]
	ParentHandle Field[string]
	Country      Field[string]
	Org          OrgInfo
	Status       Field[[]string]
	Registered   Field[TimeValue]
	Updated      Field[TimeValue]
	Redacted     []RedactionNotice
	Sources      []SourceResult
	Conflicts    []Conflict
}

// IPSourceRecord is MergeIP's input shape -- one per source attempted,
// produced by internal/collect's IP adapters.
type IPSourceRecord struct {
	Meta           SourceResult
	Present        bool
	Handle         string
	Name           string
	Type           string
	StartAddress   string
	EndAddress     string
	CIDR           string
	IPVersion      string
	ParentHandle   string
	Country        string
	OrgName        string
	OrgID          string
	AbuseEmail     string
	AbusePhone     string
	Status         []string // already EPP-normalized by the adapter
	Registered     TimeValue
	Updated        TimeValue
	RedactedFields map[string]bool
	Redactions     []RedactionNotice
}
