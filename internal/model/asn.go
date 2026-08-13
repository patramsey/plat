package model

// ASN-record field-name constants, used as Conflict.Field /
// RedactionNotice.Field values. Org-related fields (FieldOrgName,
// FieldOrgID, FieldOrgAbuseEmail, FieldOrgAbusePhone) are reused verbatim
// from ip.go rather than duplicated here, since ASNRecord.Org is the same
// OrgInfo type as IPRecord.Org.
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

// ASNRecord is the unified, provenance-annotated autonomous-system lookup
// result -- the output of merge.MergeASN. It is a sibling of IPRecord, not
// a variant of it: an ASN has a start/end autnum range instead of an
// address range or CIDR, and has no IP version or parent handle.
//
// StartAutnum/EndAutnum are Field[string], not Field[uint32], even though
// an autnum is numeric. This mirrors IPRecord.StartAddress/EndAddress
// (also Field[string] despite being numeric-ish): mergeState.scalar --
// shared with the domain and IP merge paths, and not to be modified for
// this feature -- takes []scalarCandidate whose Value is a string and
// returns Field[string]. Keeping StartAutnum/EndAutnum as strings lets
// merge.MergeASN reuse scalar() with no carve-out and avoids adding a
// numeric field-view to the machine renderer. The adapter boundary
// (internal/collect/adapt_asn.go) converts the RDAP response's uint32
// startAutnum/endAutnum to string via strconv.FormatUint.
type ASNRecord struct {
	Handle      Field[string]
	Name        Field[string]
	Type        Field[string]
	StartAutnum Field[string]
	EndAutnum   Field[string]
	Country     Field[string]
	Org         OrgInfo
	Status      Field[[]string]
	Registered  Field[TimeValue]
	Updated     Field[TimeValue]
	Redacted    []RedactionNotice
	Sources     []SourceResult
	Conflicts   []Conflict
}

// ASNSourceRecord is MergeASN's input shape -- one per source attempted,
// produced by internal/collect's ASN adapters.
type ASNSourceRecord struct {
	Meta           SourceResult
	Present        bool
	Handle         string
	Name           string
	Type           string
	StartAutnum    string
	EndAutnum      string
	Country        string
	OrgName        string
	OrgID          string
	AbuseEmail     string
	AbusePhone     string
	Status         []string // RIR's own status strings, passed through unchanged (not EPP vocabulary)
	Registered     TimeValue
	Updated        TimeValue
	RedactedFields map[string]bool
	Redactions     []RedactionNotice
}

// See the SourceRecord versions in record.go for why these exist and why
// IsPresent is not called Present.
func (r ASNSourceRecord) IsPresent() bool    { return r.Present }
func (r ASNSourceRecord) SourceID() SourceID { return r.Meta.Source }

// See the IPSourceRecord version in ip.go. SourceRecord deliberately
// does not get this method.
func (r ASNSourceRecord) Statuses() []string { return r.Status }
