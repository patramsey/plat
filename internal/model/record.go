package model

import "time"

// Field-name constants used as Conflict.Field / RedactionNotice.Field
// values, so callers never hand-type a field name string more than once.
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

// TimeValue parallels rdap.RDAPTime and parse.Date so adapters can map
// either into it 1:1 without losing the raw string when parsing failed.
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

// Record is the unified, provenance-annotated domain lookup result — the
// output of merge.Merge.
type Record struct {
	Domain      Field[string]
	Handle      Field[string]
	Registrar   RegistrarInfo
	Status      Field[[]string]
	Created     Field[TimeValue]
	Updated     Field[TimeValue]
	Expires     Field[TimeValue]
	Nameservers Field[[]string]
	DNSSEC      Field[bool]
	Lifecycle   *LifecycleInfo
	Redacted    []RedactionNotice
	Sources     []SourceResult
	Conflicts   []Conflict
}

// RegistrarFields is the plain-string registrar identity an adapter
// extracts from one source, before merge.Merge turns it into
// Record.Registrar's Field[string]s with provenance.
type RegistrarFields struct {
	Name       string
	IANAID     string
	URL        string
	AbuseEmail string
	AbusePhone string
}

// SourceRecord is merge.Merge's input shape — one per source that was
// attempted, produced by internal/collect's adapters from rdap.Result /
// whois.Hop.
type SourceRecord struct {
	Meta           SourceResult
	Present        bool
	Domain         string
	Handle         string
	Registrar      RegistrarFields
	Status         []string // already EPP-normalized by the adapter
	Created        TimeValue
	Updated        TimeValue
	Expires        TimeValue
	Nameservers    []string // raw, as reported by the source — merge.Merge normalizes (lowercase, no trailing dot)
	DNSSEC         *bool    // nil = source said nothing about DNSSEC
	RedactedFields map[string]bool
	Redactions     []RedactionNotice
}
