// Package source holds the pre-merge shapes internal/collect produces and
// internal/merge consumes, plus the two normalisation helpers collect needs.
//
// These live apart from the data model deliberately. They are inputs to the
// merge, not results of it: no consumer of the public API can encounter a
// SourceRecord, and publishing one would commit plat to a shape that exists
// only because of how the merge happens to be staged today.
package source

import "github.com/patramsey/plat/internal/model"

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
	Meta           model.SourceResult
	Present        bool
	Domain         string
	Handle         string
	Registrar      RegistrarFields
	Status         []string // already EPP-normalized by the adapter
	Created        model.TimeValue
	Updated        model.TimeValue
	Expires        model.TimeValue
	Nameservers    []string // raw, as reported by the source — merge.Merge normalizes (lowercase, no trailing dot)
	DNSSEC         *bool    // nil = source said nothing about DNSSEC
	RedactedFields map[string]bool
	Redactions     []model.RedactionNotice
}

// IsPresent and SourceID expose the two fields every source-record type
// shares, so merge's generic helpers can reach them. Go generics cannot
// read struct fields through a type parameter, only methods.
//
// Named IsPresent rather than Present because Present is already a field
// on this struct; a method may not share a name with a field of the same
// type.
func (r SourceRecord) IsPresent() bool          { return r.Present }
func (r SourceRecord) SourceID() model.SourceID { return r.Meta.Source }

// IPSourceRecord is MergeIP's input shape -- one per source attempted,
// produced by internal/collect's IP adapters.
type IPSourceRecord struct {
	Meta           model.SourceResult
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
	Status         []string // RIR's own status strings, passed through unchanged (not EPP vocabulary)
	Registered     model.TimeValue
	Updated        model.TimeValue
	RedactedFields map[string]bool
	Redactions     []model.RedactionNotice
}

// See SourceRecord's IsPresent/SourceID above for why these exist and why
// IsPresent is not called Present.
func (r IPSourceRecord) IsPresent() bool          { return r.Present }
func (r IPSourceRecord) SourceID() model.SourceID { return r.Meta.Source }

// Statuses exposes Status for merge's statusUnion generic. Named
// Statuses rather than Status because Status is already a field on this
// struct. SourceRecord deliberately does NOT get this method: domain
// status merging applies an EPP-specific step that must not be shared
// (see mergeState.status in internal/merge/merge.go).
func (r IPSourceRecord) Statuses() []string { return r.Status }

// ASNSourceRecord is MergeASN's input shape -- one per source attempted,
// produced by internal/collect's ASN adapters.
type ASNSourceRecord struct {
	Meta           model.SourceResult
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
	Registered     model.TimeValue
	Updated        model.TimeValue
	RedactedFields map[string]bool
	Redactions     []model.RedactionNotice
}

// See SourceRecord's IsPresent/SourceID above for why these exist and why
// IsPresent is not called Present.
func (r ASNSourceRecord) IsPresent() bool          { return r.Present }
func (r ASNSourceRecord) SourceID() model.SourceID { return r.Meta.Source }

// See IPSourceRecord's Statuses above. SourceRecord deliberately does not
// get this method.
func (r ASNSourceRecord) Statuses() []string { return r.Status }
