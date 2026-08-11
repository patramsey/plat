package rdap

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// DomainResponse is a trimmed RFC 9083 domain object view. Entities/jCard
// (registrar name, contacts) parsing is deferred to the merge-engine
// milestone.
type DomainResponse struct {
	ObjectClassName string       `json:"objectClassName"`
	LDHName         string       `json:"ldhName"`
	UnicodeName     string       `json:"unicodeName"`
	Handle          string       `json:"handle"`
	Status          StatusList   `json:"status"`
	Events          []Event      `json:"events"`
	Nameservers     []Nameserver `json:"nameservers"`
	Links           LinkList     `json:"links"`
	Entities        EntityList   `json:"entities"`
	Remarks         RemarkList   `json:"remarks"`
	// Port43 is RFC 9083's optional pointer to the legacy port-43 WHOIS
	// server for this object, if the server publishes one. Most registry
	// RDAP responses leave this null; some registrar RDAP responses (e.g.
	// Name.com's) populate it even when the registry's own WHOIS doesn't
	// run for the TLD at all — see internal/collect's registrar-WHOIS
	// port43 fallback.
	Port43 string `json:"port43"`
}

// Event is a single RDAP domain lifecycle event.
type Event struct {
	Action string   `json:"eventAction"`
	Date   RDAPTime `json:"eventDate"`
}

// Nameserver is a trimmed RFC 9083 nameserver object view.
type Nameserver struct {
	LDHName     string `json:"ldhName"`
	UnicodeName string `json:"unicodeName"`
}

// StatusList tolerates RDAP status being either a JSON array of strings
// (per RFC 9083) or, on some non-conformant servers, a bare string. It
// never fails to unmarshal — a malformed value just degrades to empty
// rather than aborting the whole document's decode.
type StatusList []string

func (s *StatusList) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" {
		*s = nil
		return nil
	}
	if trimmed[0] == '[' {
		var list []string
		if err := json.Unmarshal(b, &list); err != nil {
			*s = nil
			return nil
		}
		*s = list
		return nil
	}
	var single string
	if err := json.Unmarshal(b, &single); err != nil {
		*s = nil
		return nil
	}
	*s = StatusList{single}
	return nil
}

// RDAPTime tolerates real-world event-date variance. Raw always holds the
// original string; Time/Parsed are only meaningful when Parsed is true.
// Unmarshal never fails on a bad date — that would abort parsing of an
// otherwise-good document over one cosmetic field.
type RDAPTime struct {
	Raw    string
	Time   time.Time
	Parsed bool
}

var rdapTimeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05Z07:00",
	"2006-01-02 15:04:05",
	"2006-01-02",
}

func (t *RDAPTime) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		t.Raw = strings.Trim(string(b), `"`)
		t.Parsed = false
		return nil
	}
	t.Raw = s
	for _, layout := range rdapTimeLayouts {
		if ts, err := time.Parse(layout, s); err == nil {
			t.Time = ts.UTC()
			t.Parsed = true
			return nil
		}
	}
	t.Parsed = false
	return nil
}

type eventSlot int

const (
	slotUnknown eventSlot = iota
	slotCreated
	slotUpdated
	slotExpires
)

// normalizeEventAction maps an RDAP eventAction string to a known slot
// using an open-set synonym lookup, not a closed switch on exact RFC 9083
// strings — real registries use variants RFC 9083 doesn't enumerate.
// Unrecognized actions map to slotUnknown; the event is still retained in
// DomainResponse.Events, just not surfaced by the named accessors.
//
// "soft expiration" (.is) and "record expires" (.kg) were found via a live
// 2433-domain audit and confirmed live to each be the only expiration-
// related event on their record (not a distinct, separate concept sitting
// alongside a differently-named "real" expiration -- the same live audit
// found and deliberately excluded one such case on the WHOIS side, .ru's
// "free-date", which is a later, genuinely different post-grace-period
// deletion date, not a synonym for expires).
func normalizeEventAction(a string) eventSlot {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case "registration", "registered", "created", "creation":
		return slotCreated
	case "last changed", "last update", "last updated", "updated", "modification":
		return slotUpdated
	case "expiration", "expires", "expiry", "registrar expiration", "registry expiration",
		"soft expiration", "record expires":
		return slotExpires
	default:
		return slotUnknown
	}
}

func (d *DomainResponse) eventBySlot(slot eventSlot) (RDAPTime, bool) {
	for _, e := range d.Events {
		if normalizeEventAction(e.Action) == slot {
			return e.Date, true
		}
	}
	return RDAPTime{}, false
}

// Created returns the registration event's date, if present.
func (d *DomainResponse) Created() (RDAPTime, bool) { return d.eventBySlot(slotCreated) }

// Updated returns the last-changed event's date, if present.
func (d *DomainResponse) Updated() (RDAPTime, bool) { return d.eventBySlot(slotUpdated) }

// Expires returns the expiration event's date, if present.
func (d *DomainResponse) Expires() (RDAPTime, bool) { return d.eventBySlot(slotExpires) }

// Link is a trimmed RFC 9083 link object.
type Link struct {
	Value string `json:"value"`
	Rel   string `json:"rel"`
	Href  string `json:"href"`
	Type  string `json:"type"`
}

// LinkList tolerates the "links" array being malformed (missing, wrong
// shape, or containing non-object entries) — it degrades to an empty list
// rather than aborting the whole document's decode, matching StatusList's
// philosophy.
type LinkList []Link

func (l *LinkList) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" {
		*l = nil
		return nil
	}
	var links []Link
	if err := json.Unmarshal(b, &links); err != nil {
		*l = nil
		return nil
	}
	*l = links
	return nil
}

// RelatedRegistrarURL returns the href of the first "related" link,
// preferring one whose type is application/rdap+json but falling back to
// any related link if none match. Returns false if no related link exists.
func (d *DomainResponse) RelatedRegistrarURL() (string, bool) {
	var fallback string
	haveFallback := false
	for _, link := range d.Links {
		if !strings.EqualFold(link.Rel, "related") {
			continue
		}
		if strings.EqualFold(link.Type, "application/rdap+json") {
			return link.Href, true
		}
		if !haveFallback {
			fallback = link.Href
			haveFallback = true
		}
	}
	if haveFallback {
		return fallback, true
	}
	return "", false
}

// Entity is a trimmed RFC 9083 entity object — only the fields needed to
// extract a registrar's or abuse contact's identity from its vCard.
// Registrant/admin/tech/billing contact values are deliberately not
// modeled — see the "Redaction and contacts" section of README.md.
type Entity struct {
	Roles      []string   `json:"roles"`
	VCardArray VCardArray `json:"vcardArray"`
}

// EntityList tolerates the "entities" array being malformed, mirroring
// LinkList's philosophy — degrade to empty rather than aborting the
// decode.
type EntityList []Entity

func (e *EntityList) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" {
		*e = nil
		return nil
	}
	var list []Entity
	if err := json.Unmarshal(b, &list); err != nil {
		*e = nil
		return nil
	}
	*e = list
	return nil
}

// VCardArray tolerates RFC 7095's jCard shape: a 2-element array where
// element 0 is the literal "vcard" and element 1 is an array of property
// arrays ([name, params, valueType, value, ...]). It extracts only "fn"
// (full name), "email", and "tel" — everything else in the vCard (the
// "genuinely unpleasant" bulk of RFC 7095) is deliberately ignored. Any
// deviation from the expected shape — missing elements, wrong types, an
// absent jCard entirely — degrades to an empty extraction rather than
// erroring; jCard is not worth hard-failing a whole document decode over.
type VCardArray struct {
	FullName string
	Email    string
	Tel      string
}

func (v *VCardArray) UnmarshalJSON(b []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil || len(raw) != 2 {
		return nil
	}
	var props []json.RawMessage
	if err := json.Unmarshal(raw[1], &props); err != nil {
		return nil
	}
	for _, p := range props {
		var prop []json.RawMessage
		if err := json.Unmarshal(p, &prop); err != nil || len(prop) < 4 {
			continue
		}
		var name string
		if err := json.Unmarshal(prop[0], &name); err != nil {
			continue
		}
		var value string
		if err := json.Unmarshal(prop[3], &value); err != nil {
			continue // non-string value (e.g. a structured "n" property) — skip it
		}
		switch strings.ToLower(name) {
		case "fn":
			v.FullName = value
		case "email":
			v.Email = value
		case "tel":
			v.Tel = value
		}
	}
	return nil
}

// RegistrarEntity returns the first entity whose Roles includes
// "registrar" (case-insensitive), if any.
func (d *DomainResponse) RegistrarEntity() (Entity, bool) {
	return d.entityByRole("registrar")
}

// AbuseEntity returns the first entity whose Roles includes "abuse". Per
// RDAP convention this may be nested under the registrar entity in some
// implementations; M3 only looks at top-level entities, since abuse
// contact info is frequently duplicated there too — nested traversal is
// left for a later milestone.
func (d *DomainResponse) AbuseEntity() (Entity, bool) {
	return d.entityByRole("abuse")
}

func (d *DomainResponse) entityByRole(role string) (Entity, bool) {
	for _, e := range d.Entities {
		for _, r := range e.Roles {
			if strings.EqualFold(r, role) {
				return e, true
			}
		}
	}
	return Entity{}, false
}

// Remark is a trimmed RFC 9083 remark/notice object.
type Remark struct {
	Title       string   `json:"title"`
	Type        string   `json:"type"`
	Description []string `json:"description"`
}

// RemarkList tolerates the "remarks" array being malformed, mirroring
// LinkList's philosophy.
type RemarkList []Remark

func (r *RemarkList) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" {
		*r = nil
		return nil
	}
	var list []Remark
	if err := json.Unmarshal(b, &list); err != nil {
		*r = nil
		return nil
	}
	*r = list
	return nil
}

// RedactionRemarks returns remarks whose title or type suggests redacted
// data — a shallow, informational signal, not a full RFC 9537 evaluation
// (which is deferred to a later milestone).
func (d *DomainResponse) RedactionRemarks() []Remark {
	var out []Remark
	for _, r := range d.Remarks {
		lt := strings.ToLower(r.Title)
		ly := strings.ToLower(r.Type)
		if strings.Contains(lt, "redact") || strings.Contains(lt, "privacy") ||
			strings.Contains(ly, "redact") || strings.Contains(ly, "privacy") {
			out = append(out, r)
		}
	}
	return out
}

// CIDR0 is an RFC 9083 cidr0 extension entry: the CIDR form of an IP
// network's range. Exactly one of V4Prefix/V6Prefix is populated.
type CIDR0 struct {
	V4Prefix string `json:"v4prefix"`
	V6Prefix string `json:"v6prefix"`
	Length   int    `json:"length"`
}

// Prefix renders the entry as standard CIDR notation ("8.8.8.0/24"),
// or "" if neither prefix field was populated.
func (c CIDR0) Prefix() string {
	switch {
	case c.V4Prefix != "":
		return fmt.Sprintf("%s/%d", c.V4Prefix, c.Length)
	case c.V6Prefix != "":
		return fmt.Sprintf("%s/%d", c.V6Prefix, c.Length)
	default:
		return ""
	}
}

// IPNetworkResponse is a trimmed RFC 9083 "ip network" object view. Note
// what is absent relative to DomainResponse: no expiry, no registrar, no
// nameservers, no DNSSEC -- IP allocations have none of those.
type IPNetworkResponse struct {
	ObjectClassName string     `json:"objectClassName"`
	Handle          string     `json:"handle"`
	StartAddress    string     `json:"startAddress"`
	EndAddress      string     `json:"endAddress"`
	IPVersion       string     `json:"ipVersion"`
	Name            string     `json:"name"`
	Type            string     `json:"type"`
	Country         string     `json:"country"`
	ParentHandle    string     `json:"parentHandle"`
	Status          StatusList `json:"status"`
	CIDR0CIDRs      []CIDR0    `json:"cidr0_cidrs"`
	Events          []Event    `json:"events"`
	Entities        EntityList `json:"entities"`
	Remarks         RemarkList `json:"remarks"`
	Port43          string     `json:"port43"`
}

// entityByRole mirrors DomainResponse.entityByRole -- kept as a separate
// method rather than refactored into a shared free function alongside it,
// since the domain path must stay untouched (see the domainAt/ipAt
// precedent from the bootstrap package).
func (n *IPNetworkResponse) entityByRole(role string) (Entity, bool) {
	for _, e := range n.Entities {
		for _, r := range e.Roles {
			if strings.EqualFold(r, role) {
				return e, true
			}
		}
	}
	return Entity{}, false
}

// RegistrantEntity returns the first entity whose Roles includes
// "registrant" (case-insensitive), if any. An IP network's "registrant"
// entity is its owning organization -- e.g. ARIN's response for 8.8.8.8
// carries an entity with handle "GOGL" and roles ["registrant"].
func (n *IPNetworkResponse) RegistrantEntity() (Entity, bool) {
	return n.entityByRole("registrant")
}

// AbuseEntity returns the first entity whose Roles includes "abuse", if
// any. Mirrors DomainResponse.AbuseEntity.
func (n *IPNetworkResponse) AbuseEntity() (Entity, bool) {
	return n.entityByRole("abuse")
}

// eventBySlot mirrors DomainResponse.eventBySlot.
func (n *IPNetworkResponse) eventBySlot(slot eventSlot) (RDAPTime, bool) {
	for _, e := range n.Events {
		if normalizeEventAction(e.Action) == slot {
			return e.Date, true
		}
	}
	return RDAPTime{}, false
}

// Registered returns the registration event's date, if present. Mirrors
// DomainResponse.Created -- named Registered rather than Created since an
// IP allocation is "registered" with a RIR, not "created" the way a
// domain is.
func (n *IPNetworkResponse) Registered() (RDAPTime, bool) { return n.eventBySlot(slotCreated) }

// Updated returns the last-changed event's date, if present. Mirrors
// DomainResponse.Updated.
func (n *IPNetworkResponse) Updated() (RDAPTime, bool) { return n.eventBySlot(slotUpdated) }

// ASNResponse is a trimmed RFC 9083 "autnum" object view. Like
// IPNetworkResponse, it has no expiry, registrar, nameservers, or DNSSEC.
type ASNResponse struct {
	ObjectClassName string     `json:"objectClassName"`
	Handle          string     `json:"handle"`
	StartAutnum     uint32     `json:"startAutnum"`
	EndAutnum       uint32     `json:"endAutnum"`
	Name            string     `json:"name"`
	Type            string     `json:"type"`
	Country         string     `json:"country"`
	Status          StatusList `json:"status"`
	Events          []Event    `json:"events"`
	Entities        EntityList `json:"entities"`
	Remarks         RemarkList `json:"remarks"`
	Port43          string     `json:"port43"`
}

// entityByRole mirrors DomainResponse.entityByRole -- kept as a separate
// method rather than refactored into a shared free function alongside it,
// since the domain and IP paths must stay untouched (see the
// domainAt/ipAt precedent from the bootstrap package).
func (a *ASNResponse) entityByRole(role string) (Entity, bool) {
	for _, e := range a.Entities {
		for _, r := range e.Roles {
			if strings.EqualFold(r, role) {
				return e, true
			}
		}
	}
	return Entity{}, false
}

// RegistrantEntity returns the first entity whose Roles includes
// "registrant" (case-insensitive), if any. Mirrors
// IPNetworkResponse.RegistrantEntity.
func (a *ASNResponse) RegistrantEntity() (Entity, bool) {
	return a.entityByRole("registrant")
}

// AbuseEntity returns the first entity whose Roles includes "abuse", if
// any. Mirrors DomainResponse.AbuseEntity.
func (a *ASNResponse) AbuseEntity() (Entity, bool) {
	return a.entityByRole("abuse")
}

// eventBySlot mirrors DomainResponse.eventBySlot.
func (a *ASNResponse) eventBySlot(slot eventSlot) (RDAPTime, bool) {
	for _, e := range a.Events {
		if normalizeEventAction(e.Action) == slot {
			return e.Date, true
		}
	}
	return RDAPTime{}, false
}

// Registered returns the registration event's date, if present. Mirrors
// IPNetworkResponse.Registered -- named Registered rather than Created
// since an ASN is "registered" with a RIR, not "created" the way a domain
// is.
func (a *ASNResponse) Registered() (RDAPTime, bool) { return a.eventBySlot(slotCreated) }

// Updated returns the last-changed event's date, if present. Mirrors
// DomainResponse.Updated.
func (a *ASNResponse) Updated() (RDAPTime, bool) { return a.eventBySlot(slotUpdated) }

// RedactionRemarks returns remarks whose title or type suggests redacted
// data. Mirrors DomainResponse.RedactionRemarks -- same shallow,
// informational signal, not a full RFC 9537 evaluation.
func (a *ASNResponse) RedactionRemarks() []Remark {
	var out []Remark
	for _, r := range a.Remarks {
		lt := strings.ToLower(r.Title)
		ly := strings.ToLower(r.Type)
		if strings.Contains(lt, "redact") || strings.Contains(lt, "privacy") ||
			strings.Contains(ly, "redact") || strings.Contains(ly, "privacy") {
			out = append(out, r)
		}
	}
	return out
}
