package machine

import (
	"encoding/json"
	"io"

	"github.com/patramsey/plat/internal/model"
)

type orgView struct {
	Name       *fieldValue `json:"name,omitempty"`
	ID         *fieldValue `json:"id,omitempty"`
	AbuseEmail *fieldValue `json:"abuseEmail,omitempty"`
	AbusePhone *fieldValue `json:"abusePhone,omitempty"`
}

type ipRecordView struct {
	SchemaVersion int             `json:"schemaVersion"`
	ObjectType    string          `json:"objectType"`
	Handle        *fieldValue     `json:"handle,omitempty"`
	Name          *fieldValue     `json:"name,omitempty"`
	Type          *fieldValue     `json:"type,omitempty"`
	StartAddress  *fieldValue     `json:"startAddress,omitempty"`
	EndAddress    *fieldValue     `json:"endAddress,omitempty"`
	CIDR          *fieldValue     `json:"cidr,omitempty"`
	IPVersion     *fieldValue     `json:"ipVersion,omitempty"`
	ParentHandle  *fieldValue     `json:"parentHandle,omitempty"`
	Country       *fieldValue     `json:"country,omitempty"`
	Org           *orgView        `json:"org,omitempty"`
	Status        *listFieldValue `json:"status,omitempty"`
	Registered    *timeFieldValue `json:"registered,omitempty"`
	Updated       *timeFieldValue `json:"updated,omitempty"`
	Conflicts     []conflictView  `json:"conflicts"`
	Redacted      []redactionView `json:"redacted"`
	Sources       []sourceView    `json:"sources"`
}

func buildOrgView(o model.OrgInfo) *orgView {
	name := stringFieldView(o.Name)
	id := stringFieldView(o.ID)
	abuseEmail := stringFieldView(o.AbuseEmail)
	abusePhone := stringFieldView(o.AbusePhone)
	if name == nil && id == nil && abuseEmail == nil && abusePhone == nil {
		return nil
	}
	return &orgView{Name: name, ID: id, AbuseEmail: abuseEmail, AbusePhone: abusePhone}
}

func buildIPView(r model.IPRecord, opts Options) ipRecordView {
	v := ipRecordView{
		SchemaVersion: SchemaVersion,
		ObjectType:    "ip",
		Handle:        stringFieldView(r.Handle),
		Name:          stringFieldView(r.Name),
		Type:          stringFieldView(r.Type),
		StartAddress:  stringFieldView(r.StartAddress),
		EndAddress:    stringFieldView(r.EndAddress),
		CIDR:          stringFieldView(r.CIDR),
		IPVersion:     stringFieldView(r.IPVersion),
		ParentHandle:  stringFieldView(r.ParentHandle),
		Country:       stringFieldView(r.Country),
		Org:           buildOrgView(r.Org),
		Status:        listFieldView(r.Status),
		Registered:    timeFieldView(r.Registered),
		Updated:       timeFieldView(r.Updated),
		Conflicts:     []conflictView{},
		Redacted:      []redactionView{},
		Sources:       []sourceView{},
	}
	for _, c := range r.Conflicts {
		values := make(map[string]string, len(c.Values))
		for src, val := range c.Values {
			values[string(src)] = val
		}
		v.Conflicts = append(v.Conflicts, conflictView{Field: c.Field, Values: values})
	}
	for _, red := range r.Redacted {
		v.Redacted = append(v.Redacted, redactionView{Field: red.Field, Source: string(red.Source), Reason: red.Reason})
	}
	for _, s := range r.Sources {
		sv := sourceView{
			Source:    string(s.Source),
			OK:        s.OK,
			NotFound:  s.NotFound,
			LatencyMs: s.Latency.Milliseconds(),
			Error:     s.Err,
		}
		if opts.Raw && len(s.Raw) > 0 {
			if json.Valid(s.Raw) {
				sv.Raw = json.RawMessage(s.Raw)
			} else if encoded, err := json.Marshal(string(s.Raw)); err == nil {
				sv.Raw = json.RawMessage(encoded)
			}
		}
		v.Sources = append(v.Sources, sv)
	}
	return v
}

// EncodeIP writes r as a single compact JSON object followed by a
// newline — the IP-record counterpart to Encode.
func EncodeIP(w io.Writer, r model.IPRecord, opts Options) error {
	v := buildIPView(r, opts)
	enc := json.NewEncoder(w)
	return enc.Encode(v)
}

// EncodeIPNDJSON writes r as one compact JSON object followed by a
// newline — the shape used for -o ndjson multi-target output, one record
// per line. Mechanically identical to EncodeIP; kept as a separate name
// so call sites make the multi-target intent explicit.
func EncodeIPNDJSON(w io.Writer, r model.IPRecord, opts Options) error {
	return EncodeIP(w, r, opts)
}
