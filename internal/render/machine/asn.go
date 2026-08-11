package machine

import (
	"encoding/json"
	"io"

	"github.com/patramsey/plat/internal/model"
)

type asnRecordView struct {
	SchemaVersion int             `json:"schemaVersion"`
	ObjectType    string          `json:"objectType"`
	Handle        *fieldValue     `json:"handle,omitempty"`
	Name          *fieldValue     `json:"name,omitempty"`
	Type          *fieldValue     `json:"type,omitempty"`
	StartAutnum   *fieldValue     `json:"startAutnum,omitempty"`
	EndAutnum     *fieldValue     `json:"endAutnum,omitempty"`
	Country       *fieldValue     `json:"country,omitempty"`
	Org           *orgView        `json:"org,omitempty"`
	Status        *listFieldValue `json:"status,omitempty"`
	Registered    *timeFieldValue `json:"registered,omitempty"`
	Updated       *timeFieldValue `json:"updated,omitempty"`
	Conflicts     []conflictView  `json:"conflicts"`
	Redacted      []redactionView `json:"redacted"`
	Sources       []sourceView    `json:"sources"`
}

func buildASNView(r model.ASNRecord, opts Options) asnRecordView {
	v := asnRecordView{
		SchemaVersion: SchemaVersion,
		ObjectType:    "asn",
		Handle:        stringFieldView(r.Handle),
		Name:          stringFieldView(r.Name),
		Type:          stringFieldView(r.Type),
		StartAutnum:   stringFieldView(r.StartAutnum),
		EndAutnum:     stringFieldView(r.EndAutnum),
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

// EncodeASN writes r as a single compact JSON object followed by a
// newline — the ASN-record counterpart to Encode.
func EncodeASN(w io.Writer, r model.ASNRecord, opts Options) error {
	v := buildASNView(r, opts)
	enc := json.NewEncoder(w)
	return enc.Encode(v)
}

// EncodeASNNDJSON writes r as one compact JSON object followed by a
// newline — the shape used for -o ndjson multi-target output, one record
// per line. Mechanically identical to EncodeASN; kept as a separate name
// so call sites make the multi-target intent explicit.
func EncodeASNNDJSON(w io.Writer, r model.ASNRecord, opts Options) error {
	return EncodeASN(w, r, opts)
}
