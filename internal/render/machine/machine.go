// Package machine encodes a model.Record as the stable JSON/NDJSON wire
// format described in docs/schema.md. The wire shapes here are a
// deliberately separate view-model from model.Record's Go-internal
// shapes (Field[T]'s generic {Value,Sources}, TimeValue's raw
// {Time,Raw,Parsed}) — this package owns the public API contract, and a
// breaking change to any shape below must bump SchemaVersion.
package machine

import (
	"encoding/json"
	"io"
	"time"

	"github.com/patramsey/plat/internal/model"
)

// SchemaVersion is the current machine-output schema version.
const SchemaVersion = 1

// Options controls what Encode/EncodeNDJSON include.
type Options struct {
	// Raw includes each source's raw response payload (sources[].raw).
	Raw bool
}

type fieldValue struct {
	Value   string   `json:"value"`
	Sources []string `json:"sources"`
}

type listFieldValue struct {
	Value   []string `json:"value"`
	Sources []string `json:"sources"`
}

type boolFieldValue struct {
	Value   bool     `json:"value"`
	Sources []string `json:"sources"`
}

type timeFieldValue struct {
	Value   *string  `json:"value"`
	Raw     string   `json:"raw"`
	Parsed  bool     `json:"parsed"`
	Sources []string `json:"sources"`
}

type registrarView struct {
	Name       *fieldValue `json:"name,omitempty"`
	IANAID     *fieldValue `json:"ianaId,omitempty"`
	URL        *fieldValue `json:"url,omitempty"`
	AbuseEmail *fieldValue `json:"abuseEmail,omitempty"`
	AbusePhone *fieldValue `json:"abusePhone,omitempty"`
}

type conflictView struct {
	Field  string            `json:"field"`
	Values map[string]string `json:"values"`
}

type redactionView struct {
	Field  string `json:"field"`
	Source string `json:"source"`
	Reason string `json:"reason"`
}

type sourceView struct {
	Source    string          `json:"source"`
	OK        bool            `json:"ok"`
	NotFound  bool            `json:"notFound"`
	LatencyMs int64           `json:"latencyMs"`
	Error     string          `json:"error,omitempty"`
	Raw       json.RawMessage `json:"raw,omitempty"`
}

type recordView struct {
	SchemaVersion int             `json:"schemaVersion"`
	Domain        *fieldValue     `json:"domain,omitempty"`
	Handle        *fieldValue     `json:"handle,omitempty"`
	Registrar     *registrarView  `json:"registrar,omitempty"`
	Status        *listFieldValue `json:"status,omitempty"`
	Created       *timeFieldValue `json:"created,omitempty"`
	Updated       *timeFieldValue `json:"updated,omitempty"`
	Expires       *timeFieldValue `json:"expires,omitempty"`
	Nameservers   *listFieldValue `json:"nameservers,omitempty"`
	DNSSEC        *boolFieldValue `json:"dnssec,omitempty"`
	Conflicts     []conflictView  `json:"conflicts"`
	Redacted      []redactionView `json:"redacted"`
	Sources       []sourceView    `json:"sources"`
}

func sourceIDs(ids []model.SourceID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}

func stringFieldView(f model.Field[string]) *fieldValue {
	if !f.Present() {
		return nil
	}
	return &fieldValue{Value: f.Value, Sources: sourceIDs(f.Sources)}
}

func listFieldView(f model.Field[[]string]) *listFieldValue {
	// Deliberately not f.Present(): a genuine merge conflict (see
	// internal/merge's nameservers()) can leave Sources empty while Value
	// stays populated with the merged union -- the key must still appear
	// in JSON, just with an empty sources array.
	if len(f.Value) == 0 {
		return nil
	}
	val := f.Value
	if val == nil {
		val = []string{}
	}
	return &listFieldValue{Value: val, Sources: sourceIDs(f.Sources)}
}

func boolFieldView(f model.Field[bool]) *boolFieldValue {
	if !f.Present() {
		return nil
	}
	return &boolFieldValue{Value: f.Value, Sources: sourceIDs(f.Sources)}
}

func timeFieldView(f model.Field[model.TimeValue]) *timeFieldValue {
	if !f.Present() {
		return nil
	}
	tv := &timeFieldValue{Raw: f.Value.Raw, Parsed: f.Value.Parsed, Sources: sourceIDs(f.Sources)}
	if f.Value.Parsed {
		s := f.Value.Time.UTC().Format(time.RFC3339)
		tv.Value = &s
	}
	return tv
}

func buildRegistrarView(r model.RegistrarInfo) *registrarView {
	name := stringFieldView(r.Name)
	ianaID := stringFieldView(r.IANAID)
	url := stringFieldView(r.URL)
	abuseEmail := stringFieldView(r.AbuseEmail)
	abusePhone := stringFieldView(r.AbusePhone)
	if name == nil && ianaID == nil && url == nil && abuseEmail == nil && abusePhone == nil {
		return nil
	}
	return &registrarView{Name: name, IANAID: ianaID, URL: url, AbuseEmail: abuseEmail, AbusePhone: abusePhone}
}

func buildView(r model.Record, opts Options) recordView {
	v := recordView{
		SchemaVersion: SchemaVersion,
		Domain:        stringFieldView(r.Domain),
		Handle:        stringFieldView(r.Handle),
		Registrar:     buildRegistrarView(r.Registrar),
		Status:        listFieldView(r.Status),
		Created:       timeFieldView(r.Created),
		Updated:       timeFieldView(r.Updated),
		Expires:       timeFieldView(r.Expires),
		Nameservers:   listFieldView(r.Nameservers),
		DNSSEC:        boolFieldView(r.DNSSEC),
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

// Encode writes r as a single compact JSON object followed by a newline.
func Encode(w io.Writer, r model.Record, opts Options) error {
	v := buildView(r, opts)
	enc := json.NewEncoder(w)
	return enc.Encode(v)
}

// EncodeNDJSON writes r as one compact JSON object followed by a newline
// — the shape used for -o ndjson multi-domain output, one record per
// line. Mechanically identical to Encode; kept as a separate name so
// call sites make the multi-domain intent explicit.
func EncodeNDJSON(w io.Writer, r model.Record, opts Options) error {
	return Encode(w, r, opts)
}

// EncodeError writes a machine-mode error object to w:
// {"error": "...", "domain": "..."}. Used for stderr so stdout stays
// schema-clean even when a lookup fails in machine mode.
func EncodeError(w io.Writer, domainName string, err error) error {
	enc := json.NewEncoder(w)
	return enc.Encode(struct {
		Error  string `json:"error"`
		Domain string `json:"domain"`
	}{Error: err.Error(), Domain: domainName})
}
