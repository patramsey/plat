package machine

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/patramsey/plat/internal/model"
)

// Decode reads a single machine-output document -- the JSON one -o json
// invocation writes -- back into a comparable Snapshot. It is the read
// side of Encode, added for --diff.
//
// The view structs stay unexported deliberately: the JSON schema is the
// contract this package promises (see SchemaVersion), not the Go types
// that happen to produce it. Snapshot and Field are the whole exported
// surface, which keeps a future change to a view struct from being a
// breaking API change.
var (
	ErrUnsupportedSchema = errors.New("unsupported schemaVersion")
	ErrUnknownObjectType = errors.New("unknown objectType")
	ErrMultipleRecords   = errors.New("multiple records in input")
)

// Snapshot is a decoded machine-output document. Name carries the
// record's own identity -- domain name, CIDR, or AS handle -- so callers
// can reject a snapshot that does not match what they looked up.
type Snapshot struct {
	SchemaVersion int
	ObjectType    string
	Name          string

	domain *recordView
	ip     *ipRecordView
	asn    *asnRecordView
}

// Field is one comparable field, already reduced to the string form a
// diff reports. Key matches model.FieldSpec.Key and Label comes from the
// same field-order tables the human and plain renderers iterate, so a
// diff never invents a label those renderers would not use.
type Field struct {
	Key   string
	Label string
	Value string   // scalar fields
	List  []string // list-valued fields; nil for scalars
}

func Decode(r io.Reader) (Snapshot, error) {
	dec := json.NewDecoder(r)

	var probe struct {
		SchemaVersion int    `json:"schemaVersion"`
		ObjectType    string `json:"objectType"`
	}
	raw := json.RawMessage{}
	if err := dec.Decode(&raw); err != nil {
		return Snapshot{}, fmt.Errorf("reading snapshot: %w", err)
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return Snapshot{}, fmt.Errorf("reading snapshot: %w", err)
	}

	// A second document means an ndjson file. Reject rather than
	// silently diffing only the first record.
	if dec.More() {
		return Snapshot{}, ErrMultipleRecords
	}

	if probe.SchemaVersion != SchemaVersion {
		return Snapshot{}, fmt.Errorf("%w: %d (this plat understands %d)", ErrUnsupportedSchema, probe.SchemaVersion, SchemaVersion)
	}

	s := Snapshot{SchemaVersion: probe.SchemaVersion, ObjectType: probe.ObjectType}
	switch probe.ObjectType {
	case "domain":
		var v recordView
		if err := json.Unmarshal(raw, &v); err != nil {
			return Snapshot{}, fmt.Errorf("reading domain snapshot: %w", err)
		}
		s.domain = &v
		if v.Domain != nil {
			s.Name = v.Domain.Value
		}
	case "ip":
		var v ipRecordView
		if err := json.Unmarshal(raw, &v); err != nil {
			return Snapshot{}, fmt.Errorf("reading ip snapshot: %w", err)
		}
		s.ip = &v
		if v.CIDR != nil {
			s.Name = v.CIDR.Value
		} else if v.Handle != nil {
			s.Name = v.Handle.Value
		}
	case "asn":
		var v asnRecordView
		if err := json.Unmarshal(raw, &v); err != nil {
			return Snapshot{}, fmt.Errorf("reading asn snapshot: %w", err)
		}
		s.asn = &v
		if v.Handle != nil {
			s.Name = v.Handle.Value
		}
	default:
		return Snapshot{}, fmt.Errorf("%w: %q", ErrUnknownObjectType, probe.ObjectType)
	}
	return s, nil
}

// Fields flattens the snapshot into the canonical field order for its
// object type. Absent fields are omitted entirely -- a field appearing or
// disappearing between two snapshots is itself a reportable change, so
// emitting empty placeholders would erase that distinction.
func (s Snapshot) Fields() []Field {
	switch {
	case s.domain != nil:
		return domainFields(s.domain)
	case s.ip != nil:
		return ipFields(s.ip)
	case s.asn != nil:
		return asnFields(s.asn)
	}
	return nil
}

func scalar(f *fieldValue) (string, bool) {
	if f == nil {
		return "", false
	}
	return f.Value, true
}

// tstamp reads a timestamp field's comparable string form. Value is nil
// when the source's raw timestamp failed to parse (Parsed is false); the
// field is still present in that case, so it falls back to the raw string
// rather than being treated as absent -- matching how the human and plain
// renderers show "<raw> (unparsed)" instead of hiding the field.
func tstamp(f *timeFieldValue) (string, bool) {
	if f == nil {
		return "", false
	}
	if f.Value != nil {
		return *f.Value, true
	}
	return f.Raw, true
}

func domainFields(v *recordView) []Field {
	out := make([]Field, 0, len(model.FieldOrder))
	for _, fd := range model.FieldOrder {
		f := Field{Key: fd.Key, Label: fd.Label}
		switch fd.Key {
		case model.FieldDomain:
			if s, ok := scalar(v.Domain); ok {
				f.Value = s
			} else {
				continue
			}
		case model.FieldHandle:
			if s, ok := scalar(v.Handle); ok {
				f.Value = s
			} else {
				continue
			}
		case model.FieldRegistrarName:
			if v.Registrar == nil {
				continue
			}
			s, ok := scalar(v.Registrar.Name)
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldRegistrarIANAID:
			if v.Registrar == nil {
				continue
			}
			s, ok := scalar(v.Registrar.IANAID)
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldRegistrarURL:
			if v.Registrar == nil {
				continue
			}
			s, ok := scalar(v.Registrar.URL)
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldRegistrarAbuseEmail:
			if v.Registrar == nil {
				continue
			}
			s, ok := scalar(v.Registrar.AbuseEmail)
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldRegistrarAbusePhone:
			if v.Registrar == nil {
				continue
			}
			s, ok := scalar(v.Registrar.AbusePhone)
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldStatus:
			if v.Status == nil {
				continue
			}
			f.List = v.Status.Value
		case model.FieldCreated:
			if s, ok := tstamp(v.Created); ok {
				f.Value = s
			} else {
				continue
			}
		case model.FieldUpdated:
			if s, ok := tstamp(v.Updated); ok {
				f.Value = s
			} else {
				continue
			}
		case model.FieldExpires:
			if s, ok := tstamp(v.Expires); ok {
				f.Value = s
			} else {
				continue
			}
		case model.FieldNameservers:
			if v.Nameservers == nil {
				continue
			}
			f.List = v.Nameservers.Value
		case model.FieldDNSSEC:
			if v.DNSSEC == nil {
				continue
			}
			f.Value = strconv.FormatBool(v.DNSSEC.Value)
		default:
			panic(fmt.Sprintf("machine: unhandled model.FieldOrder entry %q", fd.Key))
		}
		out = append(out, f)
	}
	return out
}

// orgScalar reads one of the four org fields, tolerating a nil org block.
func orgScalar(o *orgView, pick func(*orgView) *fieldValue) (string, bool) {
	if o == nil {
		return "", false
	}
	return scalar(pick(o))
}

func ipFields(v *ipRecordView) []Field {
	out := make([]Field, 0, len(model.IPFieldOrder))
	for _, fd := range model.IPFieldOrder {
		f := Field{Key: fd.Key, Label: fd.Label}
		switch fd.Key {
		case model.FieldIPName:
			s, ok := scalar(v.Name)
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldIPHandle:
			s, ok := scalar(v.Handle)
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldIPStartAddress:
			// Labeled "Range": start and end combined, matching the
			// human and plain renderers.
			start, ok := scalar(v.StartAddress)
			if !ok {
				continue
			}
			if end, ok := scalar(v.EndAddress); ok {
				f.Value = start + " - " + end
			} else {
				f.Value = start
			}
		case model.FieldIPCIDR:
			s, ok := scalar(v.CIDR)
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldIPType:
			s, ok := scalar(v.Type)
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldIPVersion:
			s, ok := scalar(v.IPVersion)
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldIPParent:
			s, ok := scalar(v.ParentHandle)
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldOrgName:
			s, ok := orgScalar(v.Org, func(o *orgView) *fieldValue { return o.Name })
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldOrgID:
			s, ok := orgScalar(v.Org, func(o *orgView) *fieldValue { return o.ID })
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldIPCountry:
			s, ok := scalar(v.Country)
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldOrgAbuseEmail:
			s, ok := orgScalar(v.Org, func(o *orgView) *fieldValue { return o.AbuseEmail })
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldOrgAbusePhone:
			s, ok := orgScalar(v.Org, func(o *orgView) *fieldValue { return o.AbusePhone })
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldIPStatus:
			if v.Status == nil {
				continue
			}
			f.List = v.Status.Value
		case model.FieldIPRegistered:
			s, ok := tstamp(v.Registered)
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldIPUpdated:
			s, ok := tstamp(v.Updated)
			if !ok {
				continue
			}
			f.Value = s
		default:
			panic(fmt.Sprintf("machine: unhandled model.IPFieldOrder entry %q", fd.Key))
		}
		out = append(out, f)
	}
	return out
}

func asnFields(v *asnRecordView) []Field {
	out := make([]Field, 0, len(model.ASNFieldOrder))
	for _, fd := range model.ASNFieldOrder {
		f := Field{Key: fd.Key, Label: fd.Label}
		switch fd.Key {
		case model.FieldASNName:
			s, ok := scalar(v.Name)
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldASNHandle:
			s, ok := scalar(v.Handle)
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldASNStartAutnum:
			// Labeled "Range": start and end combined, matching the
			// human and plain renderers.
			start, ok := scalar(v.StartAutnum)
			if !ok {
				continue
			}
			if end, ok := scalar(v.EndAutnum); ok {
				f.Value = start + " - " + end
			} else {
				f.Value = start
			}
		case model.FieldASNType:
			s, ok := scalar(v.Type)
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldOrgName:
			s, ok := orgScalar(v.Org, func(o *orgView) *fieldValue { return o.Name })
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldOrgID:
			s, ok := orgScalar(v.Org, func(o *orgView) *fieldValue { return o.ID })
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldASNCountry:
			s, ok := scalar(v.Country)
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldOrgAbuseEmail:
			s, ok := orgScalar(v.Org, func(o *orgView) *fieldValue { return o.AbuseEmail })
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldOrgAbusePhone:
			s, ok := orgScalar(v.Org, func(o *orgView) *fieldValue { return o.AbusePhone })
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldASNStatus:
			if v.Status == nil {
				continue
			}
			f.List = v.Status.Value
		case model.FieldASNRegistered:
			s, ok := tstamp(v.Registered)
			if !ok {
				continue
			}
			f.Value = s
		case model.FieldASNUpdated:
			s, ok := tstamp(v.Updated)
			if !ok {
				continue
			}
			f.Value = s
		default:
			panic(fmt.Sprintf("machine: unhandled model.ASNFieldOrder entry %q", fd.Key))
		}
		out = append(out, f)
	}
	return out
}
