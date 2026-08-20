package plat

import (
	"errors"
	"io"

	"github.com/patramsey/plat/internal/render/machine"
)

// SchemaVersion is the version of the JSON document EncodeJSON and
// EncodeNDJSON emit. It is the same schema the plat CLI's -o json produces,
// and the same number that appears in the output's "schemaVersion" field.
// A breaking change to the document's shape bumps it.
const SchemaVersion = machine.SchemaVersion

// EncodeOptions controls what the encoders include.
type EncodeOptions struct {
	// Raw includes each source's unparsed response payload, under
	// sources[].raw. It is off by default because the payloads are large
	// and most consumers want the merged record, not the wire data.
	Raw bool
}

// ErrNoRecord reports an attempt to encode a Result that carries no record.
// Lookup always populates one -- even when every source fails -- so this can
// only arise from a hand-built Result, and it is an error rather than a
// silent "null" so the mistake surfaces where it is made.
var ErrNoRecord = errors.New("plat: Result carries no record")

// EncodeJSON writes res as a schemaVersion 1 JSON document, the same bytes
// the plat CLI's -o json emits for the same record. It selects the encoder
// from res.Kind, so a caller never chooses between per-object-type
// encoders.
func EncodeJSON(w io.Writer, res Result, opts EncodeOptions) error {
	m := machine.Options{Raw: opts.Raw}
	switch {
	case res.Domain != nil:
		return machine.Encode(w, *res.Domain, m)
	case res.IP != nil:
		return machine.EncodeIP(w, *res.IP, m)
	case res.ASN != nil:
		return machine.EncodeASN(w, *res.ASN, m)
	}
	return ErrNoRecord
}

// EncodeNDJSON writes res as a single newline-delimited JSON record, the
// form the CLI's -o ndjson emits, for streaming many results into one
// stream.
func EncodeNDJSON(w io.Writer, res Result, opts EncodeOptions) error {
	m := machine.Options{Raw: opts.Raw}
	switch {
	case res.Domain != nil:
		return machine.EncodeNDJSON(w, *res.Domain, m)
	case res.IP != nil:
		return machine.EncodeIPNDJSON(w, *res.IP, m)
	case res.ASN != nil:
		return machine.EncodeASNNDJSON(w, *res.ASN, m)
	}
	return ErrNoRecord
}
