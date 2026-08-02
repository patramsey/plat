package rdap

import (
	"encoding/json"
	"os"
	"testing"
)

// FuzzDomainResponseUnmarshal targets DomainResponse's JSON decode path,
// which runs on a malicious-server-controlled RDAP response (see
// SECURITY.md's "parser panics ... triggered by malformed or hostile
// server responses"). Lower risk than internal/whois/parse's hand-rolled
// text parser -- encoding/json never panics on malformed input, and
// StatusList/RDAPTime/EntityList/VCardArray's custom UnmarshalJSON
// implementations are already bounds-checked before every slice/array
// index -- but still worth the same regression coverage for symmetry and
// to catch any future change that breaks one of those bounds checks.
func FuzzDomainResponseUnmarshal(f *testing.F) {
	fixtures := []string{
		"com-example.json",
		"eu-gdpr-example.json",
		"expired-example.json",
		"idn-example.json",
		"org-thick-example.json",
		"registrar-example.json",
	}
	for _, name := range fixtures {
		b, err := os.ReadFile("../../testdata/rdap/" + name)
		if err != nil {
			f.Fatalf("reading fixture %s: %v", name, err)
		}
		f.Add(b)
	}
	f.Add([]byte(""))
	f.Add([]byte("null"))
	f.Add([]byte(`{"vcardArray": ["vcard", "not-an-array"]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var d DomainResponse
		_ = json.Unmarshal(data, &d)
	})
}
