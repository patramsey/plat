package plat

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/patramsey/plat/internal/render/machine"
)

// sampleResults builds one Result per Kind, by hand rather than by lookup,
// so these tests need no servers at all.
func sampleResults(t *testing.T) map[Kind]Result {
	t.Helper()
	dom := Record{Domain: Field[string]{Value: "example.com"}}
	ip := IPRecord{Handle: Field[string]{Value: "NET-192-0-2-0-1"}}
	asn := ASNRecord{Handle: Field[string]{Value: "AS64496"}}
	return map[Kind]Result{
		KindDomain: {Kind: KindDomain, Input: "example.com", Domain: &dom},
		KindIP:     {Kind: KindIP, Input: "192.0.2.7", IP: &ip},
		KindASN:    {Kind: KindASN, Input: "AS64496", ASN: &asn},
	}
}

// TestEncodeJSON_MatchesTheCLIByteForByte is the test that matters: both
// the CLI and the library claim to emit schemaVersion 1, so the library's
// bytes must be the CLI's bytes, not a second implementation that merely
// looks similar.
func TestEncodeJSON_MatchesTheCLIByteForByte(t *testing.T) {
	res := sampleResults(t)

	cases := []struct {
		kind Kind
		want func(w *bytes.Buffer) error
	}{
		{KindDomain, func(w *bytes.Buffer) error {
			return machine.Encode(w, *res[KindDomain].Domain, machine.Options{})
		}},
		{KindIP, func(w *bytes.Buffer) error {
			return machine.EncodeIP(w, *res[KindIP].IP, machine.Options{})
		}},
		{KindASN, func(w *bytes.Buffer) error {
			return machine.EncodeASN(w, *res[KindASN].ASN, machine.Options{})
		}},
	}

	for _, tc := range cases {
		t.Run(tc.kind.String(), func(t *testing.T) {
			var got, want bytes.Buffer
			if err := EncodeJSON(&got, res[tc.kind], EncodeOptions{}); err != nil {
				t.Fatalf("EncodeJSON: %v", err)
			}
			if err := tc.want(&want); err != nil {
				t.Fatalf("machine encode: %v", err)
			}
			if got.String() != want.String() {
				t.Errorf("EncodeJSON output differs from the CLI's.\ngot:  %s\nwant: %s", got.String(), want.String())
			}
		})
	}
}

// TestEncodeJSON_DispatchesOnKind fails if the dispatcher always used the
// domain encoder: an IP record encoded as a domain would carry
// "objectType":"domain".
func TestEncodeJSON_DispatchesOnKind(t *testing.T) {
	res := sampleResults(t)
	for kind, want := range map[Kind]string{
		KindDomain: `"objectType":"domain"`,
		KindIP:     `"objectType":"ip"`,
		KindASN:    `"objectType":"asn"`,
	} {
		var buf bytes.Buffer
		if err := EncodeJSON(&buf, res[kind], EncodeOptions{}); err != nil {
			t.Fatalf("EncodeJSON(%v): %v", kind, err)
		}
		if !strings.Contains(strings.ReplaceAll(buf.String(), " ", ""), want) {
			t.Errorf("%v encoded without %s:\n%s", kind, want, buf.String())
		}
	}
}

func TestEncodeNDJSON_MatchesTheCLI(t *testing.T) {
	res := sampleResults(t)
	var got, want bytes.Buffer
	if err := EncodeNDJSON(&got, res[KindDomain], EncodeOptions{}); err != nil {
		t.Fatalf("EncodeNDJSON: %v", err)
	}
	if err := machine.EncodeNDJSON(&want, *res[KindDomain].Domain, machine.Options{}); err != nil {
		t.Fatalf("machine.EncodeNDJSON: %v", err)
	}
	if got.String() != want.String() {
		t.Errorf("EncodeNDJSON differs.\ngot:  %q\nwant: %q", got.String(), want.String())
	}
}

func TestEncodeJSON_ZeroResultErrors(t *testing.T) {
	var buf bytes.Buffer
	if err := EncodeJSON(&buf, Result{}, EncodeOptions{}); err == nil {
		t.Fatalf("encoding a zero Result returned nil error and wrote %q", buf.String())
	}
}

// TestSchemaVersionMatchesTheEmittedDocument compares the constant against
// what the encoder actually writes. Comparing it to machine.SchemaVersion
// instead would be a tautology -- SchemaVersion is DEFINED as that constant,
// so such a test could never fail and would guard nothing.
func TestSchemaVersionMatchesTheEmittedDocument(t *testing.T) {
	res := sampleResults(t)
	var buf bytes.Buffer
	if err := EncodeJSON(&buf, res[KindDomain], EncodeOptions{}); err != nil {
		t.Fatalf("EncodeJSON: %v", err)
	}
	want := fmt.Sprintf(`"schemaVersion":%d`, SchemaVersion)
	if !strings.Contains(strings.ReplaceAll(buf.String(), " ", ""), want) {
		t.Errorf("emitted document does not carry %s:\n%s", want, buf.String())
	}
}

func TestEncodeJSON_RawIsForwarded(t *testing.T) {
	rec := Record{
		Domain:  Field[string]{Value: "example.com"},
		Sources: []SourceResult{{Source: SourceRegistryRDAP, OK: true, Raw: []byte(`{"x":1}`)}},
	}
	res := Result{Kind: KindDomain, Input: "example.com", Domain: &rec}

	var with, without bytes.Buffer
	if err := EncodeJSON(&with, res, EncodeOptions{Raw: true}); err != nil {
		t.Fatalf("EncodeJSON(Raw): %v", err)
	}
	if err := EncodeJSON(&without, res, EncodeOptions{}); err != nil {
		t.Fatalf("EncodeJSON: %v", err)
	}
	if with.String() == without.String() {
		t.Fatal("Raw:true produced identical output to Raw:false; the option is not forwarded")
	}
	if !strings.Contains(with.String(), `"x"`) {
		t.Errorf("Raw:true output does not contain the raw payload:\n%s", with.String())
	}
}
