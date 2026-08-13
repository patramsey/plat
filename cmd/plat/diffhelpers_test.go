package main

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/patramsey/plat/internal/domain"
	"github.com/patramsey/plat/internal/model"
	"github.com/patramsey/plat/internal/render"
	"github.com/patramsey/plat/internal/render/machine"
)

// TestArticle tables over article's four object-type inputs -- a pure
// function, so this pins its indefinite-article choice directly rather
// than only exercising it indirectly through a loadSnapshot mismatch
// message.
func TestArticle(t *testing.T) {
	tests := []struct {
		objectType string
		want       string
	}{
		{"ip", "an"},
		{"asn", "an"},
		{"domain", "a"},
		{"nameserver", "a"}, // anything outside {ip, asn} falls to the default branch
	}
	for _, tt := range tests {
		t.Run(tt.objectType, func(t *testing.T) {
			if got := article(tt.objectType); got != tt.want {
				t.Errorf("article(%q) = %q, want %q", tt.objectType, got, tt.want)
			}
		})
	}
}

// TestLoadSnapshot_Rejections covers loadSnapshot's guardrail branches
// that TestDiff_RejectsNameMismatch/TestDiff_RejectsNdjson (main_test.go,
// driven through run()) don't reach: the file-open error, a malformed-JSON
// snapshot (Decode's generic default-wrapped error, not one of its three
// sentinel errors), an unsupported schemaVersion, an unrecognized
// objectType, and an object-type mismatch (which also exercises both of
// article's branches inside the same message: "a domain record" /
// "an ip record").
func TestLoadSnapshot_Rejections(t *testing.T) {
	domainQuery := domain.Query{Kind: domain.KindDomain, Name: domain.Name{Punycode: "example.com"}}

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := loadSnapshot(filepath.Join(t.TempDir(), "does-not-exist.json"), domainQuery)
		if err == nil {
			t.Fatal("expected an error for a nonexistent --diff path")
		}
		var ue usageError
		if !errors.As(err, &ue) {
			t.Errorf("err = %v (%T), want a usageError", err, err)
		}
		if !strings.Contains(err.Error(), "--diff:") {
			t.Errorf("err = %q, want it prefixed with \"--diff:\"", err.Error())
		}
	})

	t.Run("malformed JSON", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "snap.json")
		if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadSnapshot(path, domainQuery)
		if err == nil {
			t.Fatal("expected an error for a malformed-JSON snapshot")
		}
		if !strings.Contains(err.Error(), "--diff:") {
			t.Errorf("err = %q, want it prefixed with \"--diff:\"", err.Error())
		}
	})

	t.Run("unsupported schemaVersion", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "snap.json")
		if err := os.WriteFile(path, []byte(`{"schemaVersion":99,"objectType":"domain"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadSnapshot(path, domainQuery)
		if err == nil || !strings.Contains(err.Error(), "unsupported schemaVersion") {
			t.Errorf("err = %v, want an unsupported-schemaVersion message", err)
		}
	})

	t.Run("unrecognized objectType", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "snap.json")
		if err := os.WriteFile(path, []byte(`{"schemaVersion":1,"objectType":"nameserver"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadSnapshot(path, domainQuery)
		if err == nil || !strings.Contains(err.Error(), "unrecognized objectType") {
			t.Errorf("err = %v, want an unrecognized-objectType message", err)
		}
	})

	t.Run("object type mismatch reports both articles", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "snap.json")
		body := `{"schemaVersion":1,"objectType":"domain","domain":{"value":"example.com","sources":["registry-rdap"]},"conflicts":[],"redacted":[],"sources":[]}`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		ipQuery := domain.Query{Kind: domain.KindIPv4, IP: netip.MustParseAddr("8.8.8.8")}
		_, err := loadSnapshot(path, ipQuery)
		if err == nil {
			t.Fatal("expected an object-type mismatch error")
		}
		got := err.Error()
		if !strings.Contains(got, "a domain record") {
			t.Errorf("err = %q, want it to say \"a domain record\" (article(\"domain\") == \"a\")", got)
		}
		if !strings.Contains(got, "the query is an ip") {
			t.Errorf("err = %q, want it to say \"the query is an ip\" (article(\"ip\") == \"an\")", got)
		}
	})
}

// TestDiffRender_FormatBranches drives diffRender directly (rather than
// through lookupOne) to reach the FormatJSON/FormatNDJSON and FormatHuman
// branches of its format switch -- every lookupOne end-to-end --diff test
// in lookupone_test.go only ever passes render.FormatPlain for the diff
// step itself (FormatJSON there is used for the baseline snapshot, not the
// diff render), so RenderJSON and RenderHuman were never reached through
// diffRender before this test.
func TestDiffRender_FormatBranches(t *testing.T) {
	prior := decodeSnapshot(t, model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	})
	freshRecord := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
		Status: model.Field[[]string]{Value: []string{"active"}, Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	encode := func(w io.Writer) error { return machine.Encode(w, freshRecord, machine.Options{}) }

	tests := []struct {
		name    string
		format  render.Format
		wantSub string
	}{
		{"JSON", render.FormatJSON, `"kind":"added"`},
		{"NDJSON", render.FormatNDJSON, `"kind":"added"`},
		{"Human", render.FormatHuman, "Status"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			code, err := diffRender(&buf, tt.format, prior, encode, uiConfig{})
			if err != nil {
				t.Fatalf("diffRender: %v", err)
			}
			if code != 4 {
				t.Errorf("code = %d, want 4 (Status was added)", code)
			}
			if !strings.Contains(buf.String(), tt.wantSub) {
				t.Errorf("output missing %q, got:\n%s", tt.wantSub, buf.String())
			}
		})
	}
}

// TestDiffRender_NoChanges covers diffRender's code==0 path directly.
func TestDiffRender_NoChanges(t *testing.T) {
	rec := model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	}
	prior := decodeSnapshot(t, rec)
	encode := func(w io.Writer) error { return machine.Encode(w, rec, machine.Options{}) }

	var buf bytes.Buffer
	code, err := diffRender(&buf, render.FormatJSON, prior, encode, uiConfig{})
	if err != nil {
		t.Fatalf("diffRender: %v", err)
	}
	if code != 0 {
		t.Errorf("code = %d, want 0 (nothing changed)", code)
	}
	if !strings.Contains(buf.String(), `"changes":[]`) {
		t.Errorf("output missing an empty changes array, got:\n%s", buf.String())
	}
}

// TestDiffRender_EncodeError covers diffRender's first error return: a
// failing encode func (standing in for a write failure on the fresh
// record) must surface as an error, not be swallowed.
func TestDiffRender_EncodeError(t *testing.T) {
	prior := decodeSnapshot(t, model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	})
	wantErr := errors.New("forced encode failure")
	encode := func(w io.Writer) error { return wantErr }

	var buf bytes.Buffer
	code, err := diffRender(&buf, render.FormatPlain, prior, encode, uiConfig{})
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
	if code != 0 {
		t.Errorf("code = %d, want 0 on an encode error", code)
	}
}

// TestDiffRender_DecodeError covers diffRender's second error return: when
// encode succeeds but writes something machine.Decode can't parse (e.g. a
// caller wiring the wrong encode func for the object type, or any other
// shape mismatch), the round-trip must surface an error rather than
// silently diffing garbage.
func TestDiffRender_DecodeError(t *testing.T) {
	prior := decodeSnapshot(t, model.Record{
		Domain: model.Field[string]{Value: "example.com", Sources: []model.SourceID{model.SourceRegistryRDAP}},
	})
	encode := func(w io.Writer) error {
		_, err := w.Write([]byte("not json"))
		return err
	}

	var buf bytes.Buffer
	code, err := diffRender(&buf, render.FormatPlain, prior, encode, uiConfig{})
	if err == nil {
		t.Fatal("expected an error when the encoded output doesn't parse as a snapshot")
	}
	if code != 0 {
		t.Errorf("code = %d, want 0 on a decode error", code)
	}
}

// decodeSnapshot round-trips rec through Encode/Decode, the same
// transformation diffRender itself applies to the fresh side, so the test
// fixtures below compare like with like.
func decodeSnapshot(t *testing.T, rec model.Record) machine.Snapshot {
	t.Helper()
	var buf bytes.Buffer
	if err := machine.Encode(&buf, rec, machine.Options{}); err != nil {
		t.Fatalf("machine.Encode: %v", err)
	}
	snap, err := machine.Decode(&buf)
	if err != nil {
		t.Fatalf("machine.Decode: %v", err)
	}
	return snap
}
