package diff

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"charm.land/lipgloss/v2"

	"github.com/patramsey/plat/internal/render/human"
)

func sampleChanges() []Change {
	return []Change{
		{Key: "expires", Label: "Expires", Kind: Changed, Before: "2026-08-03", After: "2027-08-03"},
		{Key: "nameservers", Label: "Nameservers", Kind: ListChanged,
			AddedItems: []string{"c.new.net"}, RemovedItems: []string{"a.old.net"}},
		{Key: "dnssec", Label: "DNSSEC", Kind: Added, After: "true"},
	}
}

func TestRenderPlain_ShowsEveryChange(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderPlain(&buf, "example.com", sampleChanges()); err != nil {
		t.Fatalf("RenderPlain: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"example.com", "Expires", "2026-08-03", "2027-08-03",
		"Nameservers", "c.new.net", "a.old.net", "DNSSEC", "true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plain output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Errorf("plain output must contain no ANSI escapes:\n%q", out)
	}
}

func TestRenderPlain_NoChanges(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderPlain(&buf, "example.com", nil); err != nil {
		t.Fatalf("RenderPlain: %v", err)
	}
	if !strings.Contains(buf.String(), "no changes") {
		t.Errorf("want a \"no changes\" line, got:\n%s", buf.String())
	}
}

func TestRenderJSON_Shape(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, "example.com", sampleChanges()); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var got struct {
		DiffSchemaVersion int    `json:"diffSchemaVersion"`
		Name              string `json:"name"`
		Changes           []struct {
			Key          string   `json:"key"`
			Label        string   `json:"label"`
			Kind         string   `json:"kind"`
			Before       string   `json:"before,omitempty"`
			After        string   `json:"after,omitempty"`
			AddedItems   []string `json:"addedItems,omitempty"`
			RemovedItems []string `json:"removedItems,omitempty"`
		} `json:"changes"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if got.DiffSchemaVersion != DiffSchemaVersion {
		t.Errorf("diffSchemaVersion = %d, want %d", got.DiffSchemaVersion, DiffSchemaVersion)
	}
	if got.Name != "example.com" {
		t.Errorf("name = %q, want example.com", got.Name)
	}
	if len(got.Changes) != 3 {
		t.Fatalf("got %d changes, want 3", len(got.Changes))
	}
	if got.Changes[0].Kind != "changed" {
		t.Errorf("kind = %q, want changed", got.Changes[0].Kind)
	}
	if got.Changes[1].Kind != "listChanged" {
		t.Errorf("kind = %q, want listChanged", got.Changes[1].Kind)
	}
}

// TestRenderJSON_EmptyChangesIsEmptyArray pins that "no changes" encodes
// as [] rather than null -- a consumer doing `.changes | length` must not
// have to special-case null.
func TestRenderJSON_EmptyChangesIsEmptyArray(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, "example.com", nil); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if !strings.Contains(buf.String(), `"changes":[]`) {
		t.Errorf("want \"changes\":[] for the empty case, got:\n%s", buf.String())
	}
}

// TestRenderHuman_WrapsLongNameserverListAtNarrowWidth is modeled on
// internal/render/human's TestRender_SourceLegendWrapsAtNarrowWidth: it
// renders at several narrow widths and asserts no output line exceeds
// the target, measuring with lipgloss.Width (ANSI-aware) rather than
// len(), which would miscount the styled output. A ListChanged
// nameserver change with several long hostnames is exactly the content
// shape that motivated RenderHuman's width parameter actually wrapping
// (describe() joins added/removed hostnames with "+"/"-" and spaces,
// which can run arbitrarily long).
func TestRenderHuman_WrapsLongNameserverListAtNarrowWidth(t *testing.T) {
	changes := []Change{
		{
			Key: "nameservers", Label: "Nameservers", Kind: ListChanged,
			AddedItems: []string{
				"ns1.newregistrar-verylongname.example.net",
				"ns2.newregistrar-verylongname.example.net",
			},
			RemovedItems: []string{
				"ns1.oldregistrar-verylongname.example.net",
			},
		},
	}
	th := human.NewTheme(false)
	for _, width := range []int{40, 60, 80} {
		var buf bytes.Buffer
		if err := RenderHuman(&buf, "example.com", changes, th, width); err != nil {
			t.Fatalf("width %d: RenderHuman: %v", width, err)
		}
		out := buf.String()
		for l := range strings.SplitSeq(out, "\n") {
			if w := lipgloss.Width(l); w > width {
				t.Errorf("width %d: line exceeds it (got %d visible columns): %q", width, w, l)
			}
		}
		// Only check short, stable prefixes survive, not the full
		// hostnames -- at narrow widths lipgloss's word-wrap legitimately
		// breaks even a single long word (e.g. at a hyphen), same caveat
		// TestRender_SourceLegendWrapsAtNarrowWidth notes in the human
		// package. The prefixes are short enough to never need splitting
		// themselves at any of the tested widths.
		for _, want := range []string{"ns1", "ns2"} {
			if !strings.Contains(out, want) {
				t.Errorf("width %d: expected %q to still appear, got:\n%s", width, want, out)
			}
		}
	}
}
