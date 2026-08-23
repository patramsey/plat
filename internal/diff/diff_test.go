package diff

import (
	"slices"
	"testing"

	"github.com/patramsey/plat/internal/render/machine"
)

func scalarField(key, label, value string) machine.Field {
	return machine.Field{Key: key, Label: label, Value: value}
}

func listField(key, label string, items ...string) machine.Field {
	return machine.Field{Key: key, Label: label, List: items}
}

func TestCompare(t *testing.T) {
	for _, tt := range []struct {
		name          string
		before, after []machine.Field
		want          []Change
	}{
		{
			name:   "no changes",
			before: []machine.Field{scalarField("expires", "Expires", "2026-08-03")},
			after:  []machine.Field{scalarField("expires", "Expires", "2026-08-03")},
			want:   nil,
		},
		{
			name:   "scalar changed",
			before: []machine.Field{scalarField("expires", "Expires", "2026-08-03")},
			after:  []machine.Field{scalarField("expires", "Expires", "2027-08-03")},
			want: []Change{{
				Key: "expires", Label: "Expires", Kind: Changed,
				Before: "2026-08-03", After: "2027-08-03",
			}},
		},
		{
			name:   "field appeared",
			before: nil,
			after:  []machine.Field{scalarField("expires", "Expires", "2027-08-03")},
			want: []Change{{
				Key: "expires", Label: "Expires", Kind: Added, After: "2027-08-03",
			}},
		},
		{
			name:   "field disappeared",
			before: []machine.Field{scalarField("expires", "Expires", "2026-08-03")},
			after:  nil,
			want: []Change{{
				Key: "expires", Label: "Expires", Kind: Removed, Before: "2026-08-03",
			}},
		},
		{
			name:   "list item added and removed",
			before: []machine.Field{listField("nameservers", "Nameservers", "a.old.net", "b.keep.net")},
			after:  []machine.Field{listField("nameservers", "Nameservers", "b.keep.net", "c.new.net")},
			want: []Change{{
				Key: "nameservers", Label: "Nameservers", Kind: ListChanged,
				AddedItems: []string{"c.new.net"}, RemovedItems: []string{"a.old.net"},
			}},
		},
		{
			// The case that matters for real users: a snapshot saved
			// before v0.3.1 has unsorted nameservers, because sorting
			// them was the fix in #51. An order-sensitive comparison
			// would report every such snapshot as wholly changed.
			name:   "list reordered but equal is not a change",
			before: []machine.Field{listField("nameservers", "Nameservers", "b.iana-servers.net", "a.iana-servers.net")},
			after:  []machine.Field{listField("nameservers", "Nameservers", "a.iana-servers.net", "b.iana-servers.net")},
			want:   nil,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := Compare(tt.before, tt.after)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d changes, want %d: %+v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i].Key != tt.want[i].Key || got[i].Label != tt.want[i].Label || got[i].Kind != tt.want[i].Kind ||
					got[i].Before != tt.want[i].Before || got[i].After != tt.want[i].After {
					t.Errorf("change %d = %+v, want %+v", i, got[i], tt.want[i])
				}
				if !equalStrings(got[i].AddedItems, tt.want[i].AddedItems) {
					t.Errorf("change %d AddedItems = %q, want %q", i, got[i].AddedItems, tt.want[i].AddedItems)
				}
				if !equalStrings(got[i].RemovedItems, tt.want[i].RemovedItems) {
					t.Errorf("change %d RemovedItems = %q, want %q", i, got[i].RemovedItems, tt.want[i].RemovedItems)
				}
			}
		})
	}
}

// TestCompare_PureListAdditionAndRemoval pins that a list can register a
// change while gaining OR losing items alone -- not just both at once.
// Without this, flipping diff.go's "len(added) == 0 && len(removed) == 0"
// to "||" silences every one-sided list change and the whole suite stays
// green -- exit 0 instead of 4, on the question --diff exists to answer.
func TestCompare_PureListAdditionAndRemoval(t *testing.T) {
	base := []machine.Field{{Key: "nameservers", Label: "Nameservers", List: []string{"a.example.com"}}}

	t.Run("pure addition", func(t *testing.T) {
		after := []machine.Field{{Key: "nameservers", Label: "Nameservers", List: []string{"a.example.com", "b.example.com"}}}
		changes := Compare(base, after)
		if len(changes) != 1 {
			t.Fatalf("changes = %+v, want exactly one", changes)
		}
		if got := changes[0].AddedItems; !slices.Equal(got, []string{"b.example.com"}) {
			t.Errorf("AddedItems = %q, want [b.example.com]", got)
		}
		if len(changes[0].RemovedItems) != 0 {
			t.Errorf("RemovedItems = %q, want none", changes[0].RemovedItems)
		}
	})

	t.Run("pure removal", func(t *testing.T) {
		after := []machine.Field{{Key: "nameservers", Label: "Nameservers", List: []string{}}}
		changes := Compare(base, after)
		if len(changes) != 1 {
			t.Fatalf("changes = %+v, want exactly one", changes)
		}
		if got := changes[0].RemovedItems; !slices.Equal(got, []string{"a.example.com"}) {
			t.Errorf("RemovedItems = %q, want [a.example.com]", got)
		}
	})
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestCompare_PreservesFieldOrder pins that changes come back in the
// canonical field order of the inputs, not map order -- output that
// reshuffles between runs is the bug #51 fixed elsewhere.
func TestCompare_PreservesFieldOrder(t *testing.T) {
	before := []machine.Field{
		scalarField("created", "Created", "2000-01-01"),
		scalarField("updated", "Updated", "2020-01-01"),
		scalarField("expires", "Expires", "2026-01-01"),
	}
	after := []machine.Field{
		scalarField("created", "Created", "2000-01-02"),
		scalarField("updated", "Updated", "2020-01-02"),
		scalarField("expires", "Expires", "2026-01-02"),
	}
	got := Compare(before, after)
	want := []string{"created", "updated", "expires"}
	if len(got) != 3 {
		t.Fatalf("got %d changes, want 3", len(got))
	}
	for i, key := range want {
		if got[i].Key != key {
			t.Errorf("change %d key = %q, want %q", i, got[i].Key, key)
		}
	}
}

// TestKindString asserts the display string for every declared Kind value
// plus the unknown/default branch (a Kind value outside the declared
// iota range) -- Kind.String's switch has no way to fail other than a
// typo in one of these five return paths, and nothing elsewhere in this
// package or in cmd/plat's end-to-end tests forces every branch, since
// --diff only ever produces well-formed Kind values.
func TestKindString(t *testing.T) {
	tests := []struct {
		name string
		k    Kind
		want string
	}{
		{"Changed", Changed, "changed"},
		{"Added", Added, "added"},
		{"Removed", Removed, "removed"},
		{"ListChanged", ListChanged, "listChanged"},
		{"unknown value falls through to the default branch", Kind(99), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.k.String(); got != tt.want {
				t.Errorf("Kind(%d).String() = %q, want %q", tt.k, got, tt.want)
			}
		})
	}
}
