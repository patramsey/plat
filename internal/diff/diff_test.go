package diff

import (
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
				if got[i].Key != tt.want[i].Key || got[i].Kind != tt.want[i].Kind ||
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
