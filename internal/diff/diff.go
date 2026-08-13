// Package diff compares two plat snapshots field by field.
//
// It deliberately compares values only. Provenance and conflicts are
// ignored: sources flap, and a rate-limited RIR or a timed-out registrar
// WHOIS would otherwise produce churn on nearly every field and drown the
// real signal. As long as some source still supplies a value, a flaky run
// produces no diff at all.
package diff

import (
	"sort"

	"github.com/patramsey/plat/internal/render/machine"
)

// Kind classifies one field's change.
type Kind int

const (
	Changed     Kind = iota // scalar value differs
	Added                   // field absent before, present after
	Removed                 // field present before, absent after
	ListChanged             // list-valued field gained or lost items
)

func (k Kind) String() string {
	switch k {
	case Changed:
		return "changed"
	case Added:
		return "added"
	case Removed:
		return "removed"
	case ListChanged:
		return "listChanged"
	}
	return "unknown"
}

// Change is one reported difference.
type Change struct {
	Key          string
	Label        string
	Kind         Kind
	Before       string   // empty when Kind is Added
	After        string   // empty when Kind is Removed
	AddedItems   []string // ListChanged only
	RemovedItems []string // ListChanged only
}

// Compare reports how after differs from before, in the field order of
// the inputs. Returns nil when nothing changed.
func Compare(before, after []machine.Field) []Change {
	beforeByKey := index(before)
	afterByKey := index(after)

	var out []Change

	// Walk `after` first so the output follows the canonical field order
	// of the fresh lookup.
	for _, af := range after {
		bf, existed := beforeByKey[af.Key]
		if !existed {
			out = append(out, Change{
				Key: af.Key, Label: af.Label, Kind: Added,
				After: af.Value, AddedItems: af.List,
			})
			continue
		}
		if c, ok := compareField(bf, af); ok {
			out = append(out, c)
		}
	}

	// Then anything that vanished, in `before`'s order.
	for _, bf := range before {
		if _, still := afterByKey[bf.Key]; !still {
			out = append(out, Change{
				Key: bf.Key, Label: bf.Label, Kind: Removed,
				Before: bf.Value, RemovedItems: bf.List,
			})
		}
	}
	return out
}

func index(fields []machine.Field) map[string]machine.Field {
	m := make(map[string]machine.Field, len(fields))
	for _, f := range fields {
		m[f.Key] = f
	}
	return m
}

// compareField reports one field's change, if any. List fields are
// compared as sets: reordering is not a change. Snapshots saved before
// v0.3.1 have unsorted nameservers and status (sorting them was #51's
// fix), so an order-sensitive comparison would report every older
// snapshot as wholly changed.
func compareField(before, after machine.Field) (Change, bool) {
	if before.List != nil || after.List != nil {
		added, removed := setDiff(before.List, after.List)
		if len(added) == 0 && len(removed) == 0 {
			return Change{}, false
		}
		return Change{
			Key: after.Key, Label: after.Label, Kind: ListChanged,
			AddedItems: added, RemovedItems: removed,
		}, true
	}
	if before.Value == after.Value {
		return Change{}, false
	}
	return Change{
		Key: after.Key, Label: after.Label, Kind: Changed,
		Before: before.Value, After: after.Value,
	}, true
}

// setDiff returns items present only in after, and only in before. Both
// results are sorted so output is deterministic regardless of input
// order.
func setDiff(before, after []string) (added, removed []string) {
	inBefore := make(map[string]bool, len(before))
	for _, s := range before {
		inBefore[s] = true
	}
	inAfter := make(map[string]bool, len(after))
	for _, s := range after {
		inAfter[s] = true
	}
	for s := range inAfter {
		if !inBefore[s] {
			added = append(added, s)
		}
	}
	for s := range inBefore {
		if !inAfter[s] {
			removed = append(removed, s)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}
