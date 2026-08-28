package model

import "slices"

// PresentSources returns the sources a rendered view of r will actually
// attribute a value to, deduplicated and ordered by Precedence.
//
// This is deliberately NOT r.Sources. A source can be queried, answer
// successfully, and still contribute no field value that survives the
// merge -- in which case its two-letter code appears nowhere in the
// output, and a legend entry explaining it reads as "plat failed to reach
// that source" rather than "that source had nothing to add". The renderers
// build their legend from this instead, so the key only ever decodes codes
// the reader can actually see.
//
// Conflict.Values keys are included because --conflicts prints codes from
// them too.
func PresentSources(r Record) []SourceID {
	c := newSourceCollector()
	c.add(r.Domain.Sources)
	c.add(r.Handle.Sources)
	c.add(r.Registrar.Name.Sources)
	c.add(r.Registrar.IANAID.Sources)
	c.add(r.Registrar.URL.Sources)
	c.add(r.Registrar.AbuseEmail.Sources)
	c.add(r.Registrar.AbusePhone.Sources)
	c.add(r.Status.Sources)
	c.add(r.Created.Sources)
	c.add(r.Updated.Sources)
	c.add(r.Expires.Sources)
	c.add(r.Nameservers.Sources)
	c.add(r.DNSSEC.Sources)
	c.addConflicts(r.Conflicts)
	return c.sorted()
}

// PresentSourcesIP is PresentSources for an IP network record.
func PresentSourcesIP(r IPRecord) []SourceID {
	c := newSourceCollector()
	c.add(r.Name.Sources)
	c.add(r.Handle.Sources)
	c.add(r.StartAddress.Sources)
	c.add(r.EndAddress.Sources)
	c.add(r.CIDR.Sources)
	c.add(r.Type.Sources)
	c.add(r.IPVersion.Sources)
	c.add(r.ParentHandle.Sources)
	c.add(r.Country.Sources)
	c.add(r.Status.Sources)
	c.add(r.Registered.Sources)
	c.add(r.Updated.Sources)
	c.add(r.Org.Name.Sources)
	c.add(r.Org.ID.Sources)
	c.add(r.Org.AbuseEmail.Sources)
	c.add(r.Org.AbusePhone.Sources)
	c.addConflicts(r.Conflicts)
	return c.sorted()
}

// PresentSourcesASN is PresentSources for an autonomous system record.
func PresentSourcesASN(r ASNRecord) []SourceID {
	c := newSourceCollector()
	c.add(r.Name.Sources)
	c.add(r.Handle.Sources)
	c.add(r.StartAutnum.Sources)
	c.add(r.EndAutnum.Sources)
	c.add(r.Type.Sources)
	c.add(r.Country.Sources)
	c.add(r.Status.Sources)
	c.add(r.Registered.Sources)
	c.add(r.Updated.Sources)
	c.add(r.Org.Name.Sources)
	c.add(r.Org.ID.Sources)
	c.add(r.Org.AbuseEmail.Sources)
	c.add(r.Org.AbusePhone.Sources)
	c.addConflicts(r.Conflicts)
	return c.sorted()
}

type sourceCollector struct{ seen map[SourceID]bool }

func newSourceCollector() *sourceCollector {
	return &sourceCollector{seen: make(map[SourceID]bool, len(Precedence))}
}

func (c *sourceCollector) add(sources []SourceID) {
	for _, s := range sources {
		c.seen[s] = true
	}
}

func (c *sourceCollector) addConflicts(conflicts []Conflict) {
	for _, cf := range conflicts {
		for s := range cf.Values {
			c.seen[s] = true
		}
	}
}

// sorted emits in Precedence order, then any unknown source alphabetically
// after them -- Rank() already sorts unknowns last, and going through the
// map directly would make output flaky, since Go randomizes map iteration.
func (c *sourceCollector) sorted() []SourceID {
	out := make([]SourceID, 0, len(c.seen))
	for _, s := range Precedence {
		if c.seen[s] {
			out = append(out, s)
			delete(c.seen, s)
		}
	}
	rest := make([]SourceID, 0, len(c.seen))
	for s := range c.seen {
		rest = append(rest, s)
	}
	slices.Sort(rest)
	return append(out, rest...)
}
