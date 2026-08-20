// Package plat looks up ownership of a domain, IP address, or autonomous
// system. It queries RDAP and WHOIS concurrently -- from both registry
// and registrar for domains, from the responsible RIR for IPs and ASNs --
// and merges what comes back into one record with per-field provenance:
// which source supplied each value, and where sources disagree.
//
// # Getting started
//
// Build a Client with New, then call Lookup for each name, address, or
// AS number:
//
//	c, err := plat.New(ctx, plat.Options{})
//	if err != nil {
//		// New rarely fails: a failed bootstrap fetch falls back to a
//		// cached copy and then to a snapshot embedded in the binary.
//	}
//	res, err := c.Lookup(ctx, "example.com")
//
// Lookup classifies the input and returns a Result holding exactly one
// of Domain, IP, or ASN, matching Result.Kind.
//
// # Reuse the Client
//
// A Client holds the IANA RDAP bootstrap data, a per-server WHOIS pacing
// limiter, and a cache of IANA WHOIS referrals -- all worth keeping
// across calls. A program looking up many names should build one Client
// and reuse it for every Lookup, not construct one per name: doing the
// latter throws away the bootstrap fetch and, more importantly, resets
// the pacing limiter each time, so it can no longer see that a burst of
// lookups is hitting one WHOIS server repeatedly. A Client is safe for
// concurrent use, so this works from multiple goroutines too.
//
// Pacing itself is on by default and is scoped per WHOIS server: it
// exists so a bulk run cannot hammer one server, and it costs nothing
// for a server a lookup only queries once. It is not free in every case
// -- if one lookup's own referral chain reaches the same WHOIS host
// twice (a registry that refers the registrar query back to itself,
// which is what example.com does), the second query waits out the full
// interval. Options.DisableWHOISPacing turns pacing off, which is the
// right choice for a program that only ever does one lookup at a time.
//
// # Provenance is the point
//
// Every field on Record, IPRecord, and ASNRecord is a Field[T], carrying
// both the merged value and the list of sources that supplied it. This
// is not incidental metadata -- it is the reason plat merges sources at
// all rather than just picking one. Where sources disagree beyond what
// merge tolerates (e.g. clock skew on timestamps), the field keeps its
// highest-precedence value and the disagreement is recorded in
// Conflicts, never silently dropped.
//
// # A failing source is not an error
//
// RDAP or WHOIS being unreachable for one source is normal, not
// exceptional: as long as at least one source returns data, Lookup
// returns a Result with a nil error, and the per-source detail --
// including which sources failed and why -- lives in the record's
// Sources field. ErrNotFound and ErrLookupFailed are returned alongside
// a populated Result too, so a caller diagnosing either case still has
// that detail to inspect.
//
// # Internal types, public aliases
//
// Record, IPRecord, ASNRecord, and their component types are aliases to
// types defined in an internal package: the same type, so no conversion
// happens at the boundary, but the implementation underneath stays free
// to change without breaking anything built against this package.
//
// # Producing plat's JSON output
//
// EncodeJSON writes a Result as plat's documented "schemaVersion": 1
// JSON document -- byte-identical to what the CLI's -o json prints for
// the same record, including with EncodeOptions.Raw for embedded source
// payloads. EncodeNDJSON writes the same document as a single
// newline-delimited record; for one Result the two encoders produce
// identical bytes; NDJSON's value is streaming many Results into one
// stream, the way the CLI's -o ndjson does across multiple names.
//
// # Stability
//
// This API is v0 and may change before 1.0.
package plat
