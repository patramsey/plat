package parse

import "testing"

// ipSpecificKeys and asnSpecificKeys are hardcoded snapshots of the
// type-specific keys declared directly in ipFields' and asnFields' own
// map literals (ip.go, asn.go) -- independent of the live tables for the
// same reason commonFieldKeys is (see TestCommonVocabularyReachesBothParsers'
// doc comment in ip_test.go): buildFields merges commonFields into the
// specific map in place, so by the time ipFields/asnFields exist, a
// collision has already been silently resolved in commonFields' favor and
// the evidence of what the type-specific literal used to hold is gone.
// Only a list kept independently of buildFields' output can catch that.
var ipSpecificKeys = []string{
	"netrange", "inetnum", "inet6num", "cidr", "netname", "nethandle", "parent", "nettype", "status",
}

var asnSpecificKeys = []string{
	"asnumber", "aut-num", "asname", "as-name", "ashandle",
}

// TestFieldTableInvariants covers the two structural properties Fix 1 and
// Fix 4 of the final-review brief exist to guarantee:
//
//  1. No entry in commonFields, ipFields, or asnFields has a nil set --
//     set is always called unconditionally by both parsers' main loops, so
//     a nil one panics on first matching WHOIS line.
//  2. ipFields["status"] is the only getter-less entry across ipFields and
//     asnFields. liftCommon (fields.go) now propagates a nil get instead
//     of wrapping it in a non-nil, panicking closure, so a getter-less
//     commonFields entry would show up here as a *lifted* getter-less
//     entry in both tables -- exactly the hole Fix 1 closes.
//  3. No type-specific key (ipSpecificKeys/asnSpecificKeys) collides with
//     a commonFields key. buildFields does `specific[k] = liftCommon(...)`
//     unconditionally, so a collision silently discards the type-specific
//     entry -- and arguably backwards, since a deliberate type-specific
//     override should win. This is Fix 4: rather than making buildFields
//     panic at init (heavier, harder to diagnose), the disjointness is
//     asserted here instead.
func TestFieldTableInvariants(t *testing.T) {
	t.Run("non-nil set", func(t *testing.T) {
		for k, ref := range commonFields {
			if ref.set == nil {
				t.Errorf("commonFields[%q].set is nil", k)
			}
		}
		for k, ref := range ipFields {
			if ref.set == nil {
				t.Errorf("ipFields[%q].set is nil", k)
			}
		}
		for k, ref := range asnFields {
			if ref.set == nil {
				t.Errorf("asnFields[%q].set is nil", k)
			}
		}
	})

	t.Run("only ipFields status is getter-less", func(t *testing.T) {
		var getterless []string
		for k, ref := range ipFields {
			if ref.get == nil {
				getterless = append(getterless, "ipFields[\""+k+"\"]")
			}
		}
		for k, ref := range asnFields {
			if ref.get == nil {
				getterless = append(getterless, "asnFields[\""+k+"\"]")
			}
		}
		if len(getterless) != 1 || getterless[0] != `ipFields["status"]` {
			t.Errorf(`getter-less entries = %v, want exactly [ipFields["status"]]`, getterless)
		}
	})

	t.Run("type-specific keys disjoint from commonFields", func(t *testing.T) {
		for _, k := range ipSpecificKeys {
			if _, collides := commonFields[k]; collides {
				t.Errorf("ip-specific key %q collides with a commonFields key -- buildFields would silently discard the type-specific entry", k)
			}
		}
		for _, k := range asnSpecificKeys {
			if _, collides := commonFields[k]; collides {
				t.Errorf("asn-specific key %q collides with a commonFields key -- buildFields would silently discard the type-specific entry", k)
			}
		}
	})
}
