package model

// SourceID identifies which of the four possible sources a piece of data
// came from.
type SourceID string

const (
	SourceRegistrarRDAP  SourceID = "registrar-rdap"
	SourceRegistryRDAP   SourceID = "registry-rdap"
	SourceRegistrarWHOIS SourceID = "registrar-whois"
	SourceRegistryWHOIS  SourceID = "registry-whois"
)

// Precedence is the merge trust order, most to least trusted. A source's
// index in this slice is its precedence rank (lower is more trusted).
var Precedence = []SourceID{
	SourceRegistrarRDAP,
	SourceRegistryRDAP,
	SourceRegistrarWHOIS,
	SourceRegistryWHOIS,
}

// Rank returns s's index in Precedence, or len(Precedence) if s is not a
// known source (sorts unknown sources last).
func Rank(s SourceID) int {
	for i, p := range Precedence {
		if p == s {
			return i
		}
	}
	return len(Precedence)
}
