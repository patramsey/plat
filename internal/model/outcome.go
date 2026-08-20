package model

// Outcome classifies a lookup by what its sources collectively returned.
// It exists so the CLI (which maps it to an exit code) and the public
// library (which maps it to an error) cannot drift apart about what
// counts as "not found" versus "failed".
type Outcome int

const (
	// OutcomeOK means at least one source returned data. Other sources
	// failing is normal and does not downgrade this.
	OutcomeOK Outcome = iota
	// OutcomeNotFound means every source reported the object does not
	// exist, and none failed for another reason.
	OutcomeNotFound
	// OutcomeFailed means no source returned data and at least one failed
	// for a reason other than not-found -- including the case of no
	// sources at all. A not-found mixed with a hard failure lands here
	// rather than in OutcomeNotFound: an unreachable source might have
	// held the record, so plat will not claim the object is absent.
	OutcomeFailed
)

// Classify applies the rules above to a record's per-source results.
func Classify(sources []SourceResult) Outcome {
	if len(sources) == 0 {
		return OutcomeFailed
	}
	hasData, hasNotFound, hasFailed := false, false, false
	for _, s := range sources {
		switch {
		case s.OK:
			hasData = true
		case s.NotFound:
			hasNotFound = true
		default:
			hasFailed = true
		}
	}
	if hasData {
		return OutcomeOK
	}
	if hasNotFound && !hasFailed {
		return OutcomeNotFound
	}
	return OutcomeFailed
}
