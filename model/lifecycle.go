package model

import "time"

// LifecycleStage names a phase in ICANN's Expired Registration Recovery
// Policy (ERRP) timeline for gTLDs.
type LifecycleStage string

const (
	LifecycleAutoRenewGrace  LifecycleStage = "autoRenewGrace"
	LifecycleRedemptionGrace LifecycleStage = "redemptionGrace"
	LifecyclePendingRestore  LifecycleStage = "pendingRestore"
	LifecyclePendingDelete   LifecycleStage = "pendingDelete"
)

// LifecycleInfo is plat's own interpretation of where a gTLD domain sits
// in ICANN's Expired Registration Recovery Policy (ERRP) timeline,
// derived from the record's own merged Status and timestamps. Unlike
// Field[T], it carries no per-source provenance -- it's a reading of
// already-merged data, not a value any single source reported directly.
// Present (non-nil) only for a gTLD whose Status places it in a
// recognized ERRP stage; nil for every ccTLD and for a gTLD not
// currently expired.
type LifecycleInfo struct {
	Stage       LifecycleStage
	Label       string // human-readable stage name, e.g. "Redemption Grace Period"
	Description string // what the stage means and what's still possible

	// EstimatedEndsBy is an upper-bound estimate of when this stage ends,
	// computed from a fixed duration (ERRP mandates 30 days for
	// Redemption Grace) or a common registry-configured convention (Auto-
	// Renew Grace and Pending Delete are not themselves ICANN-mandated --
	// EstimateBasis, below, says which is which for a given value). It is
	// never parsed from a source, so unlike TimeValue it carries no
	// Raw/Parsed pair. Nil when not computable (no usable anchor
	// timestamp, or -- for LifecyclePendingRestore -- no fixed or
	// conventional duration exists to cite).
	EstimatedEndsBy *time.Time
	// EstimateBasis explains, in prose that itself states the value is
	// an estimate, how EstimatedEndsBy was derived and which policy it's
	// based on. Empty when EstimatedEndsBy is nil.
	EstimateBasis string
}
