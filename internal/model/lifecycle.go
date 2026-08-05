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

// LifecycleInfo is a derived interpretation of where a gTLD domain sits
// in ICANN's Expired Registration Recovery Policy (ERRP) timeline,
// computed by internal/merge from the merged Record's Status and
// timestamps. Unlike Field[T], it carries no per-source provenance --
// it's plat's own reading of already-merged data, not a value any single
// source reported directly. Present (non-nil) only for gTLDs with a
// recognized lifecycle-relevant status; see internal/merge's
// deriveLifecycle.
type LifecycleInfo struct {
	Stage       LifecycleStage
	Label       string // human-readable stage name, e.g. "Redemption Grace Period"
	Description string // what the stage means and what's still possible

	// EstimatedEndsBy is an upper-bound estimate of when this stage ends,
	// computed from a fixed duration (ERRP mandates 30 days for
	// Redemption Grace) or a common registry-configured convention (the
	// Auto-Renew Grace and Pending Delete durations are not themselves
	// ICANN-mandated -- see internal/merge's EstimateBasis strings for
	// which is which) -- never parsed from a source, so unlike TimeValue
	// it carries no Raw/Parsed pair. Nil when not computable (no usable
	// anchor timestamp, or -- for LifecyclePendingRestore -- no fixed or
	// conventional duration exists to cite).
	EstimatedEndsBy *time.Time
	// EstimateBasis explains, in prose that itself states the value is
	// an estimate, how EstimatedEndsBy was derived and which policy it's
	// based on. Empty when EstimatedEndsBy is nil.
	EstimateBasis string
}
