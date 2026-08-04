package merge

import (
	"strings"
	"time"

	"github.com/patramsey/plat/internal/model"
)

const (
	autoRenewGraceCap  = 45 * 24 * time.Hour
	redemptionGraceLen = 30 * 24 * time.Hour
	pendingDeleteLen   = 5 * 24 * time.Hour
)

// lifecycleStatusPriority maps each EPP status this package recognizes as
// lifecycle-relevant to its model.LifecycleStage, in priority order --
// checked top to bottom, first match wins. Mirrors
// internal/render/human's domainVerdict "crit beats good" precedent: a
// more urgent/definitive stage wins over a stale or overlapping one if a
// Record's Status somehow carries more than one at once.
var lifecycleStatusPriority = []struct {
	status string
	stage  model.LifecycleStage
}{
	{"pendingDelete", model.LifecyclePendingDelete},
	{"redemptionPeriod", model.LifecycleRedemptionGrace},
	{"pendingRestore", model.LifecyclePendingRestore},
	{"autoRenewPeriod", model.LifecycleAutoRenewGrace},
}

// deriveLifecycle interprets rec's already-merged Status/Updated/Expires
// into a LifecycleInfo describing where the domain sits in ICANN's
// Expired Domain Deletion Policy (EDDP) timeline. Returns nil for ccTLDs
// (2-letter TLDs, which set independent policies EDDP doesn't govern) and
// for gTLDs with no recognized lifecycle-relevant status.
func deriveLifecycle(rec model.Record) *model.LifecycleInfo {
	if !isGTLD(rec.Domain.Value) {
		return nil
	}
	stage, ok := matchLifecycleStage(rec.Status.Value)
	if !ok {
		return nil
	}
	switch stage {
	case model.LifecyclePendingDelete:
		return pendingDeleteInfo(rec)
	case model.LifecycleRedemptionGrace:
		return redemptionGraceInfo(rec)
	case model.LifecyclePendingRestore:
		return pendingRestoreInfo()
	case model.LifecycleAutoRenewGrace:
		return autoRenewGraceInfo(rec)
	}
	return nil
}

// isGTLD reports whether domain's TLD (its last dot-separated label) is 3
// or more characters -- the standard ICANN/ISO 3166 convention that every
// ccTLD is exactly 2 letters and every gTLD is 3 or more, so no lookup
// table is needed. An empty or dot-less domain is treated as not a gTLD.
func isGTLD(domain string) bool {
	if domain == "" {
		return false
	}
	i := strings.LastIndexByte(domain, '.')
	if i < 0 || i == len(domain)-1 {
		return false
	}
	return len(domain)-i-1 >= 3
}

func matchLifecycleStage(statuses []string) (model.LifecycleStage, bool) {
	set := make(map[string]bool, len(statuses))
	for _, s := range statuses {
		set[s] = true
	}
	for _, p := range lifecycleStatusPriority {
		if set[p.status] {
			return p.stage, true
		}
	}
	return "", false
}

func pendingDeleteInfo(rec model.Record) *model.LifecycleInfo {
	info := &model.LifecycleInfo{
		Stage:       model.LifecyclePendingDelete,
		Label:       "Pending Delete",
		Description: "The domain can no longer be restored. It will be deleted and released for new registration once this period ends.",
	}
	if anchor, ok := parsedTime(rec.Updated); ok {
		end := anchor.Add(pendingDeleteLen)
		info.EstimatedEndsBy = &end
		info.EstimateBasis = "Estimate based on ICANN's fixed 5-day Pending Delete period for gTLDs, calculated from this record's last-updated time. Actual timing is set by the registry and may differ slightly."
	}
	return info
}

func redemptionGraceInfo(rec model.Record) *model.LifecycleInfo {
	info := &model.LifecycleInfo{
		Stage:       model.LifecycleRedemptionGrace,
		Label:       "Redemption Grace Period",
		Description: "This domain has expired and is no longer eligible for normal renewal. The registrant can still recover it by asking the registrar for a restore, typically for an added fee. If it isn't restored, the domain moves to Pending Delete and is later released for new registration.",
	}
	if anchor, ok := parsedTime(rec.Updated); ok {
		end := anchor.Add(redemptionGraceLen)
		info.EstimatedEndsBy = &end
		info.EstimateBasis = "Estimate based on ICANN's fixed 30-day Redemption Grace Period policy for gTLDs, calculated from this record's last-updated time. Actual timing is set by the registry/registrar and may be earlier."
	}
	return info
}

func pendingRestoreInfo() *model.LifecycleInfo {
	return &model.LifecycleInfo{
		Stage:       model.LifecyclePendingRestore,
		Label:       "Pending Restore",
		Description: "A restore request is being processed by the registry; this is normally resolved within a few days.",
	}
}

func autoRenewGraceInfo(rec model.Record) *model.LifecycleInfo {
	info := &model.LifecycleInfo{
		Stage:       model.LifecycleAutoRenewGrace,
		Label:       "Auto-Renew Grace Period",
		Description: "The domain has expired. The registrar may still renew it automatically during this window, or let it lapse further into the Redemption Grace Period. Nothing to do yet unless you want to ensure renewal goes through.",
	}
	if anchor, ok := parsedTime(rec.Expires); ok {
		end := anchor.Add(autoRenewGraceCap)
		info.EstimatedEndsBy = &end
		info.EstimateBasis = "Estimate based on ICANN's 45-day cap on the optional Auto-Renew Grace Period for gTLDs, calculated from this record's expiration date. Many registrars use a shorter window, so this domain's actual renew/delete decision could come sooner."
	}
	return info
}

func parsedTime(f model.Field[model.TimeValue]) (time.Time, bool) {
	if !f.Present() || !f.Value.Parsed {
		return time.Time{}, false
	}
	return f.Value.Time, true
}
