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

// deriveLifecycle interprets rec's already-merged Status/Updated/Expires,
// plus present (the sorted, attempted SourceRecords Merge derived rec
// from), into a LifecycleInfo describing where the domain sits in
// ICANN's Expired Domain Deletion Policy (EDDP) timeline. Returns nil for
// ccTLDs (2-letter TLDs, which set independent policies EDDP doesn't
// govern) and for gTLDs with no recognized lifecycle-relevant status.
func deriveLifecycle(rec model.Record, present []model.SourceRecord) *model.LifecycleInfo {
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
		return autoRenewGraceInfo(present)
	}
	return nil
}

// isGTLD reports whether domain's TLD (its last dot-separated label) is
// eligible for lifecycle interpretation: a plain-ASCII label 3 or more
// characters long, following the standard ICANN/ISO 3166 convention that
// every ccTLD is exactly 2 letters and every gTLD is 3 or more, so no
// lookup table is needed for the ASCII case. An empty or dot-less domain
// is treated as ineligible.
//
// Deliberate limitation: ANY internationalized (IDN) TLD -- whether ccTLD
// or gTLD, in punycode ("xn--..." ACE) or native Unicode form -- is
// treated as ineligible, not just IDN ccTLDs. There is no reliable way to
// tell an IDN ccTLD (e.g. "рф", Russian, punycode "xn--p1ai") apart from
// an IDN gTLD (e.g. "在线", punycode "xn--3ds443g") using only length or
// the "xn--" prefix -- both can be short or long once encoded.
// Distinguishing them correctly requires a real ccTLD/gTLD classification
// list (e.g. from IANA's root zone delegation data), which this package
// deliberately doesn't carry, matching the plan's "no lookup table" choice.
// The practical effect: expired IDN gTLD domains (a narrow, uncommon case)
// don't get lifecycle interpretation either, alongside every IDN ccTLD
// (which is the actual goal).
func isGTLD(domain string) bool {
	if domain == "" {
		return false
	}
	i := strings.LastIndexByte(domain, '.')
	if i < 0 || i == len(domain)-1 {
		return false
	}
	tld := domain[i+1:]
	if strings.HasPrefix(tld, "xn--") || !isASCII(tld) {
		return false
	}
	return len(tld) >= 3
}

// isASCII reports whether s contains only plain ASCII bytes.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
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

func autoRenewGraceInfo(present []model.SourceRecord) *model.LifecycleInfo {
	info := &model.LifecycleInfo{
		Stage:       model.LifecycleAutoRenewGrace,
		Label:       "Auto-Renew Grace Period",
		Description: "The domain has expired. The registrar may still renew it automatically during this window, or let it lapse further into the Redemption Grace Period. Nothing to do yet unless you want to ensure renewal goes through.",
	}
	if anchor, ok := registrarExpires(present); ok {
		end := anchor.Add(autoRenewGraceCap)
		info.EstimatedEndsBy = &end
		info.EstimateBasis = "Estimate based on ICANN's 45-day cap on the optional Auto-Renew Grace Period for gTLDs, calculated from the registrar's reported expiration date -- the registry's own expiration date reflects the registry's already-performed auto-renewal, not the domain's original term, so it isn't used here. Many registrars use a shorter window, so this domain's actual renew/delete decision could come sooner."
	}
	return info
}

// registrarExpires returns the first present, parsed Expires timestamp
// reported directly by a registrar source (registrar-rdap preferred over
// registrar-whois, since present is already precedence-sorted). Only a
// registrar source is trustworthy here: during Auto-Renew Grace Period
// the registry has already bumped its own Expires forward by a full
// renewal term as part of the grace-period mechanic itself, while the
// registrar's reported Expires continues to reflect the domain's real,
// original expiration -- confirmed against a live registry/registrar
// WHOIS pair (registry showed a date bumped a year forward; registrar
// showed the true original expiration and the autoRenewPeriod status).
// Verisign's own WHOIS notice text says as much: "consult the sponsoring
// registrar's Whois database" for the actual date.
func registrarExpires(present []model.SourceRecord) (time.Time, bool) {
	for _, s := range present {
		if s.Meta.Source != model.SourceRegistrarRDAP && s.Meta.Source != model.SourceRegistrarWHOIS {
			continue
		}
		if s.Expires.Raw != "" && s.Expires.Parsed {
			return s.Expires.Time, true
		}
	}
	return time.Time{}, false
}

func parsedTime(f model.Field[model.TimeValue]) (time.Time, bool) {
	if !f.Present() || !f.Value.Parsed {
		return time.Time{}, false
	}
	return f.Value.Time, true
}
