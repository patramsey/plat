package human

import (
	"strings"

	"github.com/patramsey/plat/internal/model"
)

// writeLifecycle renders r.Lifecycle -- plat's own interpretation of
// where an expired gTLD domain sits in ICANN's Expired Domain Deletion
// Policy timeline -- as its own section, using the same severity palette
// statusStyle already applies to the underlying EPP status: Pending
// Delete and Redemption Grace Period read as "at risk" (th.Err), Pending
// Restore and Auto-Renew Grace Period as a lower-key warning (th.Warn).
// No-op when l is nil -- ccTLDs and domains with no recognized lifecycle
// status never get this section (see internal/merge's deriveLifecycle).
func writeLifecycle(b *strings.Builder, th Theme, width int, l *model.LifecycleInfo) {
	if l == nil {
		return
	}
	style := th.Warn
	if l.Stage == model.LifecyclePendingDelete || l.Stage == model.LifecycleRedemptionGrace {
		style = th.Err
	}
	bodyWidth := width - 2
	if bodyWidth < 10 {
		bodyWidth = 10
	}
	b.WriteString("\n" + style.Render(l.Label) + "\n")
	for _, line := range wrapValue(l.Description, bodyWidth) {
		b.WriteString("  " + line + "\n")
	}
	if l.EstimatedEndsBy != nil {
		estimate := "No later than " + l.EstimatedEndsBy.UTC().Format("Jan 2, 2006") + " — " + l.EstimateBasis
		for _, line := range wrapValue(estimate, bodyWidth) {
			b.WriteString("  " + th.Muted.Render(line) + "\n")
		}
	}
}
