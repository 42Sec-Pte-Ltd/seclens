package rfc7208

import (
	"fmt"
	"strings"

	"seclens/internal/report"
)

func appendRedirectChainRecommendation(res *report.SPFResult) {
	if !res.HasRedirect || res.RedirectDepth <= maxLookupTerms {
		return
	}
	for _, iss := range res.Issues {
		if strings.Contains(iss, "redirect chain length") {
			return
		}
	}
	res.Issues = append(res.Issues, fmt.Sprintf(
		"redirect chain length %d >10; we successfully followed the target for display and full scoring (leniency while <20 and terminating), but this exceeds the RFC 7208 §4.6.4 limit of 10 total counting terms during evaluation (redirect= counts as 1). Receivers may return PermError. Recommendation: reduce delegation depth or consolidate into direct mechanisms.",
		res.RedirectDepth,
	))
}