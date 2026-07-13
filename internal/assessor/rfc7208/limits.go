package rfc7208

import (
	"fmt"
	"strings"

	"seclens/internal/report"
)

const maxRedirectDepth = 20
const maxLookupTerms = 10

// maxSPFDNSLookups is a global, chain-wide budget on the number of DNS
// lookups triggered while following include:/redirect= targets for a single
// top-level Check() call. RFC 7208 §4.6.4 caps this at 10 for spec
// compliance, but that limit is only evaluated passively after a (possibly
// very large) chain has already been fully fetched. maxSPFDNSLookups is
// enforced actively, before each additional lookup, so a malicious domain
// cannot force an unbounded number of DNS queries via a wide fan-out of
// include: mechanisms at each of the (already depth-capped) 20 levels. The
// value is intentionally higher than the RFC's 10 so legitimate, complex
// chains within the existing depth cap are not falsely rejected.
const maxSPFDNSLookups = 30

func enforceLookupLimit(res *report.SPFResult) {
	if res.LookupCount <= maxLookupTerms {
		return
	}
	already := false
	for _, iss := range res.Issues {
		if strings.Contains(iss, "too many DNS lookups") {
			already = true
			break
		}
	}
	if !already {
		res.Issues = append(res.Issues, fmt.Sprintf("too many DNS lookups (%d > 10) — PermError per RFC 7208 §4.6.4", res.LookupCount))
	}
	// Prod parity: nested include chains may exceed 10 while still being operational; warn until safety cap.
	if res.LookupCount > maxRedirectDepth {
		res.Status = "fail"
	} else if res.Status != "fail" {
		res.Status = "warn"
	}
}