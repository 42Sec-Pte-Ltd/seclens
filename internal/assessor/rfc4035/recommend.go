package rfc4035

import (
	"fmt"

	"seclens/internal/assessor/rfc4034"
	"seclens/internal/report"
)

// EnrichRecommendations appends optional deployment hints based on parsed DS/DNSKEY signals.
func EnrichRecommendations(res *report.DNSSECResult) {
	if res == nil || !res.TLDSupported {
		return
	}
	if !res.DSPresent {
		res.Issues = append(res.Issues, "no DS record — domain is not DNSSEC-signed (or parent not publishing delegation)")
		return
	}
	if !res.DNSKEYPresent {
		res.Issues = append(res.Issues, "DS record present but no DNSKEY at zone apex — incomplete DNSSEC chain")
	}
	if res.DSPresent && res.DNSKEYPresent && !resolverValidated(res) {
		res.Issues = append(res.Issues, "resolver did not return AD (Authenticated Data) — validation may be incomplete from this vantage point")
	}
	for _, raw := range res.DSRecords {
		parsed := rfc4034.ParseDS(raw)
		if !parsed.SyntaxOK {
			res.Issues = append(res.Issues, fmt.Sprintf("malformed DS record: %q", raw))
			continue
		}
		if w := rfc4034.AlgorithmWarning(parsed.Algorithm); w != "" {
			res.Issues = append(res.Issues, w)
		}
		if w := rfc4034.DigestTypeWarning(parsed.DigestType); w != "" {
			res.Issues = append(res.Issues, w)
		}
	}
}