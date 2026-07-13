package rfc7489

import (
	"fmt"
	"strings"
)

// DMARCHost returns the _dmarc DNS name for a domain.
func DMARCHost(domain string) string {
	return "_dmarc." + strings.TrimSuffix(strings.TrimSpace(domain), ".")
}

// RecommendedRecord returns a suggested DMARC TXT value for deployment.
func RecommendedRecord(domain string, nullMXProfile bool) string {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if nullMXProfile {
		return "v=DMARC1; p=reject"
	}
	return fmt.Sprintf("v=DMARC1; p=reject; rua=mailto:dmarc@%s; pct=100; adkim=r; aspf=r", domain)
}