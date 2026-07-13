package rfc8460

import (
	"fmt"
	"strings"
)

// RecommendedDNSTXT returns the _smtp._tls TXT record for TLS-RPT deployment.
func RecommendedDNSTXT(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimSuffix(domain, ".")
	return fmt.Sprintf("v=TLSRPTv1; rua=mailto:tlsrpt@%s", domain)
}