package rfc8461

import (
	"fmt"
	"strings"
)

// BuildRecommendedPolicy returns an RFC 8461 Appendix A style policy body (no DNS-only id field).
func BuildRecommendedPolicy(mxHosts []string) string {
	var b strings.Builder
	b.WriteString("version: STSv1\n")
	b.WriteString("mode: enforce\n")
	wroteMX := false
	for _, h := range mxHosts {
		h = strings.TrimSpace(h)
		h = strings.TrimSuffix(h, ".")
		if h != "" && h != "." {
			fmt.Fprintf(&b, "mx: %s\n", asciiHost(h))
			wroteMX = true
		}
	}
	if !wroteMX {
		b.WriteString("mx: <your-mx-host.example.com>\n")
	}
	b.WriteString("max_age: 86400\n")
	return b.String()
}

// RecommendedDNSTXT returns the _mta-sts TXT record to pair with RecommendedPolicy.
func RecommendedDNSTXT(existingID string, idValid bool) string {
	id := strings.TrimSpace(existingID)
	if !idValid || id == "" {
		id = FreshDNSPolicyID()
	}
	return fmt.Sprintf("v=STSv1; id=%s;", id)
}