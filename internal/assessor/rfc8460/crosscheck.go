package rfc8460

import (
	"strings"

	"seclens/internal/report"
)

// EnrichCrossChecks adds RFC 8460 companion hints after parallel assessor checks complete.
func EnrichCrossChecks(mtasts *report.MTASTSResult, tlsrpt *report.TLSRPTResult) {
	if mtasts == nil {
		return
	}
	if strings.EqualFold(mtasts.Mode, "testing") && (tlsrpt == nil || !tlsrpt.Present) {
		mtasts.Issues = append(mtasts.Issues, "mode=testing without TLS-RPT (_smtp._tls): failure visibility is limited (RFC 8461 §6 + RFC 8460)")
	}
}