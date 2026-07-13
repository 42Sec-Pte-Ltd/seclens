package rfc7489

import (
	"context"
	"fmt"
	"strings"

	"seclens/internal/report"
)

// Request is the input for an RFC 7489 DMARC assessment.
type Request struct {
	Domain        string
	NullMXProfile bool
}

// Check evaluates DMARC per RFC 7489 (_dmarc TXT lookup + parse + analyze).
func Check(ctx context.Context, req Request, deps Deps) report.DMARCResult {
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if !deps.Gate.ValidShape(domain) || !deps.Gate.Allowed(domain) {
		return report.DMARCResult{Status: "info", Message: "skipped (input gated)"}
	}

	name := "_dmarc." + strings.TrimSuffix(domain, ".")
	txts, err := deps.DNS.LookupTXT(ctx, name)
	if err != nil {
		return report.DMARCResult{
			Present: false,
			Status:  "fail",
			Message: fmt.Sprintf("DMARC lookup error: %v", err),
		}
	}

	raw, present, txtIssue := selectDMARCTXT(txts)
	if txtIssue != "" {
		return report.DMARCResult{
			Present:  false,
			Status:   "fail",
			Message:  "Invalid DMARC DNS publication",
			Issues:   []string{txtIssue},
			SyntaxOK: false,
		}
	}
	if !present {
		return report.DMARCResult{
			Present:  false,
			Pct:      100,
			Status:   "info",
			SyntaxOK: false,
			Message:  "No DMARC record published",
			Issues:   []string{"no DMARC — spoofing protection is incomplete even with SPF"},
		}
	}

	return AnalyzeRaw(raw, req.NullMXProfile)
}