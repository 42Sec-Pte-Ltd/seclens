package rfc7208

import (
	"context"
	"strings"

	"seclens/internal/report"
)

// Request is the input for an RFC 7208 SPF assessment.
type Request struct {
	Domain string
}

// Check evaluates SPF per RFC 7208 (TXT fetch, parse, include/redirect following).
func Check(ctx context.Context, req Request, deps Deps) report.SPFResult {
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if !deps.Gate.ValidShape(domain) || !deps.Gate.Allowed(domain) {
		return report.SPFResult{Present: false, Status: "info", Message: "skipped (input gated)"}
	}
	lookups := 0
	return checkWithRedirects(ctx, deps, domain, 0, &lookups)
}