package bimi

import (
	"context"
	"fmt"
	"strings"

	"seclens/internal/assessor/rfc7489"
	"seclens/internal/assessor/txtselect"
	"seclens/internal/report"
)

// DMARCGaps lists unmet BIMI DMARC prerequisites for the author domain.
// pct is compared to 100. The assessor stores an absent pct as 100.
// org is consulted only when orgDomain differs from domain.
func DMARCGaps(domain string, author *report.DMARCResult, orgDomain string, org *report.DMARCResult) []string {
	gaps := authorGaps(author)
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	orgDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(orgDomain), "."))
	if orgDomain == "" || orgDomain == domain {
		return gaps
	}
	return append(gaps, orgGaps(orgDomain, org)...)
}

func authorGaps(d *report.DMARCResult) []string {
	if d == nil {
		return []string{"DMARC result unavailable"}
	}
	if !d.Present {
		return []string{"DMARC record absent"}
	}
	var out []string
	if !d.SyntaxOK {
		out = append(out, "DMARC syntax is not valid")
	}
	if d.Policy != "quarantine" && d.Policy != "reject" {
		out = append(out, fmt.Sprintf("DMARC p=%s is not quarantine or reject", d.Policy))
	}
	if d.Pct != 100 {
		out = append(out, fmt.Sprintf("DMARC pct=%d (want 100 or absent)", d.Pct))
	}
	if d.SubPolicy == "none" {
		out = append(out, "DMARC sp=none")
	}
	return out
}

func orgGaps(orgDomain string, d *report.DMARCResult) []string {
	if d == nil || !d.Present {
		if d != nil && len(d.Issues) > 0 {
			return []string{fmt.Sprintf("organizational domain %s DMARC: %s", orgDomain, d.Issues[0])}
		}
		if d != nil && d.Message != "" {
			return []string{fmt.Sprintf("organizational domain %s DMARC lookup: %s", orgDomain, d.Message)}
		}
		return []string{fmt.Sprintf("organizational domain %s DMARC record absent", orgDomain)}
	}
	var out []string
	if !d.SyntaxOK {
		out = append(out, fmt.Sprintf("organizational domain %s DMARC syntax is not valid", orgDomain))
	}
	if d.Policy != "quarantine" && d.Policy != "reject" {
		out = append(out, fmt.Sprintf("organizational domain %s DMARC p=%s is not quarantine or reject", orgDomain, d.Policy))
	}
	if d.Pct != 100 {
		out = append(out, fmt.Sprintf("organizational domain %s DMARC pct=%d (want 100 or absent)", orgDomain, d.Pct))
	}
	if d.SubPolicy == "none" {
		out = append(out, fmt.Sprintf("organizational domain %s DMARC sp=none", orgDomain))
	}
	return out
}

// lookupOrgDMARC reads _dmarc.<orgDomain> once. The author result is not re-queried.
func lookupOrgDMARC(ctx context.Context, orgDomain string, dns DNS) *report.DMARCResult {
	name := rfc7489.DMARCHost(orgDomain)
	txts, err := dns.LookupTXT(ctx, name)
	if err != nil {
		return &report.DMARCResult{
			Present: false,
			Status:  "fail",
			Message: fmt.Sprintf("DMARC lookup error: %v", err),
		}
	}
	raw, present, issue := txtselect.SelectSingle(txts, "v=DMARC1",
		"multiple _dmarc TXT records starting with v=DMARC1", false)
	if issue != "" || !present {
		res := &report.DMARCResult{Present: false, SyntaxOK: false}
		if issue != "" {
			res.Issues = []string{issue}
		}
		return res
	}
	analyzed := rfc7489.AnalyzeRaw(raw, false)
	return &analyzed
}
