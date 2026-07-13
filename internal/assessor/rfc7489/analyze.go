package rfc7489

import (
	"fmt"
	"strings"

	"seclens/internal/report"
)

// AnalyzeRaw parses, validates, and analyzes a raw DMARC TXT value (no DNS lookup).
func AnalyzeRaw(raw string, nullMXProfile bool) report.DMARCResult {
	rec := ParseRecord(raw)
	tagOK, tagIssues := ValidateTags(rec)
	uriIssues := ValidateURIs(rec)

	res := report.DMARCResult{
		Present:  true,
		Raw:      raw,
		Pct:      EffectivePct(rec),
		Status:   "info",
		SyntaxOK: tagOK,
	}

	if rec.VersionSet {
		res.Version = strings.ToLower(rec.Version)
	}
	if rec.PolicySet {
		res.Policy = rec.Policy
	}
	if rec.SubPolicySet {
		res.SubPolicy = rec.SubPolicy
	}
	if len(rec.RUA) > 0 {
		res.RUA = append([]string(nil), rec.RUA...)
	}
	if len(rec.RUF) > 0 {
		res.RUF = append([]string(nil), rec.RUF...)
	}
	res.ADKIM = EffectiveADKIM(rec)
	res.ASPF = EffectiveASPF(rec)
	if rec.FOSet {
		res.FO = rec.FO
	}
	if rec.RISet {
		res.RI = rec.RI
	}

	res.Issues = append(res.Issues, tagIssues...)
	res.Issues = append(res.Issues, uriIssues...)

	if !tagOK {
		res.Status = "fail"
		res.Message = "DMARC record has syntax errors (RFC 7489 §6.3)"
		return res
	}

	// Semantic / posture analysis (scoring uses Policy + SyntaxOK).
	switch res.Policy {
	case "reject":
		// best for the domain (25 pts)
	case "quarantine":
		res.Issues = append(res.Issues, "p=quarantine is better than none (15 pts partial) but weaker than reject for most senders")
	case "none":
		res.Issues = append(res.Issues, "p=none (monitoring only) — provides almost no blocking of spoofed mail (0 pts)")
		res.Status = "warn"
	default:
		res.Issues = append(res.Issues, "unknown p= value")
		res.Status = "fail"
	}

	if res.SubPolicy == "none" {
		res.Issues = append(res.Issues, "sp=none (subdomains have no DMARC protection) — weakens subdomain coverage even if p= is strong")
	} else if res.SubPolicy == "quarantine" {
		if res.Policy != "quarantine" {
			res.Issues = append(res.Issues, "sp=quarantine protects subdomains (while p=none only on the apex) — partial for subs")
		}
	} else if res.SubPolicy == "reject" {
		if res.Policy != "reject" {
			res.Issues = append(res.Issues, "sp=reject protects subdomains (p=none or weaker only on the apex itself)")
		}
	}

	if !nullMXProfile {
		domainPolActive := res.Policy != "none" && res.Policy != ""
		if domainPolActive && len(res.RUA) == 0 {
			res.Issues = append(res.Issues, "no rua= reporting address — you will not see aggregate reports of spoofing attempts")
		}
		if res.Pct < 100 && domainPolActive {
			res.Issues = append(res.Issues, fmt.Sprintf("pct=%d — only %d%% of mail is subject to the policy (common during rollout)", res.Pct, res.Pct))
		}
	}

	if len(res.Issues) == len(tagIssues)+len(uriIssues) {
		res.Status = "pass"
		res.Message = "DMARC present with strong policy"
	} else if res.Status == "info" {
		res.Status = "warn"
		res.Message = "DMARC present but not fully enforcing"
	}
	if res.Message == "" {
		res.Message = "DMARC record analyzed"
	}

	return res
}