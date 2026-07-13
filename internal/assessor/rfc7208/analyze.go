package rfc7208

import (
	"fmt"
	"strings"

	"seclens/internal/report"
)

// AnalyzeRecord parses and analyzes a raw SPF record without DNS following.
// Exported for assessor status-contract tests and unit tests.
func AnalyzeRecord(raw string, gate Gate) report.SPFResult {
	res := report.SPFResult{
		Present: raw != "",
		Raw:     raw,
		Status:  "info",
	}

	if raw == "" {
		res.Message = "No SPF record found"
		res.Issues = append(res.Issues, "missing SPF (publishing is near-universal hygiene for mail domains)")
		return res
	}

	rec, parseIssues := tokenizeRecord(raw)
	for _, iss := range parseIssues {
		if iss == "record does not start with v=spf1" || iss == "empty SPF record" {
			res.Issues = append(res.Issues, iss)
			res.Status = "fail"
			if iss == "record does not start with v=spf1" {
				res.Message = "Invalid SPF (wrong version/start)"
			} else {
				res.Message = "Empty SPF record"
			}
			return res
		}
	}

	res.Version = rec.version
	res.Mechanisms = rec.mechanisms
	res.Includes = rec.includes
	res.LookupCount = rec.lookupCount
	res.HasRedirect = rec.hasRedirect
	res.RedirectTarget = rec.redirectTarget
	res.AllQualifier = rec.allQualifier

	for _, iss := range parseIssues {
		res.Issues = append(res.Issues, iss)
		res.Status = "fail"
	}

	for _, tok := range rec.tokens {
		if !isValidSPFTerm(tok.mech) {
			res.Issues = append(res.Issues, fmt.Sprintf("invalid mechanism or modifier %q (PermError per RFC 7208)", tok.raw))
			res.Status = "fail"
		}
		validateMechanismDomainSpec(tok, gate, &res)
	}

	applyTerminationAnalysis(&res)

	if rec.lookupCount > maxLookupTerms {
		res.Issues = append(res.Issues, fmt.Sprintf("too many DNS lookups (%d > 10) — receivers may treat as permerror", rec.lookupCount))
		res.Status = "fail"
	} else if rec.lookupCount > 8 {
		res.Issues = append(res.Issues, fmt.Sprintf("high number of DNS lookups (%d) — close to the 10 limit, risky with includes", rec.lookupCount))
	}

	if res.HasRedirect && res.AllQualifier != "" {
		res.Issues = append(res.Issues, "redirect= used together with an all mechanism — redirect is only evaluated if no all matches")
	}

	for _, tok := range rec.tokens {
		lp := tok.lower
		if lp == "ptr" || strings.HasPrefix(lp, "ptr:") {
			res.Issues = append(res.Issues, "ptr mechanism is strongly discouraged (expensive + rarely useful)")
		}
	}

	reconcileLocalStatus(&res)
	return res
}

func validateMechanismDomainSpec(tok token, gate Gate, res *report.SPFResult) {
	lt := strings.ToLower(tok.mech)
	switch {
	case strings.HasPrefix(lt, "include:"):
		target := strings.TrimPrefix(tok.mech, "include:")
		if !validateDomainSpec(target, gate) {
			res.Issues = append(res.Issues, fmt.Sprintf("invalid include domain-spec %q (PermError per RFC 7208)", target))
			res.Status = "fail"
		}
	case strings.HasPrefix(lt, "redirect="):
		target := strings.TrimPrefix(tok.mech, "redirect=")
		if !validateDomainSpec(target, gate) {
			res.Issues = append(res.Issues, fmt.Sprintf("invalid redirect domain-spec %q (PermError per RFC 7208)", target))
			res.Status = "fail"
		}
	case strings.HasPrefix(lt, "exists:"):
		target := strings.TrimPrefix(tok.mech, "exists:")
		if !validateDomainSpec(target, gate) {
			res.Issues = append(res.Issues, fmt.Sprintf("invalid exists domain-spec %q (PermError per RFC 7208)", target))
			res.Status = "fail"
		}
	case strings.HasPrefix(lt, "exp="):
		target := strings.TrimPrefix(tok.mech, "exp=")
		if !validateDomainSpec(target, gate) {
			res.Issues = append(res.Issues, fmt.Sprintf("invalid exp domain-spec %q (PermError per RFC 7208)", target))
			res.Status = "fail"
		}
	}
}

func applyTerminationAnalysis(res *report.SPFResult) {
	if res.AllQualifier == "" && !res.HasRedirect {
		res.Issues = append(res.Issues, "no 'all' mechanism — policy is not terminated (implicit +all behavior for unmatched)")
		res.Status = "fail"
	}
	switch res.AllQualifier {
	case "-":
	case "~":
		res.Issues = append(res.Issues, "~all (softfail) is common but weaker than -all for anti-spoofing")
	case "+", "":
		if !res.HasRedirect {
			res.Issues = append(res.Issues, "+all or missing all allows almost anyone to spoof (very bad)")
			res.Status = "fail"
		}
	case "?":
		res.Issues = append(res.Issues, "?all (neutral) gives almost no protection")
	}
}

func reconcileLocalStatus(res *report.SPFResult) {
	if len(res.Issues) == 0 {
		res.Status = "pass"
		res.Message = "SPF present and reasonably strict"
	} else if res.Status == "info" {
		res.Status = "warn"
		res.Message = "SPF present but has issues"
	}
	if res.Message == "" {
		res.Message = "SPF present with findings"
	}
}

func reconcileFinalStatus(res *report.SPFResult) {
	// Absent SPF: keep the discovery message; do not overwrite with "SPF present …" copy.
	if !res.Present {
		if res.Status == "info" || res.Status == "" {
			res.Status = "warn"
		}
		if res.Message == "" {
			res.Message = "No SPF record found"
		}
		return
	}
	if res.Status == "fail" {
		return
	}
	if len(res.Issues) == 0 && res.AllQualifier == "-" {
		res.Status = "pass"
		res.Message = "SPF present and RFC 7208 compliant with strict policy"
	} else if len(res.Issues) == 0 {
		res.Status = "warn"
		res.Message = "SPF present and RFC 7208 compliant but not maximally strict"
	} else if res.Status == "info" || res.Status == "" {
		res.Status = "warn"
		res.Message = "SPF present, RFC compliant but with findings"
	}
}