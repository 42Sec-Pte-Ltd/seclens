package rfc7208

import (
	"context"
	"fmt"
	"strings"

	"seclens/internal/report"
)

// checkWithRedirects evaluates domain's SPF record and follows any
// redirect=/include: targets recursively. lookups is a pointer to a
// counter shared across the *entire* recursion tree for one top-level
// Check() call (all callers here run sequentially, no goroutines, so a
// plain *int is safe without a mutex). It is incremented once per
// recursive follow (depth > 0) and checked against maxSPFDNSLookups
// before performing the additional DNS lookup, actively bounding the
// total number of lookups regardless of how many include: mechanisms
// appear per level.
func checkWithRedirects(ctx context.Context, deps Deps, domain string, depth int, lookups *int) report.SPFResult {
	if depth > maxRedirectDepth {
		return report.SPFResult{
			Present: false,
			Status:  "fail",
			Message: "SPF redirect depth exceeded (safety limit 20)",
			Issues:  []string{"too many redirects or redirect loop (safety)"},
		}
	}

	if depth > 0 {
		*lookups++
		if *lookups > maxSPFDNSLookups {
			return report.SPFResult{
				Present: false,
				Status:  "fail",
				Message: fmt.Sprintf("too many DNS lookups (SPF chain exceeds %d limit)", maxSPFDNSLookups),
				Issues:  []string{fmt.Sprintf("too many DNS lookups (SPF chain exceeds %d limit) — PermError per RFC 7208 §4.6.4", maxSPFDNSLookups)},
			}
		}
	}

	raw, err := fetchSPF(ctx, deps, domain)
	if err != nil {
		if strings.Contains(err.Error(), "multiple v=spf1") {
			return report.SPFResult{
				Present: true,
				Status:  "fail",
				Message: "Multiple SPF records published",
				Issues:  []string{"multiple v=spf1 TXT records — PermError per RFC 7208 §4.5 (only one allowed)"},
			}
		}
		return report.SPFResult{
			Present: false,
			Status:  "fail",
			Message: fmt.Sprintf("SPF lookup error: %v", err),
			Issues:  []string{"DNS lookup failed"},
		}
	}

	res := AnalyzeRecord(raw, deps.Gate)
	parentIncludes := append([]string{}, res.Includes...)

	if res.HasRedirect && res.AllQualifier == "" {
		followRedirect(ctx, deps, domain, depth, raw, parentIncludes, &res, lookups)
	}

	// Always follow direct includes published on the parent record, even when redirect was followed.
	followIncludes(ctx, deps, depth, parentIncludes, &res, lookups)

	appendRedirectChainRecommendation(&res)
	enforceLookupLimit(&res)
	reconcileFinalStatus(&res)
	buildSPFChain(domain, raw, parentIncludes, &res)

	return res
}

func followRedirect(ctx context.Context, deps Deps, domain string, depth int, raw string, parentIncludes []string, res *report.SPFResult, lookups *int) {
	target := strings.ToLower(strings.TrimSpace(res.RedirectTarget))
	if target == "" || target == strings.ToLower(strings.TrimSpace(domain)) {
		return
	}
	if !deps.Gate.ValidMechanismDomain(target) {
		return
	}

	targetRes := checkWithRedirects(ctx, deps, target, depth+1, lookups)

	res.AllQualifier = targetRes.AllQualifier
	res.LookupCount += targetRes.LookupCount

	res.RedirectDepth = 1 + targetRes.RedirectDepth
	res.EffectiveLookupCount = targetRes.LookupCount

	if targetRes.RedirectedSPFRaw != "" {
		res.RedirectedSPFRaw = targetRes.RedirectedSPFRaw
	} else {
		res.RedirectedSPFRaw = targetRes.Raw
	}

	if len(targetRes.Issues) > 0 {
		res.Issues = append(res.Issues, fmt.Sprintf("redirect target %s issues: %s", target, strings.Join(targetRes.Issues, "; ")))
	}

	for k, v := range targetRes.IncludedRaws {
		if res.IncludedRaws == nil {
			res.IncludedRaws = make(map[string]string)
		}
		res.IncludedRaws[k] = v
	}

	res.Includes = targetRes.Includes

	if targetRes.Status == "fail" {
		res.Status = "fail"
	} else if targetRes.AllQualifier == "~" || targetRes.AllQualifier == "?" || targetRes.AllQualifier == "+" || targetRes.AllQualifier == "" {
		res.Status = "warn"
	}

	res.RedirectTarget = target
}

func followIncludes(ctx context.Context, deps Deps, depth int, parentIncludes []string, res *report.SPFResult, lookups *int) {
	for _, inc := range parentIncludes {
		if *lookups > maxSPFDNSLookups {
			break
		}
		if !deps.Gate.ValidMechanismDomain(inc) {
			continue
		}
		incRes := checkWithRedirects(ctx, deps, inc, depth+1, lookups)
		res.LookupCount += incRes.LookupCount

		if incRes.Status == "fail" {
			if isRealPermError(incRes.Issues) {
				res.Status = "fail"
			}
		}

		filtered := filterSubPolicyIssues(incRes)
		if len(filtered) > 0 {
			res.Issues = append(res.Issues, fmt.Sprintf("include %s issues: %s", inc, strings.Join(filtered, "; ")))
		}

		if incRes.Raw != "" {
			if res.IncludedRaws == nil {
				res.IncludedRaws = make(map[string]string)
			}
			res.IncludedRaws[inc] = incRes.Raw
		}
		for k, v := range incRes.IncludedRaws {
			if res.IncludedRaws == nil {
				res.IncludedRaws = make(map[string]string)
			}
			res.IncludedRaws[k] = v
		}
	}
}

func isRealPermError(issues []string) bool {
	for _, iss := range issues {
		l := strings.ToLower(iss)
		if strings.Contains(l, "dns lookup failed") ||
			strings.Contains(l, "multiple v=spf1") ||
			strings.Contains(l, "invalid mechanism") ||
			strings.Contains(l, "too many dns lookups") {
			return true
		}
	}
	return false
}

func filterSubPolicyIssues(incRes report.SPFResult) []string {
	filtered := make([]string, 0, len(incRes.Issues))
	for _, iss := range incRes.Issues {
		l := strings.ToLower(iss)
		if strings.Contains(l, "~all (softfail) is common but weaker than -all for anti-spoofing") {
			continue
		}
		if strings.Contains(l, "no 'all' mechanism — policy is not terminated") ||
			strings.Contains(l, "+all or missing all allows almost anyone to spoof (very bad)") {
			if incRes.AllQualifier != "" {
				continue
			}
		}
		filtered = append(filtered, iss)
	}
	return filtered
}

func buildSPFChain(domain, raw string, parentIncludes []string, res *report.SPFResult) {
	chain := []report.SPFChainEntry{
		{
			Level:  0,
			Domain: domain,
			Raw:    raw,
			Type:   "published",
		},
	}
	effLevel := 0
	if res.HasRedirect && res.RedirectedSPFRaw != "" && res.RedirectTarget != "" {
		chain = append(chain, report.SPFChainEntry{
			Level:       1,
			Domain:      res.RedirectTarget,
			Raw:         res.RedirectedSPFRaw,
			Type:        "redirect-target",
			IsEffective: true,
			Note:        "effective policy – only this terminating *all counts per RFC 7208",
		})
		effLevel = 1
	} else if res.AllQualifier != "" {
		chain[0].IsEffective = true
		chain[0].Note = "effective policy – *all here counts per RFC 7208"
	}

	displayIncludes := res.Includes
	if len(displayIncludes) == 0 {
		displayIncludes = parentIncludes
	}
	for _, inc := range displayIncludes {
		if r, ok := res.IncludedRaws[inc]; ok {
			chain = append(chain, report.SPFChainEntry{
				Level:  effLevel + 1,
				Domain: inc,
				Raw:    r,
				Type:   "include",
				Note:   "followed from effective policy level",
			})
		}
	}

	for k, v := range res.IncludedRaws {
		isDirect := false
		for _, inc := range displayIncludes {
			if inc == k {
				isDirect = true
				break
			}
		}
		if !isDirect {
			chain = append(chain, report.SPFChainEntry{
				Level:  effLevel + 2,
				Domain: k,
				Raw:    v,
				Type:   "include",
				Note:   "nested/deeper include followed from a direct include",
			})
		}
	}
	res.SPFChain = chain
}