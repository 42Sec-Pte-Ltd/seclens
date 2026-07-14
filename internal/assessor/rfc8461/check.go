package rfc8461

import (
	"context"
	"fmt"
	"strings"

	"seclens/internal/report"
)

// Request is the input for an RFC 8461 policy assessment.
type Request struct {
	Domain  string
	MXHosts []string
}

// Check evaluates MTA-STS per RFC 8461 (DNS TXT + HTTPS policy + MX matching).
func Check(ctx context.Context, req Request, deps Deps) report.MTASTSResult {
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if !deps.Gate.ValidShape(domain) || !deps.Gate.Allowed(domain) {
		return report.MTASTSResult{Status: "info", Message: "skipped (input gated)"}
	}

	res := report.MTASTSResult{Status: "info"}
	name := "_mta-sts." + strings.TrimSuffix(domain, ".")
	txts, _ := deps.DNS.LookupTXT(ctx, name)

	rawTXT, advertised, txtIssue := selectMTASTSTXT(txts)
	if txtIssue != "" {
		res.Issues = append(res.Issues, txtIssue)
		res.Message = "Invalid MTA-STS DNS advertisement"
		res.Status = "warn"
		return res
	}
	res.RawDNSTXT = rawTXT
	res.DNSAdvertised = advertised

	if !res.DNSAdvertised {
		res.Message = "No MTA-STS DNS advertisement (v=STSv1)"
		res.Issues = append(res.Issues, "MTA-STS not advertised in DNS (very low adoption ~1% in large scans)")
		return res
	}

	id, idValid := parseDNSPolicyID(rawTXT)
	res.PolicyID = id
	res.DNSIDValid = idValid
	if !idValid {
		res.Issues = append(res.Issues, "DNS _mta-sts TXT missing or has invalid id= (RFC 8461 §3.1 requires id= with 1–32 alphanumeric characters)")
	}

	fetch, err := resolvePolicyFetch(ctx, deps, domain)
	if err != nil {
		res.Issues = append(res.Issues, classifyFetchError(err))
		res.Message = "MTA-STS advertised but policy fetch failed"
		res.Status = "warn"
		return res
	}

	if !contentTypeIsTextPlain(fetch.contentType) {
		res.Issues = append(res.Issues, fmt.Sprintf("policy Content-Type %q should be text/plain (RFC 8461 §3.3)", fetch.contentType))
	}

	res.RawPolicy = fetch.body
	res.PolicyFetched = true

	policy := parsePolicyBody(fetch.body)
	res.Version = policy.version
	res.Mode = policy.mode
	res.MXPatterns = policy.mx
	res.MaxAge = policy.maxAge

	syntaxOK, syntaxIssues := validatePolicy(policy)
	res.PolicySyntaxOK = syntaxOK
	res.Issues = append(res.Issues, syntaxIssues...)

	if len(req.MXHosts) == 0 {
		res.MXCoverageOK = false
		res.Issues = append(res.Issues, "no resolvable public MX hosts to validate against policy mx: patterns")
	} else {
		res.MXCoverageOK = isMXCovered(req.MXHosts, policy.mx)
	}

	switch policy.mode {
	case "enforce":
		// Full pass requires RFC 8461 §3.1 ABNF-valid DNS id= (1*32 ALPHA/DIGIT).
		// id= lives only in the _mta-sts TXT record, not in the policy file (§3.2 / Appendix A).
		if res.MXCoverageOK && syntaxOK && idValid {
			res.Status = "pass"
			res.Message = "MTA-STS fully configured (RFC 8461: enforce + MX covered + valid DNS id=)"
		} else if !res.MXCoverageOK {
			res.Status = "warn"
			res.Issues = append(res.Issues, "mode=enforce but one or more MX hosts are not authorized by the policy mx: lines (RFC 8461 §4.1)")
			res.Message = "MTA-STS policy does not cover current MX set"
		} else if !idValid {
			res.Status = "warn"
			res.Message = "MTA-STS enforce + MX OK but DNS id= missing or invalid (RFC 8461 §3.1)"
		} else {
			res.Status = "warn"
			res.Message = "MTA-STS enforce mode but configuration incomplete"
		}
	case "testing":
		res.Status = "warn"
		res.Issues = append(res.Issues, "mode=testing (reports only; does not block bad TLS/MX per RFC 8461 §5)")
		res.Message = "MTA-STS advertised and policy fetched (mode=testing)"
	case "none":
		res.Status = "warn"
		res.Issues = append(res.Issues, "mode=none: MTA-STS opt-out — policy disabled (RFC 8461 §8.3)")
		res.Message = "MTA-STS policy published with mode=none (disabled)"
	default:
		res.Status = "warn"
		res.Message = "MTA-STS advertised and policy fetched"
	}

	if !syntaxOK && res.Status == "pass" {
		res.Status = "warn"
	}

	if policy.maxAge > 0 && policy.maxAge < 86400 {
		res.Issues = append(res.Issues, fmt.Sprintf("max_age=%d is quite short (RFC 8461 §3.2 recommends weeks or greater; assessor flags <86400)", policy.maxAge))
	}

	return res
}

