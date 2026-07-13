package rfc8460

import (
	"context"
	"strings"

	"seclens/internal/report"
)

// Request is the input for an RFC 8460 TLS-RPT assessment.
type Request struct {
	Domain string
}

// Check evaluates TLS-RPT per RFC 8460 (_smtp._tls TXT + rua validation).
func Check(ctx context.Context, req Request, deps Deps) report.TLSRPTResult {
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if !deps.Gate.ValidShape(domain) || !deps.Gate.Allowed(domain) {
		return report.TLSRPTResult{Status: "info", Message: "skipped (input gated)"}
	}

	res := report.TLSRPTResult{Status: "info"}
	name := "_smtp._tls." + strings.TrimSuffix(domain, ".")
	txts, _ := deps.DNS.LookupTXT(ctx, name)

	rawTXT, present, txtIssue := selectTLSRPTTXT(txts)
	res.Raw = rawTXT
	res.Present = present
	if txtIssue != "" {
		// Present=true: TLS-RPT is advertised but DNS selection/syntax is invalid.
		res.SyntaxOK = false
		res.Issues = append(res.Issues, txtIssue)
		res.Message = "Invalid TLS-RPT DNS advertisement"
		res.Status = "warn"
		return res
	}

	if !present {
		res.Message = "No TLS-RPT record (_smtp._tls)"
		res.Issues = append(res.Issues, "TLS-RPT gives visibility into STARTTLS failures; low adoption is common")
		return res
	}

	parsed := parseTLSRPTRecord(rawTXT)
	res.Version = parsed.version
	res.SyntaxOK = parsed.syntaxOK
	res.RUA = parsed.rua
	res.RUAPresent = len(parsed.rua) > 0

	if !parsed.syntaxOK {
		res.Status = "warn"
		res.Message = "TLS-RPT record has invalid syntax"
		res.Issues = append(res.Issues, "v= must be TLSRPTv1 (RFC 8460 §3.1)")
		return res
	}

	validRUA, ruaIssues := validateRUAURIs(parsed.rua)
	res.Issues = append(res.Issues, ruaIssues...)

	if len(validRUA) >= 1 {
		res.Status = "pass"
		res.Message = "TLS-RPT advertised (v=" + res.Version + ", rua=" + strings.Join(validRUA, ",") + ")"
		return res
	}

	res.Status = "warn"
	if !res.RUAPresent {
		res.Message = "TLS-RPT advertised but missing rua="
		res.Issues = append(res.Issues, "rua= is required for TLS-RPT reporting (RFC 8460)")
	} else {
		res.Message = "TLS-RPT advertised but rua has no valid mailto: or https: URIs"
	}
	return res
}