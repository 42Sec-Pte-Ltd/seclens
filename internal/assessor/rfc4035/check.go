package rfc4035

import (
	"context"
	"strings"

	"seclens/internal/assessor/rfc4034"
	"seclens/internal/report"
)

// Request is the input for an RFC 4035 DNSSEC assessment.
type Request struct {
	Domain string
}

// Check evaluates DNSSEC chain signals per RFC 4034/4035 (DS, DNSKEY, resolver AD).
func Check(ctx context.Context, req Request, deps Deps) report.DNSSECResult {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(req.Domain), "."))
	if !deps.Gate.ValidShape(domain) || !deps.Gate.Allowed(domain) {
		return report.DNSSECResult{Status: "info", Message: "skipped (input gated)"}
	}

	res := report.DNSSECResult{Status: "info"}
	res.TLDSupported = ParentSupportsDNSSEC(ctx, domain, deps.DNS)
	if !res.TLDSupported {
		ApplyStatus(&res)
		return res
	}

	dsQR, _ := deps.DNS.LookupRRWithMeta(ctx, domain, qtypeDS)
	res.DSPresent = len(dsQR.RRs) > 0
	allDSOK := res.DSPresent
	for _, rr := range dsQR.RRs {
		res.DSRecords = append(res.DSRecords, rr.Data)
		if !rfc4034.ParseDS(rr.Data).SyntaxOK {
			allDSOK = false
		}
	}
	res.SyntaxOK = allDSOK && res.DSPresent

	dnskeyQR, _ := deps.DNS.LookupRRWithMeta(ctx, domain, qtypeDNSKEY)
	for _, rr := range dnskeyQR.RRs {
		if rfc4034.DNSKEYPresent(rr.Data) {
			res.DNSKEYPresent = true
			break
		}
	}

	res.ResolverAD = ProbeAD(ctx, domain, deps.DNS)
	res.AD = res.ResolverAD

	EnrichRecommendations(&res)
	ApplyStatus(&res)
	return res
}