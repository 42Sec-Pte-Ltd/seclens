package rfc4035

import (
	"testing"

	"seclens/internal/assessor/rfc4034"
	"seclens/internal/assessor/testutil"
	"seclens/internal/report"
)

func TestEnrichRecommendations_Matrix(t *testing.T) {
	const (
		goodDS         = "2371 13 2 E9D6FAE1DAD409B0EE20831B6B70C03C773E41A8"
		deprecatedAlg  = "2371 5 2 E9D6FAE1DAD409B0EE20831B6B70C03C773E41A8"
		deprecatedDig  = "2371 13 1 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
		malformedDS    = "2371 13 2"
	)

	cases := []struct {
		name       string
		in         report.DNSSECResult
		wantIssues []string
	}{
		{
			name: "deprecated algorithm",
			in: report.DNSSECResult{
				TLDSupported: true,
				DSPresent:    true,
				DNSKEYPresent: true,
				ResolverAD:   true,
				DSRecords:    []string{deprecatedAlg},
			},
			wantIssues: []string{rfc4034.AlgorithmWarning(rfc4034.AlgRSASHA1)},
		},
		{
			name: "deprecated digest",
			in: report.DNSSECResult{
				TLDSupported: true,
				DSPresent:    true,
				DNSKEYPresent: true,
				ResolverAD:   true,
				DSRecords:    []string{deprecatedDig},
			},
			wantIssues: []string{rfc4034.DigestTypeWarning(rfc4034.DigestSHA1)},
		},
		{
			name: "ds without dnskey",
			in: report.DNSSECResult{
				TLDSupported: true,
				DSPresent:    true,
				DNSKEYPresent: false,
				ResolverAD:   true,
				DSRecords:    []string{goodDS},
			},
			wantIssues: []string{"DS record present but no DNSKEY at zone apex"},
		},
		{
			name: "no ad",
			in: report.DNSSECResult{
				TLDSupported: true,
				DSPresent:    true,
				DNSKEYPresent: true,
				ResolverAD:   false,
				DSRecords:    []string{goodDS},
			},
			wantIssues: []string{"resolver did not return AD"},
		},
		{
			name: "malformed ds",
			in: report.DNSSECResult{
				TLDSupported: true,
				DSPresent:    true,
				DNSKEYPresent: true,
				ResolverAD:   true,
				DSRecords:    []string{malformedDS},
			},
			wantIssues: []string{"malformed DS record"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := tc.in
			EnrichRecommendations(&res)
			testutil.AssertIssuesContain(t, res.Issues, tc.wantIssues...)
		})
	}
}

func TestEnrichRecommendations_SkipsWhenNotApplicable(t *testing.T) {
	res := report.DNSSECResult{TLDSupported: false, DSPresent: true, DSRecords: []string{"2371 5 2 AABB"}}
	EnrichRecommendations(&res)
	if len(res.Issues) != 0 {
		t.Fatalf("expected no issues when TLD unsupported: %v", res.Issues)
	}

	res = report.DNSSECResult{TLDSupported: true, DSPresent: false}
	EnrichRecommendations(&res)
	testutil.AssertIssuesContain(t, res.Issues, "no DS record")
}