package rfc4035

import (
	"context"
	"testing"

	"seclens/internal/assessor/testutil"
	"seclens/internal/report"
)

func TestCheck_Matrix(t *testing.T) {
	const (
		parentDS  = "2371 13 2 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"
		goodDS    = "2371 13 2 E9D6FAE1DAD409B0EE20831B6B70C03C773E41A8"
		goodDNSKEY = "257 3 13 AwEAAc6h7Rfk3A1D0u1i0vYrK8mH3uG8o0o0o0o0o0o0o0o0o0o0o0o0o0o0"
	)

	cases := []struct {
		name       string
		domain     string
		gate       Gate
		answers    map[string]map[uint16]QueryResult
		wantStatus string
		assert     func(t *testing.T, res report.DNSSECResult)
	}{
		{
			name:       "gated",
			domain:     "example.com",
			gate:       testutil.DenyGate{},
			wantStatus: "info",
			assert: func(t *testing.T, res report.DNSSECResult) {
				if res.Message != "skipped (input gated)" {
					t.Fatalf("message=%q want skipped (input gated)", res.Message)
				}
			},
		},
		{
			name:       "tld unsupported",
			domain:     "example.test",
			gate:       testutil.AllowGate{},
			answers:    map[string]map[uint16]QueryResult{},
			wantStatus: "info",
			assert: func(t *testing.T, res report.DNSSECResult) {
				if res.TLDSupported {
					t.Fatal("expected TLDSupported false")
				}
				if res.Message != notApplicableMessage {
					t.Fatalf("message=%q", res.Message)
				}
			},
		},
		{
			name:   "ds ad pass full chain",
			domain: "signed.example.com",
			gate:   testutil.AllowGate{},
			answers: map[string]map[uint16]QueryResult{
				"com": {qtypeDS: {RRs: []RR{{Data: parentDS}}}},
				"signed.example.com": {
					qtypeDS:     {AD: true, RRs: []RR{{Data: goodDS}}},
					qtypeDNSKEY: {RRs: []RR{{Data: goodDNSKEY}}},
					qtypeTXT:    {AD: true, RRs: []RR{{Data: "v=spf1 -all"}}},
				},
			},
			wantStatus: "pass",
			assert: func(t *testing.T, res report.DNSSECResult) {
				if !res.DSPresent || !res.DNSKEYPresent || !res.ResolverAD || !res.SyntaxOK {
					t.Fatalf("result=%+v", res)
				}
			},
		},
		{
			name:   "ds ad warn without dnskey",
			domain: "ad-signed.example.com",
			gate:   testutil.AllowGate{},
			answers: map[string]map[uint16]QueryResult{
				"com": {qtypeDS: {RRs: []RR{{Data: parentDS}}}},
				"ad-signed.example.com": {
					qtypeDS:  {AD: true, RRs: []RR{{Data: goodDS}}},
					qtypeTXT: {AD: true, RRs: []RR{{Data: "v=spf1 -all"}}},
				},
			},
			wantStatus: "warn",
			assert: func(t *testing.T, res report.DNSSECResult) {
				if !res.DSPresent || res.DNSKEYPresent || !res.ResolverAD {
					t.Fatalf("result=%+v", res)
				}
			},
		},
		{
			name:   "ds only warn",
			domain: "partial.example.com",
			gate:   testutil.AllowGate{},
			answers: map[string]map[uint16]QueryResult{
				"com": {qtypeDS: {RRs: []RR{{Data: parentDS}}}},
				"partial.example.com": {
					qtypeDS:  {RRs: []RR{{Data: goodDS}}},
					qtypeTXT: {AD: false, RRs: []RR{{Data: "v=spf1 -all"}}},
				},
			},
			wantStatus: "warn",
			assert: func(t *testing.T, res report.DNSSECResult) {
				if !res.DSPresent || res.ResolverAD || !res.SyntaxOK {
					t.Fatalf("result=%+v", res)
				}
			},
		},
		{
			name:   "malformed ds",
			domain: "bad-ds.example.com",
			gate:   testutil.AllowGate{},
			answers: map[string]map[uint16]QueryResult{
				"com": {qtypeDS: {RRs: []RR{{Data: parentDS}}}},
				"bad-ds.example.com": {
					qtypeDS:  {RRs: []RR{{Data: "2371 13 2"}}},
					qtypeTXT: {AD: false},
				},
			},
			wantStatus: "warn",
			assert: func(t *testing.T, res report.DNSSECResult) {
				if !res.DSPresent || res.SyntaxOK {
					t.Fatalf("result=%+v", res)
				}
				testutil.AssertIssuesContain(t, res.Issues, "malformed DS record")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dns := &mockDNS{answers: tc.answers}
			res := Check(context.Background(), Request{Domain: tc.domain}, Deps{DNS: dns, Gate: tc.gate})
			testutil.AssertStatus(t, res.Status, tc.wantStatus, tc.name)
			if tc.assert != nil {
				tc.assert(t, res)
			}
		})
	}
}

func TestProbeAD_DSFallback(t *testing.T) {
	const goodDS = "2371 13 2 E9D6FAE1DAD409B0EE20831B6B70C03C773E41A8"
	domain := "fallback.example.com"
	dns := &mockDNS{answers: map[string]map[uint16]QueryResult{
		domain: {
			qtypeTXT: {Status: 3},
			qtypeDS:  {AD: true, Status: 0, RRs: []RR{{Data: goodDS}}},
		},
	}}
	if !ProbeAD(context.Background(), domain, dns) {
		t.Fatal("expected AD from DS fallback when TXT is NXDOMAIN")
	}
}