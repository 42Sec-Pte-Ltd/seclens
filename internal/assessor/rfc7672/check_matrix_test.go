package rfc7672

import (
	"context"
	"strings"
	"testing"

	"seclens/internal/report"
)

// daneCheckMatrix documents RFC 7672 status outcomes for representative DNS/MX inputs.
// Status is the UI badge source of truth; decorative fields (MXCovered, SyntaxOK, DNSSECValidated)
// may differ until post-fan-in enrichment runs.
var daneCheckMatrix = []struct {
	name            string
	domain          string
	mxHosts         []string
	setupDNS        func() *mockDNS
	gate            Gate
	wantStatus      string
	wantMXCovered   bool
	wantSyntaxOK    bool
	wantAdvertised  int
	wantIssueSubstr string
	enrichDNSSEC    *report.DNSSECResult
	wantFinalStatus string
	wantDNSSECVal   bool
}{
	{
		name:           "no MX info",
		domain:         "example.com",
		mxHosts:        nil,
		setupDNS:       newMockDNS,
		gate:           allowGate{},
		wantStatus:     "info",
		wantMXCovered:  false,
		wantSyntaxOK:   false,
		wantAdvertised: 0,
	},
	{
		name:           "gate skip",
		domain:         "example.com",
		mxHosts:        []string{"mx.example.com"},
		setupDNS:       newMockDNS,
		gate:           denyGate{},
		wantStatus:     "info",
		wantMXCovered:  false,
		wantSyntaxOK:   false,
		wantAdvertised: 0,
	},
	{
		name:    "partial TLSA warn",
		domain:  "example.com",
		mxHosts: []string{"mx1.example.com", "mx2.example.com"},
		setupDNS: func() *mockDNS {
			return newMockDNS().addTLSA("_25._tcp.mx1.example.com", "3 1 1 AABBCCDD")
		},
		gate:            allowGate{},
		wantStatus:      "warn",
		wantMXCovered:   false,
		wantSyntaxOK:    true,
		wantAdvertised:  1,
		wantIssueSubstr: "all MX hosts",
	},
	{
		name:    "full coverage pass after EnrichWithDNSSEC",
		domain:  "example.com",
		mxHosts: []string{"mx1.example.com", "mx2.example.com"},
		setupDNS: func() *mockDNS {
			return newMockDNS().
				addTLSA("_25._tcp.mx1.example.com", "3 1 1 AABBCCDD").
				addTLSA("_25._tcp.mx2.example.com", "3 1 1 AABBCCDD")
		},
		gate:           allowGate{},
		wantStatus:     "warn",
		wantMXCovered:  true,
		wantSyntaxOK:   true,
		wantAdvertised: 2,
		enrichDNSSEC: &report.DNSSECResult{
			DSPresent: true, DNSKEYPresent: true, ResolverAD: true, TLDSupported: true,
		},
		wantFinalStatus: "pass",
		wantDNSSECVal:   true,
	},
	{
		name:    "invalid TLSA syntax",
		domain:  "example.com",
		mxHosts: []string{"mx.example.com"},
		setupDNS: func() *mockDNS {
			return newMockDNS().addTLSA("_25._tcp.mx.example.com", "3 1 1 abc")
		},
		gate:            allowGate{},
		wantStatus:      "warn",
		wantMXCovered:   false,
		wantSyntaxOK:    false,
		wantAdvertised:  1,
		wantIssueSubstr: "invalid TLSA syntax",
	},
	{
		name:    "RFC3597 hash format",
		domain:  "example.com",
		mxHosts: []string{"mx.example.com"},
		setupDNS: func() *mockDNS {
			return newMockDNS().addTLSA("_25._tcp.mx.example.com", `\# 4 03 01 01 ab`)
		},
		gate:           allowGate{},
		wantStatus:     "warn",
		wantMXCovered:  true,
		wantSyntaxOK:   true,
		wantAdvertised: 1,
		enrichDNSSEC: &report.DNSSECResult{
			DSPresent: true, ResolverAD: true,
		},
		wantFinalStatus: "warn",
		wantDNSSECVal:   false,
	},
	{
		name:    "CNAME depth greater than 5",
		domain:  "example.com",
		mxHosts: []string{"mx.example.com"},
		setupDNS: func() *mockDNS {
			// maxTLSACNAMEDepth is 5; 6 hops exceeds the limit and TLSA must not be discovered.
			return newMockDNS().addCNAMEDepthChain("_25._tcp.mx.example.com", "3 1 1 DEADBEEF", 6)
		},
		gate:           allowGate{},
		wantStatus:     "info",
		wantMXCovered:  false,
		wantSyntaxOK:   false,
		wantAdvertised: 0,
	},
}

func TestCheck_Matrix(t *testing.T) {
	ctx := context.Background()
	for _, tc := range daneCheckMatrix {
		t.Run(tc.name, func(t *testing.T) {
			dns := tc.setupDNS()
			res := Check(ctx, Request{Domain: tc.domain, MXHosts: tc.mxHosts}, Deps{DNS: dns, Gate: tc.gate})

			if res.Status != tc.wantStatus {
				t.Fatalf("status=%q want %q message=%q", res.Status, tc.wantStatus, res.Message)
			}
			if res.MXCovered != tc.wantMXCovered {
				t.Fatalf("MXCovered=%v want %v", res.MXCovered, tc.wantMXCovered)
			}
			if res.SyntaxOK != tc.wantSyntaxOK {
				t.Fatalf("SyntaxOK=%v want %v", res.SyntaxOK, tc.wantSyntaxOK)
			}
			if len(res.AdvertisedFor) != tc.wantAdvertised {
				t.Fatalf("AdvertisedFor=%v want %d hosts", res.AdvertisedFor, tc.wantAdvertised)
			}
			if tc.wantIssueSubstr != "" {
				joined := strings.Join(res.Issues, " ")
				if !strings.Contains(joined, tc.wantIssueSubstr) {
					t.Fatalf("issues missing %q: %v", tc.wantIssueSubstr, res.Issues)
				}
			}

			if tc.name == "gate skip" && res.Message != "skipped (input gated)" {
				t.Fatalf("message=%q want skipped (input gated)", res.Message)
			}
			if tc.name == "no MX info" && !strings.Contains(res.Message, "No resolvable MX hosts") {
				t.Fatalf("message=%q want no MX hosts hint", res.Message)
			}

			if tc.enrichDNSSEC != nil {
				EnrichWithDNSSEC(&res, tc.enrichDNSSEC)
				if res.Status != tc.wantFinalStatus {
					t.Fatalf("post-enrich status=%q want %q", res.Status, tc.wantFinalStatus)
				}
				if res.DNSSECValidated != tc.wantDNSSECVal {
					t.Fatalf("DNSSECValidated=%v want %v", res.DNSSECValidated, tc.wantDNSSECVal)
				}
			}
		})
	}
}

func TestFetchTLSA_CNAMEDepthExceeded(t *testing.T) {
	dns := newMockDNS().addCNAMEDepthChain("_25._tcp.mx.example.com", "3 1 1 DEADBEEF", 6)
	qr, err := fetchTLSA(context.Background(), dns, "_25._tcp.mx.example.com")
	if err == nil {
		t.Fatal("expected error when CNAME depth exceeds limit")
	}
	if len(qr.RRs) != 0 {
		t.Fatalf("expected no TLSA RRs, got %v", qr.RRs)
	}
}

func TestFetchTLSA_CNAMEDepthWithinLimit(t *testing.T) {
	dns := newMockDNS().addCNAMEDepthChain("_25._tcp.mx.example.com", "3 1 1 CAFEBABE", 3)
	qr, err := fetchTLSA(context.Background(), dns, "_25._tcp.mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(qr.RRs) != 1 || qr.RRs[0].Data != "3 1 1 CAFEBABE" {
		t.Fatalf("rrs=%v", qr.RRs)
	}
}