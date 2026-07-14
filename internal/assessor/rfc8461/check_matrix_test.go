package rfc8461

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"seclens/internal/assessor/testutil"
	"seclens/internal/report"
)

const matrixDomain = "example.com"

// matrixDNS wraps testutil.MockTXT and satisfies DNS (ResolveHostIPs unused when PolicyFetcher is injected).
type matrixDNS struct {
	testutil.MockTXT
}

func (matrixDNS) ResolveHostIPs(_ context.Context, _ string) ([]net.IP, error) {
	return nil, nil
}

type mockPolicyFetcher struct {
	body string
	err  error
}

func NewMockPolicyFetcher(body string, err error) PolicyFetcher {
	return &mockPolicyFetcher{body: body, err: err}
}

func (m *mockPolicyFetcher) FetchPolicy(_ context.Context, _ Deps, _ string) (policyFetchResult, error) {
	return policyFetchResult{body: m.body, contentType: "text/plain", statusCode: 200}, m.err
}

// publicIPGuard mirrors production bridge behavior for tests (allows non-private IPs).
type publicIPGuard struct{}

func (publicIPGuard) PublicIPs(ips []net.IP) []net.IP {
	var out []net.IP
	for _, ip := range ips {
		if ip != nil && !ip.IsPrivate() && !ip.IsLoopback() {
			out = append(out, ip)
		}
	}
	return out
}

func (publicIPGuard) IsPrivateOrLocal(ip net.IP) bool {
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback())
}

func enforcePolicy(mxPattern string) string {
	return fmt.Sprintf("version: STSv1\nmode: enforce\nmx: %s\nmax_age: 86400\n", mxPattern)
}

func modePolicy(mode string) string {
	return fmt.Sprintf("version: STSv1\nmode: %s\nmx: *.example.com\nmax_age: 86400\n", mode)
}

func matrixDeps(txt []string, fetcher PolicyFetcher, gate Gate) Deps {
	return Deps{
		DNS: matrixDNS{MockTXT: testutil.MockTXT{
			"_mta-sts." + matrixDomain: txt,
		}},
		Gate:          gate,
		IPGuard:       publicIPGuard{},
		PolicyFetcher: fetcher,
	}
}

func TestCheckMatrix(t *testing.T) {
	ctx := context.Background()
	mxCovered := []string{"mx1.example.com", "mx2.example.com"}
	mxGap := []string{"mx1.example.com", "mail.other.example"}

	tests := []struct {
		name       string
		txt        []string
		mxHosts    []string
		policyBody string
		fetchErr   error
		gate       Gate
		wantStatus string
		wantIssues []string
		check      func(t *testing.T, res report.MTASTSResult)
	}{
		{
			name:       "not advertised info",
			txt:        nil,
			wantStatus: "info",
			wantIssues: []string{"not advertised"},
		},
		{
			name:       "multiple TXT warn",
			txt:        []string{"v=STSv1; id=1;", "v=STSv1; id=2;"},
			wantStatus: "warn",
			wantIssues: []string{"exactly one"},
		},
		{
			name:       "enforce+MX pass",
			txt:        []string{"v=STSv1; id=20160831085700Z;"},
			mxHosts:    mxCovered,
			policyBody: enforcePolicy("*.example.com"),
			wantStatus: "pass",
		},
		{
			name:       "enforce+MX gap warn",
			txt:        []string{"v=STSv1; id=20160831085700Z;"},
			mxHosts:    mxGap,
			policyBody: enforcePolicy("*.example.com"),
			wantStatus: "warn",
			wantIssues: []string{"not authorized"},
		},
		{
			name:       "mode=testing",
			txt:        []string{"v=STSv1; id=20160831085700Z;"},
			mxHosts:    mxCovered,
			policyBody: modePolicy("testing"),
			wantStatus: "warn",
			wantIssues: []string{"mode=testing"},
		},
		{
			name:       "mode=none",
			txt:        []string{"v=STSv1; id=20160831085700Z;"},
			policyBody: modePolicy("none"),
			wantStatus: "warn",
			wantIssues: []string{"mode=none"},
		},
		{
			name:       "fetch error warn",
			txt:        []string{"v=STSv1; id=20160831085700Z;"},
			fetchErr:   errors.New("policy https fetch: connection refused"),
			wantStatus: "warn",
			wantIssues: []string{"could not be fetched"},
		},
		{
			name:       "invalid id= blocks pass (RFC 8461 §3.1 ABNF)",
			txt:        []string{"v=STSv1; id=2026-06-24T12:00:00Z;"},
			mxHosts:    mxCovered,
			policyBody: enforcePolicy("*.example.com"),
			wantStatus: "warn",
			wantIssues: []string{"invalid id="},
			check: func(t *testing.T, res report.MTASTSResult) {
				t.Helper()
				if res.DNSIDValid {
					t.Fatal("DNSIDValid want false for non-alphanumeric id")
				}
				if res.PolicyID != "2026-06-24T12:00:00Z" {
					t.Fatalf("PolicyID=%q", res.PolicyID)
				}
			},
		},
		{
			name:       "gate skip",
			txt:        []string{"v=STSv1; id=20160831085700Z;"},
			policyBody: enforcePolicy("*.example.com"),
			gate:       testutil.DenyGate{},
			wantStatus: "info",
			check: func(t *testing.T, res report.MTASTSResult) {
				t.Helper()
				if res.Message != "skipped (input gated)" {
					t.Fatalf("message=%q", res.Message)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gate := tt.gate
			if gate == nil {
				gate = testutil.AllowGate{}
			}
			var fetcher PolicyFetcher
			if len(tt.txt) == 1 && tt.fetchErr == nil && tt.policyBody != "" {
				fetcher = NewMockPolicyFetcher(tt.policyBody, nil)
			}
			if tt.fetchErr != nil {
				fetcher = NewMockPolicyFetcher("", tt.fetchErr)
			}

			deps := matrixDeps(tt.txt, fetcher, gate)
			res := Check(ctx, Request{Domain: matrixDomain, MXHosts: tt.mxHosts}, deps)
			testutil.AssertStatus(t, res.Status, tt.wantStatus, tt.name)
			if len(tt.wantIssues) > 0 {
				testutil.AssertIssuesContain(t, res.Issues, tt.wantIssues...)
			}
			if tt.check != nil {
				tt.check(t, res)
			}
		})
	}
}