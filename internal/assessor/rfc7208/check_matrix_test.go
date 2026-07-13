package rfc7208

import (
	"context"
	"fmt"
	"testing"

	"seclens/internal/assessor/testutil"
	"seclens/internal/report"
)

const matrixDomain = "example.com"

func matrixDeps(dns testutil.MockTXT) Deps {
	return Deps{DNS: dns, Gate: testutil.SPFGate{}}
}

// linearIncludeChain builds apex → hop0 → … → hop(n-2) → term with one include per level.
// Total counted DNS lookup terms = n.
func linearIncludeChain(apex string, n int) testutil.MockTXT {
	if n < 1 {
		panic("linearIncludeChain: n must be >= 1")
	}
	m := testutil.MockTXT{}
	term := fmt.Sprintf("term.%s", apex)
	m[term] = []string{"v=spf1 ip4:203.0.113.10 -all"}
	if n == 1 {
		m[apex] = []string{"v=spf1 ip4:203.0.113.10 -all"}
		return m
	}
	prev := term
	for i := n - 2; i >= 0; i-- {
		hop := fmt.Sprintf("hop%d.%s", i, apex)
		m[hop] = []string{fmt.Sprintf("v=spf1 include:%s -all", prev)}
		prev = hop
	}
	m[apex] = []string{fmt.Sprintf("v=spf1 include:%s -all", prev)}
	return m
}

func TestCheck_Matrix(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		domain        string
		dns           testutil.MockTXT
		dnsErr        bool
		wantStatus    string
		wantPresent   *bool
		wantMessage   string
		issueContains string
		check         func(t *testing.T, res report.SPFResult)
	}{
		{
			name:       "input gated short domain",
			domain:     "abc",
			dns:        testutil.MockTXT{matrixDomain: {"v=spf1 -all"}},
			wantStatus: "info",
		},
		{
			name:          "absent SPF no v=spf1 TXT",
			domain:        matrixDomain,
			dns:           testutil.MockTXT{matrixDomain: {"google-site-verification=abc"}},
			wantStatus:    "warn",
			wantPresent:   boolPtr(false),
			wantMessage:   "No SPF record found",
			issueContains: "missing SPF",
		},
		{
			name:          "DNS lookup error",
			domain:        matrixDomain,
			dnsErr:        true,
			wantStatus:    "fail",
			issueContains: "DNS lookup failed",
		},
		{
			name:          "multiple v=spf1 TXT records",
			domain:        matrixDomain,
			dns:           testutil.MockTXT{matrixDomain: {"v=spf1 -all", "v=spf1 ~all"}},
			wantStatus:    "fail",
			wantPresent:   boolPtr(true),
			issueContains: "multiple v=spf1",
		},
		{
			name:       "strict -all pass",
			domain:     matrixDomain,
			dns:        testutil.MockTXT{matrixDomain: {"v=spf1 ip4:203.0.113.0/24 -all"}},
			wantStatus: "pass",
		},
		{
			name:          "softfail ~all warn",
			domain:        matrixDomain,
			dns:           testutil.MockTXT{matrixDomain: {"v=spf1 include:_spf.google.com ~all"}},
			wantStatus:    "warn",
			issueContains: "~all",
		},
		{
			name:   "glued v=spf1include normalized",
			domain: matrixDomain,
			dns: testutil.MockTXT{
				matrixDomain:       {"v=spf1include:mail.example.com ~all"},
				"mail.example.com": {"v=spf1 ip4:198.51.100.2 -all"},
			},
			wantStatus: "warn",
			check: func(t *testing.T, res report.SPFResult) {
				t.Helper()
				if _, ok := res.IncludedRaws["mail.example.com"]; !ok {
					t.Fatalf("glued record should follow include:mail.example.com; IncludedRaws=%v", res.IncludedRaws)
				}
			},
		},
		{
			name:   "macro include domain-spec not PermError",
			domain: matrixDomain,
			dns: testutil.MockTXT{
				matrixDomain:              {"v=spf1 include:%{d}.spf.example.com -all"},
				"%{d}.spf.example.com":    {"v=spf1 ip4:203.0.113.5 -all"},
			},
			wantStatus: "pass",
			check: func(t *testing.T, res report.SPFResult) {
				t.Helper()
				for _, iss := range res.Issues {
					if iss == `invalid include domain-spec "%{d}.spf.example.com" (PermError per RFC 7208)` {
						t.Fatalf("macro domain-spec must not PermError: %v", res.Issues)
					}
				}
				if _, ok := res.IncludedRaws["%{d}.spf.example.com"]; !ok {
					t.Fatalf("macro include should be followed; IncludedRaws=%v", res.IncludedRaws)
				}
			},
		},
		{
			name:          "nested lookup 11 warn",
			domain:        matrixDomain,
			dns:           linearIncludeChain(matrixDomain, 11),
			wantStatus:    "warn",
			issueContains: "too many DNS lookups",
		},
		{
			name:          "nested lookup 15 warn",
			domain:        matrixDomain,
			dns:           linearIncludeChain(matrixDomain, 15),
			wantStatus:    "warn",
			issueContains: "too many DNS lookups",
		},
		{
			name:          "nested lookup 21 fail",
			domain:        matrixDomain,
			dns:           linearIncludeChain(matrixDomain, 21),
			wantStatus:    "fail",
			issueContains: "too many DNS lookups",
		},
		{
			name:          "invalid include domain-spec PermError",
			domain:        matrixDomain,
			dns:           testutil.MockTXT{matrixDomain: {"v=spf1 include:..bad.example.com -all"}},
			wantStatus:    "fail",
			issueContains: "invalid include domain-spec",
		},
		{
			name:   "redirect chain to strict policy",
			domain: matrixDomain,
			dns: testutil.MockTXT{
				matrixDomain:       {"v=spf1 redirect=_spf.example.com"},
				"_spf.example.com": {"v=spf1 include:mail.example.com -all"},
				"mail.example.com": {"v=spf1 ip4:203.0.113.10 -all"},
			},
			wantStatus: "pass",
			check: func(t *testing.T, res report.SPFResult) {
				t.Helper()
				if res.RedirectTarget != "_spf.example.com" {
					t.Fatalf("RedirectTarget=%q want _spf.example.com", res.RedirectTarget)
				}
				if res.AllQualifier != "-" {
					t.Fatalf("AllQualifier=%q want -", res.AllQualifier)
				}
				if len(res.SPFChain) < 2 {
					t.Fatalf("SPFChain too short: %+v", res.SPFChain)
				}
			},
		},
		{
			name:   "redirect chain to softfail warn",
			domain: matrixDomain,
			dns: testutil.MockTXT{
				matrixDomain:       {"v=spf1 redirect=_spf.example.com"},
				"_spf.example.com": {"v=spf1 ip4:203.0.113.1 ~all"},
			},
			wantStatus: "warn",
		},
		{
			name:   "redirect with parent include still followed",
			domain: matrixDomain,
			dns: testutil.MockTXT{
				matrixDomain:           {"v=spf1 redirect=_spf.example.com include:fragment.example.com"},
				"_spf.example.com":     {"v=spf1 -all"},
				"fragment.example.com": {"v=spf1 ip4:198.51.100.1 -all"},
			},
			wantStatus: "pass",
			check: func(t *testing.T, res report.SPFResult) {
				t.Helper()
				if _, ok := res.IncludedRaws["fragment.example.com"]; !ok {
					t.Fatalf("parent include must be followed after redirect; IncludedRaws=%v", res.IncludedRaws)
				}
			},
		},
		{
			name:          "missing all fail",
			domain:        matrixDomain,
			dns:           testutil.MockTXT{matrixDomain: {"v=spf1 include:mail.example.com"}},
			wantStatus:    "fail",
			issueContains: "no 'all' mechanism",
		},
		{
			name:          "plus all fail",
			domain:        matrixDomain,
			dns:           testutil.MockTXT{matrixDomain: {"v=spf1 +all"}},
			wantStatus:    "fail",
			issueContains: "+all",
		},
		{
			name:   "include target multiple SPF fail",
			domain: matrixDomain,
			dns: testutil.MockTXT{
				matrixDomain:     {"v=spf1 include:bad.example.com -all"},
				"bad.example.com": {"v=spf1 -all", "v=spf1 ~all"},
			},
			wantStatus:    "fail",
			issueContains: "multiple v=spf1",
		},
		{
			name:          "empty apex TXT absent",
			domain:        matrixDomain,
			dns:           testutil.MockTXT{},
			wantStatus:    "warn",
			wantPresent:   boolPtr(false),
			wantMessage:   "No SPF record found",
			issueContains: "missing SPF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var deps Deps
			if tt.dnsErr {
				deps = Deps{DNS: testutil.ErrTXT{}, Gate: testutil.SPFGate{}}
			} else {
				deps = matrixDeps(tt.dns)
			}
			domain := tt.domain
			if domain == "" {
				domain = matrixDomain
			}

			res := Check(ctx, Request{Domain: domain}, deps)
			testutil.AssertStatus(t, res.Status, tt.wantStatus, tt.name)

			if tt.wantPresent != nil && res.Present != *tt.wantPresent {
				t.Fatalf("%s: Present=%v want %v", tt.name, res.Present, *tt.wantPresent)
			}
			if tt.wantMessage != "" && res.Message != tt.wantMessage {
				t.Fatalf("%s: Message=%q want %q", tt.name, res.Message, tt.wantMessage)
			}
			if tt.issueContains != "" {
				testutil.AssertIssuesContain(t, res.Issues, tt.issueContains)
			}
			if tt.check != nil {
				tt.check(t, res)
			}
		})
	}
}

func boolPtr(v bool) *bool { return &v }