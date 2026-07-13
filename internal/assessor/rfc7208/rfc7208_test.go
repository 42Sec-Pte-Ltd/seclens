package rfc7208

import (
	"context"
	"strings"
	"testing"
)

type testGate struct{}

func (testGate) ValidShape(domain string) bool { return isTestDomainShape(domain) }
func (testGate) Allowed(domain string) bool    { return true }
func (testGate) ValidMechanismDomain(domain string) bool {
	return isTestSPFMechanismDomain(domain)
}

var testDeps = Deps{Gate: testGate{}}

func isTestDomainShape(d string) bool {
	d = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
	if d == "" || strings.Contains(d, "..") || strings.Contains(d, "_") {
		return false
	}
	return strings.Contains(d, ".")
}

func isTestSPFMechanismDomain(d string) bool {
	d = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
	if d == "" || len(d) > 253 || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") || strings.Contains(d, "..") {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.Contains(label, "%{") {
			if !validTestSPFMacroLabel(label) {
				return false
			}
			continue
		}
	}
	return true
}

func validTestSPFMacroLabel(label string) bool {
	for i := 0; i < len(label); {
		switch label[i] {
		case '%':
			if i+2 >= len(label) || label[i+1] != '{' {
				return false
			}
			j := i + 2
			for j < len(label) && label[j] != '}' {
				c := label[j]
				if !((c >= 'a' && c <= 'z') || c == '-' || (c >= '0' && c <= '9')) {
					return false
				}
				j++
			}
			if j >= len(label) || label[j] != '}' {
				return false
			}
			i = j + 1
		default:
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				return false
			}
			i++
		}
	}
	return len(label) > 0
}

func TestAnalyzeRecord(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantStatus string
		wantAll    string
		wantIssues int
	}{
		{
			name:       "strict google-like",
			raw:        "v=spf1 include:_spf.google.com ~all",
			wantStatus: "warn",
			wantAll:    "~",
			wantIssues: 1,
		},
		{
			name:       "hard fail good",
			raw:        "v=spf1 ip4:1.2.3.4 -all",
			wantStatus: "pass",
			wantAll:    "-",
			wantIssues: 0,
		},
		{
			name:       "missing all",
			raw:        "v=spf1 include:foo.com",
			wantStatus: "fail",
			wantAll:    "",
			wantIssues: 2,
		},
		{
			name:       "plus all bad",
			raw:        "v=spf1 +all",
			wantStatus: "fail",
			wantAll:    "+",
			wantIssues: 1,
		},
		{
			name:       "empty",
			raw:        "",
			wantStatus: "info",
			wantAll:    "",
			wantIssues: 1,
		},
		{
			name:       "pure redirect (counts as lookup; no local all penalty)",
			raw:        "v=spf1 redirect=_spf.example.com",
			wantStatus: "pass",
			wantAll:    "",
			wantIssues: 0,
		},
		{
			name:       "redirect with local all (mixing warning)",
			raw:        "v=spf1 redirect=_spf.example.com -all",
			wantStatus: "warn",
			wantAll:    "-",
			wantIssues: 1,
		},
		{
			name:       "invalid mechanism causes PermError/fail",
			raw:        "v=spf1 foo:bar baz -all",
			wantStatus: "fail",
			wantAll:    "-",
			wantIssues: 2,
		},
		{
			name:       "wrong version string is invalid (exact v=spf1 required)",
			raw:        "v=spf2 -all",
			wantStatus: "fail",
			wantAll:    "",
			wantIssues: 1,
		},
		{
			name:       "ip4 and ip6 and exists and exp are accepted as valid",
			raw:        "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 exists:_spfcheck.example.com exp=explain.example.com -all",
			wantStatus: "pass",
			wantAll:    "-",
			wantIssues: 0,
		},
		{
			name:       "case-insensitive version V=SPF1 accepted",
			raw:        "V=SPF1 -all",
			wantStatus: "pass",
			wantAll:    "-",
			wantIssues: 0,
		},
		{
			name:       "too many DNS lookups >10 in raw record (strict RFC path)",
			raw:        "v=spf1 include:1.com include:2.com include:3.com include:4.com include:5.com include:6.com include:7.com include:8.com include:9.com include:10.com include:11.com -all",
			wantStatus: "fail",
			wantAll:    "-",
			wantIssues: 1,
		},
		{
			name:       "high DNS lookups (9) triggers warning not hard fail",
			raw:        "v=spf1 include:1.com include:2.com include:3.com include:4.com include:5.com include:6.com include:7.com include:8.com include:9.com -all",
			wantStatus: "warn",
			wantAll:    "-",
			wantIssues: 1,
		},
		{
			name:       "multiple redirect= modifiers is PermError (strict)",
			raw:        "v=spf1 redirect=foo.example.com redirect=bar.example.com -all",
			wantStatus: "fail",
			wantAll:    "-",
			wantIssues: 2,
		},
		{
			name:       "ptr mechanism adds discouraged issue (but status warn not fail if terminated)",
			raw:        "v=spf1 ptr -all",
			wantStatus: "warn",
			wantAll:    "-",
			wantIssues: 1,
		},
		{
			name:       "invalid version prefix v=spf1foo",
			raw:        "v=spf1foo -all",
			wantStatus: "fail",
			wantAll:    "",
			wantIssues: 1,
		},
		{
			name:       "macro include domain-spec valid",
			raw:        "v=spf1 include:%{d}.spf.example.com -all",
			wantStatus: "pass",
			wantAll:    "-",
			wantIssues: 0,
		},
		{
			name:       "complex macro include domain-spec valid",
			raw:        "v=spf1 include:%{ir}.%{v}.%{d}.spf.example.com -all",
			wantStatus: "pass",
			wantAll:    "-",
			wantIssues: 0,
		},
		{
			name:       "invalid macro in include domain-spec PermError",
			raw:        "v=spf1 include:%{d.spf.example.com -all",
			wantStatus: "fail",
			wantAll:    "-",
			wantIssues: 1,
		},
		{
			name:       "macro redirect domain-spec valid",
			raw:        "v=spf1 redirect=%{d}.spf.example.com",
			wantStatus: "pass",
			wantAll:    "",
			wantIssues: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := AnalyzeRecord(tt.raw, testDeps.Gate)
			if res.Status != tt.wantStatus {
				t.Errorf("status = %s, want %s", res.Status, tt.wantStatus)
			}
			if res.AllQualifier != tt.wantAll {
				t.Errorf("allQualifier = %q, want %q", res.AllQualifier, tt.wantAll)
			}
			if len(res.Issues) != tt.wantIssues {
				t.Errorf("issues count = %d, want %d (issues: %v)", len(res.Issues), tt.wantIssues, res.Issues)
			}
		})
	}
}

func TestValidateIP4Mechanism(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"1.2.3.4", true},
		{"192.0.2.0/24", true},
		{"0.0.0.0/0", true},
		{"255.255.255.255/32", true},
		{"999.999.999.999", false},
		{"1.2.3.4/33", false},
		{"1.2.3.4/-1", false},
		{"not-an-ip", false},
		{"", false},
	}
	for _, tt := range tests {
		got := validateIP4Mechanism(tt.value)
		if got != tt.want {
			t.Errorf("validateIP4Mechanism(%q) = %v, want %v", tt.value, got, tt.want)
		}
	}
}

func TestValidateIP6Mechanism(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"2001:db8::", true},
		{"2001:db8::/32", true},
		{"::1", true},
		{"2001:db8::/129", false},
		{"1.2.3.4", false},
		{"not-ipv6", false},
	}
	for _, tt := range tests {
		got := validateIP6Mechanism(tt.value)
		if got != tt.want {
			t.Errorf("validateIP6Mechanism(%q) = %v, want %v", tt.value, got, tt.want)
		}
	}
}

func TestInvalidIP4CausesPermError(t *testing.T) {
	res := AnalyzeRecord("v=spf1 ip4:999.999.999.999 -all", testDeps.Gate)
	if res.Status != "fail" {
		t.Fatalf("status = %s, want fail", res.Status)
	}
	found := false
	for _, iss := range res.Issues {
		if iss == `invalid mechanism or modifier "ip4:999.999.999.999" (PermError per RFC 7208)` {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected invalid ip4 issue, got %v", res.Issues)
	}
}

func TestSPFMechanismDomainUnderscore(t *testing.T) {
	if !isTestSPFMechanismDomain("_spf.google.com") {
		t.Fatal("_spf.google.com must be valid SPF mechanism domain")
	}
	if isTestDomainShape("_spf.google.com") {
		t.Fatal("apex gate must reject underscore labels; mechanism gate is separate")
	}
	res := AnalyzeRecord("v=spf1 include:_spf.google.com -all", testDeps.Gate)
	if res.Status != "pass" {
		t.Fatalf("include:_spf.google.com status=%s want pass issues=%v", res.Status, res.Issues)
	}
}

type mockDNS map[string][]string

func (m mockDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if txts, ok := m[name]; ok {
		return txts, nil
	}
	return nil, nil
}

func TestCheckRedirectChainMockDNS(t *testing.T) {
	dns := mockDNS{
		"example.com":      {"v=spf1 redirect=_spf.example.com"},
		"_spf.example.com": {"v=spf1 include:mail.example.com -all"},
		"mail.example.com": {"v=spf1 ip4:203.0.113.10 -all"},
	}
	deps := Deps{
		DNS:  dns,
		Gate: testGate{},
	}

	res := Check(context.Background(), Request{Domain: "example.com"}, deps)
	if !res.Present {
		t.Fatal("expected present SPF")
	}
	if res.AllQualifier != "-" {
		t.Fatalf("AllQualifier=%q want -", res.AllQualifier)
	}
	if res.RedirectTarget != "_spf.example.com" {
		t.Fatalf("RedirectTarget=%q", res.RedirectTarget)
	}
	if res.RedirectedSPFRaw != "v=spf1 include:mail.example.com -all" {
		t.Fatalf("RedirectedSPFRaw=%q", res.RedirectedSPFRaw)
	}
	if len(res.SPFChain) < 2 {
		t.Fatalf("SPFChain too short: %+v", res.SPFChain)
	}
}

func TestCheckFollowsParentIncludeAfterRedirect(t *testing.T) {
	dns := mockDNS{
		"example.com":        {"v=spf1 redirect=_spf.example.com include:fragment.example.com"},
		"_spf.example.com":   {"v=spf1 -all"},
		"fragment.example.com": {"v=spf1 ip4:198.51.100.1 -all"},
	}
	deps := Deps{
		DNS:  dns,
		Gate: testGate{},
	}

	res := Check(context.Background(), Request{Domain: "example.com"}, deps)
	if _, ok := res.IncludedRaws["fragment.example.com"]; !ok {
		t.Fatalf("parent include must be followed even after redirect; IncludedRaws=%v", res.IncludedRaws)
	}
}

func TestAnalyzeRecord_Absent(t *testing.T) {
	res := AnalyzeRecord("", testDeps.Gate)
	if res.Present {
		t.Fatal("Present should be false for empty raw")
	}
	if res.Message != "No SPF record found" {
		t.Fatalf("Message = %q, want No SPF record found", res.Message)
	}
}