package rfc8461

import (
	"net"
	"strings"
	"testing"
)

func TestSelectMTASTSTXT(t *testing.T) {
	tests := []struct {
		name      string
		txts      []string
		wantAdv   bool
		wantIssue string
	}{
		{name: "none", txts: nil},
		{name: "single valid", txts: []string{"v=STSv1; id=20160831085700Z;"}, wantAdv: true},
		{name: "must start with version", txts: []string{"id=1; v=STSv1"}, wantAdv: false},
		{name: "contains not enough", txts: []string{"prefix v=STSv1; id=1"}, wantAdv: false},
		{name: "multiple valid", txts: []string{"v=STSv1; id=1;", "v=STSv1; id=2;"}, wantIssue: "exactly one"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, adv, issue := selectMTASTSTXT(tt.txts)
			if adv != tt.wantAdv {
				t.Fatalf("advertised=%v want %v issue=%q", adv, tt.wantAdv, issue)
			}
			if tt.wantIssue != "" && !strings.Contains(issue, tt.wantIssue) {
				t.Fatalf("issue=%q want substring %q", issue, tt.wantIssue)
			}
		})
	}
}

func TestParseDNSPolicyID(t *testing.T) {
	tests := []struct {
		txt      string
		wantID   string
		wantValid bool
	}{
		{"v=STSv1; id=20160831085700Z;", "20160831085700Z", true},
		{"v=STSv1; id=2026-06-24T12:00:00Z;", "2026-06-24T12:00:00Z", false},
		{"v=STSv1;", "", false},
		{"v=STSv1; id=abc;", "abc", true},
	}
	for _, tt := range tests {
		id, valid := ParseDNSPolicyID(tt.txt)
		if id != tt.wantID || valid != tt.wantValid {
			t.Fatalf("ParseDNSPolicyID(%q) = (%q,%v) want (%q,%v)", tt.txt, id, valid, tt.wantID, tt.wantValid)
		}
	}
}

func TestMXHostMatchesPattern(t *testing.T) {
	tests := []struct {
		host, pattern string
		want          bool
	}{
		{"mail.example.com", "mail.example.com", true},
		{"mail.example.com", "*.example.com", true},
		{"example.com", "*.example.com", false},
		{"foo.bar.example.com", "*.example.com", false},
		{"mx1.example.com", "*.example.com", true},
	}
	for _, tt := range tests {
		got := mxHostMatchesPattern(tt.host, tt.pattern)
		if got != tt.want {
			t.Errorf("mxHostMatchesPattern(%q,%q)=%v want %v", tt.host, tt.pattern, got, tt.want)
		}
	}
}

func TestIsMXCovered(t *testing.T) {
	if isMXCovered(nil, []string{"mx.example.com"}) {
		t.Fatal("empty mx hosts should not be covered")
	}
	if !isMXCovered([]string{"a.example.com"}, []string{"*.example.com"}) {
		t.Fatal("expected wildcard coverage")
	}
}

func TestParsePolicyBodyFirstWins(t *testing.T) {
	body := "version: STSv1\nmode: enforce\nmode: testing\nmax_age: 100\nmax_age: 200\nmx: a.example.com\n"
	p := parsePolicyBody(body)
	if p.mode != "enforce" || p.maxAge != 100 {
		t.Fatalf("first-wins failed: mode=%q max_age=%d", p.mode, p.maxAge)
	}
}

func TestValidatePolicy(t *testing.T) {
	ok, issues := validatePolicy(policyFields{
		versionSet: true, version: "STSv1",
		modeSet: true, mode: "none",
		maxAgeSet: true, maxAge: 60,
	})
	if !ok || len(issues) != 0 {
		t.Fatalf("mode=none without mx should be valid: ok=%v issues=%v", ok, issues)
	}

	ok, issues = validatePolicy(policyFields{
		versionSet: true, version: "STSv1",
		modeSet: true, mode: "enforce",
		maxAgeSet: true, maxAge: 99999999,
		mx: []string{"mx.example.com"},
	})
	if ok || len(issues) == 0 {
		t.Fatalf("expected max_age issue, ok=%v issues=%v", ok, issues)
	}
}

func TestBuildRecommendedPolicy(t *testing.T) {
	got := BuildRecommendedPolicy([]string{"mx1.example.com", "mx2.example.com."})
	for _, want := range []string{"version: STSv1", "mode: enforce", "mx: mx1.example.com", "mx: mx2.example.com", "max_age: 86400"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "id:") {
		t.Fatalf("recommended policy must not contain policy id: field per RFC 8461 Appendix A:\n%s", got)
	}
}

func TestRecommendedDNSTXT(t *testing.T) {
	if got := RecommendedDNSTXT("20160831085700Z", true); got != "v=STSv1; id=20160831085700Z;" {
		t.Fatalf("got %q", got)
	}
	if got := RecommendedDNSTXT("bad-id!", false); !strings.HasPrefix(got, "v=STSv1; id=") {
		t.Fatalf("got %q", got)
	}
}

func TestConnectGuard(t *testing.T) {
	deps := Deps{IPGuard: ipGuardStub{}}
	_, err := connectGuard(deps, nil, "mta-sts.example.com")
	if err == nil || !strings.Contains(err.Error(), "no addresses resolved") {
		t.Fatalf("err=%v", err)
	}
	ips := []net.IP{net.ParseIP("93.184.216.34")}
	got, err := connectGuard(deps, ips, "mta-sts.example.com")
	if err != nil || len(got) != 1 {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

type ipGuardStub struct{}

func (ipGuardStub) PublicIPs(ips []net.IP) []net.IP {
	var out []net.IP
	for _, ip := range ips {
		if ip != nil && !ip.IsPrivate() {
			out = append(out, ip)
		}
	}
	return out
}

func (ipGuardStub) IsPrivateOrLocal(ip net.IP) bool {
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback())
}

func TestContentTypeIsTextPlain(t *testing.T) {
	if !contentTypeIsTextPlain("text/plain; charset=utf-8") {
		t.Fatal("expected text/plain")
	}
	if contentTypeIsTextPlain("text/html") {
		t.Fatal("expected false for html")
	}
}