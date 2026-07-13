package assessor

import (
	"net"
	"testing"
)

func TestHasPublicIP(t *testing.T) {
	tests := []struct {
		name string
		ips  []net.IP
		want bool
	}{
		{
			name: "empty fail-closed",
			ips:  nil,
			want: false,
		},
		{
			name: "private only",
			ips: []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("192.168.1.1"),
				net.ParseIP("127.0.0.1"),
			},
			want: false,
		},
		{
			name: "public mixed with private",
			ips: []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("8.8.8.8"),
			},
			want: true,
		},
		{
			name: "public only",
			ips: []net.IP{
				net.ParseIP("1.1.1.1"),
				net.ParseIP("2001:4860:4860::8888"),
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasPublicIP(tt.ips); got != tt.want {
				t.Errorf("hasPublicIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicIPs(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("93.184.216.34"),
		net.ParseIP("fe80::1"),
	}
	got := publicIPs(ips)
	if len(got) != 1 {
		t.Fatalf("publicIPs() len = %d, want 1: %v", len(got), got)
	}
	if got[0].String() != "93.184.216.34" {
		t.Errorf("publicIPs() = %v, want only 93.184.216.34", got)
	}
}

func TestDomainGuards(t *testing.T) {
	guardTests := []struct {
		name        string
		domain      string
		wantValid   bool
		wantAllowed bool
	}{
		{"valid two labels", "example.com", true, true},
		{"valid with sub", "sub.mail.example.com", true, true},
		{"valid hyphen", "ex-ample.com", true, true},
		{"valid trailing dot trimmed", "example.com.", true, true},
		{"single label", "com", false, true},
		{"empty", "", false, true},
		{"leading dot", ".example.com", false, true},
		{"double dot", "ex..com", false, true},
		{"underscore forbidden in label", "ex_ample.com", false, true},
		{"label too long >63", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", false, true},
		{"starts with hyphen", "-example.com", false, true},
		{"ends with hyphen", "example-.com", false, true},
		{"label with invalid char", "ex!ample.com", false, true},
		{"numeric label ok", "123.com", true, true},
		{"dotted numeric labels", "1.2.3.4", true, true},
	}
	for _, tt := range guardTests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidDomainShape(tt.domain); got != tt.wantValid {
				t.Errorf("isValidDomainShape(%q) = %v, want %v", tt.domain, got, tt.wantValid)
			}
			if got := isAllowedDomain(tt.domain); got != tt.wantAllowed {
				t.Errorf("isAllowedDomain(%q) = %v, want %v", tt.domain, got, tt.wantAllowed)
			}
		})
	}

	origList := domainAllowlist
	defer func() { domainAllowlist = origList }()
	domainAllowlist = []string{"example.com", "allowed.org"}
	if !isAllowedDomain("foo.example.com") {
		t.Error("suffix match under allowlist should allow")
	}
	if !isAllowedDomain("example.com") {
		t.Error("exact match under allowlist should allow")
	}
	if isAllowedDomain("evil.com") {
		t.Error("non-matching domain must be denied when allowlist is set")
	}
	if !isValidDomainShape("evil.com") {
		t.Error("evil.com is valid shape even if not allowed")
	}
}

func TestIsValidSPFMechanismDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   bool
	}{
		{"_spf.google.com", true},
		{"spf.mailgun.org", true},
		{"example.com", true},
		{"", false},
		{"_bad..host.com", false},
		{"%{ir}.%{v}.%{d}.spf.has.pphosted.com", true},
		{"%{d}.55.spf-protect.agari.com", true},
	}
	for _, tt := range tests {
		if got := isValidSPFMechanismDomain(tt.domain); got != tt.want {
			t.Errorf("isValidSPFMechanismDomain(%q)=%v want %v", tt.domain, got, tt.want)
		}
	}
	if isValidDomainShape("_spf.google.com") {
		t.Error("apex gating must still reject underscore labels")
	}
}