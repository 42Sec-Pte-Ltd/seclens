package rfc8460

import (
	"strings"
	"testing"
)

func TestSelectTLSRPTTXT(t *testing.T) {
	tests := []struct {
		name      string
		txts      []string
		wantPres  bool
		wantIssue string
	}{
		{name: "none", txts: nil},
		{name: "single valid", txts: []string{"v=TLSRPTv1; rua=mailto:tlsrpt@example.com;"}, wantPres: true},
		{name: "must start with version", txts: []string{"rua=mailto:a@b.com; v=TLSRPTv1;"}, wantPres: false},
		{name: "contains not enough", txts: []string{"prefix v=TLSRPTv1; rua=mailto:a@b.com"}, wantPres: false},
		{name: "multiple valid", txts: []string{"v=TLSRPTv1; rua=mailto:a@b.com;", "v=TLSRPTv1; rua=mailto:c@d.com;"}, wantPres: true, wantIssue: "exactly one"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, pres, issue := selectTLSRPTTXT(tt.txts)
			if pres != tt.wantPres {
				t.Fatalf("present=%v want %v issue=%q", pres, tt.wantPres, issue)
			}
			if tt.wantIssue != "" && !strings.Contains(issue, tt.wantIssue) {
				t.Fatalf("issue=%q want substring %q", issue, tt.wantIssue)
			}
		})
	}
}

func TestParseTLSRPTRecord(t *testing.T) {
	tests := []struct {
		txt         string
		wantVersion string
		wantRUA     []string
		wantSyntax  bool
	}{
		{
			txt:         "v=TLSRPTv1; rua=mailto:tlsrpt@example.com;",
			wantVersion: "TLSRPTv1",
			wantRUA:     []string{"mailto:tlsrpt@example.com"},
			wantSyntax:  true,
		},
		{
			txt:         "v=TLSRPTv1; rua=mailto:a@b.com,https://reports.example.com/tls",
			wantVersion: "TLSRPTv1",
			wantRUA:     []string{"mailto:a@b.com", "https://reports.example.com/tls"},
			wantSyntax:  true,
		},
		{
			txt:        "v=TLSRPTv0; rua=mailto:a@b.com;",
			wantSyntax: false,
		},
		{
			txt:        "not tlsrpt",
			wantSyntax: false,
		},
	}
	for _, tt := range tests {
		got := parseTLSRPTRecord(tt.txt)
		if got.syntaxOK != tt.wantSyntax {
			t.Fatalf("parseTLSRPTRecord(%q) syntaxOK=%v want %v", tt.txt, got.syntaxOK, tt.wantSyntax)
		}
		if tt.wantSyntax && got.version != tt.wantVersion {
			t.Fatalf("version=%q want %q", got.version, tt.wantVersion)
		}
		if tt.wantRUA != nil && strings.Join(got.rua, ",") != strings.Join(tt.wantRUA, ",") {
			t.Fatalf("rua=%v want %v", got.rua, tt.wantRUA)
		}
	}
}

func TestValidateRUAURIs(t *testing.T) {
	tests := []struct {
		uri   string
		valid bool
	}{
		{"mailto:tlsrpt@example.com", true},
		{"mailto:reports@sub.example.com", true},
		{"https://reports.example.com/tls", true},
		{"http://reports.example.com/tls", false},
		{"ftp://reports.example.com/tls", false},
		{"mailto:", false},
		{"mailto:not-an-email", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isValidRUAURI(tt.uri); got != tt.valid {
			t.Errorf("isValidRUAURI(%q)=%v want %v", tt.uri, got, tt.valid)
		}
	}

	valid, issues := validateRUAURIs([]string{"mailto:a@b.com", "http://bad.example.com"})
	if len(valid) != 1 || valid[0] != "mailto:a@b.com" {
		t.Fatalf("valid=%v want [mailto:a@b.com]", valid)
	}
	if len(issues) != 1 {
		t.Fatalf("issues=%v want one invalid URI issue", issues)
	}
}

func TestRecommendedDNSTXT(t *testing.T) {
	if got := RecommendedDNSTXT("Example.COM."); got != "v=TLSRPTv1; rua=mailto:tlsrpt@example.com" {
		t.Fatalf("got %q", got)
	}
}