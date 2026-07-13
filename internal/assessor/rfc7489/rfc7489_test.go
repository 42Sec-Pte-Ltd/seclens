package rfc7489

import (
	"strings"
	"testing"
)

func TestSelectDMARCTXT(t *testing.T) {
	tests := []struct {
		name      string
		txts      []string
		wantPres  bool
		wantIssue string
	}{
		{name: "none", txts: nil},
		{name: "single valid", txts: []string{"v=DMARC1; p=reject;"}, wantPres: true},
		{name: "case insensitive", txts: []string{"V=dmarc1; p=none"}, wantPres: true},
		{name: "must start with version", txts: []string{"prefix v=DMARC1; p=reject"}, wantPres: false},
		{name: "multiple valid", txts: []string{"v=DMARC1; p=reject", "v=DMARC1; p=none"}, wantIssue: "exactly one"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, pres, issue := selectDMARCTXT(tt.txts)
			if pres != tt.wantPres {
				t.Fatalf("present=%v want %v issue=%q", pres, tt.wantPres, issue)
			}
			if tt.wantIssue != "" && !strings.Contains(issue, tt.wantIssue) {
				t.Fatalf("issue=%q want substring %q", issue, tt.wantIssue)
			}
		})
	}
}

func TestParseRecordFirstWins(t *testing.T) {
	raw := "v=DMARC1; p=reject; p=none; pct=50; pct=25; fo=1; fo=0:1"
	rec := ParseRecord(raw)
	if rec.Policy != "reject" || rec.Pct != 50 || rec.FO != "1" {
		t.Fatalf("first-wins failed: p=%q pct=%d fo=%q", rec.Policy, rec.Pct, rec.FO)
	}
}

func TestValidateTagsMissingP(t *testing.T) {
	rec := ParseRecord("v=DMARC1; rua=mailto:dmarc@example.com")
	ok, issues := ValidateTags(rec)
	if ok {
		t.Fatal("expected syntax failure without p=")
	}
	if len(issues) == 0 || !strings.Contains(issues[0], "p=") {
		t.Fatalf("issues=%v want missing p=", issues)
	}
}

func TestValidateTagsPctRange(t *testing.T) {
	rec := ParseRecord("v=DMARC1; p=reject; pct=150")
	ok, issues := ValidateTags(rec)
	if ok {
		t.Fatal("expected pct out of range to fail syntax")
	}
	found := false
	for _, iss := range issues {
		if strings.Contains(iss, "pct=150") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("issues=%v want pct range", issues)
	}
}

func TestAnalyzeRaw(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		nullMX     bool
		wantStatus string
		wantPolicy string
		wantSyntax bool
		wantIssues int
	}{
		{
			name:       "strong reject",
			raw:        "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
			wantStatus: "pass",
			wantPolicy: "reject",
			wantSyntax: true,
			wantIssues: 0,
		},
		{
			name:       "p=none only",
			raw:        "v=DMARC1; p=none; rua=mailto:reports@example.com",
			wantStatus: "warn",
			wantPolicy: "none",
			wantSyntax: true,
			wantIssues: 1,
		},
		{
			name:       "quarantine with low pct",
			raw:        "v=DMARC1; p=quarantine; pct=25; rua=mailto:foo@bar.com",
			wantStatus: "warn",
			wantPolicy: "quarantine",
			wantSyntax: true,
			wantIssues: 1,
		},
		{
			name:       "missing rua on enforcing policy",
			raw:        "v=DMARC1; p=reject",
			wantStatus: "warn",
			wantPolicy: "reject",
			wantSyntax: true,
			wantIssues: 1,
		},
		{
			name:       "missing required p=",
			raw:        "v=DMARC1; rua=mailto:dmarc@example.com",
			wantStatus: "fail",
			wantPolicy: "",
			wantSyntax: false,
			wantIssues: 1,
		},
		{
			name:       "quarantine with sp=none",
			raw:        "v=DMARC1; p=quarantine; rua=mailto:reports@example.com; sp=none; pct=100",
			wantStatus: "warn",
			wantPolicy: "quarantine",
			wantSyntax: true,
			wantIssues: 2,
		},
		{
			name:       "reject with sp=reject",
			raw:        "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com",
			wantStatus: "pass",
			wantPolicy: "reject",
			wantSyntax: true,
			wantIssues: 0,
		},
		{
			name:       "reject no sp",
			raw:        "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
			wantStatus: "pass",
			wantPolicy: "reject",
			wantSyntax: true,
			wantIssues: 0,
		},
		{
			name:       "p=none apex + sp=reject",
			raw:        "v=DMARC1; p=none; sp=reject; rua=mailto:reports@example.com",
			wantStatus: "warn",
			wantPolicy: "none",
			wantSyntax: true,
			wantIssues: 2,
		},
		{
			name:       "fo and ri present",
			raw:        "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; fo=0:1:d:s; ri=3600",
			wantStatus: "pass",
			wantPolicy: "reject",
			wantSyntax: true,
			wantIssues: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := AnalyzeRaw(tt.raw, tt.nullMX)
			if res.Status != tt.wantStatus {
				t.Errorf("status=%s want=%s (issues=%v)", res.Status, tt.wantStatus, res.Issues)
			}
			if res.Policy != tt.wantPolicy {
				t.Errorf("policy=%s want=%s", res.Policy, tt.wantPolicy)
			}
			if res.SyntaxOK != tt.wantSyntax {
				t.Errorf("SyntaxOK=%v want=%v", res.SyntaxOK, tt.wantSyntax)
			}
			if len(res.Issues) < tt.wantIssues {
				t.Errorf("issues=%d (want at least %d): %v", len(res.Issues), tt.wantIssues, res.Issues)
			}
		})
	}
}

func TestAnalyzeRaw_NullMXProfile(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantStatus string
		wantIssues int
	}{
		{
			name:       "reject without rua passes",
			raw:        "v=DMARC1; p=reject",
			wantStatus: "pass",
			wantIssues: 0,
		},
		{
			name:       "reject with low pct passes (no mail to apply policy)",
			raw:        "v=DMARC1; p=reject; pct=25",
			wantStatus: "pass",
			wantIssues: 0,
		},
		{
			name:       "p=none still warns",
			raw:        "v=DMARC1; p=none",
			wantStatus: "warn",
			wantIssues: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := AnalyzeRaw(tt.raw, true)
			if res.Status != tt.wantStatus {
				t.Errorf("status=%s want=%s (issues=%v)", res.Status, tt.wantStatus, res.Issues)
			}
			if len(res.Issues) != tt.wantIssues {
				t.Errorf("issues=%d want=%d: %v", len(res.Issues), tt.wantIssues, res.Issues)
			}
			for _, iss := range res.Issues {
				if strings.Contains(iss, "rua=") {
					t.Errorf("null_mx profile must not flag rua: %q", iss)
				}
			}
		})
	}
}

func TestAnalyzeRaw_FOAndRI(t *testing.T) {
	res := AnalyzeRaw("v=DMARC1; p=reject; rua=mailto:a@b.com; fo=1; ri=7200", false)
	if res.FO != "1" {
		t.Errorf("FO=%q want 1", res.FO)
	}
	if res.RI != 7200 {
		t.Errorf("RI=%d want 7200", res.RI)
	}
}

func TestRecommendedRecord(t *testing.T) {
	if got := RecommendedRecord("example.com", false); !strings.Contains(got, "rua=mailto:dmarc@example.com") {
		t.Fatalf("mail profile: %q", got)
	}
	if got := RecommendedRecord("example.com", true); got != "v=DMARC1; p=reject" {
		t.Fatalf("null mx: %q", got)
	}
}