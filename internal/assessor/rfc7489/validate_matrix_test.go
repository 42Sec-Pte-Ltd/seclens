package rfc7489

import (
	"strings"
	"testing"

	"seclens/internal/assessor/testutil"
)

const validBase = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
const uriTestBase = "v=DMARC1; p=reject"

func TestValidateTags_Matrix(t *testing.T) {
	tests := []struct {
		name          string
		raw           string
		wantOK        bool
		issueContains string
	}{
		// adkim
		{name: "adkim=r valid", raw: validBase + "; adkim=r", wantOK: true},
		{name: "adkim=s valid", raw: validBase + "; adkim=s", wantOK: true},
		{name: "adkim invalid", raw: validBase + "; adkim=strict", wantOK: false, issueContains: "adkim="},

		// aspf
		{name: "aspf=r valid", raw: validBase + "; aspf=r", wantOK: true},
		{name: "aspf=s valid", raw: validBase + "; aspf=s", wantOK: true},
		{name: "aspf invalid", raw: validBase + "; aspf=relaxed", wantOK: false, issueContains: "aspf="},

		// fo
		{name: "fo=0 valid", raw: validBase + "; fo=0", wantOK: true},
		{name: "fo=1 valid", raw: validBase + "; fo=1", wantOK: true},
		{name: "fo=d valid", raw: validBase + "; fo=d", wantOK: true},
		{name: "fo=s valid", raw: validBase + "; fo=s", wantOK: true},
		{name: "fo colon list valid", raw: validBase + "; fo=0:1:d:s", wantOK: true},
		{name: "fo invalid option", raw: validBase + "; fo=2", wantOK: false, issueContains: "fo="},
		{name: "fo empty segment invalid", raw: validBase + "; fo=0:", wantOK: false, issueContains: "fo="},

		// ri
		{name: "ri=3600 valid", raw: validBase + "; ri=3600", wantOK: true},
		{name: "ri=1 valid", raw: validBase + "; ri=1", wantOK: true},
		{name: "ri=0 invalid", raw: validBase + "; ri=0", wantOK: false, issueContains: "ri=0"},
		{name: "ri negative invalid", raw: validBase + "; ri=-1", wantOK: false, issueContains: "ri="},

		// pct
		{name: "pct=0 valid", raw: validBase + "; pct=0", wantOK: true},
		{name: "pct=50 valid", raw: validBase + "; pct=50", wantOK: true},
		{name: "pct=100 valid", raw: validBase + "; pct=100", wantOK: true},
		{name: "pct=-1 invalid", raw: validBase + "; pct=-1", wantOK: false, issueContains: "pct="},
		{name: "pct=101 invalid", raw: validBase + "; pct=101", wantOK: false, issueContains: "pct="},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := ParseRecord(tt.raw)
			ok, issues := ValidateTags(rec)
			if ok != tt.wantOK {
				t.Fatalf("%s: syntaxOK=%v want %v issues=%v", tt.name, ok, tt.wantOK, issues)
			}
			if tt.issueContains != "" {
				testutil.AssertIssuesContain(t, issues, tt.issueContains)
			}
		})
	}
}

func TestValidateURIs_Matrix(t *testing.T) {
	tests := []struct {
		name          string
		tag           string
		uri           string
		wantIssues    int
		issueContains string
	}{
		// rua
		{name: "rua mailto valid", tag: "rua", uri: "mailto:dmarc@example.com", wantIssues: 0},
		{name: "rua https invalid", tag: "rua", uri: "https://reports.example.com/dmarc", wantIssues: 1, issueContains: "rua="},
		{name: "rua bare email invalid", tag: "rua", uri: "dmarc@example.com", wantIssues: 1, issueContains: "rua="},

		// ruf
		{name: "ruf mailto valid", tag: "ruf", uri: "mailto:forensic@example.com", wantIssues: 0},
		{name: "ruf https invalid", tag: "ruf", uri: "https://reports.example.com/forensic", wantIssues: 1, issueContains: "ruf="},
		{name: "ruf bare email invalid", tag: "ruf", uri: "forensic@example.com", wantIssues: 1, issueContains: "ruf="},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := uriTestBase + "; " + tt.tag + "=" + tt.uri
			rec := ParseRecord(raw)
			issues := ValidateURIs(rec)
			if len(issues) != tt.wantIssues {
				t.Fatalf("%s: issues=%v want count %d", tt.name, issues, tt.wantIssues)
			}
			if tt.issueContains != "" {
				testutil.AssertIssuesContain(t, issues, tt.issueContains)
			}
			if tt.wantIssues == 0 && len(issues) > 0 {
				t.Fatalf("%s: unexpected issues %v", tt.name, issues)
			}
		})
	}
}

func TestValidateURIs_Matrix_MultipleURIs(t *testing.T) {
	rec := ParseRecord(uriTestBase + "; rua=mailto:a@b.com,https://bad.example.com")
	issues := ValidateURIs(rec)
	if len(issues) != 1 {
		t.Fatalf("issues=%v want one invalid rua URI", issues)
	}
	if !strings.Contains(issues[0], "rua=") {
		t.Fatalf("issue=%q want rua= prefix", issues[0])
	}
}