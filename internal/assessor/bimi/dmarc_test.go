package bimi

import (
	"testing"

	"seclens/internal/report"
)

func TestDMARCGaps(t *testing.T) {
	t.Parallel()
	ok := &report.DMARCResult{Present: true, SyntaxOK: true, Policy: "reject", Pct: 100}
	cases := []struct {
		name    string
		domain  string
		author  *report.DMARCResult
		orgName string
		org     *report.DMARCResult
		want    []string
	}{
		{
			name:   "reject pct absent stored as 100",
			domain: "example.com",
			author: ok,
		},
		{
			name:   "quarantine",
			domain: "example.com",
			author: &report.DMARCResult{Present: true, SyntaxOK: true, Policy: "quarantine", Pct: 100},
		},
		{
			name:   "absent",
			domain: "example.com",
			author: &report.DMARCResult{Present: false, Pct: 100},
			want:   []string{"DMARC record absent"},
		},
		{
			name:   "nil",
			domain: "example.com",
			want:   []string{"DMARC result unavailable"},
		},
		{
			name:   "reject pct below 100",
			domain: "example.com",
			author: &report.DMARCResult{Present: true, SyntaxOK: true, Policy: "reject", Pct: 50},
			want:   []string{"DMARC pct=50 (want 100 or absent)"},
		},
		{
			name:   "p none and sp none and pct",
			domain: "example.com",
			author: &report.DMARCResult{Present: true, SyntaxOK: true, Policy: "none", Pct: 50, SubPolicy: "none"},
			want: []string{
				"DMARC p=none is not quarantine or reject",
				"DMARC pct=50 (want 100 or absent)",
				"DMARC sp=none",
			},
		},
		{
			name:   "syntax plus weak policy",
			domain: "example.com",
			author: &report.DMARCResult{Present: true, SyntaxOK: false, Policy: "reject", Pct: 100},
			want:   []string{"DMARC syntax is not valid"},
		},
		{
			name:    "subdomain org p none",
			domain:  "mail.example.com",
			author:  ok,
			orgName: "example.com",
			org:     &report.DMARCResult{Present: true, SyntaxOK: true, Policy: "none", Pct: 100},
			want:    []string{"organizational domain example.com DMARC p=none is not quarantine or reject"},
		},
		{
			name:    "subdomain org absent",
			domain:  "mail.example.com",
			author:  ok,
			orgName: "example.com",
			org:     &report.DMARCResult{Present: false},
			want:    []string{"organizational domain example.com DMARC record absent"},
		},
		{
			name:    "subdomain org sp none",
			domain:  "news.example.co.uk",
			author:  ok,
			orgName: "example.co.uk",
			org:     &report.DMARCResult{Present: true, SyntaxOK: true, Policy: "quarantine", Pct: 100, SubPolicy: "none"},
			want:    []string{"organizational domain example.co.uk DMARC sp=none"},
		},
		{
			name:    "same domain does not repeat org",
			domain:  "example.com",
			author:  ok,
			orgName: "example.com",
			org:     &report.DMARCResult{Present: true, SyntaxOK: true, Policy: "none", Pct: 100},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DMARCGaps(tc.domain, tc.author, tc.orgName, tc.org)
			if len(got) != len(tc.want) {
				t.Fatalf("gaps %q want %q", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("gaps %q want %q", got, tc.want)
				}
			}
		})
	}
}
