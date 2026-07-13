package rfc7672

import (
	"strings"
	"testing"

	"seclens/internal/report"
)

func TestEnrichMTASTSCrossCheck(t *testing.T) {
	precedenceIssue := "DANE validation takes precedence over MTA-STS when both apply (RFC 8461 §2)"

	tests := []struct {
		name       string
		mtasts     *report.MTASTSResult
		dane       *report.DANEResult
		wantIssue  bool
		wantIssues int
	}{
		{
			name: "both fully configured adds precedence hint",
			mtasts: &report.MTASTSResult{
				Status: "pass",
				Issues: nil,
			},
			dane: &report.DANEResult{
				Status:          "pass",
				DNSSECValidated: true,
				MXCovered:       true,
				SyntaxOK:        true,
				AdvertisedFor:   []string{"mx.example.com"},
			},
			wantIssue:  true,
			wantIssues: 1,
		},
		{
			name: "DANE without DNSSECValidated — no hint",
			mtasts: &report.MTASTSResult{
				Status: "pass",
				Issues: nil,
			},
			dane: &report.DANEResult{
				Status:          "pass",
				DNSSECValidated: false,
				MXCovered:       true,
				SyntaxOK:        true,
				AdvertisedFor:   []string{"mx.example.com"},
			},
			wantIssue: false,
		},
		{
			name: "MTA-STS not pass — no hint",
			mtasts: &report.MTASTSResult{
				Status: "warn",
				Issues: nil,
			},
			dane: &report.DANEResult{
				Status:          "pass",
				DNSSECValidated: true,
				MXCovered:       true,
				SyntaxOK:        true,
				AdvertisedFor:   []string{"mx.example.com"},
			},
			wantIssue: false,
		},
		{
			name: "partial DANE coverage — no hint",
			mtasts: &report.MTASTSResult{
				Status: "pass",
				Issues: nil,
			},
			dane: &report.DANEResult{
				Status:          "warn",
				DNSSECValidated: true,
				MXCovered:       false,
				SyntaxOK:        true,
				AdvertisedFor:   []string{"mx1.example.com"},
			},
			wantIssue: false,
		},
		{
			name:       "nil MTA-STS — no panic",
			mtasts:     nil,
			dane:       &report.DANEResult{Status: "pass", DNSSECValidated: true, MXCovered: true, SyntaxOK: true},
			wantIssue:  false,
			wantIssues: 0,
		},
		{
			name:       "nil DANE — no panic",
			mtasts:     &report.MTASTSResult{Status: "pass"},
			dane:       nil,
			wantIssue:  false,
			wantIssues: 0,
		},
		{
			name: "existing issues preserved when hint added",
			mtasts: &report.MTASTSResult{
				Status: "pass",
				Issues: []string{"prior issue"},
			},
			dane: &report.DANEResult{
				Status:          "pass",
				DNSSECValidated: true,
				MXCovered:       true,
				SyntaxOK:        true,
				AdvertisedFor:   []string{"mx.example.com"},
			},
			wantIssue:  true,
			wantIssues: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			EnrichMTASTSCrossCheck(tt.mtasts, tt.dane)
			if tt.mtasts == nil {
				return
			}
			found := false
			for _, iss := range tt.mtasts.Issues {
				if iss == precedenceIssue {
					found = true
				}
			}
			if found != tt.wantIssue {
				t.Fatalf("precedence hint present=%v want %v issues=%v", found, tt.wantIssue, tt.mtasts.Issues)
			}
			if tt.wantIssues > 0 && len(tt.mtasts.Issues) != tt.wantIssues {
				t.Fatalf("issues count=%d want %d: %v", len(tt.mtasts.Issues), tt.wantIssues, tt.mtasts.Issues)
			}
			if tt.wantIssue && !strings.Contains(strings.Join(tt.mtasts.Issues, " "), "RFC 8461") {
				t.Fatalf("expected RFC 8461 reference in issues: %v", tt.mtasts.Issues)
			}
		})
	}
}