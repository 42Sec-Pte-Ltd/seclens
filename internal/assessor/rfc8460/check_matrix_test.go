package rfc8460

import (
	"context"
	"testing"

	"seclens/internal/assessor/testutil"
)

func TestCheck_Matrix(t *testing.T) {
	const domain = "example.com"
	const qname = "_smtp._tls.example.com"

	tests := []struct {
		name        string
		txt         testutil.MockTXT
		gate        Gate
		wantStatus  string
		wantPresent *bool
		wantSyntax  *bool
		issueSubs   []string
	}{
		{
			name:       "absent info",
			txt:        testutil.MockTXT{},
			gate:       testutil.AllowGate{},
			wantStatus: "info",
			issueSubs:  []string{"TLS-RPT gives visibility"},
		},
		{
			name: "multiple TXT warn",
			txt: testutil.MockTXT{
				qname: {
					"v=TLSRPTv1; rua=mailto:a@b.com;",
					"v=TLSRPTv1; rua=mailto:c@d.com;",
				},
			},
			gate:        testutil.AllowGate{},
			wantStatus:  "warn",
			wantPresent: boolPtr(true),
			wantSyntax:  boolPtr(false),
			issueSubs:   []string{"exactly one"},
		},
		{
			name: "wrong version warn",
			txt: testutil.MockTXT{
				qname: {"v=TLSRPTv1; v=TLSRPTv0; rua=mailto:tlsrpt@example.com;"},
			},
			gate:       testutil.AllowGate{},
			wantStatus: "warn",
			issueSubs:  []string{"v= must be TLSRPTv1"},
		},
		{
			name: "no rua warn",
			txt: testutil.MockTXT{
				qname: {"v=TLSRPTv1;"},
			},
			gate:       testutil.AllowGate{},
			wantStatus: "warn",
			issueSubs:  []string{"rua= is required"},
		},
		{
			name: "valid mailto rua pass",
			txt: testutil.MockTXT{
				qname: {"v=TLSRPTv1; rua=mailto:tlsrpt@example.com;"},
			},
			gate:       testutil.AllowGate{},
			wantStatus: "pass",
		},
		{
			name:       "gate skip",
			txt:        testutil.MockTXT{qname: {"v=TLSRPTv1; rua=mailto:tlsrpt@example.com;"}},
			gate:       testutil.DenyGate{},
			wantStatus: "info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Check(context.Background(), Request{Domain: domain}, Deps{
				DNS:  tt.txt,
				Gate: tt.gate,
			})
			testutil.AssertStatus(t, res.Status, tt.wantStatus, tt.name)
			if tt.wantPresent != nil && res.Present != *tt.wantPresent {
				t.Fatalf("Present=%v want %v", res.Present, *tt.wantPresent)
			}
			if tt.wantSyntax != nil && res.SyntaxOK != *tt.wantSyntax {
				t.Fatalf("SyntaxOK=%v want %v", res.SyntaxOK, *tt.wantSyntax)
			}
			if len(tt.issueSubs) > 0 {
				testutil.AssertIssuesContain(t, res.Issues, tt.issueSubs...)
			}
		})
	}
}

func boolPtr(v bool) *bool { return &v }