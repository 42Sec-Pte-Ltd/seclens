package rfc7489

import (
	"context"
	"testing"

	"seclens/internal/assessor/testutil"
)

const checkMatrixDomain = "example.com"

func dmarcTXTName(domain string) string {
	return "_dmarc." + domain
}

func TestCheck_Matrix(t *testing.T) {
	ctx := context.Background()
	name := dmarcTXTName(checkMatrixDomain)

	tests := []struct {
		name          string
		req           Request
		deps          Deps
		wantStatus    string
		wantPresent   bool
		wantPolicy    string
		wantSyntaxOK  *bool
		issueContains string
	}{
		{
			name:       "input gated",
			req:        Request{Domain: checkMatrixDomain},
			deps:       Deps{DNS: testutil.MockTXT{}, Gate: testutil.DenyGate{}},
			wantStatus: "info",
		},
		{
			name:         "absent no DMARC TXT",
			req:          Request{Domain: checkMatrixDomain},
			deps:         Deps{DNS: testutil.MockTXT{}, Gate: testutil.AllowGate{}},
			wantStatus:   "info",
			wantPresent:  false,
			wantPolicy:   "",
			wantSyntaxOK: boolPtr(false),
		},
		{
			name:       "lookup fail",
			req:        Request{Domain: checkMatrixDomain},
			deps:       Deps{DNS: testutil.ErrTXT{}, Gate: testutil.AllowGate{}},
			wantStatus: "fail",
		},
		{
			name: "multiple DMARC TXT records",
			req:  Request{Domain: checkMatrixDomain},
			deps: Deps{
				DNS: testutil.MockTXT{
					name: {
						"v=DMARC1; p=reject",
						"v=DMARC1; p=none",
					},
				},
				Gate: testutil.AllowGate{},
			},
			wantStatus:    "fail",
			wantPresent:   false,
			issueContains: "exactly one",
		},
		{
			name: "p=reject with rua",
			req:  Request{Domain: checkMatrixDomain},
			deps: Deps{
				DNS: testutil.MockTXT{
					name: {"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"},
				},
				Gate: testutil.AllowGate{},
			},
			wantStatus:  "pass",
			wantPresent: true,
			wantPolicy:  "reject",
		},
		{
			name: "p=quarantine with rua",
			req:  Request{Domain: checkMatrixDomain},
			deps: Deps{
				DNS: testutil.MockTXT{
					name: {"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"},
				},
				Gate: testutil.AllowGate{},
			},
			wantStatus:  "warn",
			wantPresent: true,
			wantPolicy:  "quarantine",
		},
		{
			name: "p=none with rua",
			req:  Request{Domain: checkMatrixDomain},
			deps: Deps{
				DNS: testutil.MockTXT{
					name: {"v=DMARC1; p=none; rua=mailto:dmarc@example.com"},
				},
				Gate: testutil.AllowGate{},
			},
			wantStatus:  "warn",
			wantPresent: true,
			wantPolicy:  "none",
		},
		{
			name: "missing p= fails syntax",
			req:  Request{Domain: checkMatrixDomain},
			deps: Deps{
				DNS: testutil.MockTXT{
					name: {"v=DMARC1; rua=mailto:dmarc@example.com"},
				},
				Gate: testutil.AllowGate{},
			},
			wantStatus:   "fail",
			wantPresent:  true,
			wantPolicy:   "",
			wantSyntaxOK: boolPtr(false),
			issueContains: "p=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Check(ctx, tt.req, tt.deps)
			testutil.AssertStatus(t, res.Status, tt.wantStatus, tt.name)

			if res.Present != tt.wantPresent {
				t.Fatalf("%s: Present=%v want %v", tt.name, res.Present, tt.wantPresent)
			}
			if tt.wantPolicy != "" && res.Policy != tt.wantPolicy {
				t.Fatalf("%s: Policy=%q want %q", tt.name, res.Policy, tt.wantPolicy)
			}
			if tt.wantPolicy == "" && res.Policy != "" {
				t.Fatalf("%s: Policy=%q want empty", tt.name, res.Policy)
			}
			if tt.wantSyntaxOK != nil && res.SyntaxOK != *tt.wantSyntaxOK {
				t.Fatalf("%s: SyntaxOK=%v want %v", tt.name, res.SyntaxOK, *tt.wantSyntaxOK)
			}
			if tt.issueContains != "" {
				testutil.AssertIssuesContain(t, res.Issues, tt.issueContains)
			}
		})
	}
}

func TestCheck_Matrix_NullMXProfile(t *testing.T) {
	ctx := context.Background()
	name := dmarcTXTName(checkMatrixDomain)

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
			name:       "reject with low pct passes",
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
			deps := Deps{
				DNS: testutil.MockTXT{name: {tt.raw}},
				Gate: testutil.AllowGate{},
			}
			req := Request{Domain: checkMatrixDomain, NullMXProfile: true}
			res := Check(ctx, req, deps)
			testutil.AssertStatus(t, res.Status, tt.wantStatus, tt.name)
			if len(res.Issues) != tt.wantIssues {
				t.Fatalf("%s: issues=%d want %d: %v", tt.name, len(res.Issues), tt.wantIssues, res.Issues)
			}
		})
	}
}

func boolPtr(v bool) *bool { return &v }