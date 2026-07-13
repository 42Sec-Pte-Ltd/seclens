package rfc7505

import (
	"testing"

	"seclens/internal/assessor/testutil"
	"seclens/internal/report"
)

// TestCheckMatrix exercises Check() outcomes across RFC 7505 null MX configurations.
// Complements rfc7505_test.go with table-driven status/violation/posture/issue coverage.
func TestCheckMatrix(t *testing.T) {
	tests := []struct {
		name          string
		mxs           []report.MXRecord
		wantStatus    string
		wantViolation string
		wantPosture   string
		wantIssues    []string
	}{
		{
			name:          "valid null mx dot",
			mxs:           []report.MXRecord{{Pref: 0, Host: "."}},
			wantStatus:    "pass",
			wantViolation: ViolationNone.String(),
			wantPosture:   PostureNullMXOnly,
		},
		{
			name:          "valid null mx legacy empty host",
			mxs:           []report.MXRecord{{Pref: 0, Host: ""}},
			wantStatus:    "pass",
			wantViolation: ViolationNone.String(),
			wantPosture:   PostureNullMXOnly,
		},
		{
			name:          "no mx nil",
			mxs:           nil,
			wantStatus:    "fail",
			wantViolation: ViolationNone.String(),
			wantPosture:   PostureNoMX,
			wantIssues:    []string{"exactly one MX record"},
		},
		{
			name:          "no mx empty slice",
			mxs:           []report.MXRecord{},
			wantStatus:    "fail",
			wantViolation: ViolationNone.String(),
			wantPosture:   PostureNoMX,
			wantIssues:    []string{"null MX profile requires"},
		},
		{
			name:          "multiple null mx",
			mxs:           []report.MXRecord{{Pref: 0, Host: "."}, {Pref: 0, Host: "."}},
			wantStatus:    "fail",
			wantViolation: ViolationMultipleMX.String(),
			wantPosture:   PostureNoMX, // all RRs are null MX; no non-null mail path
			wantIssues:    []string{"exactly one MX record"},
		},
		{
			name:          "multiple real mx",
			mxs:           []report.MXRecord{{Pref: 10, Host: "a.example.com"}, {Pref: 20, Host: "b.example.com"}},
			wantStatus:    "fail",
			wantViolation: ViolationMultipleMX.String(),
			wantPosture:   PostureMailEnabled,
			wantIssues:    []string{"exactly one MX record"},
		},
		{
			name:          "mixed null and real mx",
			mxs:           []report.MXRecord{{Pref: 0, Host: "."}, {Pref: 10, Host: "mail.example.com"}},
			wantStatus:    "fail",
			wantViolation: ViolationMixedMX.String(),
			wantPosture:   PostureMixedInvalid,
			wantIssues:    []string{"RFC 7505 §3", "only MX"},
		},
		{
			name:          "wrong preference dot exchange",
			mxs:           []report.MXRecord{{Pref: 10, Host: "."}},
			wantStatus:    "fail",
			wantViolation: ViolationWrongPreference.String(),
			wantPosture:   PostureMailEnabled,
			wantIssues:    []string{"preference must be 0"},
		},
		{
			name:          "wrong exchange zero preference",
			mxs:           []report.MXRecord{{Pref: 0, Host: "mail.example.com"}},
			wantStatus:    "fail",
			wantViolation: ViolationWrongExchange.String(),
			wantPosture:   PostureMailEnabled,
			wantIssues:    []string{`host must be "."`},
		},
		{
			name:          "wrong preference and exchange",
			mxs:           []report.MXRecord{{Pref: 10, Host: "mail.example.com"}},
			wantStatus:    "fail",
			wantViolation: ViolationWrongPreference.String(),
			wantPosture:   PostureMailEnabled,
			wantIssues:    []string{"preference must be 0", `host must be "."`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Check(tt.mxs)

			testutil.AssertStatus(t, res.Status, tt.wantStatus, tt.name)
			if res.Violation != tt.wantViolation {
				t.Fatalf("%s: violation=%q want %q", tt.name, res.Violation, tt.wantViolation)
			}
			if res.Posture != tt.wantPosture {
				t.Fatalf("%s: posture=%q want %q", tt.name, res.Posture, tt.wantPosture)
			}
			if tt.wantStatus == "pass" && res.Message == "" {
				t.Fatalf("%s: expected non-empty pass message", tt.name)
			}
			if len(tt.wantIssues) > 0 {
				testutil.AssertIssuesContain(t, res.Issues, tt.wantIssues...)
			}
			if got := DetectViolation(tt.mxs); got.String() != res.Violation {
				t.Fatalf("%s: DetectViolation=%q Check.Violation=%q", tt.name, got, res.Violation)
			}
		})
	}
}

// TestCheckMatrix_NoInputGate documents that Check() has no Gate parameter.
// Null MX validation runs on pre-fetched MX records; AllowGate/DenyGate apply at assessor entry only.
func TestCheckMatrix_NoInputGate(t *testing.T) {
	mxs := []report.MXRecord{{Pref: 0, Host: "."}}

	allow := testutil.AllowGate{}
	deny := testutil.DenyGate{}

	if !allow.ValidShape("example.com") || !allow.Allowed("example.com") {
		t.Fatal("AllowGate fixture should pass example.com")
	}
	if deny.ValidShape("example.com") || deny.Allowed("example.com") {
		t.Fatal("DenyGate fixture should block example.com")
	}

	res := Check(mxs)
	testutil.AssertStatus(t, res.Status, "pass", "Check without gate")
}

// TestIsMailEnabledMatrix covers inbound-mail posture edge cases beyond rfc7505_test.go.
func TestIsMailEnabledMatrix(t *testing.T) {
	tests := []struct {
		name string
		mxs  []report.MXRecord
		want bool
	}{
		{"nil mx", nil, false},
		{"empty mx", []report.MXRecord{}, false},
		{"valid null mx", []report.MXRecord{{Pref: 0, Host: "."}}, false},
		{"real mx", []report.MXRecord{{Pref: 10, Host: "mail.example.com"}}, true},
		{"mixed mx", []report.MXRecord{{Pref: 0, Host: "."}, {Pref: 10, Host: "mail.example.com"}}, true},
		{"wrong pref dot treated as non-null", []report.MXRecord{{Pref: 10, Host: "."}}, true},
		{"wrong host zero pref treated as non-null", []report.MXRecord{{Pref: 0, Host: "mail.example.com"}}, true},
		{"multiple real mx", []report.MXRecord{{Pref: 10, Host: "a.example.com"}, {Pref: 20, Host: "b.example.com"}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsMailEnabled(tt.mxs); got != tt.want {
				t.Fatalf("IsMailEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}