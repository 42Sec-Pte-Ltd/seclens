package rfc7505

import (
	"strings"
	"testing"

	"seclens/internal/report"
)

func TestNormalizeExchange(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{".", "."},
		{"mail.example.com.", "mail.example.com"},
		{"route1.mx.cloudflare.net.", "route1.mx.cloudflare.net"},
	}
	for _, tc := range tests {
		if got := NormalizeExchange(tc.in); got != tc.want {
			t.Errorf("NormalizeExchange(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHasNullMXRR(t *testing.T) {
	if !HasNullMXRR([]report.MXRecord{{Pref: 0, Host: "."}}) {
		t.Fatal("expected null MX for 0 .")
	}
	if !HasNullMXRR([]report.MXRecord{{Pref: 0, Host: ""}}) {
		t.Fatal("expected null MX for legacy empty host")
	}
	if HasNullMXRR([]report.MXRecord{{Pref: 10, Host: "mail.example.com"}}) {
		t.Fatal("did not expect null MX for real host")
	}
}

func TestIsValidNullMX(t *testing.T) {
	tests := []struct {
		name string
		mxs  []report.MXRecord
		want bool
	}{
		{"single dot", []report.MXRecord{{Pref: 0, Host: "."}}, true},
		{"single empty host", []report.MXRecord{{Pref: 0, Host: ""}}, true},
		{"no mx", nil, false},
		{"real mx", []report.MXRecord{{Pref: 10, Host: "mail.example.com"}}, false},
		{"null plus real", []report.MXRecord{{Pref: 0, Host: "."}, {Pref: 10, Host: "mail.example.com"}}, false},
		{"wrong pref", []report.MXRecord{{Pref: 10, Host: "."}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidNullMX(tt.mxs); got != tt.want {
				t.Fatalf("IsValidNullMX() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsStrictNullMXSPF(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{"v=spf1 -all", true},
		{"V=SPF1 -ALL", true},
		{"  v=spf1   -all  ", true},
		{"v=spf1 -all extra", false},
		{"v=spf1 include:foo -all", false},
		{"v=spf1 ~all", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsStrictNullMXSPF(tt.raw); got != tt.want {
			t.Errorf("IsStrictNullMXSPF(%q) = %v, want %v", tt.raw, got, tt.want)
		}
	}
}

func TestDetectViolation(t *testing.T) {
	tests := []struct {
		name string
		mxs  []report.MXRecord
		want Violation
	}{
		{"valid", []report.MXRecord{{Pref: 0, Host: "."}}, ViolationNone},
		{"no mx", nil, ViolationNone},
		{"mixed", []report.MXRecord{{Pref: 0, Host: "."}, {Pref: 10, Host: "mail.example.com"}}, ViolationMixedMX},
		{"multiple real", []report.MXRecord{{Pref: 10, Host: "a.example.com"}, {Pref: 20, Host: "b.example.com"}}, ViolationMultipleMX},
		{"wrong pref", []report.MXRecord{{Pref: 10, Host: "."}}, ViolationWrongPreference},
		{"wrong host", []report.MXRecord{{Pref: 0, Host: "mail.example.com"}}, ViolationWrongExchange},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectViolation(tt.mxs); got != tt.want {
				t.Fatalf("DetectViolation() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetectPosture(t *testing.T) {
	tests := []struct {
		name string
		mxs  []report.MXRecord
		want string
	}{
		{"no mx", nil, PostureNoMX},
		{"null only", []report.MXRecord{{Pref: 0, Host: "."}}, PostureNullMXOnly},
		{"mixed", []report.MXRecord{{Pref: 0, Host: "."}, {Pref: 10, Host: "mail.example.com"}}, PostureMixedInvalid},
		{"mail", []report.MXRecord{{Pref: 10, Host: "mail.example.com"}}, PostureMailEnabled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectPosture(tt.mxs); got != tt.want {
				t.Fatalf("DetectPosture() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCheckNullMXBranches(t *testing.T) {
	t.Run("pass valid null mx", func(t *testing.T) {
		res := Check([]report.MXRecord{{Pref: 0, Host: "."}})
		if res.Status != "pass" {
			t.Fatalf("status=%q want pass", res.Status)
		}
		if res.Violation != ViolationNone.String() {
			t.Fatalf("violation=%q want None", res.Violation)
		}
		if res.Posture != PostureNullMXOnly {
			t.Fatalf("posture=%q want NullMXOnly", res.Posture)
		}
	})

	t.Run("fail no mx", func(t *testing.T) {
		res := Check(nil)
		if res.Status != "fail" {
			t.Fatalf("status=%q want fail", res.Status)
		}
		if res.Posture != PostureNoMX {
			t.Fatalf("posture=%q want NoMX", res.Posture)
		}
		if len(res.Issues) == 0 {
			t.Fatal("expected issues for missing MX")
		}
	})

	t.Run("fail multiple mx", func(t *testing.T) {
		res := Check([]report.MXRecord{{Pref: 0, Host: "."}, {Pref: 0, Host: "."}})
		if res.Status != "fail" || res.Violation != ViolationMultipleMX.String() {
			t.Fatalf("status=%q violation=%q", res.Status, res.Violation)
		}
	})

	t.Run("fail wrong preference", func(t *testing.T) {
		res := Check([]report.MXRecord{{Pref: 10, Host: "."}})
		if res.Violation != ViolationWrongPreference.String() {
			t.Fatalf("violation=%q want WrongPreference", res.Violation)
		}
	})

	t.Run("fail wrong exchange", func(t *testing.T) {
		res := Check([]report.MXRecord{{Pref: 0, Host: "mail.example.com"}})
		if res.Violation != ViolationWrongExchange.String() {
			t.Fatalf("violation=%q want WrongExchange", res.Violation)
		}
	})

	t.Run("fail mixed mx violation", func(t *testing.T) {
		mxs := []report.MXRecord{{Pref: 0, Host: "."}, {Pref: 10, Host: "mail.example.com"}}
		res := Check(mxs)
		if res.Status != "fail" {
			t.Fatalf("status=%q want fail", res.Status)
		}
		if res.Violation != ViolationMixedMX.String() {
			t.Fatalf("violation=%q want MixedMX", res.Violation)
		}
		if res.Posture != PostureMixedInvalid {
			t.Fatalf("posture=%q want MixedInvalid", res.Posture)
		}
		found := false
		for _, iss := range res.Issues {
			if strings.Contains(iss, "RFC 7505 §3") || strings.Contains(iss, "only MX") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected RFC 7505 §3 issue, got %v", res.Issues)
		}
	})
}

func TestIsMailEnabled(t *testing.T) {
	if !IsMailEnabled([]report.MXRecord{{Pref: 10, Host: "mail.example.com"}}) {
		t.Fatal("expected mail enabled for real MX")
	}
	if !IsMailEnabled([]report.MXRecord{{Pref: 0, Host: "."}, {Pref: 10, Host: "mail.example.com"}}) {
		t.Fatal("expected mail enabled for mixed MX")
	}
	if IsMailEnabled([]report.MXRecord{{Pref: 0, Host: "."}}) {
		t.Fatal("did not expect mail enabled for valid null MX")
	}
}

func TestRecommended(t *testing.T) {
	rec := Recommended("example.com")
	if rec.MX != "0 ." || rec.SPF != "v=spf1 -all" {
		t.Fatalf("unexpected recommendations: %+v", rec)
	}
	if !strings.Contains(rec.DMARC, "p=reject") {
		t.Fatalf("dmarc=%q want p=reject", rec.DMARC)
	}
}