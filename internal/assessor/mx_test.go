package assessor

import (
	"testing"

	"seclens/internal/assessor/rfc7505"
	"seclens/internal/report"
)

func TestNormalizeMXHost(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{".", "."},
		{"mail.example.com.", "mail.example.com"},
		{"route1.mx.cloudflare.net.", "route1.mx.cloudflare.net"},
	}
	for _, tc := range tests {
		if got := rfc7505.NormalizeExchange(tc.in); got != tc.want {
			t.Errorf("NormalizeExchange(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHasNullMX(t *testing.T) {
	if !HasNullMX([]report.MXRecord{{Pref: 0, Host: "."}}) {
		t.Fatal("expected null MX for 0 .")
	}
	if !HasNullMX([]report.MXRecord{{Pref: 0, Host: ""}}) {
		t.Fatal("expected null MX for legacy empty host")
	}
	if HasNullMX([]report.MXRecord{{Pref: 10, Host: "mail.example.com"}}) {
		t.Fatal("did not expect null MX for real host")
	}
}

func TestMixedMXProfileStaysMail(t *testing.T) {
	mxs := []report.MXRecord{{Pref: 0, Host: "."}, {Pref: 10, Host: "mail.example.com"}}
	if rfc7505.IsNullMXProfile(mxs) {
		t.Fatal("mixed MX must not qualify for null_mx profile")
	}
	if !HasNullMX(mxs) {
		t.Fatal("expected HasNullMX for mixed MX")
	}
	if !rfc7505.IsMailEnabled(mxs) {
		t.Fatal("expected mail enabled for mixed MX")
	}
	res := CheckNullMX(mxs)
	if res.Violation != "MixedMX" {
		t.Fatalf("violation=%q want MixedMX", res.Violation)
	}
	if res.Status != "fail" {
		t.Fatalf("status=%q want fail", res.Status)
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
			if got := rfc7505.IsValidNullMX(tt.mxs); got != tt.want {
				t.Fatalf("IsValidNullMX() = %v, want %v", got, tt.want)
			}
		})
	}
}