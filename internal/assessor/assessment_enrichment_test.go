package assessor

import (
	"strings"
	"testing"

	"seclens/internal/report"
)

func TestApplyPostFanInEnrichment_NilReport(t *testing.T) {
	applyPostFanInEnrichment(nil) // must not panic
}

func TestApplyPostFanInEnrichment_DANE_DNSSEC(t *testing.T) {
	r := report.Report{
		Domain:        "example.com",
		IsMailEnabled: true,
		MXs:           []report.MXRecord{{Pref: 10, Host: "mx1.example.com"}, {Pref: 20, Host: "mx2.example.com"}},
		DANE: &report.DANEResult{
			AdvertisedFor: []string{"mx1.example.com"},
			MXCovered:     true,
			SyntaxOK:      true,
			Status:        "warn",
		},
		DNSSEC: &report.DNSSECResult{
			DSPresent:     true,
			DNSKEYPresent: true,
			ResolverAD:    true,
			TLDSupported:  true,
			Status:        "pass",
		},
		TLSRPT: &report.TLSRPTResult{Present: false, Status: "info"},
		MTASTS: &report.MTASTSResult{
			Status:        "pass",
			Mode:          "enforce",
			DNSAdvertised: true,
			PolicyFetched: true,
			MXCoverageOK:  true,
			DNSIDValid:    true,
			PolicyID:      "20160831085700Z",
		},
	}

	applyPostFanInEnrichment(&r)

	if !r.DANE.DNSSECValidated {
		t.Fatal("expected DANE DNSSECValidated after enrich")
	}
	if r.DANE.Status != "pass" {
		t.Fatalf("DANE status=%s want pass after DNSSEC enrich", r.DANE.Status)
	}
	if r.TLSRPT.RecommendedDNSTXT != "v=TLSRPTv1; rua=mailto:tlsrpt@example.com" {
		t.Fatalf("TLSRPT RecommendedDNSTXT=%q", r.TLSRPT.RecommendedDNSTXT)
	}
	if r.MTASTS.RecommendedDNSTXT != "v=STSv1; id=20160831085700Z;" {
		t.Fatalf("MTASTS RecommendedDNSTXT=%q", r.MTASTS.RecommendedDNSTXT)
	}
	if r.MTASTS.RecommendedPolicy == "" {
		t.Fatal("expected MTASTS RecommendedPolicy")
	}
	if !strings.Contains(r.MTASTS.RecommendedPolicy, "mx: mx1.example.com") {
		t.Fatalf("RecommendedPolicy missing mx1: %q", r.MTASTS.RecommendedPolicy)
	}
	if !strings.Contains(r.MTASTS.RecommendedPolicy, "mx: mx2.example.com") {
		t.Fatalf("RecommendedPolicy missing mx2: %q", r.MTASTS.RecommendedPolicy)
	}
	for _, iss := range r.MTASTS.Issues {
		if strings.Contains(iss, "DANE validation takes precedence") {
			t.Fatalf("unexpected DANE precedence issue: %q", iss)
		}
	}

	PopulateCheckScores(&r)
	if r.DANE.EarnedPoints != 10 {
		t.Fatalf("DANE EarnedPoints=%d want 10 after enrich+score", r.DANE.EarnedPoints)
	}
}

func TestApplyPostFanInEnrichment_DANE_DNSSECIncomplete(t *testing.T) {
	r := report.Report{
		Profile: "mail",
		DANE: &report.DANEResult{
			AdvertisedFor: []string{"mx.example.com"},
			MXCovered:     true,
			SyntaxOK:      true,
			Status:        "warn",
		},
		DNSSEC: &report.DNSSECResult{
			DSPresent:    true,
			TLDSupported: true,
			Status:       "warn",
		},
	}
	applyPostFanInEnrichment(&r)
	if r.DANE.DNSSECValidated {
		t.Fatal("expected DNSSECValidated false without resolver AD")
	}
	if r.DANE.Status != "warn" {
		t.Fatalf("DANE status=%s want warn without DNSSEC validation", r.DANE.Status)
	}
	found := false
	for _, iss := range r.DANE.Issues {
		if strings.Contains(iss, "TLSA records without DNSSEC validation") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected DANE DNSSEC caveat issue")
	}
	PopulateCheckScores(&r)
	if r.DANE.EarnedPoints != 5 {
		t.Fatalf("DANE EarnedPoints=%d want 5 without DNSSEC validation", r.DANE.EarnedPoints)
	}
}

func TestApplyPostFanInEnrichment_TLSRPT_Recommend(t *testing.T) {
	r := report.Report{
		Domain:        "mail.example.org",
		IsMailEnabled: true,
		TLSRPT:        &report.TLSRPTResult{Present: true, Status: "pass"},
	}
	applyPostFanInEnrichment(&r)
	want := "v=TLSRPTv1; rua=mailto:tlsrpt@mail.example.org"
	if r.TLSRPT.RecommendedDNSTXT != want {
		t.Fatalf("TLSRPT RecommendedDNSTXT=%q want %q", r.TLSRPT.RecommendedDNSTXT, want)
	}
}

func TestApplyPostFanInEnrichment_MTASTS_RecommendInvalidDNSID(t *testing.T) {
	r := report.Report{
		Domain:        "example.com",
		IsMailEnabled: true,
		MXs:           []report.MXRecord{{Pref: 10, Host: "mx.example.com"}},
		MTASTS: &report.MTASTSResult{
			DNSAdvertised: true,
			DNSIDValid:    false,
			PolicyID:      "bad-id!",
		},
	}
	applyPostFanInEnrichment(&r)
	if r.MTASTS.RecommendedPolicy == "" {
		t.Fatal("expected RecommendedPolicy")
	}
	if !strings.HasPrefix(r.MTASTS.RecommendedDNSTXT, "v=STSv1; id=") {
		t.Fatalf("RecommendedDNSTXT=%q", r.MTASTS.RecommendedDNSTXT)
	}
	if strings.Contains(r.MTASTS.RecommendedDNSTXT, "bad-id!") {
		t.Fatal("invalid DNS id should be replaced in recommendation")
	}
}

func TestApplyPostFanInEnrichment_MTASTS_SkipsNullMXHosts(t *testing.T) {
	r := report.Report{
		Domain:        "example.com",
		IsMailEnabled: true, // mixed MX still mail-enabled
		MXs: []report.MXRecord{
			{Pref: 0, Host: "."},
			{Pref: 10, Host: ""},
			{Pref: 20, Host: "mx.example.com"},
		},
		MTASTS: &report.MTASTSResult{DNSAdvertised: true},
	}
	applyPostFanInEnrichment(&r)
	if strings.Contains(r.MTASTS.RecommendedPolicy, "mx: .") {
		t.Fatal("null MX host should be omitted from RecommendedPolicy")
	}
	if !strings.Contains(r.MTASTS.RecommendedPolicy, "mx: mx.example.com") {
		t.Fatalf("RecommendedPolicy=%q", r.MTASTS.RecommendedPolicy)
	}
}

func TestApplyPostFanInEnrichment_EnrichCrossChecks_TestingWithoutTLSRPT(t *testing.T) {
	r := report.Report{
		Domain:        "example.com",
		IsMailEnabled: true,
		MTASTS: &report.MTASTSResult{
			Status:        "warn",
			Mode:          "testing",
			DNSAdvertised: true,
			PolicyFetched: true,
		},
		TLSRPT: &report.TLSRPTResult{Present: false, Status: "info"},
	}
	applyPostFanInEnrichment(&r)
	found := false
	for _, iss := range r.MTASTS.Issues {
		if iss == "mode=testing without TLS-RPT (_smtp._tls): failure visibility is limited (RFC 8461 §6 + RFC 8460)" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected TLS-RPT cross-check issue on testing mode")
	}
}

func TestApplyPostFanInEnrichment_EnrichCrossChecks_TestingWithTLSRPT(t *testing.T) {
	r := report.Report{
		IsMailEnabled: true,
		MTASTS: &report.MTASTSResult{
			Mode:          "testing",
			DNSAdvertised: true,
			PolicyFetched: true,
		},
		TLSRPT: &report.TLSRPTResult{Present: true, Status: "pass"},
	}
	applyPostFanInEnrichment(&r)
	for _, iss := range r.MTASTS.Issues {
		if strings.Contains(iss, "mode=testing without TLS-RPT") {
			t.Fatalf("unexpected cross-check when TLS-RPT present: %q", iss)
		}
	}
}

func TestApplyPostFanInEnrichment_SkipsNilOptionalResults(t *testing.T) {
	r := report.Report{Domain: "example.com"}
	applyPostFanInEnrichment(&r) // DANE/TLSRPT/MTASTS nil — must not panic
}

func TestApplyPostFanInEnrichment_DANEOnly(t *testing.T) {
	r := report.Report{
		DANE:   &report.DANEResult{AdvertisedFor: []string{"mx.example.com"}, Status: "info"},
		DNSSEC: &report.DNSSECResult{DSPresent: true, ResolverAD: true, TLDSupported: true},
	}
	applyPostFanInEnrichment(&r)
	if r.DANE.DNSSECValidated {
		t.Fatal("expected DNSSECValidated false without DNSKEY")
	}
}

func TestApplyPostFanInEnrichment_TLSRPTOnly(t *testing.T) {
	r := report.Report{
		Domain:        "solo.example",
		IsMailEnabled: true,
		TLSRPT:        &report.TLSRPTResult{Status: "info"},
	}
	applyPostFanInEnrichment(&r)
	if r.TLSRPT.RecommendedDNSTXT == "" {
		t.Fatal("expected TLSRPT recommendation without MTASTS")
	}
}

func TestApplyPostFanInEnrichment_NoMailSkipsMTASTSAndTLSRPTRecipes(t *testing.T) {
	// Domains without inbound mail must not get MTA-STS / TLS-RPT deploy recipes.
	r := report.Report{
		Domain:        "nomail.example",
		IsMailEnabled: false,
		Profile:       "null_mx",
		MTASTS: &report.MTASTSResult{
			Status:            "info",
			RecommendedPolicy: "version: STSv1\nmode: enforce\n",
			RecommendedDNSTXT: "v=STSv1; id=stale;",
		},
		TLSRPT: &report.TLSRPTResult{
			Status:            "info",
			RecommendedDNSTXT: "v=TLSRPTv1; rua=mailto:tlsrpt@nomail.example",
		},
	}
	applyPostFanInEnrichment(&r)
	if r.MTASTS.RecommendedPolicy != "" || r.MTASTS.RecommendedDNSTXT != "" {
		t.Fatalf("MTA-STS recommendations should be cleared for no-mail: policy=%q dns=%q",
			r.MTASTS.RecommendedPolicy, r.MTASTS.RecommendedDNSTXT)
	}
	if r.TLSRPT.RecommendedDNSTXT != "" {
		t.Fatalf("TLS-RPT recommendation should be cleared for no-mail: %q", r.TLSRPT.RecommendedDNSTXT)
	}
}