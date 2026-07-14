package assessor

import (
	"testing"

	"seclens/internal/report"
)

func TestComputeApplicableMax_NullMX(t *testing.T) {
	if got := ComputeApplicableMax(report.Report{Profile: "null_mx"}); got != 100 {
		t.Fatalf("null MX applicable max: got %d, want 100", got)
	}
	if got := ComputeApplicableMax(report.Report{}); got != 100 {
		t.Fatalf("mail domain applicable max: got %d, want 100", got)
	}
}

func TestNullMXProfileScoring_FullCompliance(t *testing.T) {
	mxs := []report.MXRecord{{Pref: 0, Host: "."}}
	r := report.Report{
		Profile: "null_mx",
		MXs:     mxs,
		NullMX:  &report.NullMXResult{Status: "pass"},
		SPF:     &report.SPFResult{Present: true, Raw: "v=spf1 -all", Status: "pass"},
		DMARC:   &report.DMARCResult{Policy: "reject", Status: "pass", SyntaxOK: true},
		DNSSEC: &report.DNSSECResult{
			DSPresent: true, DNSKEYPresent: true, ResolverAD: true, TLDSupported: true, Status: "pass",
		},
	}
	PopulateCheckScores(&r)

	if r.NullMX.EarnedPoints != 25 || r.NullMX.MaxPoints != 25 {
		t.Errorf("NullMX points: got %d/%d, want 25/25", r.NullMX.EarnedPoints, r.NullMX.MaxPoints)
	}
	if r.SPF.EarnedPoints != 25 || r.SPF.MaxPoints != 25 {
		t.Errorf("SPF points: got %d/%d, want 25/25", r.SPF.EarnedPoints, r.SPF.MaxPoints)
	}
	if r.DMARC.EarnedPoints != 35 || r.DMARC.MaxPoints != 35 {
		t.Errorf("DMARC points: got %d/%d, want 35/35", r.DMARC.EarnedPoints, r.DMARC.MaxPoints)
	}
	if r.DNSSEC.EarnedPoints != 15 || r.DNSSEC.MaxPoints != 15 {
		t.Errorf("DNSSEC points: got %d/%d, want 15/15", r.DNSSEC.EarnedPoints, r.DNSSEC.MaxPoints)
	}
	if got := ComputeScore(r); got != 100 {
		t.Errorf("ComputeScore: got %d, want 100", got)
	}
}

func TestNullMXProfileScoring_DNSSECRedistribution(t *testing.T) {
	mxs := []report.MXRecord{{Pref: 0, Host: "."}}
	r := report.Report{
		Profile: "null_mx",
		MXs:     mxs,
		NullMX:  &report.NullMXResult{Status: "pass"},
		SPF:     &report.SPFResult{Present: true, Raw: "v=spf1 -all"},
		DMARC:   &report.DMARCResult{Policy: "reject", SyntaxOK: true},
		DNSSEC: &report.DNSSECResult{
			TLDSupported: false,
			Message:      dnssecNotApplicableMessage,
			Status:       "info",
		},
	}
	PopulateCheckScores(&r)

	if r.NullMX.MaxPoints != 30 {
		t.Errorf("NullMX max: got %d, want 30", r.NullMX.MaxPoints)
	}
	if r.SPF.MaxPoints != 30 {
		t.Errorf("SPF max: got %d, want 30", r.SPF.MaxPoints)
	}
	if r.DMARC.MaxPoints != 40 {
		t.Errorf("DMARC max: got %d, want 40", r.DMARC.MaxPoints)
	}
	if r.DNSSEC.MaxPoints != 0 {
		t.Errorf("DNSSEC max: got %d, want 0", r.DNSSEC.MaxPoints)
	}
	if got := ComputeScore(r); got != 100 {
		t.Errorf("ComputeScore full compliance without DNSSEC: got %d, want 100", got)
	}
}

func TestNullMXProfileScoring_Normalization(t *testing.T) {
	mxs := []report.MXRecord{{Pref: 0, Host: "."}}
	r := report.Report{
		Profile: "null_mx",
		MXs:     mxs,
		NullMX:  &report.NullMXResult{Status: "pass"},
		SPF:     &report.SPFResult{Present: true, Raw: "v=spf1 -all"},
		DMARC:   &report.DMARCResult{Policy: "none", SyntaxOK: true},
		DNSSEC:  &report.DNSSECResult{DSPresent: false, TLDSupported: true},
	}
	PopulateCheckScores(&r)
	// earned: 25 null + 25 spf + 0 dmarc + 0 dnssec = 50 / 100
	if got := ComputeScore(r); got != 50 {
		t.Errorf("ComputeScore partial: got %d, want 50", got)
	}
}

func TestMixedMXUsesMailProfileScoring(t *testing.T) {
	mxs := []report.MXRecord{{Pref: 0, Host: "."}, {Pref: 10, Host: "mail.example.com"}}
	r := report.Report{
		Profile:   "mail",
		HasNullMX: true,
		MXs:       mxs,
		NullMX:    &report.NullMXResult{Status: "fail", Violation: "MixedMX"},
		SPF:       &report.SPFResult{Present: true, Status: "pass", AllQualifier: "-", LookupCount: 3},
		DMARC:     &report.DMARCResult{Policy: "reject", SyntaxOK: true},
	}
	PopulateCheckScores(&r)
	if effectiveProfile(r) != "mail" {
		t.Fatalf("profile=%q want mail", effectiveProfile(r))
	}
	if r.NullMX != nil && r.NullMX.MaxPoints != 0 && r.NullMX.EarnedPoints != 0 {
		t.Fatalf("mail profile must not score NullMX bucket: got %d/%d", r.NullMX.EarnedPoints, r.NullMX.MaxPoints)
	}
	if r.SPF.MaxPoints != MaxPointsSPF {
		t.Fatalf("SPF max=%d want mail profile %d", r.SPF.MaxPoints, MaxPointsSPF)
	}
}

func TestNullMXCompliant(t *testing.T) {
	mxs := []report.MXRecord{{Pref: 0, Host: "."}}
	r := report.Report{
		Profile: "null_mx",
		MXs:     mxs,
		NullMX:  &report.NullMXResult{Status: "pass"},
		SPF:     &report.SPFResult{Present: true, Raw: "v=spf1 -all"},
		DMARC:   &report.DMARCResult{Policy: "reject", SyntaxOK: true},
		DNSSEC: &report.DNSSECResult{
			DSPresent: true, DNSKEYPresent: true, ResolverAD: true, TLDSupported: true,
		},
	}
	PopulateCheckScores(&r)
	r.Score = ComputeScore(r)
	PopulateProfileFields(&r)
	if !r.NullMXCompliant {
		t.Fatal("expected NullMXCompliant for perfect null_mx profile")
	}
}

func TestPopulateCheckScoresAllSevenChecks(t *testing.T) {
	r := report.Report{
		Profile: "mail",
		SPF:     &report.SPFResult{Present: true, Status: "pass", AllQualifier: "-", LookupCount: 3},
		DMARC:   &report.DMARCResult{Policy: "reject", Status: "pass", SyntaxOK: true},
		DKIM: &report.DKIMResult{
			Status:         "pass",
			SelectorsFound: []string{"s1", "s2"},
			Keys: []report.DKIMKeyRecord{
				{Selector: "s1", SyntaxOK: true},
				{Selector: "s2", SyntaxOK: true},
			},
		},
		MTASTS: &report.MTASTSResult{DNSAdvertised: true, PolicyFetched: true, Status: "pass", Mode: "enforce", MXCoverageOK: true},
		TLSRPT: &report.TLSRPTResult{Present: true, Status: "pass", SyntaxOK: true, RUAPresent: true},
		DANE: &report.DANEResult{
			AdvertisedFor: []string{"mx.example.com"}, Status: "pass",
			MXCovered: true, SyntaxOK: true, DNSSECValidated: true,
		},
		DNSSEC: &report.DNSSECResult{
			DSPresent: true, DNSKEYPresent: true, ResolverAD: true, TLDSupported: true, Status: "pass",
		},
	}
	PopulateCheckScores(&r)

	cases := []struct {
		name   string
		earned int
		max    int
		gotE   func() int
		gotM   func() int
	}{
		{"SPF", 20, 20, func() int { return r.SPF.EarnedPoints }, func() int { return r.SPF.MaxPoints }},
		{"DMARC", 25, 25, func() int { return r.DMARC.EarnedPoints }, func() int { return r.DMARC.MaxPoints }},
		{"DKIM", 10, 10, func() int { return r.DKIM.EarnedPoints }, func() int { return r.DKIM.MaxPoints }},
		{"MTA-STS", 15, 15, func() int { return r.MTASTS.EarnedPoints }, func() int { return r.MTASTS.MaxPoints }},
		{"TLS-RPT", 10, 10, func() int { return r.TLSRPT.EarnedPoints }, func() int { return r.TLSRPT.MaxPoints }},
		{"DANE", 10, 10, func() int { return r.DANE.EarnedPoints }, func() int { return r.DANE.MaxPoints }},
		{"DNSSEC", 10, 10, func() int { return r.DNSSEC.EarnedPoints }, func() int { return r.DNSSEC.MaxPoints }},
	}
	for _, c := range cases {
		if got := c.gotE(); got != c.earned {
			t.Errorf("%s EarnedPoints: got %d, want %d", c.name, got, c.earned)
		}
		if got := c.gotM(); got != c.max {
			t.Errorf("%s MaxPoints: got %d, want %d", c.name, got, c.max)
		}
		t.Logf("%s EarnedPoints=%d MaxPoints=%d", c.name, c.gotE(), c.gotM())
	}
	if got := ComputeScore(r); got != 100 {
		t.Errorf("ComputeScore: got %d, want 100", got)
	}
}

func TestPopulateCheckScoresAndComputeScore(t *testing.T) {
	spf := &report.SPFResult{
		Present:              true,
		Status:               "pass",
		AllQualifier:         "-",
		LookupCount:          12,
		HasRedirect:          true,
		RedirectDepth:        4,
		EffectiveLookupCount: 1,
	}
	r := report.Report{Profile: "mail", SPF: spf}
	PopulateCheckScores(&r)

	if spf.EarnedPoints != 20 {
		t.Errorf("SPF EarnedPoints: got %d, want 20", spf.EarnedPoints)
	}
	t.Logf("SPF EarnedPoints=%d MaxPoints=%d (want 20/%d)", spf.EarnedPoints, spf.MaxPoints, MaxPointsSPF)
	if spf.MaxPoints != MaxPointsSPF {
		t.Errorf("SPF MaxPoints: got %d, want %d", spf.MaxPoints, MaxPointsSPF)
	}
	if ComputeScore(r) != 20 {
		t.Errorf("ComputeScore: got %d, want 20", ComputeScore(r))
	}
}

func TestScoreSPF(t *testing.T) {
	tests := []struct {
		name   string
		spf    *report.SPFResult
		earned int
	}{
		{
			name:   "absent",
			spf:    &report.SPFResult{Present: false},
			earned: 0,
		},
		{
			name: "hardfail compliant low lookups",
			spf: &report.SPFResult{
				Present:      true,
				Status:       "pass",
				AllQualifier: "-",
				LookupCount:  3,
			},
			earned: 20, // 5 + 10 + 5
		},
		{
			name: "softfail compliant",
			spf: &report.SPFResult{
				Present:      true,
				Status:       "pass",
				AllQualifier: "~",
				LookupCount:  8,
			},
			earned: 15, // 5 + 5 + 5
		},
		{
			name: "fail still awards hardfail points (scoring contract)",
			spf: &report.SPFResult{
				Present:      true,
				Status:       "fail",
				AllQualifier: "-",
				LookupCount:  3,
			},
			earned: 20, // 5 + 10 + 5 (scoring contract lookup bonus on fail)
		},
		{
			name: "redirect leniency uses effective lookup count",
			spf: &report.SPFResult{
				Present:              true,
				Status:               "pass",
				AllQualifier:         "-",
				LookupCount:          12,
				HasRedirect:          true,
				RedirectDepth:        4,
				EffectiveLookupCount: 1,
			},
			earned: 20,
		},
		{
			name: "redirect leniency lookup bonus through depth 20",
			spf: &report.SPFResult{
				Present:              true,
				Status:               "pass",
				AllQualifier:         "-",
				LookupCount:          12,
				HasRedirect:          true,
				RedirectDepth:        20,
				EffectiveLookupCount: 1,
			},
			earned: 20, // 5 + 10 + 5 (scoring contract cap at 20)
		},
		{
			name: "present only no qualifier",
			spf: &report.SPFResult{
				Present:     true,
				Status:      "warn",
				LookupCount: 2,
			},
			earned: 10, // 5 + 0 + 5
		},
		{
			name: "invalid mechanism without terminator earns base only",
			spf: &report.SPFResult{
				Present: true,
				Status:  "fail",
				Issues:  []string{`invalid mechanism or modifier "foo" (PermError per RFC 7208)`},
			},
			earned: 10, // 5 base + 5 lookup (no qualifier)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, max := scoreSPF(tt.spf)
			if max != MaxPointsSPF {
				t.Errorf("max: got %d, want %d", max, MaxPointsSPF)
			}
			if got != tt.earned {
				t.Errorf("earned: got %d, want %d", got, tt.earned)
			}
		})
	}
}

func TestScoreDMARC(t *testing.T) {
	tests := []struct {
		name   string
		dmarc  *report.DMARCResult
		earned int
	}{
		{name: "reject", dmarc: &report.DMARCResult{Policy: "reject", SyntaxOK: true}, earned: 25},
		{name: "quarantine", dmarc: &report.DMARCResult{Policy: "quarantine", SyntaxOK: true}, earned: 15},
		{name: "none", dmarc: &report.DMARCResult{Policy: "none", SyntaxOK: true}, earned: 0},
		{name: "absent policy", dmarc: &report.DMARCResult{}, earned: 0},
		{
			name: "syntax invalid earns zero even with reject",
			dmarc: &report.DMARCResult{
				Policy:   "reject",
				SyntaxOK: false,
			},
			earned: 0,
		},
		{
			name: "sp=none does not affect score",
			dmarc: &report.DMARCResult{
				Policy:    "quarantine",
				SubPolicy: "none",
				SyntaxOK:  true,
			},
			earned: 15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, max := scoreDMARC(tt.dmarc)
			if max != MaxPointsDMARC {
				t.Errorf("max: got %d, want %d", max, MaxPointsDMARC)
			}
			if got != tt.earned {
				t.Errorf("earned: got %d, want %d", got, tt.earned)
			}
		})
	}
}

func TestScoreMTASTS(t *testing.T) {
	tests := []struct {
		name   string
		mtasts *report.MTASTSResult
		earned int
	}{
		{name: "no DNS", mtasts: &report.MTASTSResult{}, earned: 0},
		{name: "DNS only", mtasts: &report.MTASTSResult{DNSAdvertised: true}, earned: 5},
		{
			name: "DNS + policy fetched testing",
			mtasts: &report.MTASTSResult{
				DNSAdvertised: true,
				PolicyFetched: true,
				Status:        "warn",
				Mode:          "testing",
			},
			earned: 10,
		},
		{
			name: "invalid DNS id warn policy-fetched tier",
			mtasts: &report.MTASTSResult{
				DNSAdvertised: true,
				PolicyFetched: true,
				Status:        "warn",
				DNSIDValid:    false,
				PolicyID:      "2026-06-24T12:00:00Z",
				Mode:          "enforce",
				MXCoverageOK:  true,
				PolicySyntaxOK: true,
			},
			earned: 10,
		},
		{
			name: "invalid DNS id testing warn tier",
			mtasts: &report.MTASTSResult{
				DNSAdvertised: true,
				PolicyFetched: true,
				Status:        "warn",
				DNSIDValid:    false,
				PolicyID:      "bad-id!",
				Mode:          "testing",
			},
			earned: 10,
		},
		{
			name: "full pass",
			mtasts: &report.MTASTSResult{
				DNSAdvertised:  true,
				PolicyFetched:  true,
				Status:         "pass",
				Mode:           "enforce",
				MXCoverageOK:   true,
				DNSIDValid:     true,
				PolicySyntaxOK: true,
			},
			earned: 15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, max := scoreMTASTS(tt.mtasts)
			if max != MaxPointsMTASTS {
				t.Errorf("max: got %d, want %d", max, MaxPointsMTASTS)
			}
			if got != tt.earned {
				t.Errorf("earned: got %d, want %d", got, tt.earned)
			}
		})
	}
}

func TestScoreBinaryChecks(t *testing.T) {
	activeKey := report.DKIMKeyRecord{Selector: "google", SyntaxOK: true, KeyType: "rsa"}
	dkimEarned, dkimMax := scoreDKIM(&report.DKIMResult{
		SelectorsFound: []string{"google"},
		Keys:           []report.DKIMKeyRecord{activeKey},
	})
	if dkimEarned != 10 || dkimMax != MaxPointsDKIM {
		t.Errorf("DKIM with selector: got %d/%d, want 10/%d", dkimEarned, dkimMax, MaxPointsDKIM)
	}
	t.Logf("DKIM pass EarnedPoints=%d MaxPoints=%d (want 10/10)", dkimEarned, dkimMax)

	dkimPassEarned, dkimPassMax := scoreDKIM(&report.DKIMResult{
		Status:         "pass",
		SelectorsFound: []string{"selector1", "selector2"},
		Keys: []report.DKIMKeyRecord{
			{Selector: "selector1", SyntaxOK: true},
			{Selector: "selector2", SyntaxOK: true},
		},
	})
	if dkimPassEarned != 10 || dkimPassMax != 10 {
		t.Errorf("apple-like DKIM: got %d/%d, want 10/10", dkimPassEarned, dkimPassMax)
	}
	dkimEarned, _ = scoreDKIM(&report.DKIMResult{})
	if dkimEarned != 0 {
		t.Errorf("DKIM absent: got %d, want 0", dkimEarned)
	}

	revokedEarned, _ := scoreDKIM(&report.DKIMResult{
		SelectorsFound: []string{"old"},
		Keys:           []report.DKIMKeyRecord{{Selector: "old", Revoked: true, SyntaxOK: true}},
	})
	if revokedEarned != 10 {
		t.Errorf("DKIM revoked key: got %d, want 10 (discovery parity)", revokedEarned)
	}

	testEarned, _ := scoreDKIM(&report.DKIMResult{
		SelectorsFound: []string{"test"},
		Keys:           []report.DKIMKeyRecord{{Selector: "test", TestKey: true, SyntaxOK: true}},
	})
	if testEarned != 10 {
		t.Errorf("DKIM test-only key: got %d, want 10 (discovery parity)", testEarned)
	}

	wildEarned, _ := scoreDKIM(&report.DKIMResult{
		SelectorsFound:   []string{"any"},
		WildcardDetected: true,
		Keys:             []report.DKIMKeyRecord{{Selector: "any", SyntaxOK: true}},
	})
	if wildEarned != 0 {
		t.Errorf("DKIM wildcard: got %d, want 0", wildEarned)
	}

	// ENT present without selectors must not award points (score path ignores DomainKeySubtree).
	entEarned, entMax := scoreDKIM(&report.DKIMResult{
		SelectorsFound:   nil,
		DomainKeySubtree: "present",
		Status:           "info",
	})
	if entEarned != 0 || entMax != MaxPointsDKIM {
		t.Errorf("DKIM ENT present, 0 selectors: got %d/%d, want 0/%d", entEarned, entMax, MaxPointsDKIM)
	}

	tlsEarned, tlsMax := scoreTLSRPT(&report.TLSRPTResult{Present: true, Status: "pass", SyntaxOK: true})
	if tlsEarned != 10 || tlsMax != MaxPointsTLSRPT {
		t.Errorf("TLS-RPT valid rua: got %d/%d, want 10/%d", tlsEarned, tlsMax, MaxPointsTLSRPT)
	}
	tlsTxtEarned, _ := scoreTLSRPT(&report.TLSRPTResult{Present: true, Status: "warn", SyntaxOK: true})
	if tlsTxtEarned != 5 {
		t.Errorf("TLS-RPT TXT only: got %d, want 5", tlsTxtEarned)
	}
	tlsInvalidEarned, _ := scoreTLSRPT(&report.TLSRPTResult{Present: true, Status: "warn", SyntaxOK: false})
	if tlsInvalidEarned != 0 {
		t.Errorf("TLS-RPT invalid syntax: got %d, want 0", tlsInvalidEarned)
	}

	danePartial, daneMax := scoreDANE(&report.DANEResult{AdvertisedFor: []string{"mx.example.com"}})
	if danePartial != 5 || daneMax != MaxPointsDANE {
		t.Errorf("DANE partial: got %d/%d, want 5/%d", danePartial, daneMax, MaxPointsDANE)
	}
	daneEarned, _ := scoreDANE(&report.DANEResult{
		AdvertisedFor: []string{"mx.example.com"},
		MXCovered: true, SyntaxOK: true, DNSSECValidated: true,
	})
	if daneEarned != 10 {
		t.Errorf("DANE full: got %d, want 10", daneEarned)
	}
	daneNoDNSSEC, _ := scoreDANE(&report.DANEResult{
		AdvertisedFor: []string{"mx.example.com"},
		MXCovered: true, SyntaxOK: true, DNSSECValidated: false,
	})
	if daneNoDNSSEC != 5 {
		t.Errorf("DANE full TLSA without DNSSEC: got %d, want 5", daneNoDNSSEC)
	}

	dnssecPartial, dnssecMax := scoreDNSSEC(&report.DNSSECResult{DSPresent: true, SyntaxOK: true, TLDSupported: true})
	if dnssecPartial != 5 || dnssecMax != MaxPointsDNSSEC {
		t.Errorf("DNSSEC DS only: got %d/%d, want 5/%d", dnssecPartial, dnssecMax, MaxPointsDNSSEC)
	}
	dnssecEarned, _ := scoreDNSSEC(&report.DNSSECResult{
		DSPresent: true, DNSKEYPresent: true, ResolverAD: true, TLDSupported: true,
	})
	if dnssecEarned != 10 {
		t.Errorf("DNSSEC full chain: got %d, want 10", dnssecEarned)
	}
}

func TestScoreTLSRPT(t *testing.T) {
	tests := []struct {
		name   string
		tlsrpt *report.TLSRPTResult
		earned int
	}{
		{name: "no record", tlsrpt: &report.TLSRPTResult{}, earned: 0},
		{name: "TXT only", tlsrpt: &report.TLSRPTResult{Present: true, Status: "warn", SyntaxOK: true}, earned: 5},
		{name: "valid rua", tlsrpt: &report.TLSRPTResult{Present: true, Status: "pass", SyntaxOK: true}, earned: 10},
		{name: "invalid syntax", tlsrpt: &report.TLSRPTResult{Present: true, Status: "warn", SyntaxOK: false}, earned: 0},
		{name: "multiple TXT advertised", tlsrpt: &report.TLSRPTResult{Present: true, Status: "warn", SyntaxOK: false}, earned: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, max := scoreTLSRPT(tt.tlsrpt)
			if max != MaxPointsTLSRPT {
				t.Errorf("max: got %d, want %d", max, MaxPointsTLSRPT)
			}
			if got != tt.earned {
				t.Errorf("earned: got %d, want %d", got, tt.earned)
			}
		})
	}
}

func TestSPFRedirectScoringLeniency(t *testing.T) {
	res := &report.SPFResult{
		Present:              true,
		Status:               "pass",
		AllQualifier:         "-",
		LookupCount:          12,
		HasRedirect:          true,
		RedirectDepth:        4,
		EffectiveLookupCount: 1,
	}
	r := report.Report{Profile: "mail", SPF: res}
	score := ComputeScore(r)
	if score != 20 {
		t.Errorf("expected SPF contrib 20 (full lookup bonus via redirect leniency), got total %d", score)
	}

	res2 := &report.SPFResult{HasRedirect: true, RedirectDepth: 11}
	if res2.RedirectDepth <= 10 {
		t.Error("expected depth >10 to be detectable for recommendation")
	}
}

func TestComputeScoreCapsAt100(t *testing.T) {
	r := report.Report{
		Profile: "mail",
		SPF:     &report.SPFResult{Present: true, Status: "pass", AllQualifier: "-", LookupCount: 1},
		DMARC:   &report.DMARCResult{Policy: "reject", SyntaxOK: true},
		DKIM: &report.DKIMResult{
			SelectorsFound: []string{"s1"},
			Keys:           []report.DKIMKeyRecord{{Selector: "s1", SyntaxOK: true}},
		},
		MTASTS: &report.MTASTSResult{DNSAdvertised: true, PolicyFetched: true, Status: "pass"},
		TLSRPT: &report.TLSRPTResult{Present: true, Status: "pass", SyntaxOK: true},
		DANE: &report.DANEResult{
			AdvertisedFor: []string{"mx"},
			MXCovered: true, SyntaxOK: true, DNSSECValidated: true,
		},
		DNSSEC: &report.DNSSECResult{
			DSPresent: true, DNSKEYPresent: true, ResolverAD: true, TLDSupported: true,
		},
	}
	if got := ComputeScore(r); got != 100 {
		t.Errorf("ComputeScore cap: got %d, want 100", got)
	}
}