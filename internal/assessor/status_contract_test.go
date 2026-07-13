package assessor

import (
	"strings"
	"testing"

	"seclens/internal/assessor/rfc4035"
	"seclens/internal/assessor/rfc7208"
	"seclens/internal/assessor/rfc7489"
	"seclens/internal/assessor/rfc7672"
	"seclens/internal/report"
)

// statusContractCases document that result.Status is the UI badge source of truth.
// Decorative fields (Policy, Mode, DSPresent, SyntaxOK, DNSSECValidated, etc.) may
// differ from Status by design (e.g. MTA-STS enforce mode but warn when MX coverage fails).
var statusContractCases = []struct {
	protocol string
	name     string
	status   string
	fields   map[string]any
}{
	// SPF
	{
		protocol: "SPF",
		name:     "pass hardfail",
		status:   "pass",
		fields:   map[string]any{"Present": true, "AllQualifier": "-", "LookupCount": 3},
	},
	{
		protocol: "SPF",
		name:     "warn softfail",
		status:   "warn",
		fields:   map[string]any{"Present": true, "AllQualifier": "~", "LookupCount": 5},
	},
	{
		protocol: "SPF",
		name:     "fail permerror",
		status:   "fail",
		fields:   map[string]any{"Present": true, "AllQualifier": "", "Issues": []string{"record does not start with v=spf1"}},
	},
	{
		protocol: "SPF",
		name:     "info absent",
		status:   "info",
		fields:   map[string]any{"Present": false},
	},
	// DMARC
	{
		protocol: "DMARC",
		name:     "pass reject policy",
		status:   "pass",
		fields:   map[string]any{"Present": true, "Policy": "reject", "SyntaxOK": true},
	},
	{
		protocol: "DMARC",
		name:     "warn with none policy",
		status:   "warn",
		fields:   map[string]any{"Present": true, "Policy": "none", "SyntaxOK": true},
	},
	{
		protocol: "DMARC",
		name:     "fail syntax invalid (Policy empty)",
		status:   "fail",
		fields:   map[string]any{"Present": true, "Policy": "", "SyntaxOK": false},
	},
	{
		protocol: "DMARC",
		name:     "warn reject without rua",
		status:   "warn",
		fields:   map[string]any{"Present": true, "Policy": "reject", "SyntaxOK": true},
	},
	{
		protocol: "DMARC",
		name:     "info not published",
		status:   "info",
		fields:   map[string]any{"Present": false, "SyntaxOK": false},
	},
	// DKIM
	{
		protocol: "DKIM",
		name:     "pass production selectors",
		status:   "pass",
		fields: map[string]any{
			"SelectorsFound": []string{"s1"}, "WildcardDetected": false,
			"Keys": []report.DKIMKeyRecord{{Selector: "s1", SyntaxOK: true}},
		},
	},
	{
		protocol: "DKIM",
		name:     "warn wildcard",
		status:   "warn",
		fields:   map[string]any{"WildcardDetected": true, "SelectorsFound": []string{}, "Keys": []report.DKIMKeyRecord{}},
	},
	{
		protocol: "DKIM",
		name:     "warn test-only keys",
		status:   "warn",
		fields: map[string]any{
			"SelectorsFound": []string{"test"}, "WildcardDetected": false,
			"Keys": []report.DKIMKeyRecord{{Selector: "test", TestKey: true, SyntaxOK: true}},
		},
	},
	{
		protocol: "DKIM",
		name:     "fail all keys invalid syntax",
		status:   "fail",
		fields: map[string]any{
			"SelectorsFound": []string{"bad"}, "WildcardDetected": false,
			"Keys": []report.DKIMKeyRecord{{Selector: "bad", SyntaxOK: false}},
		},
	},
	{
		protocol: "DKIM",
		name:     "info no selectors discovered",
		status:   "info",
		fields:   map[string]any{"SelectorsFound": []string{}, "WildcardDetected": false},
	},
	// MTA-STS
	{
		protocol: "MTA-STS",
		name:     "pass enforce full coverage",
		status:   "pass",
		fields: map[string]any{
			"DNSAdvertised": true, "PolicyFetched": true, "Mode": "enforce",
			"MXCoverageOK": true, "DNSIDValid": true, "PolicySyntaxOK": true,
		},
	},
	{
		protocol: "MTA-STS",
		name:     "warn with enforce mode (MX gap)",
		status:   "warn",
		fields:   map[string]any{"DNSAdvertised": true, "Mode": "enforce", "MXCoverageOK": false, "PolicySyntaxOK": true},
	},
	{
		protocol: "MTA-STS",
		name:     "pass enforce mode (invalid DNS id scoring contract)",
		status:   "pass",
		fields: map[string]any{
			"DNSAdvertised": true, "PolicyFetched": true, "Mode": "enforce", "MXCoverageOK": true,
			"DNSIDValid": false, "PolicySyntaxOK": true,
		},
	},
	{
		protocol: "MTA-STS",
		name:     "warn policy fetch failed",
		status:   "warn",
		fields:   map[string]any{"DNSAdvertised": true, "PolicyFetched": false, "Mode": ""},
	},
	{
		protocol: "MTA-STS",
		name:     "fail policy unreachable (decorative fetch failure)",
		status:   "fail",
		fields:   map[string]any{"DNSAdvertised": true, "PolicyFetched": false, "Mode": "enforce"},
	},
	{
		protocol: "MTA-STS",
		name:     "info not advertised",
		status:   "info",
		fields:   map[string]any{"DNSAdvertised": false, "Mode": "", "PolicySyntaxOK": false},
	},
	// TLS-RPT
	{
		protocol: "TLS-RPT",
		name:     "pass with SyntaxOK and RUAPresent",
		status:   "pass",
		fields:   map[string]any{"Present": true, "SyntaxOK": true, "RUAPresent": true},
	},
	{
		protocol: "TLS-RPT",
		name:     "warn present without valid rua",
		status:   "warn",
		fields:   map[string]any{"Present": true, "SyntaxOK": true, "RUAPresent": false},
	},
	{
		protocol: "TLS-RPT",
		name:     "warn invalid syntax",
		status:   "warn",
		fields:   map[string]any{"Present": true, "SyntaxOK": false, "RUAPresent": false},
	},
	{
		protocol: "TLS-RPT",
		name:     "fail multiple TXT records",
		status:   "fail",
		fields:   map[string]any{"Present": false, "SyntaxOK": false, "Message": "multiple _smtp._tls TXT records"},
	},
	{
		protocol: "TLS-RPT",
		name:     "info not published",
		status:   "info",
		fields:   map[string]any{"Present": false, "SyntaxOK": false},
	},
	// DANE
	{
		protocol: "DANE",
		name:     "pass with DNSSECValidated (post-enrich)",
		status:   "pass",
		fields: map[string]any{
			"AdvertisedFor": []string{"mx.example.com"}, "MXCovered": true,
			"SyntaxOK": true, "DNSSECValidated": true,
		},
	},
	{
		protocol: "DANE",
		name:     "warn full TLSA but DNSSECValidated false",
		status:   "warn",
		fields: map[string]any{
			"AdvertisedFor": []string{"mx.example.com"}, "MXCovered": true,
			"SyntaxOK": true, "DNSSECValidated": false,
		},
	},
	{
		protocol: "DANE",
		name:     "warn partial MX coverage",
		status:   "warn",
		fields: map[string]any{
			"AdvertisedFor": []string{"mx1.example.com"}, "MXCovered": false, "SyntaxOK": true,
		},
	},
	{
		protocol: "DANE",
		name:     "fail invalid TLSA syntax",
		status:   "fail",
		fields: map[string]any{
			"AdvertisedFor": []string{"mx.example.com"}, "MXCovered": true, "SyntaxOK": false,
		},
	},
	{
		protocol: "DANE",
		name:     "info without TLSA",
		status:   "info",
		fields:   map[string]any{"AdvertisedFor": []string{}, "DNSSECValidated": false, "SyntaxOK": false},
	},
	// DNSSEC
	{
		protocol: "DNSSEC",
		name:     "pass DS DNSKEY resolver AD",
		status:   "pass",
		fields: map[string]any{
			"DSPresent": true, "DNSKEYPresent": true, "ResolverAD": true, "TLDSupported": true,
		},
	},
	{
		protocol: "DNSSEC",
		name:     "warn DS only (decorative chain fields present)",
		status:   "warn",
		fields:   map[string]any{"DSPresent": true, "DNSKEYPresent": false, "SyntaxOK": true, "ResolverAD": false},
	},
	{
		protocol: "DNSSEC",
		name:     "warn DS resolver AD without DNSKEY",
		status:   "warn",
		fields:   map[string]any{"DSPresent": true, "DNSKEYPresent": false, "ResolverAD": true, "SyntaxOK": true, "TLDSupported": true},
	},
	{
		protocol: "DNSSEC",
		name:     "info without DS",
		status:   "info",
		fields:   map[string]any{"DSPresent": false, "SyntaxOK": false, "TLDSupported": true},
	},
	{
		protocol: "DNSSEC",
		name:     "fail invalid DS syntax",
		status:   "fail",
		fields:   map[string]any{"DSPresent": true, "SyntaxOK": false, "TLDSupported": true},
	},
	{
		protocol: "DNSSEC",
		name:     "info TLD unsupported",
		status:   "info",
		fields:   map[string]any{"TLDSupported": false, "DSPresent": false},
	},
	// NullMX
	{
		protocol: "NullMX",
		name:     "pass valid null MX",
		status:   "pass",
		fields:   map[string]any{"Violation": "None", "Posture": "NullMXOnly"},
	},
	{
		protocol: "NullMX",
		name:     "warn pending validation (decorative posture mismatch)",
		status:   "warn",
		fields:   map[string]any{"Violation": "None", "Posture": "MailEnabled"},
	},
	{
		protocol: "NullMX",
		name:     "info profile not applicable",
		status:   "info",
		fields:   map[string]any{"Violation": "None", "Posture": "NoMX"},
	},
	{
		protocol: "NullMX",
		name:     "fail mixed MX",
		status:   "fail",
		fields:   map[string]any{"Violation": "MixedMX", "Posture": "MixedInvalid"},
	},
	{
		protocol: "NullMX",
		name:     "fail no MX records",
		status:   "fail",
		fields:   map[string]any{"Violation": "None", "Posture": "NoMX"},
	},
	{
		protocol: "NullMX",
		name:     "fail wrong preference",
		status:   "fail",
		fields:   map[string]any{"Violation": "WrongPreference", "Posture": "MixedInvalid"},
	},
}

func TestStatusContract_ValidValues(t *testing.T) {
	allowed := map[string]bool{"pass": true, "warn": true, "fail": true, "info": true}
	for _, tc := range statusContractCases {
		t.Run(tc.protocol+"/"+tc.name, func(t *testing.T) {
			if !allowed[tc.status] {
				t.Fatalf("contract status %q must be pass|warn|fail|info", tc.status)
			}
		})
	}
}

func TestStatusContract_ProtocolCoverage(t *testing.T) {
	required := []string{"SPF", "DMARC", "DKIM", "MTA-STS", "TLS-RPT", "DANE", "DNSSEC", "NullMX"}
	requiredStatuses := []string{"pass", "warn", "fail", "info"}

	seen := make(map[string]map[string]bool)
	for _, p := range required {
		seen[p] = make(map[string]bool)
	}
	for _, tc := range statusContractCases {
		seen[tc.protocol][tc.status] = true
	}

	for _, p := range required {
		for _, st := range requiredStatuses {
			if !seen[p][st] {
				t.Errorf("protocol %s missing status contract case for %q", p, st)
			}
		}
	}
}

// TestAssessorStatusFields documents that parsers set Status from policy logic, not ad-hoc UI fields.
func TestAssessorStatusFields(t *testing.T) {
	spf := rfc7208.AnalyzeRecord("v=spf1 include:_spf.google.com ~all", statusContractSPFGate{})
	if spf.Status != "warn" {
		t.Errorf("SPF ~all: status=%s want=warn", spf.Status)
	}

	dmarc := rfc7489.AnalyzeRaw("v=DMARC1; p=reject; rua=mailto:dmarc@example.com", false)
	if dmarc.Status != "pass" {
		t.Errorf("DMARC reject: status=%s want=pass", dmarc.Status)
	}
	if !dmarc.SyntaxOK {
		t.Error("DMARC reject: SyntaxOK want true")
	}
	dmarcNone := rfc7489.AnalyzeRaw("v=DMARC1; p=none", false)
	if dmarcNone.Status != "warn" {
		t.Errorf("DMARC none: status=%s want=warn", dmarcNone.Status)
	}
	dmarcRejectNoRua := rfc7489.AnalyzeRaw("v=DMARC1; p=reject", false)
	if dmarcRejectNoRua.Status != "warn" {
		t.Errorf("DMARC reject without rua: status=%s want=warn", dmarcRejectNoRua.Status)
	}
	if !dmarcRejectNoRua.SyntaxOK || dmarcRejectNoRua.Policy != "reject" {
		t.Errorf("DMARC reject without rua: SyntaxOK=%v Policy=%q", dmarcRejectNoRua.SyntaxOK, dmarcRejectNoRua.Policy)
	}
	earned, max := scoreDMARC(&dmarcRejectNoRua)
	if earned != 25 || max != MaxPointsDMARC {
		t.Errorf("DMARC reject without rua: earned=%d max=%d want %d/%d (policy-only scoring)", earned, max, MaxPointsDMARC, MaxPointsDMARC)
	}

	dmarcNoP := rfc7489.AnalyzeRaw("v=DMARC1; rua=mailto:dmarc@example.com", false)
	if dmarcNoP.Status != "fail" {
		t.Errorf("DMARC missing p=: status=%s want=fail", dmarcNoP.Status)
	}
	if dmarcNoP.Policy != "" {
		t.Errorf("DMARC missing p=: policy=%q want empty (not none)", dmarcNoP.Policy)
	}
	if dmarcNoP.SyntaxOK {
		t.Error("DMARC missing p=: SyntaxOK want false")
	}

	dnssec := &report.DNSSECResult{DSPresent: true, DNSKEYPresent: false, SyntaxOK: true, TLDSupported: true}
	rfc4035.ApplyStatus(dnssec)
	if dnssec.Status != "warn" {
		t.Errorf("DNSSEC DS-only: status=%s want=warn", dnssec.Status)
	}

	dnssecAD := &report.DNSSECResult{DSPresent: true, DNSKEYPresent: false, ResolverAD: true, SyntaxOK: true, TLDSupported: true}
	rfc4035.ApplyStatus(dnssecAD)
	if dnssecAD.Status != "warn" {
		t.Errorf("DNSSEC DS+AD without DNSKEY: status=%s want=warn", dnssecAD.Status)
	}

	dane := &report.DANEResult{
		AdvertisedFor: []string{"mx.example.com"},
		MXCovered:     true,
		SyntaxOK:      true,
		Status:        "warn",
	}
	rfc7672.EnrichWithDNSSEC(dane, &report.DNSSECResult{DSPresent: true})
	if dane.DNSSECValidated {
		t.Error("DANE without DNSKEY/AD: DNSSECValidated want false")
	}
	if dane.Status != "warn" {
		t.Errorf("DANE without DNSSEC chain: status=%s want=warn (with caveat issue)", dane.Status)
	}
	if !strings.Contains(strings.Join(dane.Issues, " "), "DNSSEC") {
		t.Errorf("DANE without DNSSEC chain: expected DNSSEC caveat issue, got %v", dane.Issues)
	}
}

type statusContractSPFGate struct{}

func (statusContractSPFGate) ValidShape(domain string) bool           { return IsValidDomainShape(domain) }
func (statusContractSPFGate) Allowed(domain string) bool              { return IsAllowedDomain(domain) }
func (statusContractSPFGate) ValidMechanismDomain(domain string) bool { return IsValidSPFMechanismDomain(domain) }