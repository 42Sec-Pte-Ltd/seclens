package assessor

import (
	"testing"

	"seclens/internal/report"
)

// scoringStatusMatrix maps (protocol, status, fields) → EarnedPoints from scoring.go.
var scoringStatusMatrix = []struct {
	protocol   string
	name       string
	status     string
	wantEarned int
	wantMax    int
	build      func() *report.Report
}{
	{
		protocol:   "SPF",
		name:       "pass hardfail low lookups",
		status:     "pass",
		wantEarned: 20,
		wantMax:    MaxPointsSPF,
		build: func() *report.Report {
			return &report.Report{SPF: &report.SPFResult{
				Present: true, Status: "pass", AllQualifier: "-", LookupCount: 3,
			}}
		},
	},
	{
		protocol:   "SPF",
		name:       "fail with -all scoring contract",
		status:     "fail",
		wantEarned: 20, // 5 base + 10 hardfail + 5 lookup bonus (Status != fail gate only applies to ~all)
		wantMax:    MaxPointsSPF,
		build: func() *report.Report {
			return &report.Report{SPF: &report.SPFResult{
				Present: true, Status: "fail", AllQualifier: "-", LookupCount: 3,
				Issues: []string{"too many DNS lookups (11 > 10) — receivers may treat as permerror"},
			}}
		},
	},
	{
		protocol:   "SPF",
		name:       "warn softfail",
		status:     "warn",
		wantEarned: 15,
		wantMax:    MaxPointsSPF,
		build: func() *report.Report {
			return &report.Report{SPF: &report.SPFResult{
				Present: true, Status: "warn", AllQualifier: "~", LookupCount: 2,
			}}
		},
	},
	{
		protocol:   "SPF",
		name:       "info absent",
		status:     "info",
		wantEarned: 0,
		wantMax:    MaxPointsSPF,
		build: func() *report.Report {
			return &report.Report{SPF: &report.SPFResult{Present: false, Status: "info"}}
		},
	},
	{
		protocol:   "DMARC",
		name:       "pass reject",
		status:     "pass",
		wantEarned: 25,
		wantMax:    MaxPointsDMARC,
		build: func() *report.Report {
			return &report.Report{DMARC: &report.DMARCResult{Policy: "reject", Status: "pass", SyntaxOK: true}}
		},
	},
	{
		protocol:   "DMARC",
		name:       "warn none",
		status:     "warn",
		wantEarned: 0,
		wantMax:    MaxPointsDMARC,
		build: func() *report.Report {
			return &report.Report{DMARC: &report.DMARCResult{Policy: "none", Status: "warn", SyntaxOK: true}}
		},
	},
	{
		protocol:   "DMARC",
		name:       "warn reject no rua earns full policy points",
		status:     "warn",
		wantEarned: 25,
		wantMax:    MaxPointsDMARC,
		build: func() *report.Report {
			return &report.Report{DMARC: &report.DMARCResult{Present: true, Policy: "reject", Status: "warn", SyntaxOK: true}}
		},
	},
	{
		protocol:   "DKIM",
		name:       "warn with selectors discovery parity",
		status:     "warn",
		wantEarned: 10,
		wantMax:    MaxPointsDKIM,
		build: func() *report.Report {
			return &report.Report{DKIM: &report.DKIMResult{
				Status:         "warn",
				SelectorsFound:   []string{"test"},
				WildcardDetected: false,
				Keys:           []report.DKIMKeyRecord{{Selector: "test", TestKey: true, SyntaxOK: true}},
			}}
		},
	},
	{
		protocol:   "DKIM",
		name:       "pass with selectors",
		status:     "pass",
		wantEarned: 10,
		wantMax:    MaxPointsDKIM,
		build: func() *report.Report {
			return &report.Report{DKIM: &report.DKIMResult{
				Status:         "pass",
				SelectorsFound: []string{"s1", "s2"},
				Keys: []report.DKIMKeyRecord{
					{Selector: "s1", SyntaxOK: true},
					{Selector: "s2", SyntaxOK: true},
				},
			}}
		},
	},
	{
		protocol:   "DKIM",
		name:       "info no selectors",
		status:     "info",
		wantEarned: 0,
		wantMax:    MaxPointsDKIM,
		build: func() *report.Report {
			return &report.Report{DKIM: &report.DKIMResult{Status: "info", SelectorsFound: []string{}}}
		},
	},
	{
		protocol:   "MTA-STS",
		name:       "info not advertised",
		status:     "info",
		wantEarned: 0,
		wantMax:    MaxPointsMTASTS,
		build: func() *report.Report {
			return &report.Report{MTASTS: &report.MTASTSResult{Status: "info", DNSAdvertised: false}}
		},
	},
	{
		protocol:   "MTA-STS",
		name:       "warn DNS only tier",
		status:     "warn",
		wantEarned: 5,
		wantMax:    MaxPointsMTASTS,
		build: func() *report.Report {
			return &report.Report{MTASTS: &report.MTASTSResult{Status: "warn", DNSAdvertised: true}}
		},
	},
	{
		protocol:   "MTA-STS",
		name:       "warn policy fetched tier",
		status:     "warn",
		wantEarned: 10,
		wantMax:    MaxPointsMTASTS,
		build: func() *report.Report {
			return &report.Report{MTASTS: &report.MTASTSResult{
				Status: "warn", DNSAdvertised: true, PolicyFetched: true, Mode: "testing",
			}}
		},
	},
	{
		protocol:   "MTA-STS",
		name:       "pass full tier",
		status:     "pass",
		wantEarned: 15,
		wantMax:    MaxPointsMTASTS,
		build: func() *report.Report {
			return &report.Report{MTASTS: &report.MTASTSResult{
				Status: "pass", DNSAdvertised: true, PolicyFetched: true,
				Mode: "enforce", MXCoverageOK: true, DNSIDValid: true, PolicySyntaxOK: true,
			}}
		},
	},
	{
		protocol:   "MTA-STS",
		name:       "pass invalid DNS id scoring contract",
		status:     "pass",
		wantEarned: 15,
		wantMax:    MaxPointsMTASTS,
		build: func() *report.Report {
			return &report.Report{MTASTS: &report.MTASTSResult{
				Status: "pass", DNSAdvertised: true, PolicyFetched: true,
				Mode: "enforce", MXCoverageOK: true, DNSIDValid: false, PolicySyntaxOK: true,
				PolicyID: "2026-06-24T12:00:00Z",
			}}
		},
	},
	{
		protocol:   "MTA-STS",
		name:       "warn MX gap policy fetched tier",
		status:     "warn",
		wantEarned: 10,
		wantMax:    MaxPointsMTASTS,
		build: func() *report.Report {
			return &report.Report{MTASTS: &report.MTASTSResult{
				Status: "warn", DNSAdvertised: true, PolicyFetched: true,
				Mode: "enforce", MXCoverageOK: false, PolicySyntaxOK: true,
			}}
		},
	},
	{
		protocol:   "TLS-RPT",
		name:       "info absent",
		status:     "info",
		wantEarned: 0,
		wantMax:    MaxPointsTLSRPT,
		build: func() *report.Report {
			return &report.Report{TLSRPT: &report.TLSRPTResult{Status: "info", Present: false}}
		},
	},
	{
		protocol:   "TLS-RPT",
		name:       "warn TXT only",
		status:     "warn",
		wantEarned: 5,
		wantMax:    MaxPointsTLSRPT,
		build: func() *report.Report {
			return &report.Report{TLSRPT: &report.TLSRPTResult{
				Status: "warn", Present: true, SyntaxOK: true, RUAPresent: false,
			}}
		},
	},
	{
		protocol:   "TLS-RPT",
		name:       "warn invalid syntax",
		status:     "warn",
		wantEarned: 0,
		wantMax:    MaxPointsTLSRPT,
		build: func() *report.Report {
			return &report.Report{TLSRPT: &report.TLSRPTResult{
				Status: "warn", Present: true, SyntaxOK: false,
			}}
		},
	},
	{
		protocol:   "TLS-RPT",
		name:       "pass valid rua",
		status:     "pass",
		wantEarned: 10,
		wantMax:    MaxPointsTLSRPT,
		build: func() *report.Report {
			return &report.Report{TLSRPT: &report.TLSRPTResult{
				Status: "pass", Present: true, SyntaxOK: true, RUAPresent: true,
			}}
		},
	},
	{
		protocol:   "DANE",
		name:       "info no TLSA",
		status:     "info",
		wantEarned: 0,
		wantMax:    MaxPointsDANE,
		build: func() *report.Report {
			return &report.Report{DANE: &report.DANEResult{Status: "info", AdvertisedFor: []string{}}}
		},
	},
	{
		protocol:   "DANE",
		name:       "warn partial coverage",
		status:     "warn",
		wantEarned: 5,
		wantMax:    MaxPointsDANE,
		build: func() *report.Report {
			return &report.Report{DANE: &report.DANEResult{
				Status: "warn", AdvertisedFor: []string{"mx1.example.com"}, MXCovered: false, SyntaxOK: true,
			}}
		},
	},
	{
		protocol:   "DANE",
		name:       "pass full with DNSSECValidated",
		status:     "pass",
		wantEarned: 10,
		wantMax:    MaxPointsDANE,
		build: func() *report.Report {
			return &report.Report{DANE: &report.DANEResult{
				Status: "pass", AdvertisedFor: []string{"mx.example.com"},
				MXCovered: true, SyntaxOK: true, DNSSECValidated: true,
			}}
		},
	},
	{
		protocol:   "DANE",
		name:       "warn full TLSA without DNSSECValidated",
		status:     "warn",
		wantEarned: 5,
		wantMax:    MaxPointsDANE,
		build: func() *report.Report {
			return &report.Report{DANE: &report.DANEResult{
				Status: "warn", AdvertisedFor: []string{"mx.example.com"},
				MXCovered: true, SyntaxOK: true, DNSSECValidated: false,
			}}
		},
	},
	{
		protocol:   "DNSSEC",
		name:       "info no DS",
		status:     "info",
		wantEarned: 0,
		wantMax:    MaxPointsDNSSEC,
		build: func() *report.Report {
			return &report.Report{DNSSEC: &report.DNSSECResult{
				Status: "info", DSPresent: false, TLDSupported: true,
			}}
		},
	},
	{
		protocol:   "DNSSEC",
		name:       "warn DS only half tier",
		status:     "warn",
		wantEarned: 5,
		wantMax:    MaxPointsDNSSEC,
		build: func() *report.Report {
			return &report.Report{DNSSEC: &report.DNSSECResult{
				Status: "warn", DSPresent: true, DNSKEYPresent: false, ResolverAD: false, SyntaxOK: true, TLDSupported: true,
			}}
		},
	},
	{
		protocol:   "DNSSEC",
		name:       "pass full chain",
		status:     "pass",
		wantEarned: 10,
		wantMax:    MaxPointsDNSSEC,
		build: func() *report.Report {
			return &report.Report{DNSSEC: &report.DNSSECResult{
				Status: "pass", DSPresent: true, DNSKEYPresent: true, ResolverAD: true, TLDSupported: true,
			}}
		},
	},
	{
		protocol:   "DNSSEC",
		name:       "warn DS AD without DNSKEY half tier",
		status:     "warn",
		wantEarned: 5,
		wantMax:    MaxPointsDNSSEC,
		build: func() *report.Report {
			return &report.Report{DNSSEC: &report.DNSSECResult{
				Status: "warn", DSPresent: true, DNSKEYPresent: false, ResolverAD: true, SyntaxOK: true, TLDSupported: true,
			}}
		},
	},
	{
		protocol:   "NullMX",
		name:       "pass valid null MX",
		status:     "pass",
		wantEarned: 25,
		wantMax:    MaxPointsNullMXRecord,
		build: func() *report.Report {
			return &report.Report{
				Profile: "null_mx",
				MXs:     []report.MXRecord{{Pref: 0, Host: "."}},
				NullMX:  &report.NullMXResult{Status: "pass"},
			}
		},
	},
	{
		protocol:   "NullMX",
		name:       "fail mixed MX",
		status:     "fail",
		wantEarned: 0,
		wantMax:    MaxPointsNullMXRecord,
		build: func() *report.Report {
			return &report.Report{
				Profile: "null_mx",
				MXs: []report.MXRecord{
					{Pref: 0, Host: "."},
					{Pref: 10, Host: "mx.example.com"},
				},
				NullMX: &report.NullMXResult{Status: "fail", Violation: "MixedMX"},
			}
		},
	},
}

func TestScoringStatusMatrix(t *testing.T) {
	for _, tc := range scoringStatusMatrix {
		t.Run(tc.protocol+"/"+tc.name, func(t *testing.T) {
			r := tc.build()
			PopulateCheckScores(r)

			var earned, max int
			switch tc.protocol {
			case "SPF":
				earned, max = r.SPF.EarnedPoints, r.SPF.MaxPoints
			case "DMARC":
				earned, max = r.DMARC.EarnedPoints, r.DMARC.MaxPoints
			case "DKIM":
				earned, max = r.DKIM.EarnedPoints, r.DKIM.MaxPoints
			case "MTA-STS":
				earned, max = r.MTASTS.EarnedPoints, r.MTASTS.MaxPoints
			case "TLS-RPT":
				earned, max = r.TLSRPT.EarnedPoints, r.TLSRPT.MaxPoints
			case "DANE":
				earned, max = r.DANE.EarnedPoints, r.DANE.MaxPoints
			case "DNSSEC":
				earned, max = r.DNSSEC.EarnedPoints, r.DNSSEC.MaxPoints
			case "NullMX":
				earned, max = r.NullMX.EarnedPoints, r.NullMX.MaxPoints
			default:
				t.Fatalf("unknown protocol %q", tc.protocol)
			}

			if earned != tc.wantEarned {
				t.Errorf("EarnedPoints: got %d, want %d (protocol=%s status=%s)", earned, tc.wantEarned, tc.protocol, tc.status)
			}
			if max != tc.wantMax {
				t.Errorf("MaxPoints: got %d, want %d", max, tc.wantMax)
			}
		})
	}
}