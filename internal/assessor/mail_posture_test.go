package assessor

import (
	"context"
	"testing"

	"seclens/internal/assessor/rfc7208"
	"seclens/internal/assessor/rfc7489"
	"seclens/internal/assessor/testutil"
	"seclens/internal/report"
)

func TestApplyMailDomainStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		profile    string
		spf        string
		spfPresent bool
		dmarc      string
		dmarcPres  bool
		mtasts     string
		advertised bool
		dnssec     string
		ds         bool
		tld        bool
		wantSPF    string
		wantDMARC  string
		wantMTA    string
		wantDNSSEC string
	}{
		{
			name: "mail absent controls", profile: ProfileMail,
			spf: "warn", dmarc: "info", mtasts: "info", dnssec: "info", tld: true,
			wantSPF: "fail", wantDMARC: "fail", wantMTA: "warn", wantDNSSEC: "warn",
		},
		{
			name: "mail keeps lookup failures and partial dnssec", profile: ProfileMail,
			spf: "fail", dmarc: "fail", mtasts: "warn", advertised: true, dnssec: "warn", ds: true, tld: true,
			wantSPF: "fail", wantDMARC: "fail", wantMTA: "warn", wantDNSSEC: "warn",
		},
		{
			name: "mail tld without dnssec stays info", profile: ProfileMail,
			spf: "pass", spfPresent: true, dmarc: "pass", dmarcPres: true, mtasts: "pass", advertised: true,
			dnssec: "info", tld: false,
			wantSPF: "pass", wantDMARC: "pass", wantMTA: "pass", wantDNSSEC: "info",
		},
		{
			name: "no mx missing spf and dmarc warn", profile: ProfileNoMX,
			spf: "warn", dmarc: "info", dnssec: "info", tld: true,
			wantSPF: "warn", wantDMARC: "warn", wantDNSSEC: "info",
		},
		{
			name: "no mx parser info spf becomes warn", profile: ProfileNoMX,
			spf: "info", dmarc: "info", dnssec: "info", tld: true,
			wantSPF: "warn", wantDMARC: "warn", wantDNSSEC: "info",
		},
		{
			name: "null mx missing spf and dmarc warn", profile: ProfileNullMX,
			spf: "info", dmarc: "info", dnssec: "info", tld: true,
			wantSPF: "warn", wantDMARC: "warn", wantDNSSEC: "info",
		},
		{
			name: "no mx lookup failure stays fail", profile: ProfileNoMX,
			spf: "fail", dmarc: "fail", dnssec: "info", tld: true,
			wantSPF: "fail", wantDMARC: "fail", wantDNSSEC: "info",
		},
		{
			name: "null mx strict spf and reject dmarc stay pass", profile: ProfileNullMX,
			spf: "pass", spfPresent: true, dmarc: "pass", dmarcPres: true,
			dnssec: "pass", ds: true, tld: true,
			wantSPF: "pass", wantDMARC: "pass", wantDNSSEC: "pass",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &report.Report{
				Profile: tc.profile,
				SPF:     &report.SPFResult{Present: tc.spfPresent, Status: tc.spf},
				DMARC:   &report.DMARCResult{Present: tc.dmarcPres, Status: tc.dmarc},
				DNSSEC:  &report.DNSSECResult{Status: tc.dnssec, DSPresent: tc.ds, TLDSupported: tc.tld},
			}
			if tc.profile == ProfileMail {
				r.MTASTS = &report.MTASTSResult{Status: tc.mtasts, DNSAdvertised: tc.advertised}
			}
			applyMailDomainStatus(r)
			if r.SPF.Status != tc.wantSPF || r.DMARC.Status != tc.wantDMARC || r.DNSSEC.Status != tc.wantDNSSEC {
				t.Fatalf("spf=%s dmarc=%s dnssec=%s", r.SPF.Status, r.DMARC.Status, r.DNSSEC.Status)
			}
			if r.MTASTS != nil && r.MTASTS.Status != tc.wantMTA {
				t.Fatalf("mtasts=%s want %s", r.MTASTS.Status, tc.wantMTA)
			}
		})
	}
}

func TestNoMailMissingRecordsWarn(t *testing.T) {
	t.Parallel()
	for _, profile := range []string{ProfileNoMX, ProfileNullMX} {
		spf := rfc7208.Check(context.Background(), rfc7208.Request{Domain: "example.com"}, rfc7208.Deps{
			DNS:  testutil.MockTXT{"example.com": {}},
			Gate: testutil.SPFGate{},
		})
		dmarc := rfc7489.Check(context.Background(), rfc7489.Request{Domain: "example.com", NullMXProfile: profile == ProfileNullMX}, rfc7489.Deps{
			DNS:  testutil.MockTXT{},
			Gate: testutil.AllowGate{},
		})
		r := &report.Report{Profile: profile, SPF: &spf, DMARC: &dmarc}
		applyMailDomainStatus(r)
		if r.SPF.Status != "warn" || r.SPF.Message != "No SPF record found" {
			t.Fatalf("%s spf status=%s message=%q", profile, r.SPF.Status, r.SPF.Message)
		}
		if r.DMARC.Status != "warn" || r.DMARC.Message != "No DMARC record published" {
			t.Fatalf("%s dmarc status=%s message=%q", profile, r.DMARC.Status, r.DMARC.Message)
		}
	}
}

func TestNullMXBestPracticeStaysPass(t *testing.T) {
	t.Parallel()
	spf := rfc7208.Check(context.Background(), rfc7208.Request{Domain: "example.com"}, rfc7208.Deps{
		DNS:  testutil.MockTXT{"example.com": {"v=spf1 -all"}},
		Gate: testutil.SPFGate{},
	})
	dmarc := rfc7489.Check(context.Background(), rfc7489.Request{Domain: "example.com", NullMXProfile: true}, rfc7489.Deps{
		DNS:  testutil.MockTXT{"_dmarc.example.com": {"v=DMARC1; p=reject"}},
		Gate: testutil.AllowGate{},
	})
	r := &report.Report{Profile: ProfileNullMX, SPF: &spf, DMARC: &dmarc}
	applyMailDomainStatus(r)
	if r.SPF.Status != "pass" || r.SPF.Raw != "v=spf1 -all" {
		t.Fatalf("spf status=%s raw=%q issues=%v", r.SPF.Status, r.SPF.Raw, r.SPF.Issues)
	}
	if r.DMARC.Status != "pass" || r.DMARC.Policy != "reject" {
		t.Fatalf("dmarc status=%s policy=%s issues=%v", r.DMARC.Status, r.DMARC.Policy, r.DMARC.Issues)
	}
}
