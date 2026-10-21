package bimi

import (
	"os"
	"testing"
	"time"
)

func TestInspectCertFixtures(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		file     string
		subject  string
		issuer   string
		notAfter string
		expired  bool
		logotype bool
		eku      bool
		hint     string
		findings []string
	}{
		{
			file:     "testdata/vmc.pem",
			subject:  "CN=Example Mark,1.3.6.1.4.1.53087.1.13=Registered Mark",
			issuer:   "CN=Example MVA",
			notAfter: "2030-01-02T03:04:05Z",
			logotype: true,
			eku:      true,
			hint:     "vmc",
		},
		{
			file:     "testdata/cmc.pem",
			subject:  "CN=Common Mark,1.3.6.1.4.1.53087.1.13=Prior Use Mark",
			issuer:   "CN=Example MVA",
			notAfter: "2030-06-01T00:00:00Z",
			logotype: true,
			eku:      true,
			hint:     "cmc",
		},
		{
			file:     "testdata/expired.pem",
			subject:  "CN=Old Mark",
			issuer:   "CN=Example MVA",
			notAfter: "2020-01-02T03:04:05Z",
			expired:  true,
			findings: []string{
				"logotype extension 1.3.6.1.5.5.7.1.12 absent",
				"BIMI EKU 1.3.6.1.5.5.7.3.31 absent",
				"certificate expired 2020-01-02T03:04:05Z",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			body, err := os.ReadFile(tc.file)
			if err != nil {
				t.Fatal(err)
			}
			got := InspectCert(body, now)
			if got.Error != "" {
				t.Fatal(got.Error)
			}
			if got.Subject != tc.subject || got.Issuer != tc.issuer || got.NotAfter != tc.notAfter || got.Expired != tc.expired || got.LogotypeExt != tc.logotype || got.BIMIEKU != tc.eku || got.MarkHint != tc.hint {
				t.Fatalf("%+v", got)
			}
			findings := certFindings(got)
			if len(findings) != len(tc.findings) {
				t.Fatalf("findings %q want %q", findings, tc.findings)
			}
			for i := range tc.findings {
				if findings[i] != tc.findings[i] {
					t.Fatalf("findings %q want %q", findings, tc.findings)
				}
			}
		})
	}
}

func TestInspectCertNotPEM(t *testing.T) {
	t.Parallel()
	got := InspectCert([]byte("not a cert"), time.Unix(0, 0))
	if got.Error != "no PEM CERTIFICATE block" {
		t.Fatalf("%+v", got)
	}
	findings := certFindings(got)
	if len(findings) != 1 || findings[0] != "certificate: no PEM CERTIFICATE block" {
		t.Fatalf("%v", findings)
	}
}
