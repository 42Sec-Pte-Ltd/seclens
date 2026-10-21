package report

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func rowHasLabel(out, check, label string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, check) && strings.Contains(line, label) {
			return true
		}
	}
	return false
}

func TestStatusLabel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"pass", "[PASS]"},
		{"PASS", "[PASS]"},
		{"warn", "[WARN]"},
		{"fail", "[FAIL]"},
		{"error", "[FAIL]"},
		{"info", "[INFO]"},
		{"", "[INFO]"},
		{"skipped", "[INFO]"},
	}
	for _, tc := range cases {
		if got := statusLabel(tc.in); got != tc.want {
			t.Errorf("statusLabel(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestPrintTextBIMISection(t *testing.T) {
	t.Parallel()
	r := Report{
		Domain:    "example.com",
		Generated: time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC),
		BIMI: &BIMIResult{
			Status:   "present",
			DNSName:  "default._bimi.example.com",
			Message:  "BIMI record at default._bimi.example.com",
			Location: "https://example.com/a.svg",
			Evidence: "https://example.com/a.pem",
			Logo:     &BIMILogo{ContentType: "image/svg+xml", Bytes: 12, StartsWithSVG: true, BaseProfileTinyPS: true, Version12: true, HasTitle: true},
			Certificate: &BIMICert{
				Subject: "CN=Example", Issuer: "CN=Example MVA", NotAfter: "2030-01-02T03:04:05Z",
				LogotypeExt: true, BIMIEKU: true, MarkHint: "vmc",
			},
			Findings: []string{"DMARC record absent"},
		},
	}
	var buf bytes.Buffer
	r.PrintText(&buf)
	out := buf.String()
	for _, want := range []string{
		"BIMI (informational, not scored)",
		"Status: present",
		"Record: default._bimi.example.com",
		"l=: https://example.com/a.svg",
		"Logo: image/svg+xml, 12 bytes, svg=true, tiny-ps=true, version1.2=true, title=true, script=false",
		"Cert: subject=CN=Example issuer=CN=Example MVA notAfter=2030-01-02T03:04:05Z expired=false logotype=true eku=true hint=vmc",
		"- DMARC record absent",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n%s", want, out)
		}
	}
}

func TestPrintTextUsesStatusLabels(t *testing.T) {
	t.Parallel()
	r := Report{
		Domain:        "example.com",
		Generated:     time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC),
		IsMailEnabled: true,
		SPF:           &SPFResult{Status: "pass", Message: "ok"},
		DMARC:         &DMARCResult{Status: "warn", Message: "pct"},
		DKIM:          &DKIMResult{Status: "fail", Message: "none"},
		DNSSEC:        &DNSSECResult{Status: "info", Message: "n/a"},
	}
	var buf bytes.Buffer
	r.PrintText(&buf)
	out := buf.String()
	for _, want := range []string{"[PASS]", "[WARN]", "[FAIL]", "[INFO]"} {
		if !strings.Contains(out, want) {
			t.Errorf("PrintText missing %q\n%s", want, out)
		}
	}
	for _, pair := range [][2]string{
		{"SPF", "[PASS]"},
		{"DMARC", "[WARN]"},
		{"DKIM", "[FAIL]"},
		{"DNSSEC", "[INFO]"},
	} {
		if !strings.Contains(out, pair[0]) || !rowHasLabel(out, pair[0], pair[1]) {
			t.Errorf("PrintText row %s missing %s\n%s", pair[0], pair[1], out)
		}
	}
}
