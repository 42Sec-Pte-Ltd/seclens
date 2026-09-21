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
