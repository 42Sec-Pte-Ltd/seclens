package assessor

import (
	"context"
	"strings"
	"testing"
)

func TestCheckMTASTS42sec(t *testing.T) {
	ctx := context.Background()
	res := CheckMTASTS(ctx, "42sec.io", []string{"mx1.spacemail.com", "mx2.spacemail.com"})
	if !res.PolicyFetched {
		t.Fatalf("PolicyFetched=false issues=%v message=%q", res.Issues, res.Message)
	}
	if res.Mode != "enforce" {
		t.Fatalf("mode=%q want enforce", res.Mode)
	}
	if !res.MXCoverageOK {
		t.Fatalf("MXCoverageOK=false issues=%v", res.Issues)
	}
	if res.Status != "pass" && res.Status != "warn" {
		t.Fatalf("status=%q message=%q issues=%v", res.Status, res.Message, res.Issues)
	}
	if !res.DNSIDValid {
		t.Logf("live domain uses non-RFC id= format %q (RFC 8461 §3.1 allows only alphanumeric)", res.PolicyID)
	}
	if !strings.Contains(res.RawPolicy, "version: STSv1") {
		t.Fatalf("policy missing version line:\n%s", res.RawPolicy)
	}
}