package testutil

import (
	"strings"
	"testing"
)

// AssertStatus fails when got != want.
func AssertStatus(t *testing.T, got, want, ctx string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: status=%q want %q", ctx, got, want)
	}
}

// AssertIssuesContain fails when none of the substrings appear in issues.
func AssertIssuesContain(t *testing.T, issues []string, subs ...string) {
	t.Helper()
	joined := strings.Join(issues, " ")
	for _, sub := range subs {
		if !strings.Contains(joined, sub) {
			t.Fatalf("issues missing %q: %v", sub, issues)
		}
	}
}