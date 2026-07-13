package assessor

import (
	"context"
	"testing"
	"time"
)

// TestAssessEntry exercises the public Assess entry (shipped code path) with early returns.
// Verifies gating and report shape without requiring network (pre-lookup returns).
func TestAssessEntry(t *testing.T) {
	ctx := context.Background()
	opts := AssessmentOpts{Timeout: 1 * time.Second}

	// empty -> error
	if _, err := Assess(ctx, "", opts); err == nil {
		t.Error("expected error for empty domain")
	}

	// invalid shape -> error (exercises isValidDomainShape path in Assess)
	if _, err := Assess(ctx, "bad", opts); err == nil {
		t.Error("expected error for bad shape")
	}

	// valid shape but unresolvable in practice will still return report (post trim changes)
	// just ensure it returns a report, not panic, and has Domain set
	r, err := Assess(ctx, "example.invalid", opts)
	if err != nil {
		// may error or return report with errs; either ok for this structural
	}
	if r.Domain == "" && err == nil {
		t.Error("report should have domain or error")
	}
}

// TestRunBulkEntry exercises RunBulk (used by CLI multi) with small input.
func TestRunBulkEntry(t *testing.T) {
	ctx := context.Background()
	opts := AssessmentOpts{Timeout: 1 * time.Second}
	reps := RunBulk(ctx, []string{"example.invalid", "also.invalid"}, opts, 2)
	if len(reps) != 2 {
		t.Errorf("expected 2 reports, got %d", len(reps))
	}
}
