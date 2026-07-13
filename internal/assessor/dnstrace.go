package assessor

import (
	"context"
	"sync"

	"seclens/internal/report"
)

// Bounds keep DNS traces compact for storage and bulk JSONL
// consumers: summaries are always kept; raw JSON bodies are
// subject to a per-response cap and a per-report budget.
const (
	dnsTraceMaxEntries = 600
	dnsTracePerRawCap  = 16 * 1024
	dnsTraceRawBudget  = 128 * 1024
)

// dnsTraceCollector gathers per-query DoH traces for one assessment.
// Safe for concurrent use (checks fan out in goroutines).
type dnsTraceCollector struct {
	mu        sync.Mutex
	entries   []report.DNSQueryTrace
	rawBudget int
}

type dnsTraceCtxKey struct{}

// withDNSTrace attaches a fresh collector to the context; every doQuery through
// this context records its provider outcomes.
func withDNSTrace(ctx context.Context) (context.Context, *dnsTraceCollector) {
	c := &dnsTraceCollector{rawBudget: dnsTraceRawBudget}
	return context.WithValue(ctx, dnsTraceCtxKey{}, c), c
}

func dnsTraceFrom(ctx context.Context) *dnsTraceCollector {
	c, _ := ctx.Value(dnsTraceCtxKey{}).(*dnsTraceCollector)
	return c
}

func (t *dnsTraceCollector) record(e report.DNSQueryTrace) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.entries) >= dnsTraceMaxEntries {
		return
	}
	for i := range e.Providers {
		p := &e.Providers[i]
		if len(p.Raw) == 0 {
			continue
		}
		if len(p.Raw) > dnsTracePerRawCap || len(p.Raw) > t.rawBudget {
			p.Raw = nil
			p.RawOmitted = true
			continue
		}
		t.rawBudget -= len(p.Raw)
	}
	t.entries = append(t.entries, e)
}

// snapshot returns a copy of the collected entries (safe against late writers
// from goroutines still finishing after an assessment timeout).
func (t *dnsTraceCollector) snapshot() []report.DNSQueryTrace {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.entries) == 0 {
		return nil
	}
	out := make([]report.DNSQueryTrace, len(t.entries))
	copy(out, t.entries)
	return out
}
