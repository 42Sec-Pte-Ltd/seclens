package rfc4035

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

// countingDNS records LookupRRWithMeta calls and serves scripted answers by call order
// or by name+qtype when answers map is set.
type countingDNS struct {
	calls   atomic.Int32
	// sequence: optional per-call override (empty → fall through to answers/err).
	sequence []struct {
		qr  QueryResult
		err error
	}
	answers map[string]map[uint16]QueryResult
	// defaultErr when no answer and no sequence entry.
	defaultErr error
}

func (c *countingDNS) LookupRRWithMeta(_ context.Context, name string, qtype uint16) (QueryResult, error) {
	n := int(c.calls.Add(1) - 1)
	if n < len(c.sequence) {
		return c.sequence[n].qr, c.sequence[n].err
	}
	name = stringsTrimSuffixDot(name)
	if byType, ok := c.answers[name]; ok {
		if qr, ok := byType[qtype]; ok {
			return qr, nil
		}
	}
	if c.defaultErr != nil {
		return QueryResult{}, c.defaultErr
	}
	return QueryResult{Status: rcodeNXDOMAIN}, nil
}

func TestRootDSProbe_ExplicitYes(t *testing.T) {
	// Root-side DS for "com" (what a recursive resolver returns for the TLD).
	dns := &countingDNS{answers: map[string]map[uint16]QueryResult{
		"com": {qtypeDS: {Status: rcodeNOERROR, RRs: []RR{{Data: "30909 8 2 AABBCC"}}}},
	}}
	has, inc := rootDSProbe(context.Background(), "com", dns)
	if inc || !has {
		t.Fatalf("has=%v inc=%v want has=true inc=false", has, inc)
	}
	if ParentSupportsDNSSEC(context.Background(), "example.com", dns) != true {
		t.Fatal("expected parent support via root DS")
	}
}

func TestZoneDNSSEC_DefinitiveNo_EmptyDSAndDNSKEY(t *testing.T) {
	dns := &countingDNS{answers: map[string]map[uint16]QueryResult{
		"test": {
			qtypeDS:     {Status: rcodeNOERROR},
			qtypeDNSKEY: {Status: rcodeNOERROR},
		},
		"example.test": {
			qtypeDS:     {Status: rcodeNOERROR},
			qtypeDNSKEY: {Status: rcodeNOERROR},
		},
	}}
	if zoneDNSSECSupport(context.Background(), "test", dns) != zoneSupportNo {
		t.Fatal("expected definitive no")
	}
	if ParentSupportsDNSSEC(context.Background(), "example.test", dns) {
		t.Fatal("expected unsupported TLD")
	}
}

func TestZoneDNSSEC_ErrorsNotCached(t *testing.T) {
	// First two calls (DS + DNSKEY) fail; must not cache Unknown.
	// Later calls succeed with root DS for "com".
	dns := &countingDNS{}
	dns.sequence = []struct {
		qr  QueryResult
		err error
	}{
		{err: errors.New("rate limited")}, // DS
		{err: errors.New("rate limited")}, // DNSKEY
		{qr: QueryResult{Status: rcodeNOERROR, RRs: []RR{{Data: "30909 8 2 AABBCC"}}}}, // DS retry
	}

	if got := zoneDNSSECSupport(context.Background(), "com", dns); got != zoneSupportUnknown {
		t.Fatalf("first probe got %v want unknown", got)
	}
	// Cache must be empty for "com".
	zoneDNSSECCacheMu.Lock()
	_, cached := zoneDNSSECCache[dns]["com"]
	zoneDNSSECCacheMu.Unlock()
	if cached {
		t.Fatal("unknown result must not be cached")
	}

	if got := zoneDNSSECSupport(context.Background(), "com", dns); got != zoneSupportYes {
		t.Fatalf("retry after error got %v want yes", got)
	}
	// Now cached as yes: further probes should not need more lookups for "com".
	before := dns.calls.Load()
	if got := zoneDNSSECSupport(context.Background(), "com", dns); got != zoneSupportYes {
		t.Fatalf("cached probe got %v", got)
	}
	if dns.calls.Load() != before {
		t.Fatalf("expected cache hit, calls %d → %d", before, dns.calls.Load())
	}
}

func TestZoneDNSSEC_SERVFAILNotCachedAsNo(t *testing.T) {
	dns := &countingDNS{answers: map[string]map[uint16]QueryResult{
		"com": {
			qtypeDS:     {Status: rcodeSERVFAIL},
			qtypeDNSKEY: {Status: rcodeSERVFAIL},
		},
	}}
	if got := zoneDNSSECSupport(context.Background(), "com", dns); got != zoneSupportUnknown {
		t.Fatalf("got %v want unknown", got)
	}
	zoneDNSSECCacheMu.Lock()
	_, cached := zoneDNSSECCache[dns]["com"]
	zoneDNSSECCacheMu.Unlock()
	if cached {
		t.Fatal("SERVFAIL must not be cached")
	}
}

func TestParentSupportsDNSSEC_FailOpenOnUnknown(t *testing.T) {
	// All probes error → fail open (true) so we do not emit TLD-unsupported.
	dns := &countingDNS{defaultErr: errors.New("upstream down")}
	if !ParentSupportsDNSSEC(context.Background(), "example.com", dns) {
		t.Fatal("expected fail-open true when probes are inconclusive")
	}
}

func TestZoneDNSSEC_DNSKEYAloneYes(t *testing.T) {
	// No root DS, but apex DNSKEY present (signed zone).
	dns := &countingDNS{answers: map[string]map[uint16]QueryResult{
		"com": {
			qtypeDS:     {Status: rcodeNOERROR},
			qtypeDNSKEY: {Status: rcodeNOERROR, RRs: []RR{{Data: "257 3 13 AwEAAexample"}}},
		},
	}}
	if zoneDNSSECSupport(context.Background(), "com", dns) != zoneSupportYes {
		t.Fatal("expected yes via apex DNSKEY")
	}
}

func TestProbeAnswer_Classifies(t *testing.T) {
	has, empty, inc := probeAnswer(QueryResult{}, errors.New("net"))
	if has || empty || !inc {
		t.Fatalf("error: has=%v empty=%v inc=%v", has, empty, inc)
	}
	has, empty, inc = probeAnswer(QueryResult{Status: rcodeSERVFAIL}, nil)
	if has || empty || !inc {
		t.Fatalf("servfail: has=%v empty=%v inc=%v", has, empty, inc)
	}
	has, empty, inc = probeAnswer(QueryResult{Status: rcodeNOERROR, RRs: []RR{{Data: "x"}}}, nil)
	if !has || empty || inc {
		t.Fatalf("rr: has=%v empty=%v inc=%v", has, empty, inc)
	}
	has, empty, inc = probeAnswer(QueryResult{Status: rcodeNOERROR}, nil)
	if has || !empty || inc {
		t.Fatalf("nodata: has=%v empty=%v inc=%v", has, empty, inc)
	}
	has, empty, inc = probeAnswer(QueryResult{Status: rcodeNXDOMAIN}, nil)
	if has || !empty || inc {
		t.Fatalf("nx: has=%v empty=%v inc=%v", has, empty, inc)
	}
}
