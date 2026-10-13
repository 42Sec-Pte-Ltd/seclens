package rfc4035

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingDNS records LookupRRWithMeta calls and serves scripted answers by call order
// or by name+qtype when answers map is set.
type countingDNS struct {
	calls atomic.Int32
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
		{err: errors.New("rate limited")},                                              // DS
		{err: errors.New("rate limited")},                                              // DNSKEY
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

func TestZoneDNSSECSupport_Singleflight(t *testing.T) {
	dns := &slowZoneDNS{delay: 40 * time.Millisecond}
	const zone = "sf-probe.test"
	const n = 12
	var wg sync.WaitGroup
	wg.Add(n)
	errCh := make(chan zoneSupport, n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			errCh <- zoneDNSSECSupport(context.Background(), zone, dns)
		}()
	}
	wg.Wait()
	close(errCh)
	for got := range errCh {
		if got != zoneSupportYes {
			t.Fatalf("support=%v want yes", got)
		}
	}
	if calls := dns.calls.Load(); calls != 2 {
		t.Fatalf("probe calls=%d want 2 (one DS + one DNSKEY shared across %d callers)", calls, n)
	}
}

func TestStoreZoneSupport_YesNotReplacedByNo(t *testing.T) {
	dns := &countingDNS{}
	zone := "store-yes.test"
	zoneDNSSECCacheMu.Lock()
	defer zoneDNSSECCacheMu.Unlock()
	if got := storeZoneSupport(dns, zone, zoneSupportYes); got != zoneSupportYes {
		t.Fatalf("store yes=%v", got)
	}
	if got := storeZoneSupport(dns, zone, zoneSupportNo); got != zoneSupportYes {
		t.Fatalf("yes replaced by no: %v", got)
	}
	if zoneDNSSECCache[dns][zone] != zoneSupportYes {
		t.Fatalf("cache=%v want yes", zoneDNSSECCache[dns][zone])
	}
}

func TestZoneDNSSEC_CachedYesNotReplacedByNo(t *testing.T) {
	dns := &countingDNS{answers: map[string]map[uint16]QueryResult{
		"yeskeep.test": {qtypeDS: {Status: rcodeNOERROR, RRs: []RR{{Data: "30909 8 2 AABBCC"}}}},
	}}
	if got := zoneDNSSECSupport(context.Background(), "yeskeep.test", dns); got != zoneSupportYes {
		t.Fatalf("first=%v want yes", got)
	}
	dns.answers = map[string]map[uint16]QueryResult{
		"yeskeep.test": {
			qtypeDS:     {Status: rcodeNOERROR},
			qtypeDNSKEY: {Status: rcodeNOERROR},
		},
	}
	before := dns.calls.Load()
	if got := zoneDNSSECSupport(context.Background(), "yeskeep.test", dns); got != zoneSupportYes {
		t.Fatalf("cached yes replaced: got %v", got)
	}
	if dns.calls.Load() != before {
		t.Fatalf("cached yes re-probed, calls %d → %d", before, dns.calls.Load())
	}
}

func TestZoneDNSSEC_DefinitiveNoCached(t *testing.T) {
	dns := &countingDNS{answers: map[string]map[uint16]QueryResult{
		"definitive-no.test": {
			qtypeDS:     {Status: rcodeNOERROR},
			qtypeDNSKEY: {Status: rcodeNOERROR},
		},
	}}
	if got := zoneDNSSECSupport(context.Background(), "definitive-no.test", dns); got != zoneSupportNo {
		t.Fatalf("got %v want no", got)
	}
	before := dns.calls.Load()
	if got := zoneDNSSECSupport(context.Background(), "definitive-no.test", dns); got != zoneSupportNo {
		t.Fatalf("cached=%v want no", got)
	}
	if dns.calls.Load() != before {
		t.Fatalf("definitive no was not cached, calls %d → %d", before, dns.calls.Load())
	}
}

func TestZoneDNSSEC_InconclusiveHalfNotCachedAsNo(t *testing.T) {
	dns := &countingDNS{answers: map[string]map[uint16]QueryResult{
		"half.test": {qtypeDS: {Status: rcodeNOERROR}},
	}}
	dns.defaultErr = errors.New("dnskey timeout")
	if got := zoneDNSSECSupport(context.Background(), "half.test", dns); got != zoneSupportUnknown {
		t.Fatalf("got %v want unknown", got)
	}
	zoneDNSSECCacheMu.Lock()
	_, cached := zoneDNSSECCache[dns]["half.test"]
	zoneDNSSECCacheMu.Unlock()
	if cached {
		t.Fatal("No from an inconclusive DNSKEY probe must not be cached")
	}
}

func TestParentSupportsDNSSEC_UnknownDoesNotOverrideNo(t *testing.T) {
	dns := &countingDNS{
		defaultErr: errors.New("tld timeout"),
		answers: map[string]map[uint16]QueryResult{
			"com": {
				qtypeDS:     {Status: rcodeNOERROR},
				qtypeDNSKEY: {Status: rcodeNOERROR},
			},
		},
	}
	if ParentSupportsDNSSEC(context.Background(), "example.com", dns) {
		t.Fatal("definitive No on com must not be overridden by an unknown example.com probe")
	}
}

func TestParentSupportsDNSSEC_AssessedDomainDNSKEYDoesNotCount(t *testing.T) {
	cands := parentZoneCandidates("example.com")
	sawDomain := false
	for _, c := range cands {
		if c == "example.com" {
			sawDomain = true
		}
	}
	if !sawDomain {
		t.Fatal("parentZoneCandidates(example.com) must include the assessed domain for this regression")
	}
	dns := &countingDNS{answers: map[string]map[uint16]QueryResult{
		"com": {
			qtypeDS:     {Status: rcodeNOERROR},
			qtypeDNSKEY: {Status: rcodeNOERROR},
		},
		"example.com": {
			qtypeDS:     {Status: rcodeNOERROR},
			qtypeDNSKEY: {Status: rcodeNOERROR, RRs: []RR{{Data: "257 3 13 AwEAAexample"}}},
		},
	}}
	if ParentSupportsDNSSEC(context.Background(), "example.com", dns) {
		t.Fatal("apex DNSKEY on the assessed domain must not count as parent DNSSEC support")
	}
}

func TestParentSupportsDNSSEC_MissingDSAtNameDoesNotOverrideUnknownTLD(t *testing.T) {
	dns := &countingDNS{
		defaultErr: errors.New("tld timeout"),
		answers: map[string]map[uint16]QueryResult{
			"example.com": {
				qtypeDS: {Status: rcodeNOERROR},
			},
		},
	}
	if !ParentSupportsDNSSEC(context.Background(), "example.com", dns) {
		t.Fatal("empty DS at the assessed name must not turn an unknown TLD into DNSSEC-unsupported")
	}
}

func TestParentSupportsDNSSEC_ParentDNSKEYCounts(t *testing.T) {
	dns := &countingDNS{answers: map[string]map[uint16]QueryResult{
		"com": {
			qtypeDS:     {Status: rcodeNOERROR},
			qtypeDNSKEY: {Status: rcodeNOERROR},
		},
		"example.com": {
			qtypeDS:     {Status: rcodeNOERROR},
			qtypeDNSKEY: {Status: rcodeNOERROR, RRs: []RR{{Data: "257 3 13 AwEAAexample"}}},
		},
	}}
	if !ParentSupportsDNSSEC(context.Background(), "www.example.com", dns) {
		t.Fatal("apex DNSKEY on a parent zone must count as DNSSEC support")
	}
}

func TestParentSupportsDNSSEC_AssessedDomainDSStillCounts(t *testing.T) {
	dns := &countingDNS{answers: map[string]map[uint16]QueryResult{
		"com": {
			qtypeDS:     {Status: rcodeNOERROR},
			qtypeDNSKEY: {Status: rcodeNOERROR},
		},
		"example.com": {
			qtypeDS: {Status: rcodeNOERROR, RRs: []RR{{Data: "30909 8 2 AABBCC"}}},
		},
	}}
	if !ParentSupportsDNSSEC(context.Background(), "example.com", dns) {
		t.Fatal("DS at the assessed domain is parent support even when the TLD probe is No")
	}
}

type slowZoneDNS struct {
	calls atomic.Int32
	delay time.Duration
}

func (s *slowZoneDNS) LookupRRWithMeta(context.Context, string, uint16) (QueryResult, error) {
	n := s.calls.Add(1)
	time.Sleep(s.delay)
	if n == 1 {
		return QueryResult{Status: rcodeNOERROR}, nil
	}
	return QueryResult{Status: rcodeNOERROR, RRs: []RR{{Data: "257 3 13 AwEAAexample"}}}, nil
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
