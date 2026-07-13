package rfc7672

import (
	"context"
	"fmt"
)

// mockDNS is a table-driven DNS stub for RFC 7672 TLSA/CNAME lookups.
type mockDNS struct {
	answers map[string]map[uint16]QueryResult
}

func newMockDNS() *mockDNS {
	return &mockDNS{answers: map[string]map[uint16]QueryResult{}}
}

func (m *mockDNS) LookupRRWithMeta(_ context.Context, name string, qtype uint16) (QueryResult, error) {
	name = stringsTrimSuffixDot(name)
	if byType, ok := m.answers[name]; ok {
		if qr, ok := byType[qtype]; ok {
			return qr, nil
		}
	}
	return QueryResult{Status: 3}, nil
}

// addTLSA registers TLSA RRs at owner (_25._tcp.<mx-host>).
func (m *mockDNS) addTLSA(owner string, rdata ...string) *mockDNS {
	owner = stringsTrimSuffixDot(owner)
	if m.answers[owner] == nil {
		m.answers[owner] = map[uint16]QueryResult{}
	}
	rrs := make([]RR, 0, len(rdata))
	for _, d := range rdata {
		rrs = append(rrs, RR{Data: d})
	}
	m.answers[owner][qtypeTLSA] = QueryResult{RRs: rrs}
	return m
}

// addCNAME registers a CNAME at name pointing to target.
func (m *mockDNS) addCNAME(name, target string) *mockDNS {
	name = stringsTrimSuffixDot(name)
	if m.answers[name] == nil {
		m.answers[name] = map[uint16]QueryResult{}
	}
	m.answers[name][qtypeCNAME] = QueryResult{RRs: []RR{{Data: target}}}
	return m
}

// addCNAMEDepthChain builds owner -> hop1 -> ... -> hopN -> TLSA at terminal target.
// hops is the number of CNAME records to follow before reaching TLSA (must exceed maxTLSACNAMEDepth to fail).
func (m *mockDNS) addCNAMEDepthChain(owner, terminalTLSA string, hops int) *mockDNS {
	owner = stringsTrimSuffixDot(owner)
	if hops <= 0 {
		return m.addTLSA(owner, terminalTLSA)
	}
	cur := owner
	for i := 0; i < hops; i++ {
		next := fmt.Sprintf("cname-hop-%d.example.com", i+1)
		m.addCNAME(cur, next)
		cur = next
	}
	m.addTLSA(cur, terminalTLSA)
	return m
}

type allowGate struct{}

func (allowGate) ValidShape(domain string) bool { return domain != "" }
func (allowGate) Allowed(domain string) bool    { return true }

type denyGate struct{}

func (denyGate) ValidShape(domain string) bool { return false }
func (denyGate) Allowed(domain string) bool    { return false }