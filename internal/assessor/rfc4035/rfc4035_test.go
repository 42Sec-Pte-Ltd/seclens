package rfc4035

import (
	"context"
	"strings"
	"testing"
)

type mockDNS struct {
	answers map[string]map[uint16]QueryResult
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

func stringsTrimSuffixDot(s string) string {
	return strings.TrimSuffix(s, ".")
}

type allowGate struct{}

func (allowGate) ValidShape(domain string) bool { return domain != "" }
func (allowGate) Allowed(domain string) bool    { return true }

func TestParentSupportsDNSSEC_CompoundTLD(t *testing.T) {
	dns := &mockDNS{answers: map[string]map[uint16]QueryResult{
		"co.uk": {
			qtypeDS: {RRs: []RR{{Data: "2371 13 2 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"}}},
		},
	}}
	if !ParentSupportsDNSSEC(context.Background(), "example.co.uk", dns) {
		t.Fatal("expected co.uk parent to support DNSSEC")
	}
}

func TestCheck_DNSSEC_FullPass(t *testing.T) {
	domain := "signed.example.com"
	dns := &mockDNS{answers: map[string]map[uint16]QueryResult{
		"com": {
			qtypeDS: {RRs: []RR{{Data: "2371 13 2 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"}}},
		},
		domain: {
			qtypeDS: {
				AD:  true,
				RRs: []RR{{Data: "2371 13 2 E9D6FAE1DAD409B0EE20831B6B70C03C773E41A8"}},
			},
			qtypeDNSKEY: {
				RRs: []RR{{Data: "257 3 13 AwEAAc6h7Rfk3A1D0u1i0vYrK8mH3uG8o0o0o0o0o0o0o0o0o0o0o0o0o0o0"}},
			},
			qtypeTXT: {AD: true, RRs: []RR{{Data: "v=spf1 -all"}}},
		},
	}}
	res := Check(context.Background(), Request{Domain: domain}, Deps{DNS: dns, Gate: allowGate{}})
	if res.Status != "pass" {
		t.Fatalf("status=%s want pass", res.Status)
	}
	if !res.DSPresent || !res.DNSKEYPresent || !res.ResolverAD || !res.SyntaxOK {
		t.Fatalf("result=%+v", res)
	}
}

func TestCheck_DNSSEC_DSWithResolverADWarnWithoutDNSKEY(t *testing.T) {
	domain := "ad-signed.example.com"
	dns := &mockDNS{answers: map[string]map[uint16]QueryResult{
		"com": {qtypeDS: {RRs: []RR{{Data: "2371 13 2 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"}}}},
		domain: {
			qtypeDS: {AD: true, RRs: []RR{{Data: "2371 13 2 E9D6FAE1DAD409B0EE20831B6B70C03C773E41A8"}}},
			qtypeTXT: {AD: true, RRs: []RR{{Data: "v=spf1 -all"}}},
		},
	}}
	res := Check(context.Background(), Request{Domain: domain}, Deps{DNS: dns, Gate: allowGate{}})
	if res.Status != "warn" {
		t.Fatalf("status=%s want warn", res.Status)
	}
	if !res.DSPresent || res.DNSKEYPresent || !res.ResolverAD {
		t.Fatalf("result=%+v", res)
	}
}

func TestCheck_DNSSEC_DSOnlyWarn(t *testing.T) {
	domain := "partial.example.com"
	dns := &mockDNS{answers: map[string]map[uint16]QueryResult{
		"com": {qtypeDS: {RRs: []RR{{Data: "2371 13 2 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"}}}},
		domain: {
			qtypeDS: {RRs: []RR{{Data: "2371 13 2 E9D6FAE1DAD409B0EE20831B6B70C03C773E41A8"}}},
			qtypeTXT: {AD: false},
		},
	}}
	res := Check(context.Background(), Request{Domain: domain}, Deps{DNS: dns, Gate: allowGate{}})
	if res.Status != "warn" {
		t.Fatalf("status=%s want warn", res.Status)
	}
	if res.ResolverAD {
		t.Fatal("expected ResolverAD false")
	}
}

func TestCheck_DNSSEC_TLDUnsupported(t *testing.T) {
	dns := &mockDNS{answers: map[string]map[uint16]QueryResult{}}
	res := Check(context.Background(), Request{Domain: "example.test"}, Deps{DNS: dns, Gate: allowGate{}})
	if res.TLDSupported {
		t.Fatal("expected unsupported TLD")
	}
	if res.Status != "info" {
		t.Fatalf("status=%s want info", res.Status)
	}
}

func TestProbeAD(t *testing.T) {
	dns := &mockDNS{answers: map[string]map[uint16]QueryResult{
		"example.com": {
			qtypeTXT: {AD: true},
		},
	}}
	if !ProbeAD(context.Background(), "example.com", dns) {
		t.Fatal("expected AD from TXT probe")
	}
}