package rfc7672

import (
	"context"
	"strings"
	"testing"

	"seclens/internal/report"
)

func TestParseTLSA(t *testing.T) {
	tests := []struct {
		name      string
		rdata     string
		wantOK    bool
		usage     uint8
		selector  uint8
		matching  uint8
		wantAssoc string
	}{
		{name: "empty", rdata: ""},
		{name: "too few fields", rdata: "3 1 1"},
		{name: "valid EE SPKI SHA256", rdata: "3 1 1 ABCD", wantOK: true, usage: 3, selector: 1, matching: 1, wantAssoc: "ABCD"},
		{name: "valid with spaces in hex", rdata: "0 0 1 aa bb cc dd", wantOK: true, usage: 0, selector: 0, matching: 1, wantAssoc: "AABBCCDD"},
		{name: "rfc3597 unknown rr", rdata: `\# 4 03 01 01 ab`, wantOK: true, usage: 3, selector: 1, matching: 1, wantAssoc: "AB"},
		{name: "usage out of range", rdata: "4 0 0 abcd"},
		{name: "selector out of range", rdata: "3 2 1 abcd"},
		{name: "matching out of range", rdata: "3 1 3 abcd"},
		{name: "odd hex length", rdata: "3 1 1 abc"},
		{name: "non-hex", rdata: "3 1 1 abcdzz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseTLSA(tt.rdata)
			if got.SyntaxOK != tt.wantOK {
				t.Fatalf("SyntaxOK=%v want %v parsed=%+v", got.SyntaxOK, tt.wantOK, got)
			}
			if tt.wantOK {
				if got.Usage != tt.usage || got.Selector != tt.selector || got.MatchingType != tt.matching {
					t.Fatalf("fields=%d/%d/%d want %d/%d/%d", got.Usage, got.Selector, got.MatchingType, tt.usage, tt.selector, tt.matching)
				}
				if got.AssociationData != tt.wantAssoc {
					t.Fatalf("assoc=%q want %q", got.AssociationData, tt.wantAssoc)
				}
			}
		})
	}
}

func TestValidateTLSAFields(t *testing.T) {
	if !ValidateTLSAFields(3, 1, 1) {
		t.Fatal("expected valid fields")
	}
	if ValidateTLSAFields(4, 0, 0) || ValidateTLSAFields(0, 2, 0) || ValidateTLSAFields(0, 0, 3) {
		t.Fatal("expected invalid fields")
	}
}

func TestTLSAOwnerName(t *testing.T) {
	if got := TLSAOwnerName("Mail.Example.COM."); got != "_25._tcp.mail.example.com" {
		t.Fatalf("owner=%q", got)
	}
}

func TestMXCovered(t *testing.T) {
	parsed := map[string][]report.TLSARecord{
		"mx1.example.com": {{SyntaxOK: true}},
		"mx2.example.com": {{SyntaxOK: true}},
	}
	if !MXCovered([]string{"mx1.example.com", "mx2.example.com"}, parsed) {
		t.Fatal("expected full coverage")
	}
	partial := map[string][]report.TLSARecord{
		"mx1.example.com": {{SyntaxOK: true}},
	}
	if MXCovered([]string{"mx1.example.com", "mx2.example.com"}, partial) {
		t.Fatal("expected partial coverage false")
	}
	if MXCovered(nil, parsed) {
		t.Fatal("empty mx hosts should not be covered")
	}
}

func TestCheck_NoTLSA(t *testing.T) {
	dns := newMockDNS()
	res := Check(context.Background(), Request{Domain: "example.com", MXHosts: []string{"mx.example.com"}}, Deps{DNS: dns, Gate: allowGate{}})
	if res.Status != "info" || len(res.AdvertisedFor) != 0 {
		t.Fatalf("status=%s advertised=%v", res.Status, res.AdvertisedFor)
	}
}

func TestCheck_TLSAForOneMX(t *testing.T) {
	dns := newMockDNS().addTLSA("_25._tcp.mx1.example.com", "3 1 1 AABBCCDD")
	res := Check(context.Background(), Request{
		Domain:  "example.com",
		MXHosts: []string{"mx1.example.com", "mx2.example.com"},
	}, Deps{DNS: dns, Gate: allowGate{}})
	if len(res.AdvertisedFor) != 1 || res.AdvertisedFor[0] != "mx1.example.com" {
		t.Fatalf("advertised=%v", res.AdvertisedFor)
	}
	if res.MXCovered {
		t.Fatal("expected MXCovered false with one of two hosts")
	}
	if res.Status != "warn" {
		t.Fatalf("status=%s want warn", res.Status)
	}
}

func TestCheck_FullCoverage(t *testing.T) {
	dns := newMockDNS().
		addTLSA("_25._tcp.mx1.example.com", "3 1 1 AABBCCDD").
		addTLSA("_25._tcp.mx2.example.com", "3 1 1 AABBCCDD")
	res := Check(context.Background(), Request{
		Domain:  "example.com",
		MXHosts: []string{"mx1.example.com", "mx2.example.com"},
	}, Deps{DNS: dns, Gate: allowGate{}})
	if !res.MXCovered || !res.SyntaxOK {
		t.Fatalf("MXCovered=%v SyntaxOK=%v", res.MXCovered, res.SyntaxOK)
	}
	if res.Status != "warn" {
		t.Fatalf("status=%s want warn pending DNSSEC", res.Status)
	}
}

func TestFetchTLSA_CNAMEFollow(t *testing.T) {
	dns := newMockDNS().
		addCNAME("_25._tcp.mx.example.com", "tlsa.target.example.com").
		addTLSA("tlsa.target.example.com", "3 1 1 11223344")
	qr, err := fetchTLSA(context.Background(), dns, "_25._tcp.mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(qr.RRs) != 1 || qr.RRs[0].Data != "3 1 1 11223344" {
		t.Fatalf("rrs=%v", qr.RRs)
	}
}

func TestEnrichWithDNSSEC(t *testing.T) {
	dane := &report.DANEResult{
		AdvertisedFor: []string{"mx.example.com"},
		MXCovered:     true,
		SyntaxOK:      true,
		Status:        "warn",
		ParsedRecords: map[string][]report.TLSARecord{
			"mx.example.com": {{SyntaxOK: true}},
		},
	}
	dnssec := &report.DNSSECResult{
		DSPresent: true, DNSKEYPresent: true, ResolverAD: true, TLDSupported: true,
	}
	EnrichWithDNSSEC(dane, dnssec)
	if !dane.DNSSECValidated || dane.Status != "pass" {
		t.Fatalf("DNSSECValidated=%v status=%s", dane.DNSSECValidated, dane.Status)
	}

	dane2 := &report.DANEResult{
		AdvertisedFor: []string{"mx.example.com"},
		MXCovered:     false,
		SyntaxOK:      false,
		Status:        "warn",
	}
	EnrichWithDNSSEC(dane2, &report.DNSSECResult{DSPresent: true})
	if dane2.DNSSECValidated || dane2.Status != "warn" {
		t.Fatalf("expected warn without AD; DNSSECValidated=%v status=%s", dane2.DNSSECValidated, dane2.Status)
	}
	if !strings.Contains(strings.Join(dane2.Issues, " "), "DNSSEC") {
		t.Fatalf("issues=%v", dane2.Issues)
	}

	dane3 := &report.DANEResult{
		AdvertisedFor: []string{"mx.example.com"},
		MXCovered:     true,
		SyntaxOK:      true,
		Status:        "warn",
	}
	EnrichWithDNSSEC(dane3, &report.DNSSECResult{DSPresent: true})
	if dane3.Status != "warn" || !strings.Contains(dane3.Message, "DNSSEC validation incomplete") {
		t.Fatalf("expected warn without DNSSEC chain; status=%s msg=%s", dane3.Status, dane3.Message)
	}
}