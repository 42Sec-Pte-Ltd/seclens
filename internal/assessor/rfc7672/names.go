package rfc7672

import (
	"context"
	"fmt"
	"strings"
)

const (
	qtypeTLSA  = 52
	qtypeCNAME = 5
)

const maxTLSACNAMEDepth = 5

// TLSAOwnerName returns the SMTP TLSA owner name per RFC 7672 §3.1: _25._tcp.<host>.
func TLSAOwnerName(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return ""
	}
	return "_25._tcp." + host
}

// fetchTLSA looks up TLSA records at owner, optionally following CNAME chains (max depth 5).
func fetchTLSA(ctx context.Context, dns DNS, owner string) (QueryResult, error) {
	return lookupTLSAFollow(ctx, dns, owner, 0)
}

func lookupTLSAFollow(ctx context.Context, dns DNS, name string, depth int) (QueryResult, error) {
	if depth > maxTLSACNAMEDepth {
		return QueryResult{}, fmt.Errorf("tlsa cname depth exceeded")
	}
	name = strings.TrimSuffix(name, ".")
	qr, err := dns.LookupRRWithMeta(ctx, name, qtypeTLSA)
	if err != nil {
		return QueryResult{}, err
	}
	if len(qr.RRs) > 0 {
		return qr, nil
	}
	cnameQR, err := dns.LookupRRWithMeta(ctx, name, qtypeCNAME)
	if err != nil {
		return qr, nil
	}
	for _, rr := range cnameQR.RRs {
		target := strings.TrimSuffix(strings.TrimSpace(rr.Data), ".")
		if target == "" || strings.EqualFold(target, name) {
			continue
		}
		return lookupTLSAFollow(ctx, dns, target, depth+1)
	}
	return qr, nil
}