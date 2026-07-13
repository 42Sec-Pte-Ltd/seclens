package assessor

import (
	"context"
	"net"

	"seclens/internal/assessor/rfc4035"
	"seclens/internal/assessor/rfc6376"
	"seclens/internal/assessor/rfc7208"
	"seclens/internal/assessor/rfc7489"
	"seclens/internal/assessor/rfc7672"
	"seclens/internal/assessor/rfc8460"
	"seclens/internal/assessor/rfc8461"
)

// Shared DNS/gate adapters for RFC packages (avoids per-bridge type clones).

type stdGate struct{}

func (stdGate) ValidShape(domain string) bool { return IsValidDomainShape(domain) }
func (stdGate) Allowed(domain string) bool    { return IsAllowedDomain(domain) }

// Compile-time checks that stdGate matches each RFC Gate surface we use.
var (
	_ rfc4035.Gate = stdGate{}
	_ rfc6376.Gate = stdGate{}
	_ rfc7489.Gate = stdGate{}
	_ rfc7672.Gate = stdGate{}
	_ rfc8460.Gate = stdGate{}
	_ rfc8461.Gate = stdGate{}
)

type spfGate struct{ stdGate }

func (spfGate) ValidMechanismDomain(domain string) bool { return IsValidSPFMechanismDomain(domain) }

var _ rfc7208.Gate = spfGate{}

type txtDNS struct{}

func (txtDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return DefaultClient.LookupTXT(ctx, name)
}

var (
	_ rfc7208.DNS = txtDNS{}
	_ rfc7489.DNS = txtDNS{}
	_ rfc8460.DNS = txtDNS{}
)

type txtMetaDNS struct{ txtDNS }

func (txtMetaDNS) LookupTXTMeta(ctx context.Context, name string) ([]string, int, error) {
	return DefaultClient.LookupTXTMeta(ctx, name)
}

var _ rfc6376.DNS = txtMetaDNS{}

type mtastsDNS struct{ txtDNS }

func (mtastsDNS) ResolveHostIPs(ctx context.Context, host string) ([]net.IP, error) {
	return DefaultClient.resolveHostIPs(ctx, host)
}

var _ rfc8461.DNS = mtastsDNS{}

type mtastsIPGuard struct{}

func (mtastsIPGuard) PublicIPs(ips []net.IP) []net.IP  { return publicIPs(ips) }
func (mtastsIPGuard) IsPrivateOrLocal(ip net.IP) bool { return isPrivateOrLocalIP(ip) }

var _ rfc8461.IPGuard = mtastsIPGuard{}

// rrMeta maps assessor DoH results into an RFC package's RR/QueryResult shape.
func lookupRRMeta[R any, Q any](
	ctx context.Context,
	name string,
	qtype uint16,
	newQ func(ad bool, status int, rrs []R) Q,
	newR func(name string, typ uint16, data string, ttl int) R,
) (Q, error) {
	qr, err := DefaultClient.LookupRRWithMeta(ctx, name, qtype)
	if err != nil {
		var zero Q
		return zero, err
	}
	rrs := make([]R, 0, len(qr.RRs))
	for _, rr := range qr.RRs {
		rrs = append(rrs, newR(rr.Name, rr.Type, rr.Data, rr.TTL))
	}
	return newQ(qr.AD, qr.Status, rrs), nil
}

type dnssecDNS struct{}

func (dnssecDNS) LookupRRWithMeta(ctx context.Context, name string, qtype uint16) (rfc4035.QueryResult, error) {
	return lookupRRMeta(ctx, name, qtype,
		func(ad bool, status int, rrs []rfc4035.RR) rfc4035.QueryResult {
			return rfc4035.QueryResult{AD: ad, Status: status, RRs: rrs}
		},
		func(name string, typ uint16, data string, ttl int) rfc4035.RR {
			return rfc4035.RR{Name: name, Type: typ, Data: data, TTL: ttl}
		},
	)
}

var _ rfc4035.DNS = dnssecDNS{}

type daneDNS struct{}

func (daneDNS) LookupRRWithMeta(ctx context.Context, name string, qtype uint16) (rfc7672.QueryResult, error) {
	return lookupRRMeta(ctx, name, qtype,
		func(ad bool, status int, rrs []rfc7672.RR) rfc7672.QueryResult {
			return rfc7672.QueryResult{AD: ad, Status: status, RRs: rrs}
		},
		func(name string, typ uint16, data string, ttl int) rfc7672.RR {
			return rfc7672.RR{Name: name, Type: typ, Data: data, TTL: ttl}
		},
	)
}

var _ rfc7672.DNS = daneDNS{}
