package rfc8461

import (
	"context"
	"net"
)

// DNS provides TXT and host resolution for RFC 8461 policy discovery.
type DNS interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	ResolveHostIPs(ctx context.Context, host string) ([]net.IP, error)
}

type Gate interface {
	ValidShape(domain string) bool
	Allowed(domain string) bool
}

// IPGuard classifies resolved addresses for SSRF-safe HTTPS dials.
type IPGuard interface {
	PublicIPs(ips []net.IP) []net.IP
	IsPrivateOrLocal(ip net.IP) bool
}

// PolicyFetcher retrieves the HTTPS MTA-STS policy file (tests inject mocks).
type PolicyFetcher interface {
	FetchPolicy(ctx context.Context, deps Deps, domain string) (policyFetchResult, error)
}

type Deps struct {
	DNS            DNS
	Gate           Gate
	IPGuard        IPGuard
	PolicyFetcher  PolicyFetcher // nil → production fetchPolicy
}