package bimi

import (
	"context"
	"net"
)

// DNS looks up TXT and resolves HTTPS hosts. Resolution must not use the OS resolver.
type DNS interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	ResolveHostIPs(ctx context.Context, host string) ([]net.IP, error)
}

// Gate is the assessor input gate for the domain under assessment and for fetch hosts.
type Gate interface {
	ValidShape(domain string) bool
	Allowed(domain string) bool
}

// IPGuard classifies addresses for the SSRF dial check.
type IPGuard interface {
	PublicIPs(ips []net.IP) []net.IP
	IsPrivateOrLocal(ip net.IP) bool
}

// Fetcher retrieves an HTTPS body. A nil Fetcher uses the package client.
// limit is the maximum body size in bytes.
type Fetcher interface {
	Fetch(ctx context.Context, rawURL string, limit int) (body []byte, contentType string, err error)
}

// Deps are the boundaries Check needs. Business rules do not open sockets themselves
// when Fetcher or SkipFetch is set.
type Deps struct {
	DNS       DNS
	Gate      Gate
	IPGuard   IPGuard
	Fetcher   Fetcher
	SkipFetch bool
}
