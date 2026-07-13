package rfc8460

import (
	"context"
)

// DNS provides TXT resolution for RFC 8460 TLS-RPT discovery.
type DNS interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

type Gate interface {
	ValidShape(domain string) bool
	Allowed(domain string) bool
}

type Deps struct {
	DNS  DNS
	Gate Gate
}