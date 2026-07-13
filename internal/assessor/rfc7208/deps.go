package rfc7208

import (
	"context"
)

// DNS provides TXT lookups for SPF record discovery.
type DNS interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

type Gate interface {
	ValidShape(domain string) bool
	Allowed(domain string) bool
	ValidMechanismDomain(domain string) bool
}

type Deps struct {
	DNS  DNS
	Gate Gate
}