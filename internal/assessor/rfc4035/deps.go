package rfc4035

import "context"

// RR is a single DNS resource record answer.
type RR struct {
	Name string
	Type uint16
	Data string
	TTL  int
}

// QueryResult carries DNS answers plus resolver metadata (RFC 4035 AD bit, RCODE).
type QueryResult struct {
	RRs    []RR
	AD     bool
	Status int
}

// DNS performs DNS lookups for RFC 4035 DNSSEC chain checks.
type DNS interface {
	LookupRRWithMeta(ctx context.Context, name string, qtype uint16) (QueryResult, error)
}

type Gate interface {
	ValidShape(domain string) bool
	Allowed(domain string) bool
}

type Deps struct {
	DNS  DNS
	Gate Gate
}