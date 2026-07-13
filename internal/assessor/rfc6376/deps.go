package rfc6376

import "context"

// DNS provides TXT lookups for DKIM key discovery.
type DNS interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	// LookupTXTMeta returns TXT RDATA and DNS RCODE (0=NOERROR, 3=NXDOMAIN).
	// On transport error return err; status may be -1 if unknown.
	LookupTXTMeta(ctx context.Context, name string) (txts []string, rcode int, err error)
}

type Gate interface {
	ValidShape(domain string) bool
	Allowed(domain string) bool
}

type Deps struct {
	DNS  DNS
	Gate Gate
}