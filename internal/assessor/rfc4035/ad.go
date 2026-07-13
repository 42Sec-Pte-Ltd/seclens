package rfc4035

import "context"

const qtypeTXT uint16 = 16

// ProbeAD performs a lightweight lookup and returns the resolver AD bit from DoH metadata.
// TXT is tried first; DS is used as a fallback when TXT returns no useful response.
func ProbeAD(ctx context.Context, domain string, dns DNS) bool {
	txt, err := dns.LookupRRWithMeta(ctx, domain, qtypeTXT)
	if err == nil && txt.Status != 3 {
		return txt.AD
	}
	ds, err := dns.LookupRRWithMeta(ctx, domain, qtypeDS)
	if err == nil && ds.Status != 3 {
		return ds.AD
	}
	return false
}