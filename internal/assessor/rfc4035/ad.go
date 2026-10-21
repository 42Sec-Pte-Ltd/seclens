package rfc4035

import "context"

const qtypeTXT uint16 = 16

// ProbeAD performs a lightweight lookup and returns the resolver AD bit from DoH metadata.
// TXT is tried first; DS is used as a fallback when TXT returns no useful response.
func ProbeAD(ctx context.Context, domain string, dns DNS) (ad bool, unavailable bool) {
	txt, err := dns.LookupRRWithMeta(ctx, domain, qtypeTXT)
	if err == nil && txt.ADUnavailable {
		return false, true
	}
	if err == nil && txt.Status != 3 {
		return txt.AD, false
	}
	ds, err := dns.LookupRRWithMeta(ctx, domain, qtypeDS)
	if err == nil && ds.ADUnavailable {
		return false, true
	}
	if err == nil && ds.Status != 3 {
		return ds.AD, false
	}
	return false, false
}
