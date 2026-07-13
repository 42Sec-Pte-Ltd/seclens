package rfc6376

import (
	"context"
	"strings"
)

// canarySelector is an unlikely DKIM selector used to detect *._domainkey wildcards.
// Must be ≤63 octets (DNS label limit); longer names are rejected by DoH providers
// (Cloudflare/Google JSON API return 400), which silently disables wildcard detection.
const canarySelector = "seclens-dkim-wc-9f8e7d6c5b4a"

// ProbeWildcardMeta queries a canary selector and returns wildcard detection plus RCODE meta.
// canaryHasDKIM is true when the canary name has a DKIM-shaped TXT (wildcard evidence).
// On lookup error, canaryRcode is -1.
func ProbeWildcardMeta(ctx context.Context, deps Deps, domain string) (wildcard bool, canaryRcode int, canaryHasDKIM bool) {
	canaryName := canarySelector + "._domainkey." + strings.TrimSuffix(domain, ".")
	txts, rcode, err := deps.DNS.LookupTXTMeta(ctx, canaryName)
	if err != nil {
		return false, -1, false
	}
	for _, t := range txts {
		if IsDKIMTXTRecord(t) {
			return true, rcode, true
		}
	}
	return false, rcode, false
}

// ProbeWildcard keeps the existing bool-only signature for external callers.
func ProbeWildcard(ctx context.Context, deps Deps, domain string) bool {
	w, _, _ := ProbeWildcardMeta(ctx, deps, domain)
	return w
}
