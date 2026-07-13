package testutil

import "strings"

// AllowGate passes all domains through input gating.
type AllowGate struct{}

func (AllowGate) ValidShape(domain string) bool { return domain != "" }
func (AllowGate) Allowed(domain string) bool    { return true }

// DenyGate blocks all domains (skipped / input gated paths).
type DenyGate struct{}

func (DenyGate) ValidShape(domain string) bool { return false }
func (DenyGate) Allowed(domain string) bool      { return false }

// SPFGate implements RFC 7208 Gate with permissive mechanism domains.
type SPFGate struct{}

func (SPFGate) ValidShape(domain string) bool { return domain != "" && len(domain) > 3 }
func (SPFGate) Allowed(domain string) bool    { return true }

// ValidMechanismDomain is permissive for underscore labels and RFC 7208 §8 macros,
// but rejects empty/oversized names and obvious PermError shapes (e.g. empty labels).
func (SPFGate) ValidMechanismDomain(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
	if domain == "" || len(domain) > 253 || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
	}
	return true
}