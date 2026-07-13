package rfc7505

import "strings"

// NormalizeExchange canonicalizes an MX rdata hostname from DNS (RFC 7505 null MX is ".").
func NormalizeExchange(host string) string {
	if host == "." {
		return "."
	}
	return strings.TrimSuffix(host, ".")
}

// IsNullExchange reports whether host is the RFC 7505 null MX exchange ("." or legacy "").
func IsNullExchange(host string) bool {
	h := NormalizeExchange(host)
	return h == "." || h == ""
}