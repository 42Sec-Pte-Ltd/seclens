package rfc4034

import "fmt"

// Digest type identifiers (RFC 4034 Appendix A.2).
const (
	DigestSHA1   uint8 = 1
	DigestSHA256 uint8 = 2
	DigestGOST   uint8 = 3
	DigestSHA384 uint8 = 4
)

var digestTypeNames = map[uint8]string{
	DigestSHA1:   "SHA-1",
	DigestSHA256: "SHA-256",
	DigestGOST:   "GOST R 34.11-94",
	DigestSHA384: "SHA-384",
}

var deprecatedDigestTypes = map[uint8]bool{
	DigestSHA1: true,
}

// DigestTypeName returns a human-readable digest label or "unknown(N)".
func DigestTypeName(dt uint8) string {
	if name, ok := digestTypeNames[dt]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", dt)
}

// DigestTypeDeprecated reports whether the digest type is deprecated for new DS records.
func DigestTypeDeprecated(dt uint8) bool {
	return deprecatedDigestTypes[dt]
}

// DigestTypeWarning returns a non-empty warning for deprecated digest types.
func DigestTypeWarning(dt uint8) string {
	if !DigestTypeDeprecated(dt) {
		return ""
	}
	return "DS digest type " + DigestTypeName(dt) + " is deprecated; prefer SHA-256 (digest type 2)"
}