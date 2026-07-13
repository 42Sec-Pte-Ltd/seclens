package rfc4034

import (
	"fmt"
	"strconv"
	"strings"
)

// DNSSEC algorithm numbers (RFC 4034 Appendix A.1 and successors).
const (
	AlgRSAMD5           uint8 = 1
	AlgDSA              uint8 = 3
	AlgRSASHA1          uint8 = 5
	AlgDSANSEC3SHA1     uint8 = 6
	AlgRSASHA1NSEC3SHA1 uint8 = 7
	AlgRSASHA256        uint8 = 8
	AlgRSASHA512        uint8 = 10
	AlgECDSAP256SHA256  uint8 = 13
	AlgECDSAP384SHA384  uint8 = 14
	AlgED25519          uint8 = 15
	AlgED448            uint8 = 16
)

var algorithmNames = map[uint8]string{
	AlgRSAMD5:           "RSA/MD5",
	AlgDSA:              "DSA/SHA-1",
	AlgRSASHA1:          "RSA/SHA-1",
	AlgDSANSEC3SHA1:     "DSA-NSEC3-SHA1",
	AlgRSASHA1NSEC3SHA1: "RSASHA1-NSEC3-SHA1",
	AlgRSASHA256:        "RSA/SHA-256",
	AlgRSASHA512:        "RSA/SHA-512",
	AlgECDSAP256SHA256:  "ECDSAP256SHA256",
	AlgECDSAP384SHA384:  "ECDSAP384SHA384",
	AlgED25519:          "ED25519",
	AlgED448:            "ED448",
}

var deprecatedAlgorithms = map[uint8]bool{
	AlgRSAMD5:           true,
	AlgDSA:              true,
	AlgRSASHA1:          true,
	AlgDSANSEC3SHA1:     true,
	AlgRSASHA1NSEC3SHA1: true,
}

// algorithmMnemonics maps DoH / dig mnemonic labels to DNSSEC algorithm numbers.
// Cloudflare and Google DoH JSON often return "ECDSAP256SHA256" instead of "13".
var algorithmMnemonics = func() map[string]uint8 {
	out := map[string]uint8{
		"RSAMD5":           AlgRSAMD5,
		"DSA":              AlgDSA,
		"RSASHA1":          AlgRSASHA1,
		"DSANSEC3SHA1":     AlgDSANSEC3SHA1,
		"RSASHA1NSEC3SHA1": AlgRSASHA1NSEC3SHA1,
		"RSASHA256":        AlgRSASHA256,
		"RSASHA512":        AlgRSASHA512,
		"ECDSAP256SHA256":  AlgECDSAP256SHA256,
		"ECDSAP384SHA384":  AlgECDSAP384SHA384,
		"ED25519":          AlgED25519,
		"ED448":            AlgED448,
	}
	for num, name := range algorithmNames {
		key := strings.ToUpper(strings.ReplaceAll(name, "/", ""))
		out[key] = num
		key = strings.ToUpper(strings.ReplaceAll(name, "/", "SHA"))
		out[key] = num
	}
	return out
}()

// ParseAlgorithm parses a DNSSEC algorithm field from presentation form (numeric or mnemonic).
func ParseAlgorithm(field string) (uint8, bool) {
	field = strings.TrimSpace(field)
	if field == "" {
		return 0, false
	}
	if n, err := strconv.ParseUint(field, 10, 8); err == nil {
		return uint8(n), true
	}
	key := strings.ToUpper(strings.ReplaceAll(field, "/", ""))
	if alg, ok := algorithmMnemonics[key]; ok {
		return alg, true
	}
	key = strings.ToUpper(strings.ReplaceAll(field, "/", "SHA"))
	if alg, ok := algorithmMnemonics[key]; ok {
		return alg, true
	}
	return 0, false
}

// AlgorithmName returns a human-readable algorithm label or "unknown(N)".
func AlgorithmName(alg uint8) string {
	if name, ok := algorithmNames[alg]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", alg)
}

// AlgorithmDeprecated reports whether the algorithm is considered deprecated for new deployments.
func AlgorithmDeprecated(alg uint8) bool {
	return deprecatedAlgorithms[alg]
}

// AlgorithmWarning returns a non-empty warning for deprecated algorithms.
func AlgorithmWarning(alg uint8) string {
	if !AlgorithmDeprecated(alg) {
		return ""
	}
	return "DNSSEC algorithm " + AlgorithmName(alg) + " is deprecated; prefer ECDSAP256SHA256 (13) or RSA/SHA-256 (8)"
}