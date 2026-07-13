package rfc4034

import (
	"strconv"
	"strings"
)

// DNSKEYPresent reports whether raw DNSKEY RDATA has the minimum presentation structure.
// Presentation form: "<flags> <protocol> <algorithm> <public-key>" (RFC 4034 §5.3).
func DNSKEYPresent(data string) bool {
	data = strings.TrimSpace(data)
	if data == "" {
		return false
	}
	fields := strings.Fields(data)
	if len(fields) < 4 {
		return false
	}
	if _, err := strconv.ParseUint(fields[0], 10, 16); err != nil {
		return false
	}
	if proto, err := strconv.ParseUint(fields[1], 10, 8); err != nil || proto != 3 {
		return false
	}
	if _, ok := ParseAlgorithm(fields[2]); !ok {
		return false
	}
	pubKey := strings.Join(fields[3:], "")
	return strings.TrimSpace(pubKey) != ""
}