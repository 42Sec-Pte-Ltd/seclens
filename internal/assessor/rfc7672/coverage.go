package rfc7672

import (
	"strings"

	"seclens/internal/report"
)

// MXCovered reports whether every MX host has at least one syntactically valid TLSA record.
func MXCovered(mxHosts []string, parsed map[string][]report.TLSARecord) bool {
	if len(mxHosts) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, h := range mxHosts {
		h = normalizeMXHost(h)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		recs := parsed[h]
		if !hostHasValidTLSA(recs) {
			return false
		}
	}
	return len(seen) > 0
}

func hostHasValidTLSA(recs []report.TLSARecord) bool {
	for _, r := range recs {
		if r.SyntaxOK {
			return true
		}
	}
	return false
}

func normalizeMXHost(host string) string {
	return stringsTrimSuffixDot(strings.ToLower(strings.TrimSpace(host)))
}

func stringsTrimSuffixDot(s string) string {
	return strings.TrimSuffix(s, ".")
}