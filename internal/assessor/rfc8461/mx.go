package rfc8461

import (
	"strings"

	"golang.org/x/net/idna"
)

// mxHostMatchesPattern implements RFC 8461 §4.1 MX Host Validation.
func mxHostMatchesPattern(mxHost, pattern string) bool {
	mxHost = asciiHost(mxHost)
	pattern = asciiHost(pattern)

	if mxHost == pattern {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		if !strings.HasPrefix(suffix, ".") {
			suffix = "." + suffix
		}
		if strings.HasSuffix(mxHost, suffix) {
			rest := strings.TrimSuffix(mxHost, suffix)
			return len(rest) > 0 && !strings.Contains(rest, ".")
		}
	}
	return false
}

func isMXCovered(mxHosts []string, patterns []string) bool {
	if len(patterns) == 0 || len(mxHosts) == 0 {
		return false
	}
	for _, h := range mxHosts {
		covered := false
		for _, p := range patterns {
			if mxHostMatchesPattern(h, p) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func asciiHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return host
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return host
	}
	return strings.ToLower(ascii)
}