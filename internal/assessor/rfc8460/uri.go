package rfc8460

import (
	"net/mail"
	"net/url"
	"strings"
)

// validateRUAURIs returns URIs that are valid mailto: or https: per RFC 8460.
func validateRUAURIs(rua []string) (valid []string, issues []string) {
	for _, u := range rua {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if isValidRUAURI(u) {
			valid = append(valid, u)
		} else {
			issues = append(issues, "rua= URI must be mailto: or https: (got "+u+")")
		}
	}
	return valid, issues
}

func isValidRUAURI(uri string) bool {
	uri = strings.TrimSpace(uri)
	lower := strings.ToLower(uri)
	switch {
	case strings.HasPrefix(lower, "mailto:"):
		addr := strings.TrimSpace(uri[7:])
		if addr == "" {
			return false
		}
		_, err := mail.ParseAddress(addr)
		return err == nil
	case strings.HasPrefix(lower, "https://"):
		u, err := url.Parse(uri)
		return err == nil && strings.EqualFold(u.Scheme, "https") && u.Host != ""
	default:
		return false
	}
}