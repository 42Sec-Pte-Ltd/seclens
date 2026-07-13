package rfc7489

import "strings"

// ValidateURIs checks rua= and ruf= mailto URI lists (RFC 7489 §6.3).
func ValidateURIs(rec Record) (issues []string) {
	for _, u := range rec.RUA {
		if issue := validateReportURI(u, "rua"); issue != "" {
			issues = append(issues, issue)
		}
	}
	for _, u := range rec.RUF {
		if issue := validateReportURI(u, "ruf"); issue != "" {
			issues = append(issues, issue)
		}
	}
	return issues
}

func validateReportURI(uri, tag string) string {
	if !strings.HasPrefix(strings.ToLower(uri), "mailto:") {
		return tag + "= URI should start with mailto: (got " + uri + ")"
	}
	return ""
}