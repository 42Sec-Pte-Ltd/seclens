package rfc8461

import (
	"regexp"
	"strings"
	"time"

	"seclens/internal/assessor/txtselect"
)

var dnsIDPattern = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)

// selectMTASTSTXT implements RFC 8461 §3.1 TXT record selection.
func selectMTASTSTXT(txts []string) (selected string, advertised bool, issue string) {
	return txtselect.SelectSingle(txts, "v=stsv1",
		"multiple _mta-sts TXT records starting with v=STSv1 (RFC 8461 §3.1 requires exactly one)", false)
}

// ParseDNSPolicyID extracts and validates the DNS id= field (RFC 8461 §3.1 ABNF).
func ParseDNSPolicyID(rawTXT string) (id string, valid bool) {
	return parseDNSPolicyID(rawTXT)
}

// parseDNSPolicyID extracts and validates the DNS id= field (RFC 8461 §3.1 ABNF).
func parseDNSPolicyID(rawTXT string) (id string, valid bool) {
	lower := strings.ToLower(rawTXT)
	idx := strings.Index(lower, "id=")
	if idx == -1 {
		return "", false
	}
	rest := rawTXT[idx+3:]
	if sp := strings.Index(rest, ";"); sp != -1 {
		rest = rest[:sp]
	}
	id = strings.Trim(strings.TrimSpace(rest), ` "'`)
	return id, dnsIDPattern.MatchString(id)
}

// FreshDNSPolicyID returns a new RFC-compliant id (1*32 ALPHA/DIGIT).
func FreshDNSPolicyID() string {
	return time.Now().UTC().Format("20060102150405") + "Z"
}