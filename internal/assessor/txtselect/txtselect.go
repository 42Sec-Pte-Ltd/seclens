// Package txtselect implements the shared "exactly one TXT record with a given
// version prefix" selection rule used by RFC 7489 (DMARC), RFC 8460 (TLS-RPT),
// and RFC 8461 (MTA-STS) TXT record discovery.
package txtselect

import "strings"

// SelectSingle scans txts for entries whose trimmed value starts with prefix
// (case-insensitive) and returns the single matching record.
//
// If no record matches, present is false. If exactly one record matches, it is
// returned with present=true. If more than one record matches, multipleIssue is
// returned as issue; joinOnMultiple controls whether the newline-joined matches
// are still returned with present=true (RFC 8460 TLS-RPT behavior: still counted
// as advertised for cross-check purposes) or as "" with present=false (RFC 7489
// DMARC / RFC 8461 MTA-STS behavior: unusable once ambiguous).
func SelectSingle(txts []string, prefix string, multipleIssue string, joinOnMultiple bool) (selected string, present bool, issue string) {
	lowerPrefix := strings.ToLower(prefix)
	var valid []string
	for _, t := range txts {
		trimmed := strings.TrimSpace(t)
		if strings.HasPrefix(strings.ToLower(trimmed), lowerPrefix) {
			valid = append(valid, trimmed)
		}
	}
	switch len(valid) {
	case 0:
		return "", false, ""
	case 1:
		return valid[0], true, ""
	default:
		if joinOnMultiple {
			return strings.Join(valid, "\n"), true, multipleIssue
		}
		return "", false, multipleIssue
	}
}
