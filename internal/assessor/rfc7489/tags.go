package rfc7489

import (
	"fmt"
	"strings"
)

const defaultPct = 100
const defaultRI = 86400

var validPolicies = map[string]bool{"none": true, "quarantine": true, "reject": true}
var validAlignment = map[string]bool{"r": true, "s": true}
var validFOOptions = map[string]bool{"0": true, "1": true, "d": true, "s": true}

// ValidateTags checks RFC 7489 §6.3 tag syntax. Returns issues and whether the record is syntactically valid.
func ValidateTags(rec Record) (syntaxOK bool, issues []string) {
	if !rec.VersionSet || strings.ToLower(rec.Version) != "dmarc1" {
		issues = append(issues, "v= must be DMARC1 (case-insensitive, RFC 7489 §6.3)")
	}

	if !rec.PolicySet {
		issues = append(issues, "missing required p= tag (RFC 7489 §6.3)")
	} else if !validPolicies[rec.Policy] {
		issues = append(issues, "unknown p= value: "+rec.Policy)
	}

	if rec.SubPolicySet && !validPolicies[rec.SubPolicy] {
		issues = append(issues, "unknown sp= value: "+rec.SubPolicy)
	}

	pct := defaultPct
	if rec.PctSet {
		pct = rec.Pct
		if pct < 0 || pct > 100 {
			issues = append(issues, fmt.Sprintf("pct=%d out of range (RFC 7489 §6.3 allows 0–100)", pct))
		}
	} else if rec.PctInvalid {
		issues = append(issues, fmt.Sprintf("pct= must be an integer 0-100 (got %q)", rec.PctRaw))
	}

	if rec.ADKIMSet && !validAlignment[rec.ADKIM] {
		issues = append(issues, "adkim= must be r or s (got "+rec.ADKIM+")")
	}

	if rec.ASPFSet && !validAlignment[rec.ASPF] {
		issues = append(issues, "aspf= must be r or s (got "+rec.ASPF+")")
	}

	if rec.FOSet && !validFO(rec.FO) {
		issues = append(issues, "fo= contains invalid option(s) (RFC 7489 §6.3: 0, 1, d, s colon-separated)")
	}

	if rec.RISet {
		if rec.RI <= 0 {
			issues = append(issues, fmt.Sprintf("ri=%d must be a positive integer (RFC 7489 §6.3)", rec.RI))
		}
	} else if rec.RIInvalid {
		issues = append(issues, fmt.Sprintf("ri= must be a positive integer (got %q)", rec.RIRaw))
	}

	_ = pct // used for range check only; defaults applied in analyze
	syntaxOK = len(issues) == 0
	return syntaxOK, issues
}

func validFO(fo string) bool {
	if fo == "" {
		return false
	}
	for _, part := range strings.Split(fo, ":") {
		part = strings.TrimSpace(part)
		if part == "" || !validFOOptions[part] {
			return false
		}
	}
	return true
}

// EffectivePct returns pct with RFC default when unset.
func EffectivePct(rec Record) int {
	if rec.PctSet {
		return rec.Pct
	}
	return defaultPct
}

// EffectiveRI returns ri with RFC default when unset.
func EffectiveRI(rec Record) int {
	if rec.RISet {
		return rec.RI
	}
	return defaultRI
}

// EffectiveADKIM returns adkim with RFC default when unset.
func EffectiveADKIM(rec Record) string {
	if rec.ADKIMSet {
		return rec.ADKIM
	}
	return "r"
}

// EffectiveASPF returns aspf with RFC default when unset.
func EffectiveASPF(rec Record) string {
	if rec.ASPFSet {
		return rec.ASPF
	}
	return "r"
}
