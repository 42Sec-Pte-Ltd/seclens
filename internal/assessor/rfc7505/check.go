package rfc7505

import "seclens/internal/report"

// Check validates null MX configuration for the null_mx profile (RFC 7505).
func Check(mxs []report.MXRecord) report.NullMXResult {
	res := report.NullMXResult{
		Status:   "fail",
		Posture:  DetectPosture(mxs),
		Violation: ViolationNone.String(),
	}

	violation := DetectViolation(mxs)
	res.Violation = violation.String()

	if IsValidNullMX(mxs) {
		res.Status = "pass"
		res.Message = "Valid null MX (RFC 7505: single MX with preference 0 pointing to .)"
		return res
	}

	switch violation {
	case ViolationMixedMX:
		res.Message = "Mixed MX records — null MX must not coexist with other MX (RFC 7505 §3)"
		res.Issues = append(res.Issues, "null MX (0 .) must be the only MX record; remove other MX RRs (RFC 7505 §3)")
	case ViolationMultipleMX:
		res.Message = "Multiple MX records — invalid null MX configuration"
		res.Issues = append(res.Issues, "expected exactly one MX record with preference 0 and host \".\"")
	case ViolationWrongPreference:
		res.Message = "MX record is not a valid null MX"
		res.Issues = append(res.Issues, "preference must be 0 for null MX")
		if !IsNullExchange(mxs[0].Host) {
			res.Issues = append(res.Issues, "host must be \".\" for null MX")
		}
	case ViolationWrongExchange:
		res.Message = "MX record is not a valid null MX"
		res.Issues = append(res.Issues, "host must be \".\" for null MX")
		if mxs[0].Pref != 0 {
			res.Issues = append(res.Issues, "preference must be 0 for null MX")
		}
	default:
		if len(mxs) == 0 {
			res.Message = "No MX records published — choose an option: harden as non-mail, or enable mail"
			// Dual option: operators must decide whether the domain will receive mail.
			res.Issues = append(res.Issues,
				"No MX is published, so receivers have no explicit inbound-mail policy (ambiguous / legacy A-record fallback risk).",
				"Option 1 — No email planned (recommended default for parking/landing domains): publish a hardened null MX — MX \"0 .\", SPF \"v=spf1 -all\", DMARC \"v=DMARC1; p=reject\" (RFC 7505).",
				"Option 2 — Email planned: publish real MX records for your provider, then configure SPF (with provider includes + -all), DMARC (start p=none → quarantine → reject), DKIM, and later MTA-STS / TLS-RPT / DANE.",
			)
		}
	}
	return res
}

// MixedMXViolationMessage is the RFC 7505 §3 mixed-MX issue text for mail-profile reports.
const MixedMXViolationMessage = "RFC 7505 §3: null MX must not coexist with other MX records (mixed MX configuration)"