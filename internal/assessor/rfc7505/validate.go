package rfc7505

import (
	"strings"

	"seclens/internal/report"
)

// Violation classifies RFC 7505 null MX configuration problems.
type Violation int

const (
	ViolationNone Violation = iota
	ViolationMixedMX
	ViolationMultipleMX
	ViolationWrongPreference
	ViolationWrongExchange
)

// String returns the stable violation identifier stored on reports.
func (v Violation) String() string {
	switch v {
	case ViolationMixedMX:
		return "MixedMX"
	case ViolationMultipleMX:
		return "MultipleMX"
	case ViolationWrongPreference:
		return "WrongPreference"
	case ViolationWrongExchange:
		return "WrongExchange"
	default:
		return "None"
	}
}

// Posture constants describe inbound-mail posture derived from MX records.
const (
	PostureMailEnabled   = "MailEnabled"
	PostureNullMXOnly    = "NullMXOnly"
	PostureMixedInvalid  = "MixedInvalid"
	PostureNoMX          = "NoMX"
)

func isNullMXRecord(m report.MXRecord) bool {
	return m.Pref == 0 && IsNullExchange(m.Host)
}

// HasNullMXRR reports whether any MX record is a null MX RR (preference 0, exchange "." or "").
func HasNullMXRR(mxs []report.MXRecord) bool {
	for _, m := range mxs {
		if isNullMXRecord(m) {
			return true
		}
	}
	return false
}

// HasNonNullMX reports whether any MX record is not a null MX RR.
func HasNonNullMX(mxs []report.MXRecord) bool {
	for _, m := range mxs {
		if !isNullMXRecord(m) {
			return true
		}
	}
	return false
}

// IsStrictNullMXSPF reports whether raw SPF is exactly "v=spf1 -all" (case insensitive, single spaces).
func IsStrictNullMXSPF(raw string) bool {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return false
	}
	parts := strings.Fields(s)
	return len(parts) == 2 && parts[0] == "v=spf1" && parts[1] == "-all"
}

// IsValidNullMX reports RFC 7505 compliant null MX: exactly one MX with preference 0 and exchange "." or "".
func IsValidNullMX(mxs []report.MXRecord) bool {
	if len(mxs) != 1 {
		return false
	}
	return isNullMXRecord(mxs[0])
}

// DetectPosture derives inbound-mail posture from the MX set.
func DetectPosture(mxs []report.MXRecord) string {
	if len(mxs) == 0 {
		return PostureNoMX
	}
	if IsValidNullMX(mxs) {
		return PostureNullMXOnly
	}
	if HasNullMXRR(mxs) && HasNonNullMX(mxs) {
		return PostureMixedInvalid
	}
	if HasNonNullMX(mxs) {
		return PostureMailEnabled
	}
	return PostureNoMX
}

// DetectViolation returns the primary RFC 7505 null MX violation for the MX set.
func DetectViolation(mxs []report.MXRecord) Violation {
	if IsValidNullMX(mxs) {
		return ViolationNone
	}
	if len(mxs) == 0 {
		return ViolationNone
	}
	if HasNullMXRR(mxs) && HasNonNullMX(mxs) {
		return ViolationMixedMX
	}
	if len(mxs) > 1 {
		return ViolationMultipleMX
	}
	m := mxs[0]
	if m.Pref != 0 {
		return ViolationWrongPreference
	}
	if !IsNullExchange(m.Host) {
		return ViolationWrongExchange
	}
	return ViolationNone
}