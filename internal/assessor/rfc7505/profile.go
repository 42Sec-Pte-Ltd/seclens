package rfc7505

import "seclens/internal/report"

// IsNullMXProfile reports whether MX records qualify for the null_mx scoring profile.
func IsNullMXProfile(mxs []report.MXRecord) bool {
	return IsValidNullMX(mxs)
}

// IsMailEnabled reports whether the domain accepts inbound mail per MX records.
// True when any non-null MX exists (including mixed MX where mail is still accepted).
func IsMailEnabled(mxs []report.MXRecord) bool {
	return HasNonNullMX(mxs)
}