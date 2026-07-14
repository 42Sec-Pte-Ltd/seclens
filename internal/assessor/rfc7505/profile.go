package rfc7505

import "seclens/internal/report"

// IsNullMXProfile reports whether the domain is scored under the null_mx profile.
// True when no non-null MX exists: a valid RFC 7505 null MX (0 .), an empty MX set,
// or only null-MX RRs. Domains that accept mail (any real MX) stay on the mail profile.
// No-mail domains should harden with null MX + SPF -all + DMARC, not MTA-STS/DANE.
func IsNullMXProfile(mxs []report.MXRecord) bool {
	return !IsMailEnabled(mxs)
}

// IsMailEnabled reports whether the domain accepts inbound mail per MX records.
// True when any non-null MX exists (including mixed MX where mail is still accepted).
func IsMailEnabled(mxs []report.MXRecord) bool {
	return HasNonNullMX(mxs)
}