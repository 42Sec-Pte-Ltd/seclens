package assessor

import (
	"seclens/internal/assessor/rfc7505"
	"seclens/internal/report"
)

// Three inbound profiles:
//   mail    — at least one real (non-null) MX; full mail stack
//   null_mx — null MX declared (RFC 7505), no real inbound path
//   no_mx   — no MX published at all (path not chosen yet)
const (
	ProfileMail   = "mail"
	ProfileNullMX = "null_mx"
	ProfileNoMX   = "no_mx"
)

// ProfileFromMXs maps the MX set to one of the three profiles.
func ProfileFromMXs(mxs []report.MXRecord) string {
	switch rfc7505.DetectPosture(mxs) {
	case rfc7505.PostureNullMXOnly:
		return ProfileNullMX
	case rfc7505.PostureNoMX:
		return ProfileNoMX
	default:
		// MailEnabled, MixedInvalid → mail (mixed stays on mail with violation)
		return ProfileMail
	}
}

// IsNullMXProfile reports whether the domain uses the null_mx scoring/UI profile
// (RFC 7505 null MX declared, not empty No MX).
func IsNullMXProfile(r report.Report) bool {
	return effectiveProfile(r) == ProfileNullMX
}

// IsNoMXProfile reports empty-MX / no path chosen.
func IsNoMXProfile(r report.Report) bool {
	return effectiveProfile(r) == ProfileNoMX
}

// IsNoMailProfile is true for no_mx and null_mx (shared non-mail scoring buckets).
func IsNoMailProfile(r report.Report) bool {
	p := effectiveProfile(r)
	return p == ProfileNoMX || p == ProfileNullMX
}

// PopulateProfileFields sets Profile and NullMXCompliant. Safe for legacy reports.
// Call after PopulateCheckScores and ComputeScore so NullMXCompliant reflects the normalized score.
func PopulateProfileFields(r *report.Report) {
	if r == nil {
		return
	}
	r.Profile = effectiveProfile(*r)
	// Fully hardened no-mail posture (null MX + SPF -all + DMARC reject + DNSSEC when applicable).
	r.NullMXCompliant = (r.Profile == ProfileNullMX || r.Profile == ProfileNoMX) && r.Score == 100
}
