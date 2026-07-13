package assessor

import "seclens/internal/report"

const ProfileNullMX = "null_mx"
const ProfileMail = "mail"

// IsNullMXProfile reports whether the domain uses the null_mx scoring profile.
func IsNullMXProfile(r report.Report) bool {
	return effectiveProfile(r) == ProfileNullMX
}

// PopulateProfileFields sets Profile and NullMXCompliant. Safe for legacy reports.
// Call after PopulateCheckScores and ComputeScore so NullMXCompliant reflects the normalized score.
func PopulateProfileFields(r *report.Report) {
	if r == nil {
		return
	}
	r.Profile = effectiveProfile(*r)
	r.NullMXCompliant = r.Profile == ProfileNullMX && r.Score == 100
}