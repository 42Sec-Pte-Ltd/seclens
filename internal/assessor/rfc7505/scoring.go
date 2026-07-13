package rfc7505

import "seclens/internal/report"

// ScoreNullMXRecord awards max points only for a valid RFC 7505 null MX configuration.
func ScoreNullMXRecord(mxs []report.MXRecord, max int) (earned, maxOut int) {
	if IsValidNullMX(mxs) {
		return max, max
	}
	return 0, max
}