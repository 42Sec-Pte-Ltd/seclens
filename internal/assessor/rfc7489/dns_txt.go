package rfc7489

import "seclens/internal/assessor/txtselect"

// selectDMARCTXT implements RFC 7489 §6.6.4 TXT record selection.
// Records must begin with v=DMARC1 (case-insensitive). Exactly one match is required.
func selectDMARCTXT(txts []string) (selected string, present bool, issue string) {
	return txtselect.SelectSingle(txts, "v=dmarc1",
		"multiple _dmarc TXT records starting with v=DMARC1 (RFC 7489 §6.6.4 requires exactly one)", false)
}