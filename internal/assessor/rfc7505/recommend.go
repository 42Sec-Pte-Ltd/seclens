package rfc7505

import (
	"fmt"
	"strings"

	"seclens/internal/assessor/rfc7489"
)

// RecommendedRecords holds suggested DNS records for a hardened null MX posture.
type RecommendedRecords struct {
	MX    string
	SPF   string
	DMARC string
}

// Recommended returns deployment recommendations for RFC 7505 null MX domains.
func Recommended(domain string) RecommendedRecords {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	return RecommendedRecords{
		MX:    "0 .",
		SPF:   "v=spf1 -all",
		DMARC: rfc7489.RecommendedRecord(domain, true),
	}
}

// RecommendedDMARCSnippet returns the DMARC TXT snippet for null MX domains.
func RecommendedDMARCSnippet(domain string) string {
	return Recommended(domain).DMARC
}

// RecommendedMXRecord returns the suggested MX RDATA for null MX.
func RecommendedMXRecord() string {
	return "0 ."
}

// RecommendedSPFRecord returns the suggested SPF TXT for null MX.
func RecommendedSPFRecord() string {
	return "v=spf1 -all"
}

// RecommendedDNSTXT is a human-readable summary of all recommended records.
func RecommendedDNSTXT(domain string) string {
	rec := Recommended(domain)
	return fmt.Sprintf("MX: %s\nSPF: %s\nDMARC (%s): %s",
		rec.MX, rec.SPF, rfc7489.DMARCHost(domain), rec.DMARC)
}