package rfc7672

import (
	"strings"

	"seclens/internal/report"
)

// EnrichWithDNSSEC sets DNSSECValidated and adjusts DANE status after parallel DNSSEC check completes.
func EnrichWithDNSSEC(dane *report.DANEResult, dnssec *report.DNSSECResult) {
	if dane == nil {
		return
	}
	dane.DNSSECValidated = dnssecFullyValidated(dnssec)

	if len(dane.AdvertisedFor) == 0 {
		return
	}

	if dane.MXCovered && dane.SyntaxOK {
		if dane.DNSSECValidated {
			dane.Status = "pass"
			dane.Message = "DANE TLSA published for all public MX hosts; resolver AD observed (no SMTP or certificate match)"
		} else {
			dane.Status = "warn"
			dane.Issues = appendUniqueIssue(dane.Issues,
				"TLSA records without DNSSEC validation provide no security benefit (RFC 7672 §2.1 requires DNSSEC)")
			dane.Message = "DANE TLSA advertised but DNSSEC validation incomplete (resolver AD not observed; no SMTP or certificate match)"
		}
		return
	}

	if !dane.DNSSECValidated && len(dane.AdvertisedFor) > 0 {
		dane.Issues = appendUniqueIssue(dane.Issues,
			"TLSA records without DNSSEC validation provide no security benefit (RFC 7672 §2.1 requires DNSSEC)")
		if dane.Status == "warn" && dane.MXCovered && dane.SyntaxOK {
			dane.Message = "DANE TLSA advertised but DNSSEC validation incomplete (resolver AD not observed; no SMTP or certificate match)"
		} else if dane.Status != "info" {
			dane.Status = "warn"
			if dane.Message == "" || strings.Contains(dane.Message, "pending DNSSEC") {
				dane.Message = "DANE TLSA advertised but DNSSEC validation incomplete (resolver AD not observed; no SMTP or certificate match)"
			}
		}
	}
}

func dnssecFullyValidated(dnssec *report.DNSSECResult) bool {
	return dnssec.FullyValidated()
}

func appendUniqueIssue(issues []string, msg string) []string {
	for _, i := range issues {
		if i == msg {
			return issues
		}
	}
	return append(issues, msg)
}
