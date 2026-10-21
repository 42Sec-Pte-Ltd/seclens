package rfc4035

import "seclens/internal/report"

const notApplicableMessage = "DNSSEC not applicable (TLD does not support DNSSEC)"

// ApplyStatus sets tiered DNSSEC status on the result.
// pass: DS + DNSKEY + resolver AD; warn: DS only; info: TLD unsupported or no DS.
func ApplyStatus(res *report.DNSSECResult) {
	if res == nil {
		return
	}
	if !res.TLDSupported {
		res.Status = "info"
		res.Message = notApplicableMessage
		return
	}
	adNA := res.ADCheck == report.ADCheckNA
	if res.DSPresent && res.DNSKEYPresent && (adNA || resolverValidated(res)) {
		res.Status = "pass"
		if adNA {
			res.Message = "DNSSEC enabled (DS + DNSKEY published; AD bit n/a on this resolver)"
		} else {
			res.Message = "DNSSEC enabled (DS + DNSKEY published; resolver AD observed)"
		}
		return
	}
	if res.DSPresent {
		res.Status = "warn"
		switch {
		case adNA && !res.DNSKEYPresent:
			res.Message = "DNSSEC partially configured (DS present; DNSKEY missing; AD bit n/a)"
		case resolverValidated(res) && !res.DNSKEYPresent:
			res.Message = "DNSSEC partially configured (DS + resolver AD observed; DNSKEY missing)"
		case res.DNSKEYPresent && !resolverValidated(res):
			res.Message = "DNSSEC partially configured (DS + DNSKEY present; resolver AD not observed)"
		default:
			res.Message = "DNSSEC partially configured (DS present; DNSKEY or resolver AD not observed)"
		}
		return
	}
	res.Status = "info"
	res.Message = "DNSSEC not detected (DS record absent)"
}

func resolverValidated(res *report.DNSSECResult) bool {
	return res.ResolverAD || res.AD
}
