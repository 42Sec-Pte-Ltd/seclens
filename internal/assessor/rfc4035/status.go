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
	if res.DSPresent && res.DNSKEYPresent && resolverValidated(res) {
		res.Status = "pass"
		res.Message = "DNSSEC enabled (DS + DNSKEY + resolver validated)"
		return
	}
	if res.DSPresent {
		res.Status = "warn"
		if resolverValidated(res) && !res.DNSKEYPresent {
			res.Message = "DNSSEC partially configured (DS + resolver validated; DNSKEY missing)"
		} else if res.DNSKEYPresent && !resolverValidated(res) {
			res.Message = "DNSSEC partially configured (DS + DNSKEY present; resolver validation incomplete)"
		} else {
			res.Message = "DNSSEC partially configured (DS present; DNSKEY or resolver validation incomplete)"
		}
		return
	}
	res.Status = "info"
	res.Message = "DNSSEC not detected (DS record absent)"
}

func resolverValidated(res *report.DNSSECResult) bool {
	return res.ResolverAD || res.AD
}