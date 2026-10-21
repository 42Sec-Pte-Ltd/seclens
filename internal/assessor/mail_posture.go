package assessor

import "seclens/internal/report"

// applyMailDomainStatus sets the status of a missing SPF or DMARC record from the profile.
// Mail fails. no_mx and null_mx warn. Those names publish no mail server.
// A lookup failure stays fail. A present record is left as the parser set it,
// so null MX with v=spf1 -all and DMARC p=reject stays pass.
func applyMailDomainStatus(r *report.Report) {
	if r == nil {
		return
	}
	switch effectiveProfile(*r) {
	case ProfileNoMX, ProfileNullMX:
		if spf := r.SPF; spf != nil && !spf.Present && spf.Status == "info" {
			spf.Status = "warn"
		}
		if dmarc := r.DMARC; dmarc != nil && !dmarc.Present && dmarc.Status == "info" {
			dmarc.Status = "warn"
		}
	case ProfileMail:
		if spf := r.SPF; spf != nil && !spf.Present && spf.Status == "warn" {
			spf.Status = "fail"
		}
		if dmarc := r.DMARC; dmarc != nil && !dmarc.Present && dmarc.Status == "info" {
			dmarc.Status = "fail"
		}
		if m := r.MTASTS; m != nil && !m.DNSAdvertised && m.Status == "info" && m.Message != "skipped (input gated)" {
			m.Status = "warn"
		}
		if d := r.DNSSEC; d != nil && d.TLDSupported && !d.DSPresent && d.Status == "info" {
			d.Status = "warn"
		}
	}
}
