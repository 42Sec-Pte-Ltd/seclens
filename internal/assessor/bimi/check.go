package bimi

import (
	"context"
	"fmt"
	"strings"
	"time"

	"seclens/internal/report"
)

// Request is one domain plus the DMARC result already computed for that domain.
type Request struct {
	Domain string
	DMARC  *report.DMARCResult
}

// Check looks up default._bimi, falls back to the organizational domain, and
// optionally fetches l= and a=. Failures are findings. The result is not scored.
func Check(ctx context.Context, req Request, deps Deps) report.BIMIResult {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(req.Domain), "."))
	if deps.Gate == nil || !deps.Gate.ValidShape(domain) || !deps.Gate.Allowed(domain) {
		return report.BIMIResult{Status: "invalid", Message: "skipped (input gated)"}
	}

	res := report.BIMIResult{}
	raw, dnsName, queried, discFindings, hardInvalid := discover(ctx, domain, deps)
	res.Queried = queried
	res.DNSName = dnsName
	res.Findings = append(res.Findings, discFindings...)

	org := OrganizationalDomain(domain)
	var orgDMARC *report.DMARCResult
	if org != domain && deps.DNS != nil {
		orgDMARC = lookupOrgDMARC(ctx, org, deps.DNS)
	}
	res.Findings = append(res.Findings, DMARCGaps(domain, req.DMARC, org, orgDMARC)...)

	if hardInvalid {
		res.Raw = raw
		res.Status = "invalid"
		res.Message = "BIMI record is not usable"
		return res
	}
	if raw == "" {
		res.Status = "absent"
		res.DNSName = ""
		res.Message = "No BIMI record (default._bimi)"
		return res
	}

	parsed := ParseRecord(raw)
	res.Raw = raw
	res.Version = parsed.Version
	res.Location = parsed.Location
	res.Evidence = parsed.Evidence
	res.SyntaxOK = parsed.SyntaxOK
	res.Declined = parsed.Declined
	res.Findings = append(res.Findings, parsed.Errors...)

	switch {
	case !parsed.SyntaxOK:
		res.Status = "invalid"
		res.Message = "BIMI record has syntax errors"
	case parsed.Declined:
		res.Status = "declined"
		res.Message = "BIMI declination (empty l= and a=)"
	case parsed.Location == "" && parsed.Evidence != "":
		res.Status = "invalid"
		res.SyntaxOK = false
		res.Message = "l= is empty but a= is set"
		res.Findings = append(res.Findings, "l= is empty but a= is set; not a declination")
	default:
		res.Status = "present"
		res.Message = "BIMI record at " + dnsName
	}
	return finish(ctx, deps, res, time.Now().UTC())
}

func finish(ctx context.Context, deps Deps, res report.BIMIResult, now time.Time) report.BIMIResult {
	if res.Location != "" && (res.Status == "present" || res.Status == "invalid") {
		res = attachLogo(ctx, deps, res)
	}
	if res.Evidence != "" && (res.Status == "present" || res.Status == "invalid") {
		res = attachCert(ctx, deps, res, now)
	}
	return res
}

func attachLogo(ctx context.Context, deps Deps, res report.BIMIResult) report.BIMIResult {
	body, ct, skipped, err := fetchEvidence(ctx, deps, res.Location, maxLogoBytes)
	if skipped {
		res.Findings = append(res.Findings, "logo fetch skipped")
		return res
	}
	logo := InspectLogo(body, ct)
	if err != nil {
		logo.Error = err.Error()
	}
	res.Logo = &logo
	res.Findings = append(res.Findings, logoFindings(logo)...)
	return res
}

func attachCert(ctx context.Context, deps Deps, res report.BIMIResult, now time.Time) report.BIMIResult {
	body, _, skipped, err := fetchEvidence(ctx, deps, res.Evidence, maxCertBytes)
	if skipped {
		res.Findings = append(res.Findings, "certificate fetch skipped")
		return res
	}
	if err != nil {
		res.Certificate = &report.BIMICert{Error: err.Error()}
		res.Findings = append(res.Findings, certFindings(*res.Certificate)...)
		return res
	}
	cert := InspectCert(body, now)
	res.Certificate = &cert
	res.Findings = append(res.Findings, certFindings(cert)...)
	return res
}

type discovery struct {
	raw      string
	name     string
	queried  []string
	findings []string
	invalid  bool
}

func discover(ctx context.Context, domain string, deps Deps) (raw, name string, queried, findings []string, invalid bool) {
	d := walk(ctx, deps, domain)
	if d.invalid || d.raw != "" {
		return d.raw, d.name, d.queried, d.findings, d.invalid
	}
	org := OrganizationalDomain(domain)
	if org == domain {
		return "", d.name, d.queried, d.findings, false
	}
	orgDisc := walk(ctx, deps, org)
	d.queried = append(d.queried, orgDisc.queried...)
	d.findings = append(d.findings, orgDisc.findings...)
	if orgDisc.invalid || orgDisc.raw != "" {
		return orgDisc.raw, orgDisc.name, d.queried, d.findings, orgDisc.invalid
	}
	return "", orgDisc.name, d.queried, d.findings, false
}

func walk(ctx context.Context, deps Deps, domain string) discovery {
	name := "default._bimi." + strings.TrimSuffix(domain, ".")
	out := discovery{name: name, queried: []string{name}}
	if deps.DNS == nil {
		out.invalid = true
		out.findings = append(out.findings, "TXT lookup "+name+": no resolver")
		return out
	}
	txts, err := deps.DNS.LookupTXT(ctx, name)
	if err != nil {
		out.invalid = true
		out.findings = append(out.findings, fmt.Sprintf("TXT lookup %s: %v", name, err))
		return out
	}
	raw, n, bad := classifyTXT(txts)
	switch {
	case n > 1:
		out.invalid = true
		out.findings = append(out.findings, fmt.Sprintf("multiple BIMI records at %s", name))
	case n == 1:
		out.raw = raw
	case bad != "":
		out.invalid = true
		out.raw = bad
		out.findings = append(out.findings, "v=BIMI1 must be the first tag")
	}
	return out
}
