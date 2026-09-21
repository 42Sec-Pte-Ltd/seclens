package assessor

import (
	"math"
	"strconv"
	"strings"

	"seclens/internal/assessor/rfc7505"
	"seclens/internal/report"
)

// Per-check maximum point values (SSOT for scoring).
const (
	MaxPointsSPF    = 20
	MaxPointsDMARC  = 25
	MaxPointsDKIM   = 10
	MaxPointsMTASTS = 15
	MaxPointsTLSRPT = 10
	MaxPointsDANE   = 10
	MaxPointsDNSSEC = 10

	// Null MX profile raw point buckets (sum = 100 when DNSSEC applicable).
	MaxPointsNullMXRecord = 25
	MaxPointsNullMXSPF    = 25
	MaxPointsNullMXDMARC  = 35
	MaxPointsNullMXDNSSEC = 15

	// Redistributed when TLD does not support DNSSEC (+5 each from DNSSEC bucket).
	MaxPointsNullMXRecordNoDNSSEC = 30
	MaxPointsNullMXSPFNoDNSSEC    = 30
	MaxPointsNullMXDMARCNoDNSSEC  = 40
)

const dnssecNotApplicableMessage = "DNSSEC not applicable (TLD does not support DNSSEC)"

// effectiveProfile returns the scoring profile, inferring from MX records for legacy reports.
func effectiveProfile(r report.Report) string {
	switch r.Profile {
	case ProfileMail, ProfileNullMX, ProfileNoMX:
		return r.Profile
	}
	// Prefer explicit MX set when present.
	if len(r.MXs) > 0 {
		return ProfileFromMXs(r.MXs)
	}
	if r.HasNullMX {
		return ProfileNullMX
	}
	// Explicit mail-enabled with empty MXs is inconsistent; trust the flag for legacy.
	if r.IsMailEnabled {
		return ProfileMail
	}
	// Empty MXs and not mail-enabled → no_mx.
	// Do not promote leftover DKIM/MTASTS/DANE objects to mail (stale history fields).
	return ProfileNoMX
}

// nullMXDNSSECApplicable reports whether the DNSSEC bucket applies for null_mx scoring.
func nullMXDNSSECApplicable(d *report.DNSSECResult) bool {
	if d == nil {
		return true
	}
	if d.Message == dnssecNotApplicableMessage {
		return false
	}
	return true
}

// PopulateCheckScores sets EarnedPoints and MaxPoints on each sub-result using the
// same rules as ComputeScore. Call after checks complete (and when re-scoring history).
func PopulateCheckScores(r *report.Report) {
	if r == nil {
		return
	}
	if IsNoMailProfile(*r) {
		populateNullMXCheckScores(r)
		return
	}
	if r.SPF != nil {
		r.SPF.EarnedPoints, r.SPF.MaxPoints = scoreSPF(r.SPF)
	}
	if r.DMARC != nil {
		r.DMARC.EarnedPoints, r.DMARC.MaxPoints = scoreDMARC(r.DMARC)
	}
	if r.DKIM != nil {
		r.DKIM.EarnedPoints, r.DKIM.MaxPoints = scoreDKIM(r.DKIM)
	}
	if r.MTASTS != nil {
		r.MTASTS.EarnedPoints, r.MTASTS.MaxPoints = scoreMTASTS(r.MTASTS)
	}
	if r.TLSRPT != nil {
		r.TLSRPT.EarnedPoints, r.TLSRPT.MaxPoints = scoreTLSRPT(r.TLSRPT)
	}
	if r.DANE != nil {
		r.DANE.EarnedPoints, r.DANE.MaxPoints = scoreDANE(r.DANE)
	}
	if r.DNSSEC != nil {
		r.DNSSEC.EarnedPoints, r.DNSSEC.MaxPoints = scoreDNSSEC(r.DNSSEC)
	}
}

func populateNullMXCheckScores(r *report.Report) {
	tldSupported := nullMXDNSSECApplicable(r.DNSSEC)

	nullMXMax := MaxPointsNullMXRecord
	spfMax := MaxPointsNullMXSPF
	dmarcMax := MaxPointsNullMXDMARC
	dnssecMax := MaxPointsNullMXDNSSEC
	if !tldSupported {
		nullMXMax = MaxPointsNullMXRecordNoDNSSEC
		spfMax = MaxPointsNullMXSPFNoDNSSEC
		dmarcMax = MaxPointsNullMXDMARCNoDNSSEC
		dnssecMax = 0
	}

	if r.NullMX != nil {
		r.NullMX.EarnedPoints, r.NullMX.MaxPoints = rfc7505.ScoreNullMXRecord(r.MXs, nullMXMax)
	}
	if r.SPF != nil {
		r.SPF.EarnedPoints, r.SPF.MaxPoints = scoreSPFStrictNullMX(r.SPF, spfMax)
	}
	if r.DMARC != nil {
		r.DMARC.EarnedPoints, r.DMARC.MaxPoints = scoreDMARCNullMX(r.DMARC, dmarcMax)
	}
	if r.DNSSEC != nil {
		r.DNSSEC.EarnedPoints, r.DNSSEC.MaxPoints = scoreDNSSECNullMX(r.DNSSEC, dnssecMax, tldSupported)
	}
}

// ComputeApplicableMax returns the maximum score achievable for this domain's profile.
// Both profiles always sum to 100 applicable raw points.
func ComputeApplicableMax(r report.Report) int {
	_ = effectiveProfile(r)
	return 100
}

// ComputeScore calculates the normalized 0–100 score from individual check results
// without performing any new network operations.
func ComputeScore(r report.Report) int {
	var earned int
	if IsNoMailProfile(r) {
		earned = scoreNullMXProfile(r)
	} else {
		earned = scoreMailProfile(r)
	}
	return normalizeScore(earned, ComputeApplicableMax(r))
}

func normalizeScore(earned, applicableMax int) int {
	if applicableMax <= 0 {
		return 0
	}
	score := int(math.Round(float64(earned) / float64(applicableMax) * 100))
	if score > 100 {
		score = 100
	}
	return score
}

func scoreMailProfile(r report.Report) int {
	score := 0
	if r.SPF != nil {
		earned, _ := scoreSPF(r.SPF)
		score += earned
	}
	if r.DMARC != nil {
		earned, _ := scoreDMARC(r.DMARC)
		score += earned
	}
	if r.MTASTS != nil {
		earned, _ := scoreMTASTS(r.MTASTS)
		score += earned
	}
	if r.DNSSEC != nil {
		earned, _ := scoreDNSSEC(r.DNSSEC)
		score += earned
	}
	if r.DKIM != nil {
		earned, _ := scoreDKIM(r.DKIM)
		score += earned
	}
	if r.DANE != nil {
		earned, _ := scoreDANE(r.DANE)
		score += earned
	}
	if r.TLSRPT != nil {
		earned, _ := scoreTLSRPT(r.TLSRPT)
		score += earned
	}
	return score
}

func scoreNullMXProfile(r report.Report) int {
	tldSupported := nullMXDNSSECApplicable(r.DNSSEC)

	nullMXMax := MaxPointsNullMXRecord
	spfMax := MaxPointsNullMXSPF
	dmarcMax := MaxPointsNullMXDMARC
	dnssecMax := MaxPointsNullMXDNSSEC
	if !tldSupported {
		nullMXMax = MaxPointsNullMXRecordNoDNSSEC
		spfMax = MaxPointsNullMXSPFNoDNSSEC
		dmarcMax = MaxPointsNullMXDMARCNoDNSSEC
		dnssecMax = 0
	}

	score := 0
	earned, _ := rfc7505.ScoreNullMXRecord(r.MXs, nullMXMax)
	score += earned
	if r.SPF != nil {
		earned, _ := scoreSPFStrictNullMX(r.SPF, spfMax)
		score += earned
	}
	if r.DMARC != nil {
		earned, _ := scoreDMARCNullMX(r.DMARC, dmarcMax)
		score += earned
	}
	if r.DNSSEC != nil {
		earned, _ := scoreDNSSECNullMX(r.DNSSEC, dnssecMax, tldSupported)
		score += earned
	}
	return score
}

func scoreSPFStrictNullMX(spf *report.SPFResult, max int) (earned, maxOut int) {
	if spf != nil && spf.Present && rfc7505.IsStrictNullMXSPF(spf.Raw) {
		return max, max
	}
	return 0, max
}

func scoreDMARCNullMX(dmarc *report.DMARCResult, max int) (earned, maxOut int) {
	if dmarc != nil && dmarc.SyntaxOK && dmarc.Policy == "reject" {
		return max, max
	}
	return 0, max
}

func scoreDNSSECNullMX(dnssec *report.DNSSECResult, max int, applicable bool) (earned, maxOut int) {
	if !applicable || max == 0 {
		return 0, 0
	}
	return dnssecEarnedPoints(dnssec, max), max
}

// spfHasSyntaxPermError reports RFC 7208 syntax PermErrors that forfeit all SPF points.
func spfHasSyntaxPermError(spf *report.SPFResult) bool {
	if spf == nil {
		return false
	}
	for _, iss := range spf.Issues {
		l := strings.ToLower(iss)
		switch {
		case strings.Contains(l, "invalid ip4"),
			strings.Contains(l, "invalid ip6"),
			strings.Contains(l, "invalid include domain-spec"),
			strings.Contains(l, "invalid redirect domain-spec"),
			strings.Contains(l, "does not start with v=spf1"),
			strings.Contains(l, "empty spf record"),
			strings.Contains(l, "multiple redirect= modifiers"),
			strings.Contains(l, "multiple 'all' mechanisms"):
			return true
		}
	}
	if spf.Message == "Invalid SPF (wrong version/start)" || spf.Message == "Empty SPF record" {
		return true
	}
	return false
}

// SPF points: publish + policy tier (-all/~all) + lookup budget (Pulse/UI matrix; see scoring_status_matrix_test).
func scoreSPF(spf *report.SPFResult) (earned, max int) {
	max = MaxPointsSPF
	if spf == nil || !spf.Present {
		return 0, max
	}
	if spfHasSyntaxPermError(spf) {
		return 0, max
	}
	earned += 5
	switch spf.AllQualifier {
	case "-":
		earned += 10
	case "~":
		if spf.Status != "fail" {
			earned += 5
		}
	}
	lc := spf.LookupCount
	if spf.HasRedirect && spf.RedirectDepth > 0 && spf.RedirectDepth < 20 && spf.EffectiveLookupCount > 0 {
		lc = spf.EffectiveLookupCount
	}
	if lc <= 20 {
		earned += 5
	}
	return earned, max
}

// DMARC points from p= (sp= informational); invalid syntax ⇒ 0.
// Full 25/15 requires the policy to apply to 100% of mail (pct omitted or 100).
// Lower pct scales: int(math.Round(base * pct / 100)). Null-MX uses scoreDMARCNullMX.
func scoreDMARC(dmarc *report.DMARCResult) (earned, max int) {
	max = MaxPointsDMARC
	if dmarc == nil || !dmarc.SyntaxOK {
		return 0, max
	}
	var base int
	switch dmarc.Policy {
	case "reject":
		base = 25
	case "quarantine":
		base = 15
	default:
		return 0, max
	}
	pct := effectiveDMARCPct(dmarc)
	if pct >= 100 {
		return base, max
	}
	if pct <= 0 {
		return 0, max
	}
	return int(math.Round(float64(base) * float64(pct) / 100.0)), max
}

// effectiveDMARCPct is the RFC 7489 pct applied to mail-profile scoring.
// Pct>0 is used as-is. Pct==0 with no pct= tag in Raw is omitted → default 100.
// An explicit pct=0 (any case) is 0.
func effectiveDMARCPct(dmarc *report.DMARCResult) int {
	if dmarc == nil {
		return 100
	}
	if dmarc.Pct > 0 {
		if dmarc.Pct > 100 {
			return 100
		}
		return dmarc.Pct
	}
	if pct, ok := parseRawDMARCPct(dmarc.Raw); ok {
		if pct < 0 {
			return 0
		}
		if pct > 100 {
			return 100
		}
		return pct
	}
	return 100
}

func parseRawDMARCPct(raw string) (pct int, set bool) {
	if raw == "" {
		return 0, false
	}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		eq := strings.IndexByte(part, '=')
		if eq <= 0 {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(part[:eq]), "pct") {
			continue
		}
		val := strings.TrimSpace(part[eq+1:])
		if val == "" {
			return 0, true
		}
		n, err := strconv.Atoi(val)
		if err != nil {
			return 0, true
		}
		return n, true
	}
	return 0, false
}

// DKIM: 10 only if at least one production key (SyntaxOK, not revoked, not t=y).
// 0 if no selectors, wildcard, or only revoked/test keys. ENT subtree alone does not score.
func scoreDKIM(dkim *report.DKIMResult) (earned, max int) {
	max = MaxPointsDKIM
	if dkim == nil || len(dkim.SelectorsFound) == 0 || dkim.WildcardDetected {
		return 0, max
	}
	for _, k := range dkim.Keys {
		if k.SyntaxOK && !k.Revoked && !k.TestKey {
			return max, max
		}
	}
	return 0, max
}

// MTA-STS tier: 0 / 5 (DNS) / 10 (policy body) / 15 (RFC 8461 full pass).
func scoreMTASTS(mtasts *report.MTASTSResult) (earned, max int) {
	max = MaxPointsMTASTS
	if mtasts == nil || !mtasts.DNSAdvertised {
		return 0, max
	}
	if mtasts.Status == "pass" {
		return 15, max
	}
	if mtasts.PolicyFetched {
		return 10, max
	}
	return 5, max
}

// scoreTLSRPT awards tiered points (max MaxPointsTLSRPT) per RFC 8460 assessor scope:
// - 0 if no DNS advertisement
// - 5 if TXT present only (no valid rua)
// - 10 only for Status=="pass" (≥1 valid mailto:/https: rua URI)
func scoreTLSRPT(tlsrpt *report.TLSRPTResult) (earned, max int) {
	max = MaxPointsTLSRPT
	if tlsrpt == nil || !tlsrpt.Present || !tlsrpt.SyntaxOK {
		return 0, max
	}
	if tlsrpt.Status == "pass" {
		return 10, max
	}
	return 5, max
}

// scoreDANE awards tiered DANE points (DNS TLSA only; no SMTP or certificate match):
//   - 0 when no TLSA is advertised
//   - 5 when TLSA is present for any MX host
//   - 10 when all MX hosts are covered, syntax is OK, and DNSSECValidated
//     (DS+DNSKEY+resolver AD observed; set post-enrich)
func scoreDANE(dane *report.DANEResult) (earned, max int) {
	max = MaxPointsDANE
	if dane == nil || len(dane.AdvertisedFor) == 0 {
		return 0, max
	}
	if dane.MXCovered && dane.SyntaxOK && dane.DNSSECValidated {
		return max, max
	}
	return max / 2, max
}

func dnssecFullyValidated(dnssec *report.DNSSECResult) bool {
	return dnssec.FullyValidated()
}

func dnssecEarnedPoints(dnssec *report.DNSSECResult, max int) int {
	if dnssec == nil || !dnssec.TLDSupported {
		return 0
	}
	if dnssecFullyValidated(dnssec) {
		return max
	}
	if dnssec.DSPresent && dnssec.SyntaxOK {
		return max / 2
	}
	return 0
}

// scoreDNSSEC awards half points for DS only and full points for DS+DNSKEY+resolver AD.
// SecLens does not perform its own cryptographic chain validation and opens no DNS TCP.
func scoreDNSSEC(dnssec *report.DNSSECResult) (earned, max int) {
	max = MaxPointsDNSSEC
	return dnssecEarnedPoints(dnssec, max), max
}
