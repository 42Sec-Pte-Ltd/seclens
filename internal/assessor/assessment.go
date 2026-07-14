package assessor

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"seclens/internal/assessor/rfc7672"
	"seclens/internal/assessor/rfc7505"
	"seclens/internal/assessor/rfc8460"
	"seclens/internal/assessor/rfc8461"
	"seclens/internal/report"
)

// AssessmentOpts controls a single domain assessment.
// Domains are always treated as untrusted: shape/allowlist gates, SSRF guards, and caps always apply.
type AssessmentOpts struct {
	Timeout  time.Duration
	DoSMTP   bool // future: deep checks
	Resolver string
	// TraceDNS keeps multi-provider DoH provenance on the report (bulk JSONL usually leaves this off).
	TraceDNS bool
}

// Assess performs all implemented checks for a single domain and returns a Report.
func Assess(ctx context.Context, domain string, opts AssessmentOpts) (report.Report, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return report.Report{}, fmt.Errorf("empty domain")
	}

	if !isValidDomainShape(domain) {
		return report.Report{}, fmt.Errorf("invalid domain shape")
	}
	if !isAllowedDomain(domain) {
		return report.Report{}, fmt.Errorf("domain not allowed by SECLENS_DOMAIN_ALLOWLIST")
	}

	if opts.Timeout <= 0 {
		opts.Timeout = 25 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	var dnsTrace *dnsTraceCollector
	if opts.TraceDNS {
		ctx, dnsTrace = withDNSTrace(ctx)
	}

	r := report.Report{
		Domain:    domain,
		Generated: time.Now().UTC(),
	}

	// MX first: mail | null_mx | no_mx profile and hosts for DKIM/MTA-STS/DANE.
	// A hard LookupMX failure must not be treated as empty MX (no_mx dual-path).
	mxs, mxErr := DefaultClient.LookupMX(ctx, domain)
	if mxErr != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("MX DNS lookup failed: %v", mxErr))
		r.MXs = nil
		r.HasNullMX = false
		r.IsMailEnabled = false
		// Fail open to mail stack without dual-path "empty MX" guidance.
		r.Profile = ProfileMail
	} else {
		r.MXs = mxs
		r.HasNullMX = HasNullMX(mxs)
		r.Profile = ProfileFromMXs(mxs)
		r.IsMailEnabled = rfc7505.IsMailEnabled(mxs)
		if r.Profile == ProfileMail && r.HasNullMX && !rfc7505.IsValidNullMX(mxs) {
			if rfc7505.DetectViolation(mxs) == rfc7505.ViolationMixedMX {
				r.Errors = append(r.Errors, rfc7505.MixedMXViolationMessage)
			}
		}
	}

	ns, _ := DefaultClient.LookupNS(ctx, domain)
	r.Nameservers = ns

	var mxHosts []string
	for _, m := range mxs {
		if m.Host != "." && m.Host != "" {
			mxHosts = append(mxHosts, m.Host)
		}
	}

	// Drop MX that resolve only to private IPs before DANE/MTA-STS (SSRF).
	isSafe := make([]bool, len(mxHosts))
	var mxGuardWG sync.WaitGroup
	for i, h := range mxHosts {
		if !isValidDomainShape(h) {
			continue
		}
		mxGuardWG.Add(1)
		go func(idx int, host string) {
			defer mxGuardWG.Done()
			ips, _ := DefaultClient.resolveHostIPs(ctx, host)
			isSafe[idx] = hasPublicIP(ips)
		}(i, h)
	}
	mxGuardWG.Wait()

	safeMXHosts := make([]string, 0, len(mxHosts))
	for i, h := range mxHosts {
		if isSafe[i] {
			safeMXHosts = append(safeMXHosts, h)
		}
	}
	mxHosts = safeMXHosts

	type result struct {
		nullMX report.NullMXResult
		spf    report.SPFResult
		dmarc  report.DMARCResult
		dkim   report.DKIMResult
		mtasts report.MTASTSResult
		tlsrpt report.TLSRPTResult
		dane   report.DANEResult
		dnssec report.DNSSECResult
		errs   []string
	}

	ch := make(chan result, 1)

	go func() {
		res := result{}

		var cwg sync.WaitGroup
		if r.Profile == ProfileNoMX || r.Profile == ProfileNullMX {
			// No MX / Null MX profiles: null MX posture, SPF, DMARC, DNSSEC only (no mail transport).
			cwg.Add(4)
			go func() { defer cwg.Done(); res.nullMX = CheckNullMX(mxs) }()
			go func() { defer cwg.Done(); res.spf = CheckSPF(ctx, domain) }()
			go func() { defer cwg.Done(); res.dmarc = CheckDMARCForNullMX(ctx, domain) }()
			go func() { defer cwg.Done(); res.dnssec = CheckDNSSEC(ctx, domain) }()
		} else {
			// Mail profile: full mail checks; also validate null MX when a null MX RR is present
			// (e.g. RFC 7505 §3 mixed MX) so violations are surfaced without switching profiles.
			mailChecks := 7
			if r.HasNullMX {
				mailChecks++
			}
			cwg.Add(mailChecks)
			if r.HasNullMX {
				go func() { defer cwg.Done(); res.nullMX = CheckNullMX(mxs) }()
			}
			go func() { defer cwg.Done(); res.spf = CheckSPF(ctx, domain) }()
			go func() { defer cwg.Done(); res.dmarc = CheckDMARC(ctx, domain) }()
			go func() { defer cwg.Done(); res.dkim = CheckDKIM(ctx, domain, mxHosts) }()
			go func() { defer cwg.Done(); res.mtasts = CheckMTASTS(ctx, domain, mxHosts) }()
			go func() { defer cwg.Done(); res.tlsrpt = CheckTLSRPT(ctx, domain) }()
			go func() { defer cwg.Done(); res.dane = CheckDANE(ctx, domain, mxHosts) }()
			go func() { defer cwg.Done(); res.dnssec = CheckDNSSEC(ctx, domain) }()
		}
		cwg.Wait()

		ch <- res
	}()

	select {
	case res := <-ch:
		if r.Profile == ProfileNoMX || r.Profile == ProfileNullMX {
			r.NullMX = &res.nullMX
			r.SPF = &res.spf
			r.DMARC = &res.dmarc
			r.DNSSEC = &res.dnssec
		} else {
			if r.HasNullMX {
				r.NullMX = &res.nullMX
			}
			r.SPF = &res.spf
			r.DMARC = &res.dmarc
			r.DKIM = &res.dkim
			r.MTASTS = &res.mtasts
			r.TLSRPT = &res.tlsrpt
			r.DANE = &res.dane
			r.DNSSEC = &res.dnssec
		}
		r.Errors = res.errs
		applyPostFanInEnrichment(&r)
	case <-ctx.Done():
		r.Errors = append(r.Errors, fmt.Sprintf("assessment timed out or cancelled: %v", ctx.Err()))
	}

	PopulateCheckScores(&r)
	r.ApplicableMax = ComputeApplicableMax(r)
	r.Score = ComputeScore(r)
	PopulateProfileFields(&r)
	r.DNSTrace = dnsTrace.snapshot()

	return r, nil
}

// applyPostFanInEnrichment runs cross-check and recommendation steps after parallel
// protocol checks complete. PopulateCheckScores must run only after this returns.
// Mail-transport recommendations (MTA-STS / TLS-RPT) only apply when mail is enabled;
// no-mail domains get hardened null-MX guidance via the null_mx check path instead.
func applyPostFanInEnrichment(r *report.Report) {
	if r == nil {
		return
	}
	if r.DANE != nil {
		rfc7672.EnrichWithDNSSEC(r.DANE, r.DNSSEC)
	}
	// MTA-STS / TLS-RPT only make sense for domains that accept mail.
	if r.IsMailEnabled {
		if r.TLSRPT != nil {
			r.TLSRPT.RecommendedDNSTXT = rfc8460.RecommendedDNSTXT(r.Domain)
		}
		if r.MTASTS != nil {
			var hosts []string
			for _, m := range r.MXs {
				if m.Host != "." && m.Host != "" {
					hosts = append(hosts, m.Host)
				}
			}
			r.MTASTS.RecommendedPolicy = rfc8461.BuildRecommendedPolicy(hosts)
			r.MTASTS.RecommendedDNSTXT = rfc8461.RecommendedDNSTXT(r.MTASTS.PolicyID, r.MTASTS.DNSIDValid)
			rfc8460.EnrichCrossChecks(r.MTASTS, r.TLSRPT)
		}
	} else if r.MTASTS != nil {
		// Defensive: never leave mail-transport deploy recipes on a no-mail report.
		r.MTASTS.RecommendedPolicy = ""
		r.MTASTS.RecommendedDNSTXT = ""
	}
	if !r.IsMailEnabled && r.TLSRPT != nil {
		r.TLSRPT.RecommendedDNSTXT = ""
	}
}

// runBulk is a simple concurrent runner for many domains.
func RunBulk(ctx context.Context, domains []string, opts AssessmentOpts, concurrency int) []report.Report {
	if concurrency <= 0 {
		concurrency = 8
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	reports := make([]report.Report, len(domains))
	errs := make([]error, len(domains))

	for i, d := range domains {
		wg.Add(1)
		sem <- struct{}{} // acquire in launcher BEFORE go: limits goroutine creation to concurrency (fixes 1M-scale memory blowup)
		go func(idx int, dom string) {
			defer wg.Done()
			defer func() { <-sem }()

			rep, err := Assess(ctx, dom, opts)
			reports[idx] = rep
			errs[idx] = err
		}(i, d)
	}
	wg.Wait()

	// attach any top level errs into the report
	for i := range reports {
		if errs[i] != nil && reports[i].Domain != "" {
			reports[i].Errors = append(reports[i].Errors, errs[i].Error())
		}
	}
	return reports
}
