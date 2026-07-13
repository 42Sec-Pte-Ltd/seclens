package rfc7672

import (
	"context"
	"strings"
	"sync"

	"seclens/internal/report"
)

// Request is the input for an RFC 7672 DANE assessment.
type Request struct {
	Domain  string
	MXHosts []string
}

// Check evaluates DANE TLSA records for SMTP MX hosts per RFC 7672/6698.
func Check(ctx context.Context, req Request, deps Deps) report.DANEResult {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(req.Domain), "."))
	if !deps.Gate.ValidShape(domain) || !deps.Gate.Allowed(domain) {
		return report.DANEResult{Status: "info", Message: "skipped (input gated)"}
	}

	res := report.DANEResult{
		Status:        "info",
		Records:       make(map[string][]string),
		ParsedRecords: make(map[string][]report.TLSARecord),
	}

	seen := map[string]bool{}
	var uniqueMX []string
	for _, h := range req.MXHosts {
		h = normalizeMXHost(h)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		uniqueMX = append(uniqueMX, h)
	}

	if len(uniqueMX) == 0 {
		res.Message = "No resolvable MX hosts for DANE TLSA lookup"
		res.Issues = append(res.Issues, "DANE provides strong MTA-to-MTA TLS binding when combined with DNSSEC")
		return res
	}

	// TLSA lookups (plus optional CNAME-chain follow) are independent per MX host, so run them
	// concurrently. Results are collected into per-index slots and re-applied to res in the
	// original uniqueMX order afterward, keeping AdvertisedFor/Records/ParsedRecords/Issues
	// deterministic regardless of goroutine completion order.
	type mxTLSAResult struct {
		advertised bool
		records    []string
		parsed     []report.TLSARecord
		issues     []string
	}
	results := make([]mxTLSAResult, len(uniqueMX))

	var wg sync.WaitGroup
	for i, host := range uniqueMX {
		owner := TLSAOwnerName(host)
		if owner == "" {
			continue
		}
		wg.Add(1)
		go func(idx int, h, ownerName string) {
			defer wg.Done()
			qr, err := fetchTLSA(ctx, deps.DNS, ownerName)
			if err != nil || len(qr.RRs) == 0 {
				return
			}
			hr := mxTLSAResult{advertised: true}
			for _, rr := range qr.RRs {
				raw := strings.TrimSpace(rr.Data)
				if raw == "" {
					continue
				}
				hr.records = append(hr.records, raw)
				parsed := ParseTLSA(raw)
				hr.parsed = append(hr.parsed, report.TLSARecord{
					Raw:          raw,
					Usage:        parsed.Usage,
					Selector:     parsed.Selector,
					MatchingType: parsed.MatchingType,
					SyntaxOK:     parsed.SyntaxOK,
				})
				if !parsed.SyntaxOK {
					hr.issues = append(hr.issues, "invalid TLSA syntax for "+h+": "+raw)
				}
			}
			results[idx] = hr
		}(i, host, owner)
	}
	wg.Wait()

	for i, host := range uniqueMX {
		hr := results[i]
		if !hr.advertised {
			continue
		}
		res.AdvertisedFor = append(res.AdvertisedFor, host)
		if len(hr.records) > 0 {
			res.Records[host] = hr.records
		}
		if len(hr.parsed) > 0 {
			res.ParsedRecords[host] = hr.parsed
		}
		res.Issues = append(res.Issues, hr.issues...)
	}

	res.MXCovered = MXCovered(uniqueMX, res.ParsedRecords)
	res.SyntaxOK = allTLSASyntaxOK(res.ParsedRecords)

	applyStatus(&res, len(uniqueMX))
	return res
}

func allTLSASyntaxOK(parsed map[string][]report.TLSARecord) bool {
	if len(parsed) == 0 {
		return false
	}
	for _, recs := range parsed {
		for _, r := range recs {
			if !r.SyntaxOK {
				return false
			}
		}
	}
	return true
}

func applyStatus(res *report.DANEResult, mxCount int) {
	if res == nil {
		return
	}
	if len(res.AdvertisedFor) == 0 {
		res.Status = "info"
		res.Message = "No DANE TLSA records found for MX hosts"
		res.Issues = append(res.Issues, "DANE provides strong MTA-to-MTA TLS binding when combined with DNSSEC")
		return
	}
	if res.MXCovered && res.SyntaxOK {
		res.Status = "warn" // upgraded to pass after DNSSEC enrich when DNSSECValidated
		res.Message = "DANE TLSA advertised for all MX hosts (pending DNSSEC validation)"
		return
	}
	res.Status = "warn"
	if !res.MXCovered {
		res.Message = "DANE TLSA advertised for some but not all MX hosts"
		res.Issues = append(res.Issues, "all MX hosts should publish valid TLSA records at _25._tcp.<mx-host> (RFC 7672 §3)")
		return
	}
	res.Message = "DANE TLSA present but one or more records have invalid syntax"
}