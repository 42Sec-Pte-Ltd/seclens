package rfc6376

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"seclens/internal/report"
)

// Request is the input for an RFC 6376 DKIM key discovery check.
type Request struct {
	Domain  string
	MXHosts []string
}

// maxConcurrentSelectorLookups caps simultaneous DoH selector lookups per domain check,
// independent of how many selectors are probed in total (amplification guard).
const maxConcurrentSelectorLookups = 20

// Check discovers DKIM selectors and parses key records per RFC 6376.
func Check(ctx context.Context, req Request, deps Deps) report.DKIMResult {
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if !deps.Gate.ValidShape(domain) || !deps.Gate.Allowed(domain) {
		return report.DKIMResult{
			Status:           "info",
			Message:          "skipped (input gated)",
			DomainKeySubtree: SubtreeUnknown,
		}
	}

	res := report.DKIMResult{
		RawRecords:       make(map[string]string),
		Status:           "info",
		DomainKeySubtree: SubtreeUnknown,
	}

	uniqueSelectors := dkimSelectorsForDomain(domain, req.MXHosts)
	res.SelectorsProbed = len(uniqueSelectors)

	wildcardDetected, canaryRcode, canaryHasDKIM := ProbeWildcardMeta(ctx, deps, domain)
	res.WildcardDetected = wildcardDetected

	bareName := "_domainkey." + strings.TrimSuffix(domain, ".")
	bareTXT, bareRcode, bareErr := deps.DNS.LookupTXTMeta(ctx, bareName)
	if bareErr != nil {
		bareRcode = -1
		bareTXT = nil
	}
	res.DomainKeySubtree = ClassifyDomainKeySubtree(SubtreeInput{
		WildcardDetected: wildcardDetected,
		BareRcode:        bareRcode,
		BareTXT:          bareTXT,
		CanaryRcode:      canaryRcode,
		CanaryHasDKIM:    canaryHasDKIM,
	})

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentSelectorLookups)

	for _, sel := range uniqueSelectors {
		wg.Add(1)
		go func(selector string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			name := selector + "._domainkey." + strings.TrimSuffix(domain, ".")
			txts, err := deps.DNS.LookupTXT(ctx, name)
			if err == nil && len(txts) > 0 {
				for _, t := range txts {
					if IsDKIMTXTRecord(t) {
						mu.Lock()
						res.SelectorsFound = append(res.SelectorsFound, selector)
						res.RawRecords[selector] = t
						parsed := ParseDKIMRecord(t)
						state := ClassifyKeyState(parsed)
						res.Keys = append(res.Keys, report.DKIMKeyRecord{
							Selector: selector,
							Version:  parsed.Version,
							KeyType:  parsed.KeyType,
							Revoked:  state == KeyStateRevoked,
							TestKey:  state == KeyStateTest,
							SyntaxOK: parsed.SyntaxOK && state != KeyStateInvalid,
							Raw:      t,
						})
						mu.Unlock()
						return
					}
				}
			}
		}(sel)
	}
	wg.Wait()

	if wildcardDetected {
		res.SelectorsFound = []string{}
		res.RawRecords = make(map[string]string)
		res.Keys = nil
		res.DomainKeySubtree = SubtreeUnknown
		res.Status = "warn"
		res.Message = "Wildcard DKIM record detected (any selector matches the same key)"
		res.Issues = append(res.Issues, "Domain uses a wildcard on *._domainkey – many selectors will artificially match")
	} else if len(res.SelectorsFound) > 0 {
		// A concrete selector proves the _domainkey tree exists even if the bare
		// ENT probe was inconclusive (multi-provider / Black Lies noise).
		res.DomainKeySubtree = SubtreePresent
		states := make([]KeyState, 0, len(res.Keys))
		for _, k := range res.Keys {
			switch {
			case !k.SyntaxOK:
				states = append(states, KeyStateInvalid)
			case k.Revoked:
				states = append(states, KeyStateRevoked)
			case k.TestKey:
				states = append(states, KeyStateTest)
			default:
				states = append(states, KeyStateActive)
			}
		}
		if !HasProductionKey(states) {
			res.Status = "warn"
			res.Message = fmt.Sprintf("%d DKIM selector(s) found but no production keys (revoked or test-only)", len(res.SelectorsFound))
			for _, k := range res.Keys {
				if k.Revoked {
					res.Issues = append(res.Issues, fmt.Sprintf("selector %q has revoked key (empty p= per RFC 6376 §3.6.1)", k.Selector))
				}
				if k.TestKey {
					res.Issues = append(res.Issues, fmt.Sprintf("selector %q is a testing key (t=y per RFC 6376 §3.6.1)", k.Selector))
				}
			}
		} else {
			res.Status = "pass"
			res.Message = fmt.Sprintf("%d DKIM selector(s) found with v=DKIM1", len(res.SelectorsFound))
		}
	} else {
		switch res.DomainKeySubtree {
		case SubtreeAbsent:
			res.Status = "info"
			res.Message = "No DKIM subtree under _domainkey (NXDOMAIN); keys likely unpublished"
			res.Issues = append(res.Issues, "_domainkey does not exist — no DKIM labels under this domain")
		case SubtreePresent:
			res.Status = "info"
			res.Message = "DKIM subtree present but no known selectors — custom selector likely (check mail header s=)"
			res.Issues = append(res.Issues, "_domainkey empty non-terminal suggests custom or undiscovered selectors")
		default:
			res.Issues = append(res.Issues, "no common DKIM selectors published (or using very custom selector names)")
			res.Message = "No DKIM keys discovered via common selectors"
		}
	}
	return res
}
