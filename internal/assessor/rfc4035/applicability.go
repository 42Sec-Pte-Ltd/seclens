package rfc4035

import (
	"context"
	"strings"
	"sync"
)

// compoundTLDs lists common multi-label public suffixes where the parent zone is not the rightmost label.
var compoundTLDs = map[string]bool{
	"co.uk": true, "org.uk": true, "me.uk": true, "ac.uk": true, "gov.uk": true, "net.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true,
	"co.nz": true, "org.nz": true, "net.nz": true, "govt.nz": true,
	"co.jp": true, "ne.jp": true, "or.jp": true, "ac.jp": true, "go.jp": true,
	"com.br": true, "net.br": true, "org.br": true, "gov.br": true,
	"co.za": true, "org.za": true, "net.za": true, "gov.za": true,
	"com.mx": true, "org.mx": true, "gob.mx": true,
	"co.in": true, "net.in": true, "org.in": true, "gov.in": true,
	"com.sg": true, "org.sg": true, "gov.sg": true, "edu.sg": true,
	"com.hk": true, "org.hk": true, "gov.hk": true, "edu.hk": true,
	"com.tw": true, "org.tw": true, "gov.tw": true, "edu.tw": true,
	"co.kr": true, "or.kr": true, "go.kr": true, "ne.kr": true,
	"com.tr": true, "org.tr": true, "gov.tr": true, "edu.tr": true,
	"com.ar": true, "org.ar": true, "gob.ar": true,
	"co.il": true, "org.il": true, "gov.il": true, "ac.il": true,
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true,
	"com.pl": true, "net.pl": true, "org.pl": true, "gov.pl": true,
}

const (
	qtypeDS     uint16 = 43
	qtypeDNSKEY uint16 = 48

	// DNS RCODEs (RFC 1035 / DoH JSON Status).
	rcodeNOERROR  = 0
	rcodeSERVFAIL = 2
	rcodeNXDOMAIN = 3
)

// zoneSupport is the result of probing whether a parent/TLD zone participates in DNSSEC.
type zoneSupport int

const (
	// zoneSupportUnknown: transport/RCODE failure — must not be cached.
	zoneSupportUnknown zoneSupport = iota
	// zoneSupportYes: definitive evidence the zone is signed / DS-capable.
	zoneSupportYes
	// zoneSupportNo: definitive empty answers (no DS at parent, no DNSKEY at apex).
	zoneSupportNo
)

// parentZoneCandidates returns parent-zone names to probe for DNSSEC infrastructure.
// Conservative strategy: always check the rightmost label and the last two labels.
func parentZoneCandidates(domain string) []string {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(zone string) {
		if zone == "" || seen[zone] {
			return
		}
		seen[zone] = true
		out = append(out, zone)
	}

	last := parts[len(parts)-1]
	lastTwo := parts[len(parts)-2] + "." + last

	if compoundTLDs[lastTwo] {
		add(lastTwo)
		add(last)
	} else {
		add(last)
		add(lastTwo)
	}
	return out
}

// zoneDNSSECCache memoizes per-zone (e.g. "com") DNSSEC support for the lifetime of the process,
// keyed by the DNS client instance. Only definitive Yes/No results are stored — never transport
// errors or SERVFAIL. Caching errors previously made the first rate-limit against "com" poison
// every subsequent domain under that TLD for the whole process (silent corpus-wide false
// "TLD does not support DNSSEC").
//
// TLD DNSSEC support changes on the order of years, so caching definitive answers is safe and
// still avoids hammering DoH on bulk runs once a zone has been classified.
var (
	zoneDNSSECCacheMu sync.Mutex
	zoneDNSSECCache   = map[DNS]map[string]zoneSupport{}
)

// probeAnswer classifies a single LookupRRWithMeta outcome.
// hasRR: answer contained records.
// empty: successful query with no records (NOERROR/NODATA or NXDOMAIN).
// inconclusive: transport error or non-terminal RCODE (SERVFAIL, …).
func probeAnswer(qr QueryResult, err error) (hasRR, empty, inconclusive bool) {
	if err != nil {
		return false, false, true
	}
	if len(qr.RRs) > 0 {
		return true, false, false
	}
	// Empty answer is only definitive for NOERROR (NODATA) or NXDOMAIN.
	// SERVFAIL / FORMERR / REFUSED / … are treated as inconclusive.
	switch qr.Status {
	case rcodeNOERROR, rcodeNXDOMAIN:
		return false, true, false
	default:
		// Includes SERVFAIL (2) and other non-success RCODEs.
		return false, false, true
	}
}

// rootDSProbe asks for DS RRs at the zone name itself.
//
// For a classic TLD label (e.g. "com"), a recursive resolver answers this from the DNS root:
// the root's DS for that TLD is the explicit signal that the TLD is signed and can publish
// DS records for child zones. This is not "DS inside the TLD zone for itself" in the
// authoritative sense — it is the root-side delegation signer record for the TLD.
func rootDSProbe(ctx context.Context, zone string, dns DNS) (hasDS bool, inconclusive bool) {
	qr, err := dns.LookupRRWithMeta(ctx, zone, qtypeDS)
	hasRR, _, inc := probeAnswer(qr, err)
	if inc {
		return false, true
	}
	if hasRR {
		return true, false
	}
	return false, false
}

// apexDNSKEYProbe checks whether the zone apex publishes DNSKEY (zone is signed).
func apexDNSKEYProbe(ctx context.Context, zone string, dns DNS) (hasKEY bool, inconclusive bool) {
	qr, err := dns.LookupRRWithMeta(ctx, zone, qtypeDNSKEY)
	hasRR, _, inc := probeAnswer(qr, err)
	if inc {
		return false, true
	}
	return hasRR, false
}

func zoneDNSSECSupport(ctx context.Context, zone string, dns DNS) zoneSupport {
	zoneDNSSECCacheMu.Lock()
	if byZone, ok := zoneDNSSECCache[dns]; ok {
		if v, ok := byZone[zone]; ok {
			zoneDNSSECCacheMu.Unlock()
			return v
		}
	}
	zoneDNSSECCacheMu.Unlock()

	result := probeZoneDNSSEC(ctx, zone, dns)

	// Never cache unknowns (errors / SERVFAIL): the next domain under this TLD must re-probe.
	if result == zoneSupportUnknown {
		return result
	}

	zoneDNSSECCacheMu.Lock()
	if zoneDNSSECCache[dns] == nil {
		zoneDNSSECCache[dns] = map[string]zoneSupport{}
	}
	zoneDNSSECCache[dns][zone] = result
	zoneDNSSECCacheMu.Unlock()
	return result
}

func probeZoneDNSSEC(ctx context.Context, zone string, dns DNS) zoneSupport {
	// 1) Explicit root-side DS for the zone name (primary signal for TLD capability).
	hasDS, dsInc := rootDSProbe(ctx, zone, dns)
	if hasDS {
		return zoneSupportYes
	}

	// 2) Apex DNSKEY (zone is signed) as secondary signal.
	hasKEY, keyInc := apexDNSKEYProbe(ctx, zone, dns)
	if hasKEY {
		return zoneSupportYes
	}

	// Both probes inconclusive → unknown (do not claim "unsupported").
	if dsInc && keyInc {
		return zoneSupportUnknown
	}
	// One definitive empty + one error: still unknown (missing half of the evidence).
	if dsInc || keyInc {
		return zoneSupportUnknown
	}
	// Both definitive empty → TLD/parent does not present DNSSEC infrastructure.
	return zoneSupportNo
}

// ParentSupportsDNSSEC reports whether the assessed domain's parent chain can publish DS records.
//
// Definitive "yes" from any parent candidate wins immediately.
// Definitive "no" from all candidates (and no unknown) → false.
// Any inconclusive probe fails open (returns true) so rate-limits and SERVFAIL cannot
// masquerade as "DNSSEC not applicable (TLD does not support DNSSEC)".
func ParentSupportsDNSSEC(ctx context.Context, domain string, dns DNS) bool {
	candidates := parentZoneCandidates(domain)
	if len(candidates) == 0 {
		return false
	}

	sawNo := false
	sawUnknown := false
	for _, zone := range candidates {
		switch zoneDNSSECSupport(ctx, zone, dns) {
		case zoneSupportYes:
			return true
		case zoneSupportNo:
			sawNo = true
		case zoneSupportUnknown:
			sawUnknown = true
		}
	}
	if sawUnknown {
		return true
	}
	return !sawNo
}
