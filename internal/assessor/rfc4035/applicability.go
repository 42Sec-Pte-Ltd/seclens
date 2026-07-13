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
// keyed by the DNS client instance. TLD DNSSEC support changes on the order of years, not within
// a single run, so caching is safe. Without this, bulk/high-concurrency runs across many domains
// sharing the same handful of TLDs (com, net, org, ...) issue redundant DS/DNSKEY lookups against
// those TLD zones for every single domain — at 1M-domain scale this hammers the DoH resolver hard
// enough to trigger rate-limiting/errors, which makes zoneSupportsDNSSEC report false for
// everything and silently zeroes out DNSSEC adoption across the whole corpus.
var (
	zoneDNSSECCacheMu sync.Mutex
	zoneDNSSECCache   = map[DNS]map[string]bool{}
)

func zoneSupportsDNSSEC(ctx context.Context, zone string, dns DNS) bool {
	zoneDNSSECCacheMu.Lock()
	if byZone, ok := zoneDNSSECCache[dns]; ok {
		if v, ok := byZone[zone]; ok {
			zoneDNSSECCacheMu.Unlock()
			return v
		}
	}
	zoneDNSSECCacheMu.Unlock()

	supported := false
	ds, err := dns.LookupRRWithMeta(ctx, zone, qtypeDS)
	if err == nil && len(ds.RRs) > 0 {
		supported = true
	} else {
		dnskey, err2 := dns.LookupRRWithMeta(ctx, zone, qtypeDNSKEY)
		supported = err2 == nil && len(dnskey.RRs) > 0
	}

	zoneDNSSECCacheMu.Lock()
	if zoneDNSSECCache[dns] == nil {
		zoneDNSSECCache[dns] = map[string]bool{}
	}
	zoneDNSSECCache[dns][zone] = supported
	zoneDNSSECCacheMu.Unlock()
	return supported
}

// ParentSupportsDNSSEC reports whether the assessed domain's parent chain can publish DS records.
func ParentSupportsDNSSEC(ctx context.Context, domain string, dns DNS) bool {
	for _, zone := range parentZoneCandidates(domain) {
		if zoneSupportsDNSSEC(ctx, zone, dns) {
			return true
		}
	}
	return false
}