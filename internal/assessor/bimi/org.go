package bimi

import "strings"

// compoundSuffixes are the multi-label public suffixes this tree already uses
// for parent-zone probes (rfc4035.compoundTLDs). DMARC lookup here does not
// walk to the organizational domain, and the module has no public-suffix list.
var compoundSuffixes = map[string]bool{
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

// OrganizationalDomain is the registrable domain: one label under the public suffix.
// Unknown multi-label suffixes are treated as a single-label TLD.
func OrganizationalDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}
	n := 2
	lastTwo := parts[len(parts)-2] + "." + parts[len(parts)-1]
	if compoundSuffixes[lastTwo] {
		n = 3
	}
	if len(parts) <= n {
		return domain
	}
	return strings.Join(parts[len(parts)-n:], ".")
}
