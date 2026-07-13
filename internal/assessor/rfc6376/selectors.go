package rfc6376

import (
	"fmt"
	"strings"
	"time"
)

// Common DKIM selectors seen in the wild (expand as needed).
var commonDKIMSelectors = []string{
	// Generic / common
	"default", "dkim", "dkim1", "dkim2", "selector1", "selector2",
	"s1", "s2", "s1024", "k1", "k2", "k3", "mail", "email", "smtp", "sig", "sig1",
	"key", "key1", "admin", "163", "sm", "topd",
	// Year-based (custom setups)
	"2023", "2024", "2025", "2026",
	// Google / Microsoft
	"google", "office365", "o365", "ms", "protection", "onmicrosoft",
	// Transactional ESPs
	"sendgrid", "mandrill", "mailgun", "amazonses", "ses", "aws",
	"postmark", "sparkpost", "mailchimp", "mandrillapp", "klaviyo",
	"sendinblue", "brevo", "brevo1", "brevo2", "smtpapi", "mesmtp", "mte1", "mte2",
	"mailjet", "elasticemail", "sendpulse", "getresponse", "aweber",
	"hubspot", "hs1", "hs2", "pardot", "marketo", "eloqua", "exacttarget", "sfmc",
	"constantcontact", "ctct1", "ctct2", "zendesk1", "zendesk2",
	"everlytickey1", "everlytickey2", "pdk1", "pdk2",
	// Mailbox providers
	"zoho", "protonmail", "protonmail2", "protonmail3", "pm",
	"spacemail", "litesrv", "zmail", "mxvault", "afrihost",
	"exmail", "fm1", "fm2", "fm3", "km1", "km2",
	// Asia-Pacific providers
	"alibaba", "alimail", "aliyun", "baidu", "tencent", "qq", "netease", "sina", "sohu",
	"naver", "daum", "kakao", "rakuten",
	// Security / hosting / misc
	"prod", "mta", "mx", "mimecast", "proofpoint", "barracuda", "forcepoint", "symantec", "trendmicro",
}

// dkimProviderRule maps MX host patterns to provider-specific DKIM selectors.
// Rules are evaluated in order; all matching rules for each MX host contribute selectors.
type dkimProviderRule struct {
	mxKeywords []string
	selectors  []string
	extra      func() []string // optional dynamic selectors (e.g. Cloudflare cf{year}-1)
}

// dkimMXProviderRules — most specific / highest-signal rules first.
// MX host matching is substring-based on the lowered FQDN (e.g. route1.mx.cloudflare.net).
var dkimMXProviderRules = []dkimProviderRule{
	// Cloudflare Email Routing / Sending
	{mxKeywords: []string{"mx.cloudflare.net"}, selectors: []string{"cf-bounce"}, extra: cloudflareEmailRoutingDKIMSelectors},
	// Google Workspace
	{mxKeywords: []string{"aspmx.l.google.com", "googlemail.com", "smtp.google.com"}, selectors: []string{"google", "selector1", "selector2"}},
	// Microsoft 365 / Outlook
	{mxKeywords: []string{"protection.outlook.com", "mail.protection.outlook.com", "onmicrosoft.com"}, selectors: []string{"selector1", "selector2", "s1", "s2", "office365", "o365"}},
	// Proton Mail
	{mxKeywords: []string{"protonmail.ch", "mail.protonmail.ch"}, selectors: []string{"protonmail", "protonmail2", "protonmail3", "pm"}},
	// Zoho Mail
	{mxKeywords: []string{"zoho.com", "zohomail.com", "mx.zoho.com"}, selectors: []string{"zoho", "zmail"}},
	// Fastmail
	{mxKeywords: []string{"messagingengine.com", "messagingengine.net"}, selectors: []string{"fm1", "fm2", "fm3"}},
	// Apple iCloud
	{mxKeywords: []string{"mx.icloud.com", "icloud.com"}, selectors: []string{"default", "mail", "email"}},
	// Yahoo
	{mxKeywords: []string{"yahoodns.net", "yahoo.com"}, selectors: []string{"default", "s1", "s2"}},
	// Yandex
	{mxKeywords: []string{"yandex.net", "yandex.ru"}, selectors: []string{"mail", "default"}},
	// Security gateways
	{mxKeywords: []string{"mimecast.com", "mimecast-offshore.com"}, selectors: []string{"mimecast", "selector1", "selector2"}},
	{mxKeywords: []string{"pphosted.com", "proofpoint.com"}, selectors: []string{"proofpoint", "selector1", "selector2"}},
	{mxKeywords: []string{"barracudanetworks.com", "ess.barracuda.com"}, selectors: []string{"barracuda", "selector1"}},
	{mxKeywords: []string{"horizon.cs.zohohost.com"}, selectors: []string{"zoho"}},
	// Transactional ESPs
	{mxKeywords: []string{"amazon-smtp.amazon.com", "smtp-out.amazonses.com", "amazonses.com"}, selectors: []string{"amazonses", "ses", "aws"}, extra: amazonSESKnownSelectors},
	{mxKeywords: []string{"sendgrid.net", "sendgrid.com"}, selectors: []string{"sendgrid", "s1", "s2"}},
	{mxKeywords: []string{"mailgun.org", "mailgun.net"}, selectors: []string{"mailgun", "k1", "k2", "smtpapi", "pic"}},
	{mxKeywords: []string{"mandrillapp.com"}, selectors: []string{"mandrill", "mandrillapp"}},
	{mxKeywords: []string{"postmarkapp.com"}, selectors: []string{"postmark", "pm"}},
	{mxKeywords: []string{"sparkpostmail.com"}, selectors: []string{"sparkpost", "scph0123"}, extra: sparkpostYearDKIMSelectors},
	{mxKeywords: []string{"sendinblue.com", "brevo.com"}, selectors: []string{"brevo1", "brevo2", "sendinblue", "brevo"}},
	{mxKeywords: []string{"mailjet.com"}, selectors: []string{"mailjet", "k1"}},
	{mxKeywords: []string{"elasticemail.com"}, selectors: []string{"elasticemail", "api"}},
	{mxKeywords: []string{"klaviyo.com"}, selectors: []string{"klaviyo", "k1"}},
	{mxKeywords: []string{"hubspot.com", "hubspotemail.net"}, selectors: []string{"hs1", "hs2", "hubspot"}},
	{mxKeywords: []string{"ccsend.com", "constantcontact.com"}, selectors: []string{"ctct1", "ctct2", "constantcontact"}},
	{mxKeywords: []string{"zendesk.com"}, selectors: []string{"zendesk1", "zendesk2"}},
	{mxKeywords: []string{"marketo.com"}, selectors: []string{"marketo", "m1"}},
	{mxKeywords: []string{"pardot.com"}, selectors: []string{"pardot"}},
	{mxKeywords: []string{"exacttarget.com", "sfmc-content.com"}, selectors: []string{"exacttarget", "sfmc"}},
	// Hosting / regional mailbox providers
	{mxKeywords: []string{"secureserver.net", "mailstore1.secureserver.net"}, selectors: []string{"default", "dkim", "key", "mail"}},
	{mxKeywords: []string{"emailsrvr.com", "rackspace.com"}, selectors: []string{"default", "k1", "s1"}},
	{mxKeywords: []string{"spacemail.com"}, selectors: []string{"spacemail"}},
	{mxKeywords: []string{"afrihost.com"}, selectors: []string{"afrihost", "default"}},
	{mxKeywords: []string{"mxvault.com"}, selectors: []string{"mxvault", "default"}},
	// Asia-Pacific
	{mxKeywords: []string{"exmail.qq.com", "qq.com"}, selectors: []string{"exmail", "qq", "tencent"}},
	{mxKeywords: []string{"aliyun.com", "alibaba.com", "alimail.com"}, selectors: []string{"alibaba", "alimail", "aliyun"}},
	{mxKeywords: []string{"netease.com", "163.com"}, selectors: []string{"netease", "163", "sina"}},
	{mxKeywords: []string{"naver.com"}, selectors: []string{"naver"}},
	{mxKeywords: []string{"daum.net", "kakao.com"}, selectors: []string{"daum", "kakao"}},
	{mxKeywords: []string{"rakuten.co.jp"}, selectors: []string{"rakuten"}},
	{mxKeywords: []string{"baidu.com"}, selectors: []string{"baidu"}},
	{mxKeywords: []string{"sohu.com"}, selectors: []string{"sohu"}},
	// Misc ESP / marketing
	{mxKeywords: []string{"getresponse.com"}, selectors: []string{"getresponse"}},
	{mxKeywords: []string{"aweber.com"}, selectors: []string{"aweber"}},
	{mxKeywords: []string{"mailchimp.com"}, selectors: []string{"mailchimp", "k1", "k2"}},
	{mxKeywords: []string{"eloqua.com"}, selectors: []string{"eloqua"}},
	{mxKeywords: []string{"everlytic.net"}, selectors: []string{"everlytickey1", "everlytickey2"}},
	{mxKeywords: []string{"migadu.com"}, selectors: []string{"default", "dkim"}},
	{mxKeywords: []string{"litesrv.net"}, selectors: []string{"litesrv"}},
}

func mxHostMatchesRule(host string, rule dkimProviderRule) bool {
	for _, kw := range rule.mxKeywords {
		if strings.Contains(host, kw) {
			return true
		}
	}
	return false
}

// dkimSelectorsFromMX returns provider-optimized selectors derived from MX hosts.
func dkimSelectorsFromMX(mxHosts []string) []string {
	var out []string
	for _, host := range mxHosts {
		h := strings.ToLower(strings.TrimSuffix(host, "."))
		for _, rule := range dkimMXProviderRules {
			if mxHostMatchesRule(h, rule) {
				out = append(out, rule.selectors...)
				if rule.extra != nil {
					out = append(out, rule.extra()...)
				}
			}
		}
	}
	return out
}

// cloudflareEmailRoutingDKIMSelectors returns year-based selectors for Cloudflare Email Routing
// (cf{year}-1) and SparkPost transactional mail (sparkpostus{year}, e.g. notify.cloudflare.com).
func cloudflareEmailRoutingDKIMSelectors() []string {
	year := time.Now().Year()
	sels := make([]string, 0, 6)
	for y := year; y >= year-2; y-- {
		sels = append(sels, fmt.Sprintf("cf%d-1", y))
		sels = append(sels, fmt.Sprintf("sparkpostus%d", y))
	}
	return sels
}

// dkimKnownDomainSelectors are opaque/provider-specific selectors for high-traffic domains
// where MX patterns alone are insufficient (e.g. Amazon SES via amazon-smtp.amazon.com).
var dkimKnownDomainSelectors = map[string][]string{
	"amazon.com": {"i5yz2egl2d6o3oxllmizbamyhdvt6x6k"},
}

// amazonSESKnownSelectors returns documented Amazon SES opaque selectors (CNAME → *.dkim.amazonses.com).
func amazonSESKnownSelectors() []string {
	return []string{"i5yz2egl2d6o3oxllmizbamyhdvt6x6k"}
}

// sparkpostYearDKIMSelectors returns SparkPost year-stamped selectors (e.g. sparkpostus2026).
func sparkpostYearDKIMSelectors() []string {
	year := time.Now().Year()
	sels := make([]string, 0, 3)
	for y := year; y >= year-2; y-- {
		sels = append(sels, fmt.Sprintf("sparkpostus%d", y))
	}
	return sels
}

// MaxSelectors caps distinct selector probes for untrusted domains (amplification guard).
// Sized to cover the full commonDKIMSelectors list (112 entries) plus known-domain/MX-derived
// provider selectors and the SLD-derived guess, with headroom.
const MaxSelectors = 200

// dkimSelectorsForDomain builds the capped, deduplicated selector probe list.
// Provider/MX-derived selectors are prioritized so they are not dropped by MaxSelectors.
func dkimSelectorsForDomain(domain string, mxHosts []string) []string {
	key := strings.ToLower(strings.TrimSuffix(domain, "."))
	var selectorsToCheck []string
	if known, ok := dkimKnownDomainSelectors[key]; ok {
		selectorsToCheck = append(selectorsToCheck, known...)
	}
	selectorsToCheck = append(selectorsToCheck, dkimSelectorsFromMX(mxHosts)...)
	selectorsToCheck = append(selectorsToCheck, commonDKIMSelectors...)

	if parts := strings.Split(strings.TrimSuffix(domain, "."), "."); len(parts) >= 2 {
		sld := parts[len(parts)-2]
		if len(sld) > 2 {
			selectorsToCheck = append(selectorsToCheck, sld)
		}
	}

	seen := make(map[string]bool)
	uniqueSelectors := []string{}
	for _, s := range selectorsToCheck {
		if !seen[s] {
			seen[s] = true
			uniqueSelectors = append(uniqueSelectors, s)
		}
	}

	if len(uniqueSelectors) > MaxSelectors {
		uniqueSelectors = uniqueSelectors[:MaxSelectors]
	}
	return uniqueSelectors
}