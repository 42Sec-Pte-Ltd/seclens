package assessor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"seclens/internal/assessor/rfc7505"
	"seclens/internal/report"
)

// DoH provider base URLs (JSON API)
var dohProviders = map[string]string{
	"cloudflare": "https://cloudflare-dns.com/dns-query",
	"google":     "https://dns.google/resolve",
	"quad9":      "https://dns.quad9.net/dns-query",
}

// DoHResponse is the minimal JSON shape returned by Cloudflare/Google/Quad9 JSON DoH.
type DoHResponse struct {
	Status int  `json:"Status"`
	AD     bool `json:"AD"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
	Comment []string `json:"Comment,omitempty"`
}

// RR is a generic resource record result (used for DS, TLSA, etc.).
type RR struct {
	Name string
	Type uint16
	Data string
	TTL  int
}

// QueryResult carries DNS answers plus DoH metadata (RFC 4035 AD bit, RCODE).
type QueryResult struct {
	RRs    []RR
	AD     bool
	Status int
}

// DoHClient is JSON-DoH (stdlib only). Multi-URL clients fan out and pick the best answer
// (measurement parity: one provider flake must not hide records another still serves).
type DoHClient struct {
	baseURLs   []string
	HTTPClient *http.Client
	// retryCount: extra attempts on transient network/5xx/decode errors (default 0).
	retryCount int
}

// NewDoHClient returns a client for the named provider(s) (cloudflare, google, quad9).
// Accepts a comma-separated pool ("cloudflare,google") for parallel fan-out.
// Unknown/empty input falls back to the cloudflare+google pool.
func NewDoHClient(provider string) *DoHClient {
	var urls []string
	seen := map[string]bool{}
	for _, part := range strings.Split(provider, ",") {
		p := strings.ToLower(strings.TrimSpace(part))
		if base, ok := dohProviders[p]; ok && !seen[base] {
			urls = append(urls, base)
			seen[base] = true
		}
	}
	if len(urls) == 0 {
		urls = []string{dohProviders["cloudflare"], dohProviders["google"]}
	}
	return &DoHClient{
		baseURLs: urls,
		HTTPClient: &http.Client{
			Timeout: 6 * time.Second,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				MaxIdleConns:          1024,
				MaxIdleConnsPerHost:   256,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				ForceAttemptHTTP2:     true,
			},
		},
		retryCount: 2, // two retries (total 3 attempts) on transient DoH flakes (http errors, timeouts, decode) — fixes flaky include lookups like spf.smtp2go.com seen in reports
	}
}

// doOneQueryAttempt performs exactly one DoH GET+JSON request (no retry inside).
// Returns the decoded response plus the raw JSON body (for trace/observability).
func (c *DoHClient) doOneQueryAttempt(ctx context.Context, baseURL, name string, qtype uint16) (*DoHResponse, []byte, error) {
	qname := strings.TrimSuffix(name, ".")
	u := baseURL + "?name=" + url.QueryEscape(qname) + "&type=" + fmt.Sprint(qtype)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", "seclens/0.1 (+https://github.com/seclens-one/seclens; email-security-assessor)")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("doh http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, nil, fmt.Errorf("doh status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("doh read: %w", err)
	}
	var dr DoHResponse
	if err := json.Unmarshal(body, &dr); err != nil {
		return nil, nil, fmt.Errorf("doh decode: %w", err)
	}
	return &dr, body, nil
}

// doQueryProvider executes a DoH request against one provider with retries on transient errors.
func (c *DoHClient) doQueryProvider(ctx context.Context, baseURL, name string, qtype uint16) (*DoHResponse, []byte, error) {
	attempts := 1 + c.retryCount
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(120 * time.Millisecond):
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		}
		dr, raw, err := c.doOneQueryAttempt(ctx, baseURL, name, qtype)
		if err == nil {
			return dr, raw, nil
		}
		lastErr = err
	}
	return nil, nil, lastErr
}

// providerNameForURL maps a base URL back to its provider name (falls back to the URL).
func providerNameForURL(base string) string {
	for name, u := range dohProviders {
		if u == base {
			return name
		}
	}
	return base
}

// dohResponseRank orders responses by usefulness for best-result selection:
// NOERROR with answers > NOERROR empty > NXDOMAIN > other RCODEs (SERVFAIL etc.).
func dohResponseRank(dr *DoHResponse) int {
	switch {
	case dr == nil:
		return 0
	case dr.Status == 0 && len(dr.Answer) > 0:
		return 4
	case dr.Status == 0:
		return 3
	case dr.Status == 3:
		return 2
	default:
		return 1
	}
}

// betterDoHResponse reports whether a beats b. Ties are broken by answer count,
// then by the AD (DNSSEC-validated) bit; otherwise the earlier provider wins.
func betterDoHResponse(a, b *DoHResponse) bool {
	ra, rb := dohResponseRank(a), dohResponseRank(b)
	if ra != rb {
		return ra > rb
	}
	if a == nil || b == nil {
		return false
	}
	if len(a.Answer) != len(b.Answer) {
		return len(a.Answer) > len(b.Answer)
	}
	return a.AD && !b.AD
}

// doQuery executes a DoH request. With a provider pool it fans out to all
// providers in parallel and returns the best response (per betterDoHResponse),
// so a flake or stale cache at one provider cannot hide records the other serves.
// When the context carries a dnsTraceCollector (see withDNSTrace), all provider
// outcomes including the raw JSON bodies are recorded for traceability.
func (c *DoHClient) doQuery(ctx context.Context, name string, qtype uint16) (*DoHResponse, error) {
	if name == "" {
		return nil, errors.New("empty name")
	}
	if logDNSQueries {
		log.Printf("[dns] query name=%q type=%d", name, qtype)
	}

	type outcome struct {
		idx int
		dr  *DoHResponse
		raw []byte
		err error
		rtt time.Duration
	}
	run := func(i int, base string) outcome {
		start := time.Now()
		dr, raw, err := c.doQueryProvider(ctx, base, name, qtype)
		return outcome{idx: i, dr: dr, raw: raw, err: err, rtt: time.Since(start)}
	}

	outs := make([]outcome, len(c.baseURLs))
	if len(c.baseURLs) == 1 {
		outs[0] = run(0, c.baseURLs[0])
	} else {
		ch := make(chan outcome, len(c.baseURLs))
		for i, base := range c.baseURLs {
			go func(i int, base string) { ch <- run(i, base) }(i, base)
		}
		for range c.baseURLs {
			o := <-ch
			outs[o.idx] = o
		}
	}

	bestIdx := -1
	for i := range outs {
		if outs[i].dr == nil {
			continue
		}
		if bestIdx == -1 || betterDoHResponse(outs[i].dr, outs[bestIdx].dr) {
			bestIdx = i
		}
	}

	if trace := dnsTraceFrom(ctx); trace != nil {
		e := report.DNSQueryTrace{Name: strings.TrimSuffix(name, "."), Type: qtype}
		for i, o := range outs {
			p := report.DNSProviderTrace{
				Provider: providerNameForURL(c.baseURLs[i]),
				RTTMs:    o.rtt.Milliseconds(),
			}
			if o.err != nil {
				p.Error = o.err.Error()
			}
			if o.dr != nil {
				p.Status = o.dr.Status
				p.AD = o.dr.AD
				p.Answers = len(o.dr.Answer)
				p.Raw = json.RawMessage(o.raw)
			}
			e.Providers = append(e.Providers, p)
		}
		if bestIdx >= 0 {
			e.Chosen = providerNameForURL(c.baseURLs[bestIdx])
		}
		trace.record(e)
	}

	if bestIdx >= 0 {
		return outs[bestIdx].dr, nil
	}
	errs := make([]error, 0, len(outs))
	for _, o := range outs {
		if o.err != nil {
			errs = append(errs, o.err)
		}
	}
	return nil, errors.Join(errs...)
}

// concatTXTSegments takes the raw "data" value from a DoH TXT answer
// (which for long records is often multiple quoted character-strings in
// presentation form, e.g. "v=DKIM1;...part1" "part2...") and returns the
// single properly concatenated string per RFC 1035 §3.3.14 and RFC 7208 §3.3.
// Adjacent strings are joined with no separator or added whitespace.
// If the data has no quotes (some providers return decoded), we fall back to
// trimming outer quotes while preserving internal spaces (for SPF/DMARC etc.).
func concatTXTSegments(data string) string {
	data = strings.TrimSpace(data)
	if data == "" {
		return ""
	}
	// No quote chars present: treat as (mostly) already decoded single value.
	// Preserve internal spaces; only strip any surrounding quotes like before.
	if !strings.Contains(data, `"`) {
		return strings.Trim(data, `"`)
	}
	// Has quotes: extract content strictly between "..." pairs and concatenate.
	var b strings.Builder
	i := 0
	for i < len(data) {
		if data[i] == '"' {
			i++
			start := i
			for i < len(data) && data[i] != '"' {
				i++
			}
			b.WriteString(data[start:i])
			if i < len(data) && data[i] == '"' {
				i++
			}
			// Skip whitespace that separates this segment from the next quoted one
			for i < len(data) && (data[i] == ' ' || data[i] == '\t' || data[i] == '\n' || data[i] == '\r') {
				i++
			}
			continue
		}
		// Non-quote char outside a quoted segment (uncommon); copy through
		b.WriteByte(data[i])
		i++
	}
	return b.String()
}

// LookupTXT returns all TXT record strings for the name (type 16).
// Multi-string TXT records (common for long DKIM/SPF keys) are concatenated
// into a single contiguous value with no extra characters (RFC compliant).
// Returns empty slice (no error) when the name exists but has no TXT records.
func (c *DoHClient) LookupTXT(ctx context.Context, name string) ([]string, error) {
	txts, _, err := c.lookupTXTFollow(ctx, strings.TrimSuffix(name, "."), 0)
	return txts, err
}

// LookupTXTMeta returns TXT RDATA and the DNS RCODE from the DoH response.
// RCODE: 0=NOERROR, 3=NXDOMAIN, -1 on transport error / unavailable.
// CNAME chains are followed for the TXT payload; the returned rcode is from the
// leaf response that produced the final answer (or the NXDOMAIN hop).
func (c *DoHClient) LookupTXTMeta(ctx context.Context, name string) ([]string, int, error) {
	return c.lookupTXTFollow(ctx, strings.TrimSuffix(name, "."), 0)
}

const maxTXTCNAMEDepth = 5

func (c *DoHClient) lookupTXTFollow(ctx context.Context, name string, depth int) ([]string, int, error) {
	if depth > maxTXTCNAMEDepth {
		return nil, -1, fmt.Errorf("txt cname depth exceeded")
	}
	dr, err := c.doQuery(ctx, name, 16)
	if err != nil {
		return nil, -1, err
	}
	if dr.Status == 3 { // NXDOMAIN
		return nil, 3, nil
	}
	var out []string
	var cnameTarget string
	for _, a := range dr.Answer {
		switch a.Type {
		case 16:
			d := concatTXTSegments(a.Data)
			if d != "" {
				out = append(out, d)
			}
		case 5:
			if cnameTarget == "" {
				cnameTarget = strings.TrimSuffix(strings.TrimSpace(a.Data), ".")
			}
		}
	}
	if len(out) > 0 {
		return out, dr.Status, nil
	}
	if cnameTarget != "" && !strings.EqualFold(cnameTarget, name) {
		return c.lookupTXTFollow(ctx, cnameTarget, depth+1)
	}
	return nil, dr.Status, nil
}

// LookupMX returns MX records for the name (type 15).
// Data format from DoH is usually "10 mail.example.com." (preference + host).
func (c *DoHClient) LookupMX(ctx context.Context, name string) ([]report.MXRecord, error) {
	dr, err := c.doQuery(ctx, name, 15)
	if err != nil {
		return nil, err
	}
	if dr.Status == 3 {
		return nil, nil
	}
	var out []report.MXRecord
	for _, a := range dr.Answer {
		if a.Type == 15 {
			// Parse "pref host." or "pref host"
			fields := strings.Fields(a.Data)
			if len(fields) >= 2 {
				var pref uint16
				_, _ = fmt.Sscanf(fields[0], "%d", &pref)
				host := rfc7505.NormalizeExchange(fields[1])
				out = append(out, report.MXRecord{Pref: pref, Host: host})
			}
		}
	}
	return out, nil
}

// LookupRRWithMeta performs a generic query and returns RRs plus DoH AD/Status metadata.
func (c *DoHClient) LookupRRWithMeta(ctx context.Context, name string, qtype uint16) (QueryResult, error) {
	dr, err := c.doQuery(ctx, name, qtype)
	if err != nil {
		return QueryResult{}, err
	}
	if dr.Status == 3 {
		return QueryResult{Status: dr.Status}, nil
	}
	var out []RR
	for _, a := range dr.Answer {
		// Answer type already filtered against qtype (uint16); use qtype to avoid int→uint16 cast noise.
		if a.Type != int(qtype) {
			continue
		}
		var data string
		if qtype == 16 {
			data = concatTXTSegments(a.Data)
		} else {
			data = strings.Trim(a.Data, `"`)
		}
		out = append(out, RR{
			Name: a.Name,
			Type: qtype,
			Data: data,
			TTL:  a.TTL,
		})
	}
	return QueryResult{RRs: out, AD: dr.AD, Status: dr.Status}, nil
}

// LookupRR performs a generic query and returns raw RR data for the requested type.
// Useful for DS (43), TLSA (52), DNSKEY, etc.
// TXT-like data is concatenated for multi-string records.
func (c *DoHClient) LookupRR(ctx context.Context, name string, qtype uint16) ([]RR, error) {
	qr, err := c.LookupRRWithMeta(ctx, name, qtype)
	return qr.RRs, err
}

// LookupNS returns NS records (nameservers) for the name (type 2).
func (c *DoHClient) LookupNS(ctx context.Context, name string) ([]string, error) {
	dr, err := c.doQuery(ctx, name, 2)
	if err != nil {
		return nil, err
	}
	if dr.Status == 3 {
		return nil, nil
	}
	var out []string
	for _, a := range dr.Answer {
		if a.Type == 2 {
			host := strings.TrimSuffix(strings.Trim(a.Data, `"`), ".")
			if host != "" {
				out = append(out, host)
			}
		}
	}
	return out, nil
}

// --- Outbound hardening: early gating, private-range guards, observability ---

// Apex scan targets only (no underscore labels); stricter than raw DNS names to limit query amplification.
var domainLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// RFC 7208 mechanism targets may use underscore labels (_spf.google.com).
var spfMechanismLabelRE = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

// Apex shape gate before any DNS/HTTPS work (not a full IDNA validator; punycode preferred).
func isValidDomainShape(d string) bool {
	d = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
	if d == "" || len(d) > 253 || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") || strings.Contains(d, "..") {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || !domainLabelRE.MatchString(l) {
			return false
		}
	}
	return true
}

func IsValidDomainShape(d string) bool { return isValidDomainShape(d) }

// RFC 7208 domain-spec in include/exists/redirect/exp (allows _ labels and §8 macros).
func isValidSPFMechanismDomain(d string) bool {
	d = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
	if d == "" || len(d) > 253 || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") || strings.Contains(d, "..") {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 1 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return false
		}
		if strings.Contains(l, "%{") {
			if !validSPFMacroLabel(l) {
				return false
			}
			continue
		}
		if !spfMechanismLabelRE.MatchString(l) {
			return false
		}
	}
	return true
}

// validSPFMacroLabel accepts a single domain-spec label that may contain RFC 7208 macros.
func validSPFMacroLabel(label string) bool {
	for i := 0; i < len(label); {
		switch label[i] {
		case '%':
			if i+2 >= len(label) || label[i+1] != '{' {
				return false
			}
			j := i + 2
			for j < len(label) && label[j] != '}' {
				c := label[j]
				if !((c >= 'a' && c <= 'z') || c == '-' || (c >= '0' && c <= '9')) {
					return false
				}
				j++
			}
			if j >= len(label) || label[j] != '}' {
				return false
			}
			i = j + 1
		default:
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				return false
			}
			i++
		}
	}
	return len(label) > 0
}

func IsValidSPFMechanismDomain(d string) bool { return isValidSPFMechanismDomain(d) }

// Optional SECLENS_DOMAIN_ALLOWLIST (comma-separated); empty = unrestricted (research default).
var domainAllowlist = loadDomainAllowlist()

func loadDomainAllowlist() []string {
	s := os.Getenv("SECLENS_DOMAIN_ALLOWLIST")
	if s == "" {
		return nil
	}
	var list []string
	for _, part := range strings.Split(s, ",") {
		p := strings.ToLower(strings.TrimSpace(part))
		if p != "" {
			list = append(list, p)
		}
	}
	return list
}

func isAllowedDomain(d string) bool {
	if len(domainAllowlist) == 0 {
		return true
	}
	d = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
	for _, a := range domainAllowlist {
		if d == a || strings.HasSuffix(d, "."+a) {
			return true
		}
	}
	return false
}

func IsAllowedDomain(d string) bool { return isAllowedDomain(d) }

// Bulk pre-filter: keep domains with any NS/MX/A/AAAA/TXT signal (fail closed on probe errors).
func isResolvable(ctx context.Context, domain string) bool {
	d := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
	if d == "" || !isValidDomainShape(d) {
		return false
	}

	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if ns, err := DefaultClient.LookupNS(pctx, d); err == nil && len(ns) > 0 {
		return true
	}
	if mx, err := DefaultClient.LookupMX(pctx, d); err == nil && len(mx) > 0 {
		return true
	}
	if rrs, err := DefaultClient.LookupRR(pctx, d, 1); err == nil && len(rrs) > 0 {
		return true
	}
	if rrs, err := DefaultClient.LookupRR(pctx, d, 28); err == nil && len(rrs) > 0 {
		return true
	}
	if txt, err := DefaultClient.LookupTXT(pctx, d); err == nil && len(txt) > 0 {
		return true
	}
	return false
}

func IsResolvable(ctx context.Context, domain string) bool {
	return isResolvable(ctx, domain)
}

// SSRF guard ranges for direct HTTPS (MTA-STS policy fetch), not for DoH.
var privateCIDRs []*net.IPNet

func init() {
	for _, c := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4", "240.0.0.0/4",
		"::1/128", "fe80::/10", "fc00::/7", "ff00::/8",
	} {
		if _, n, err := net.ParseCIDR(c); err == nil {
			privateCIDRs = append(privateCIDRs, n)
		}
	}
}

// isPrivateOrLocalIP returns true for any IP in the private/local/special ranges above.
func isPrivateOrLocalIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	for _, n := range privateCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// A/AAAA via DoH only (SSRF guard must not use the OS resolver).
func (c *DoHClient) resolveHostIPs(ctx context.Context, host string) ([]net.IP, error) {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return nil, errors.New("empty host")
	}
	var ips []net.IP
	// A (type 1)
	if rrs, err := c.LookupRR(ctx, host, 1); err == nil {
		for _, rr := range rrs {
			if ip := net.ParseIP(strings.TrimSpace(rr.Data)); ip != nil && ip.To4() != nil {
				ips = append(ips, ip)
			}
		}
	}
	// AAAA (type 28)
	if rrs, err := c.LookupRR(ctx, host, 28); err == nil {
		for _, rr := range rrs {
			if ip := net.ParseIP(strings.TrimSpace(rr.Data)); ip != nil && ip.To4() == nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips, nil
}

// Fail-closed: empty or all-private ⇒ do not dial / do not use host for DANE feed.
func hasPublicIP(ips []net.IP) bool {
	return len(publicIPs(ips)) > 0
}

func publicIPs(ips []net.IP) []net.IP {
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if !isPrivateOrLocalIP(ip) {
			out = append(out, ip)
		}
	}
	return out
}

// SECLENS_LOG_QUERIES enables sanitized DoH query logs (off when unset/0/false).
var logDNSQueries bool

func init() {
	if v := os.Getenv("SECLENS_LOG_QUERIES"); v != "" && v != "0" && strings.ToLower(v) != "false" {
		logDNSQueries = true
	}
}

// Default multi-provider pool (fan-out; best answer wins — Top-1M measurement parity).
var DefaultClient = NewDoHClient("cloudflare,google")

// SetDefaultResolver sets the global DoH pool (CLI --resolver; comma-separated).
func SetDefaultResolver(provider string) {
	DefaultClient = NewDoHClient(provider)
}
