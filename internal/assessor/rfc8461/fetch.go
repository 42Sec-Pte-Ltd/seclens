package rfc8461

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func strictHTTPClient(timeout time.Duration, transport http.RoundTripper) *http.Client {
	c := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if transport != nil {
		c.Transport = transport
	}
	return c
}

func resolvePolicyHostIPs(ctx context.Context, deps Deps, policyDomain string) ([]net.IP, error) {
	policyDomain = strings.TrimSuffix(strings.TrimSpace(policyDomain), ".")
	if policyDomain == "" {
		return nil, fmt.Errorf("mta-sts policy host: empty name")
	}

	ips, _ := deps.DNS.ResolveHostIPs(ctx, policyDomain)
	if allowed := deps.IPGuard.PublicIPs(ips); len(allowed) > 0 {
		return allowed, nil
	}

	resolver := net.Resolver{}
	addrs, err := resolver.LookupIPAddr(ctx, policyDomain)
	if err != nil {
		return nil, fmt.Errorf("mta-sts policy host %s: resolve: %w", policyDomain, err)
	}
	fallback := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		fallback = append(fallback, a.IP)
	}
	return connectGuard(deps, fallback, policyDomain)
}

func connectGuard(deps Deps, ips []net.IP, policyDomain string) ([]net.IP, error) {
	allowed := deps.IPGuard.PublicIPs(ips)
	if len(allowed) > 0 {
		return allowed, nil
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("mta-sts policy host %s: no addresses resolved (outbound guard)", policyDomain)
	}
	return nil, fmt.Errorf("mta-sts policy host %s resolves only to private/local addresses (outbound guard)", policyDomain)
}

func policyTransport(deps Deps, policyDomain string) *http.Transport {
	policyDomain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(policyDomain)), ".")
	return &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			host = strings.TrimSuffix(strings.ToLower(host), ".")

			var target net.IP
			if ip := net.ParseIP(host); ip != nil {
				target = ip
			} else if host == policyDomain {
				allowed, resolveErr := resolvePolicyHostIPs(ctx, deps, policyDomain)
				if resolveErr != nil {
					return nil, resolveErr
				}
				target = allowed[0]
			} else {
				return nil, fmt.Errorf("mta-sts dial: unexpected host %q", host)
			}

			if deps.IPGuard.IsPrivateOrLocal(target) {
				return nil, fmt.Errorf("mta-sts dial: refused private address %s", target)
			}

			dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
			return dialer.DialContext(ctx, network, net.JoinHostPort(target.String(), port))
		},
		ForceAttemptHTTP2: true,
		MaxIdleConns:      10,
		IdleConnTimeout:   90 * time.Second,
	}
}

func resolvePolicyFetch(ctx context.Context, deps Deps, domain string) (policyFetchResult, error) {
	if deps.PolicyFetcher != nil {
		return deps.PolicyFetcher.FetchPolicy(ctx, deps, domain)
	}
	return fetchPolicy(ctx, deps, domain)
}

func fetchPolicy(ctx context.Context, deps Deps, domain string) (policyFetchResult, error) {
	policyDomain := "mta-sts." + strings.TrimSuffix(domain, ".")
	if !deps.Gate.ValidShape(policyDomain) || !deps.Gate.Allowed(domain) {
		return policyFetchResult{}, fmt.Errorf("mta-sts policy domain failed input gating")
	}

	u := &url.URL{
		Scheme: "https",
		Host:   policyDomain,
		Path:   "/.well-known/mta-sts.txt",
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return policyFetchResult{}, err
	}
	req.Header.Set("User-Agent", "seclens/0.1 (+https://github.com/seclens-one/seclens; email-security-assessor)")

	client := strictHTTPClient(8*time.Second, policyTransport(deps, policyDomain))
	resp, err := client.Do(req)
	if err != nil {
		return policyFetchResult{}, fmt.Errorf("policy https fetch: %w", err)
	}
	defer resp.Body.Close()

	result := policyFetchResult{
		contentType: resp.Header.Get("Content-Type"),
		statusCode:  resp.StatusCode,
	}
	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("policy http status %d (must be 200)", resp.StatusCode)
	}
	body, err := readPolicyBody(resp)
	if err != nil {
		return result, err
	}
	result.body = body
	return result, nil
}