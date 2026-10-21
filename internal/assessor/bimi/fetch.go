package bimi

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxLogoBytes = 32 * 1024
	maxCertBytes = 256 * 1024
	fetchTimeout = 8 * time.Second
)

func fetchEvidence(ctx context.Context, deps Deps, rawURL string, limit int) (body []byte, contentType string, skipped bool, err error) {
	if rawURL == "" {
		return nil, "", false, nil
	}
	if deps.SkipFetch {
		return nil, "", true, nil
	}
	if deps.Fetcher != nil {
		body, contentType, err = deps.Fetcher.Fetch(ctx, rawURL, limit)
		return body, contentType, false, err
	}
	body, contentType, err = fetchURL(ctx, deps, rawURL, limit)
	return body, contentType, false, err
}

func fetchURL(ctx context.Context, deps Deps, rawURL string, limit int) ([]byte, string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, "", fmt.Errorf("refusing non-https URL")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if ip := net.ParseIP(host); ip != nil {
		if deps.IPGuard != nil && deps.IPGuard.IsPrivateOrLocal(ip) {
			return nil, "", fmt.Errorf("refusing private address %s", ip)
		}
	} else if deps.Gate != nil && !deps.Gate.ValidShape(host) {
		return nil, "", fmt.Errorf("host %s failed domain shape check", host)
	}
	if port := u.Port(); port != "" && port != "443" {
		return nil, "", fmt.Errorf("refusing non-443 port %s", port)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "seclens/0.1 (BIMI evidence fetch; https://seclens.one/research/2026-10-email-security-top1m/)")

	client := &http.Client{
		Timeout: fetchTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: evidenceTransport(deps, host),
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if resp.StatusCode != http.StatusOK {
		return nil, ct, fmt.Errorf("http status %d", resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, int64(limit)+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return nil, ct, err
	}
	if len(buf) > limit {
		return nil, ct, fmt.Errorf("body exceeds %d bytes", limit)
	}
	return buf, ct, nil
}

// evidenceTransport dials only the guarded address for host, on port 443.
// Same private-range rule as the MTA-STS policy fetch, without pinning the host
// to mta-sts.<domain>.
func evidenceTransport(deps Deps, host string) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialHost, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if port != "443" {
				return nil, fmt.Errorf("bimi dial: refused non-443 port %s", port)
			}
			switch network {
			case "tcp", "tcp4", "tcp6":
			default:
				return nil, fmt.Errorf("bimi dial: refused network %q", network)
			}
			dialHost = strings.TrimSuffix(strings.ToLower(dialHost), ".")
			target, err := dialTarget(ctx, deps, host, dialHost)
			if err != nil {
				return nil, err
			}
			if deps.IPGuard != nil && deps.IPGuard.IsPrivateOrLocal(target) {
				return nil, fmt.Errorf("bimi dial: refused private address %s", target)
			}
			dialer := &net.Dialer{Timeout: 5 * time.Second}
			return dialer.DialContext(ctx, network, net.JoinHostPort(target.String(), port))
		},
	}
}

func dialTarget(ctx context.Context, deps Deps, wantHost, dialHost string) (net.IP, error) {
	if ip := net.ParseIP(dialHost); ip != nil {
		return ip, nil
	}
	if dialHost != wantHost {
		return nil, fmt.Errorf("bimi dial: unexpected host %q", dialHost)
	}
	if deps.DNS == nil {
		return nil, fmt.Errorf("bimi dial: no resolver")
	}
	ips, err := deps.DNS.ResolveHostIPs(ctx, wantHost)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", wantHost, err)
	}
	if deps.IPGuard == nil {
		if len(ips) == 0 {
			return nil, fmt.Errorf("resolve %s: no addresses", wantHost)
		}
		return ips[0], nil
	}
	allowed := deps.IPGuard.PublicIPs(ips)
	if len(allowed) == 0 {
		return nil, fmt.Errorf("resolve %s: no public addresses", wantHost)
	}
	return allowed[0], nil
}
