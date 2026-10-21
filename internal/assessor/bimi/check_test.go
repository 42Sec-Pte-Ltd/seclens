package bimi

import (
	"context"
	"errors"
	"net"
	"testing"

	"seclens/internal/report"
)

type mapDNS struct {
	txt map[string][]string
	err map[string]error
	ips map[string][]net.IP
	saw []string
}

func (m *mapDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	m.saw = append(m.saw, name)
	if m.err != nil {
		if err := m.err[name]; err != nil {
			return nil, err
		}
	}
	if m.txt == nil {
		return nil, nil
	}
	return m.txt[name], nil
}

func (m *mapDNS) ResolveHostIPs(_ context.Context, host string) ([]net.IP, error) {
	if m.ips == nil {
		return nil, nil
	}
	return m.ips[host], nil
}

type allowGate struct{}

func (allowGate) ValidShape(string) bool { return true }
func (allowGate) Allowed(string) bool    { return true }

type denyGate struct{}

func (denyGate) ValidShape(string) bool { return false }
func (denyGate) Allowed(string) bool    { return false }

type stubFetch struct {
	body []byte
	ct   string
	err  error
	urls []string
}

func (s *stubFetch) Fetch(_ context.Context, rawURL string, _ int) ([]byte, string, error) {
	s.urls = append(s.urls, rawURL)
	return s.body, s.ct, s.err
}

func strongDMARC() *report.DMARCResult {
	return &report.DMARCResult{Present: true, SyntaxOK: true, Policy: "reject", Pct: 100}
}

func TestCheckFallbackAndDMARC(t *testing.T) {
	t.Parallel()
	logo := "v=BIMI1; l=https://cdn.example/logo.svg; a=https://cdn.example/vmc.pem"

	t.Run("author record no org bimi lookup", func(t *testing.T) {
		dns := &mapDNS{txt: map[string][]string{
			"default._bimi.mail.example.com": {logo},
			"default._bimi.example.com":      {"v=BIMI1; l=;"},
			"_dmarc.example.com":             {"v=DMARC1; p=reject; pct=100"},
		}}
		got := Check(context.Background(), Request{Domain: "mail.example.com", DMARC: strongDMARC()}, Deps{
			DNS: dns, Gate: allowGate{}, SkipFetch: true,
		})
		if got.Status != "present" || got.DNSName != "default._bimi.mail.example.com" {
			t.Fatalf("status=%s name=%s findings=%v", got.Status, got.DNSName, got.Findings)
		}
		if len(got.Queried) != 1 || got.Queried[0] != "default._bimi.mail.example.com" {
			t.Fatalf("queried %v", got.Queried)
		}
		if !containsName(dns.saw, "_dmarc.example.com") {
			t.Fatalf("org DMARC was not queried: %v", dns.saw)
		}
		if containsName(dns.saw, "default._bimi.example.com") {
			t.Fatalf("org BIMI queried despite author record: %v", dns.saw)
		}
		for _, f := range got.Findings {
			if f == "logo fetch skipped" || f == "certificate fetch skipped" {
				continue
			}
			t.Fatalf("unexpected finding %q in %v", f, got.Findings)
		}
	})

	t.Run("fallback to org", func(t *testing.T) {
		dns := &mapDNS{txt: map[string][]string{
			"default._bimi.example.com": {logo},
			"_dmarc.example.com":        {"v=DMARC1; p=quarantine"},
		}}
		got := Check(context.Background(), Request{Domain: "mail.example.com", DMARC: strongDMARC()}, Deps{
			DNS: dns, Gate: allowGate{}, SkipFetch: true,
		})
		if got.Status != "present" || got.DNSName != "default._bimi.example.com" {
			t.Fatalf("status=%s name=%s msg=%s findings=%v", got.Status, got.DNSName, got.Message, got.Findings)
		}
		if len(got.Queried) != 2 || got.Queried[0] != "default._bimi.mail.example.com" || got.Queried[1] != "default._bimi.example.com" {
			t.Fatalf("queried %v", got.Queried)
		}
	})

	t.Run("multiple author records do not fall back", func(t *testing.T) {
		dns := &mapDNS{txt: map[string][]string{
			"default._bimi.mail.example.com": {logo, "v=BIMI1; l=;"},
			"default._bimi.example.com":      {logo},
		}}
		got := Check(context.Background(), Request{Domain: "mail.example.com", DMARC: strongDMARC()}, Deps{
			DNS: dns, Gate: allowGate{}, SkipFetch: true,
		})
		if got.Status != "invalid" {
			t.Fatalf("status=%s", got.Status)
		}
		want := "multiple BIMI records at default._bimi.mail.example.com"
		if len(got.Findings) == 0 || got.Findings[0] != want {
			t.Fatalf("findings %v", got.Findings)
		}
		if containsName(dns.saw, "default._bimi.example.com") {
			t.Fatalf("fell back after multiple records: %v", dns.saw)
		}
	})

	t.Run("bad version does not fall back", func(t *testing.T) {
		dns := &mapDNS{txt: map[string][]string{
			"default._bimi.mail.example.com": {"v=BIMI2; l=https://cdn.example/a.svg"},
			"default._bimi.example.com":      {logo},
		}}
		got := Check(context.Background(), Request{Domain: "mail.example.com", DMARC: strongDMARC()}, Deps{
			DNS: dns, Gate: allowGate{},
		})
		if got.Status != "invalid" || got.Findings[0] != "v=BIMI1 must be the first tag" {
			t.Fatalf("status=%s findings=%v", got.Status, got.Findings)
		}
		if containsName(dns.saw, "default._bimi.example.com") {
			t.Fatalf("fell back: %v", dns.saw)
		}
	})

	t.Run("absent apex", func(t *testing.T) {
		dns := &mapDNS{}
		got := Check(context.Background(), Request{Domain: "example.com", DMARC: strongDMARC()}, Deps{
			DNS: dns, Gate: allowGate{},
		})
		if got.Status != "absent" || got.DNSName != "" || got.Message != "No BIMI record (default._bimi)" {
			t.Fatalf("%+v", got)
		}
		if len(got.Queried) != 1 || got.Queried[0] != "default._bimi.example.com" {
			t.Fatalf("queried %v", got.Queried)
		}
	})

	t.Run("declination", func(t *testing.T) {
		dns := &mapDNS{txt: map[string][]string{
			"default._bimi.example.com": {"v=BIMI1; l=; a=;"},
		}}
		got := Check(context.Background(), Request{Domain: "example.com", DMARC: strongDMARC()}, Deps{
			DNS: dns, Gate: allowGate{},
		})
		if got.Status != "declined" || !got.Declined || got.DNSName != "default._bimi.example.com" {
			t.Fatalf("%+v", got)
		}
	})

	t.Run("lookup error", func(t *testing.T) {
		dns := &mapDNS{err: map[string]error{"default._bimi.example.com": errors.New("timeout")}}
		got := Check(context.Background(), Request{Domain: "example.com", DMARC: strongDMARC()}, Deps{
			DNS: dns, Gate: allowGate{},
		})
		if got.Status != "invalid" || got.Findings[0] != "TXT lookup default._bimi.example.com: timeout" {
			t.Fatalf("%+v", got)
		}
	})

	t.Run("co.uk fallback name", func(t *testing.T) {
		dns := &mapDNS{txt: map[string][]string{
			"default._bimi.example.co.uk": {"v=BIMI1; l=;"},
		}}
		got := Check(context.Background(), Request{Domain: "mail.example.co.uk", DMARC: strongDMARC()}, Deps{
			DNS: dns, Gate: allowGate{},
		})
		if got.Status != "declined" || got.DNSName != "default._bimi.example.co.uk" {
			t.Fatalf("status=%s name=%s queried=%v", got.Status, got.DNSName, got.Queried)
		}
	})

	t.Run("gated", func(t *testing.T) {
		got := Check(context.Background(), Request{Domain: "example.com"}, Deps{Gate: denyGate{}})
		if got.Status != "invalid" || got.Message != "skipped (input gated)" {
			t.Fatalf("%+v", got)
		}
	})

	t.Run("fetch error is a finding", func(t *testing.T) {
		dns := &mapDNS{txt: map[string][]string{
			"default._bimi.example.com": {logo},
		}}
		fetch := &stubFetch{err: errors.New("connection refused")}
		got := Check(context.Background(), Request{Domain: "example.com", DMARC: strongDMARC()}, Deps{
			DNS: dns, Gate: allowGate{}, Fetcher: fetch,
		})
		if got.Status != "present" {
			t.Fatalf("status=%s findings=%v", got.Status, got.Findings)
		}
		if len(fetch.urls) != 2 || fetch.urls[0] != "https://cdn.example/logo.svg" || fetch.urls[1] != "https://cdn.example/vmc.pem" {
			t.Fatalf("urls %v", fetch.urls)
		}
		if got.Logo == nil || got.Logo.Error != "connection refused" || got.Certificate == nil || got.Certificate.Error != "connection refused" {
			t.Fatalf("logo=%+v cert=%+v", got.Logo, got.Certificate)
		}
	})

	t.Run("subdomain org dmarc from dns", func(t *testing.T) {
		dns := &mapDNS{txt: map[string][]string{
			"default._bimi.mail.example.com": {"v=BIMI1; l=;"},
			"_dmarc.example.com":             {"v=DMARC1; p=none"},
		}}
		got := Check(context.Background(), Request{Domain: "mail.example.com", DMARC: strongDMARC()}, Deps{
			DNS: dns, Gate: allowGate{},
		})
		found := false
		for _, f := range got.Findings {
			if f == "organizational domain example.com DMARC p=none is not quarantine or reject" {
				found = true
			}
		}
		if !found {
			t.Fatalf("findings %v", got.Findings)
		}
	})
}

func TestDialTargetRejectsPrivate(t *testing.T) {
	t.Parallel()
	dns := &mapDNS{ips: map[string][]net.IP{"cdn.example": {net.ParseIP("10.1.2.3")}}}
	_, err := dialTarget(context.Background(), Deps{DNS: dns, IPGuard: localGuard{}}, "cdn.example", "cdn.example")
	if err == nil || err.Error() != "resolve cdn.example: no public addresses" {
		t.Fatalf("err=%v", err)
	}
}

type localGuard struct{}

func (localGuard) IsPrivateOrLocal(ip net.IP) bool {
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback())
}

func (localGuard) PublicIPs(ips []net.IP) []net.IP {
	var out []net.IP
	for _, ip := range ips {
		if ip != nil && !ip.IsPrivate() && !ip.IsLoopback() {
			out = append(out, ip)
		}
	}
	return out
}

func containsName(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}
