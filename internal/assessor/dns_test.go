package assessor

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"seclens/internal/report"
)

func TestHasPublicIP(t *testing.T) {
	tests := []struct {
		name string
		ips  []net.IP
		want bool
	}{
		{
			name: "empty fail-closed",
			ips:  nil,
			want: false,
		},
		{
			name: "private only",
			ips: []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("192.168.1.1"),
				net.ParseIP("127.0.0.1"),
			},
			want: false,
		},
		{
			name: "public mixed with private",
			ips: []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("8.8.8.8"),
			},
			want: true,
		},
		{
			name: "public only",
			ips: []net.IP{
				net.ParseIP("1.1.1.1"),
				net.ParseIP("2001:4860:4860::8888"),
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasPublicIP(tt.ips); got != tt.want {
				t.Errorf("hasPublicIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicIPs(t *testing.T) {
	public := net.ParseIP("93.184.216.34")
	blocked := []string{
		"127.0.0.1",
		"fe80::1",
		"::ffff:169.254.169.254",
		"::ffff:10.0.0.1",
		"100.64.0.1",
		"fd00::1",
		"::1",
		"::",
		"169.254.169.254",
		"64:ff9b::1",
		"64:ff9b:1::1",
		"2002::1",
		"fec0::1",
		"224.0.0.1",
		"ff02::1",
		"0.0.0.0",
	}
	for _, s := range blocked {
		t.Run(s, func(t *testing.T) {
			ip := net.ParseIP(s)
			if ip == nil {
				t.Fatalf("parse %q", s)
			}
			if !isPrivateOrLocalIP(ip) {
				t.Fatalf("isPrivateOrLocalIP(%s) = false, want true", s)
			}
			got := publicIPs([]net.IP{ip, public})
			if len(got) != 1 || !got[0].Equal(public) {
				t.Fatalf("publicIPs(%s + public) = %v, want only %v", s, got, public)
			}
		})
	}
	t.Run("nil", func(t *testing.T) {
		if !isPrivateOrLocalIP(nil) {
			t.Fatal("nil IP must be blocked")
		}
	})
	t.Run("public v4 and v6 kept", func(t *testing.T) {
		got := publicIPs([]net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2001:4860:4860::8888")})
		if len(got) != 2 {
			t.Fatalf("got %v", got)
		}
	})
}

func TestDomainGuards(t *testing.T) {
	guardTests := []struct {
		name        string
		domain      string
		wantValid   bool
		wantAllowed bool
	}{
		{"valid two labels", "example.com", true, true},
		{"valid with sub", "sub.mail.example.com", true, true},
		{"valid hyphen", "ex-ample.com", true, true},
		{"valid trailing dot trimmed", "example.com.", true, true},
		{"single label", "com", false, true},
		{"empty", "", false, true},
		{"leading dot", ".example.com", false, true},
		{"double dot", "ex..com", false, true},
		{"underscore forbidden in label", "ex_ample.com", false, true},
		{"label too long >63", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", false, true},
		{"starts with hyphen", "-example.com", false, true},
		{"ends with hyphen", "example-.com", false, true},
		{"label with invalid char", "ex!ample.com", false, true},
		{"numeric label ok", "123.com", true, true},
		{"dotted numeric labels", "1.2.3.4", true, true},
	}
	for _, tt := range guardTests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidDomainShape(tt.domain); got != tt.wantValid {
				t.Errorf("isValidDomainShape(%q) = %v, want %v", tt.domain, got, tt.wantValid)
			}
			if got := isAllowedDomain(tt.domain); got != tt.wantAllowed {
				t.Errorf("isAllowedDomain(%q) = %v, want %v", tt.domain, got, tt.wantAllowed)
			}
		})
	}

	origList := domainAllowlist
	defer func() { domainAllowlist = origList }()
	domainAllowlist = []string{"example.com", "allowed.org"}
	if !isAllowedDomain("foo.example.com") {
		t.Error("suffix match under allowlist should allow")
	}
	if !isAllowedDomain("example.com") {
		t.Error("exact match under allowlist should allow")
	}
	if isAllowedDomain("evil.com") {
		t.Error("non-matching domain must be denied when allowlist is set")
	}
	if !isValidDomainShape("evil.com") {
		t.Error("evil.com is valid shape even if not allowed")
	}
}

func TestIsValidSPFMechanismDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   bool
	}{
		{"_spf.google.com", true},
		{"spf.mailgun.org", true},
		{"example.com", true},
		{"", false},
		{"_bad..host.com", false},
		{"%{ir}.%{v}.%{d}.spf.has.pphosted.com", true},
		{"%{d}.55.spf-protect.agari.com", true},
	}
	for _, tt := range tests {
		if got := isValidSPFMechanismDomain(tt.domain); got != tt.want {
			t.Errorf("isValidSPFMechanismDomain(%q)=%v want %v", tt.domain, got, tt.want)
		}
	}
	if isValidDomainShape("_spf.google.com") {
		t.Error("apex gating must still reject underscore labels")
	}
}

func TestNewDoHClientNoRedirectNoEnvProxy(t *testing.T) {
	c := NewDoHClient("cloudflare")
	if c.HTTPClient == nil {
		t.Fatal("HTTPClient is nil")
	}
	if c.HTTPClient.Timeout != 6*time.Second {
		t.Fatalf("Timeout = %v, want 6s", c.HTTPClient.Timeout)
	}
	if c.HTTPClient.CheckRedirect == nil {
		t.Fatal("CheckRedirect must be set")
	}
	err := c.HTTPClient.CheckRedirect(&http.Request{}, nil)
	if !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect = %v, want ErrUseLastResponse", err)
	}
	tr, ok := c.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type %T, want *http.Transport", c.HTTPClient.Transport)
	}
	if tr.Proxy != nil {
		t.Fatal("Proxy must be unset so HTTP_PROXY is not honored")
	}
	if tr.MaxIdleConns != 1024 || tr.MaxIdleConnsPerHost != dohMaxConnsPerHost || tr.MaxConnsPerHost != dohMaxConnsPerHost {
		t.Fatalf("conn knobs: MaxIdleConns=%d MaxIdleConnsPerHost=%d MaxConnsPerHost=%d",
			tr.MaxIdleConns, tr.MaxIdleConnsPerHost, tr.MaxConnsPerHost)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.ClientSessionCache == nil {
		t.Fatal("TLS ClientSessionCache must be set")
	}
	if tr.DialContext == nil {
		t.Fatal("DialContext must be set")
	}
	if tr.IdleConnTimeout != 90*time.Second || tr.TLSHandshakeTimeout != 10*time.Second || tr.ExpectContinueTimeout != 1*time.Second {
		t.Fatalf("timeout knobs: idle=%v tls=%v expect=%v", tr.IdleConnTimeout, tr.TLSHandshakeTimeout, tr.ExpectContinueTimeout)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 must stay true")
	}
}

func TestMxFromDoH(t *testing.T) {
	t.Run("nxdomain", func(t *testing.T) {
		got, err := mxFromDoH(3, "10 mail.example.com.")
		if err != nil || got != nil {
			t.Fatalf("got (%v, %v) want (nil, nil)", got, err)
		}
	})
	t.Run("nodata", func(t *testing.T) {
		got, err := mxFromDoH(0)
		if err != nil || got != nil {
			t.Fatalf("got (%v, %v) want (nil, nil)", got, err)
		}
	})
	t.Run("noerror answers", func(t *testing.T) {
		got, err := mxFromDoH(0, "10 mail.example.com.", "20 backup.example.com.")
		if err != nil {
			t.Fatal(err)
		}
		want := []report.MXRecord{{Pref: 10, Host: "mail.example.com"}, {Pref: 20, Host: "backup.example.com"}}
		if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("got %v want %v", got, want)
		}
	})
	t.Run("servfail", func(t *testing.T) {
		_, err := mxFromDoH(2)
		if err == nil {
			t.Fatal("SERVFAIL must be an error, not empty MX")
		}
	})
	t.Run("refused", func(t *testing.T) {
		_, err := mxFromDoH(5, "10 mail.example.com.")
		if err == nil {
			t.Fatal("REFUSED must be an error even if answers are present")
		}
	})
}

const mxAnswerBody = `{"Status":0,"AD":false,"Answer":[{"name":"example.com.","type":15,"TTL":30,"data":"10 mail.example.com."}]}`

func TestDoHHedgeSkipsSecondWhenFirstHasAnswers(t *testing.T) {
	var secondHits atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = io.WriteString(w, mxAnswerBody)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = io.WriteString(w, mxAnswerBody)
	}))
	defer second.Close()

	c := NewDoHClient("cloudflare")
	c.baseURLs = []string{first.URL, second.URL}
	c.retryCount = 0
	mx, err := c.LookupMX(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(mx) != 1 || mx[0].Host != "mail.example.com" {
		t.Fatalf("mx=%v", mx)
	}
	if secondHits.Load() != 0 {
		t.Fatalf("hedge started second provider, hits=%d", secondHits.Load())
	}
}

func TestDoHHedgeUsesSecondWhenFirstHangs(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = io.WriteString(w, mxAnswerBody)
	}))
	defer second.Close()

	c := NewDoHClient("cloudflare")
	c.baseURLs = []string{first.URL, second.URL}
	c.retryCount = 0
	start := time.Now()
	mx, err := c.LookupMX(context.Background(), "example.com")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if len(mx) != 1 {
		t.Fatalf("mx=%v", mx)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("hedge too slow: %s", elapsed)
	}
}

func TestSetDefaultResolverSamePoolKeepsClient(t *testing.T) {
	defaultResolverMu.Lock()
	oldClient := DefaultClient
	oldKey := defaultResolverKey
	defaultResolverMu.Unlock()
	t.Cleanup(func() {
		defaultResolverMu.Lock()
		DefaultClient = oldClient
		defaultResolverKey = oldKey
		defaultResolverMu.Unlock()
	})

	SetDefaultResolver("cloudflare,google")
	first := DefaultClient
	SetDefaultResolver("cloudflare,google")
	if DefaultClient != first {
		t.Fatal("same pool must not allocate a new DoH client")
	}
	SetDefaultResolver("quad9")
	if DefaultClient == first {
		t.Fatal("different pool must allocate a new DoH client")
	}
}
