package rfc6376

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func containsSelector(sels []string, want string) bool {
	for _, s := range sels {
		if s == want {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestParseDKIMRecord(t *testing.T) {
	tests := []struct {
		raw      string
		version  string
		keyType  string
		flags    string
		hashAlg  string
		hasKey   bool
		syntaxOK bool
	}{
		{
			raw:      "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
			version:  "DKIM1",
			keyType:  "rsa",
			hasKey:   true,
			syntaxOK: true,
		},
		{
			raw:      "v=DKIM1; k=ed25519; t=y; h=sha256; p=abc123",
			version:  "DKIM1",
			keyType:  "ed25519",
			flags:    "y",
			hashAlg:  "sha256",
			hasKey:   true,
			syntaxOK: true,
		},
		{
			raw:      "v=DKIM1; p=",
			version:  "DKIM1",
			keyType:  "rsa",
			hasKey:   false,
			syntaxOK: true,
		},
		{
			raw:      "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5",
			keyType:  "rsa",
			hasKey:   true,
			syntaxOK: true,
		},
		{
			raw:      "v=spf1 -all",
			syntaxOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got := ParseDKIMRecord(tt.raw)
			if got.SyntaxOK != tt.syntaxOK {
				t.Fatalf("SyntaxOK=%v want %v", got.SyntaxOK, tt.syntaxOK)
			}
			if tt.syntaxOK {
				if got.Version != tt.version {
					t.Errorf("Version=%q want %q", got.Version, tt.version)
				}
				if got.KeyType != tt.keyType {
					t.Errorf("KeyType=%q want %q", got.KeyType, tt.keyType)
				}
				if got.Flags != tt.flags {
					t.Errorf("Flags=%q want %q", got.Flags, tt.flags)
				}
				if got.HashAlgos != tt.hashAlg {
					t.Errorf("HashAlgos=%q want %q", got.HashAlgos, tt.hashAlg)
				}
				hasKey := strings.TrimSpace(got.PublicKey) != ""
				if hasKey != tt.hasKey {
					t.Errorf("hasKey=%v want %v (p=%q)", hasKey, tt.hasKey, got.PublicKey)
				}
			}
		})
	}
}

func TestClassifyKeyState(t *testing.T) {
	tests := []struct {
		raw  string
		want KeyState
	}{
		{"v=DKIM1; k=rsa; p=MIIB", KeyStateActive},
		{"v=DKIM1; p=", KeyStateRevoked},
		{"v=DKIM1; t=y; p=abc", KeyStateTest},
		{"v=spf1 -all", KeyStateInvalid},
	}
	for _, tt := range tests {
		got := ClassifyKeyState(ParseDKIMRecord(tt.raw))
		if got != tt.want {
			t.Errorf("ClassifyKeyState(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestIsDKIMTXTRecord(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{"v=DKIM1; k=rsa; p=MIIB", true},
		{"p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5", true},
		{"p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA", true},
		{"v=spf1 -all", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsDKIMTXTRecord(tt.raw); got != tt.want {
			t.Errorf("IsDKIMTXTRecord(%q) = %v, want %v", tt.raw, got, tt.want)
		}
	}
}

func TestProbeWildcard(t *testing.T) {
	ctx := context.Background()
	domain := "wildcard.example"
	deps := Deps{
		DNS: fakeDNS{
			records: map[string][]string{
				canarySelector + "._domainkey." + domain: {"v=DKIM1; p=abc"},
			},
		},
	}
	if !ProbeWildcard(ctx, deps, domain) {
		t.Fatal("expected wildcard detection")
	}

	deps.DNS = fakeDNS{records: map[string][]string{}}
	if ProbeWildcard(ctx, deps, domain) {
		t.Fatal("expected no wildcard")
	}
}

func TestMXHostMatchesRule(t *testing.T) {
	rule := dkimProviderRule{mxKeywords: []string{"aspmx.l.google.com", "googlemail.com"}}
	if !mxHostMatchesRule("aspmx.l.google.com", rule) {
		t.Fatal("expected google MX to match")
	}
	if !mxHostMatchesRule("alt1.aspmx.l.google.com", rule) {
		t.Fatal("expected substring match")
	}
	if mxHostMatchesRule("mail.example.com", rule) {
		t.Fatal("unexpected match")
	}
}

func TestDKIMSelectors_CloudflareRoutingPrioritized(t *testing.T) {
	mxHosts := []string{"route1.mx.cloudflare.net."}
	sels := dkimSelectorsForDomain("example.com", mxHosts)

	hasCFYear := false
	for _, s := range sels {
		if strings.HasPrefix(s, "cf") && strings.HasSuffix(s, "-1") {
			hasCFYear = true
			break
		}
	}
	if !hasCFYear {
		t.Fatalf("expected Cloudflare cf{year}-1 selector in first %d probes, got %v", len(sels), sels)
	}
	if !containsSelector(sels, "cf-bounce") {
		t.Fatalf("expected cf-bounce in probes, got %v", sels[:min(6, len(sels))])
	}
	wantSparkPost := fmt.Sprintf("sparkpostus%d", time.Now().Year())
	if !containsSelector(sels, wantSparkPost) {
		t.Fatalf("expected %q in Cloudflare probes, got %v", wantSparkPost, sels[:min(10, len(sels))])
	}
}

func TestDKIMSelectors_ProtonFromMX(t *testing.T) {
	mxHosts := []string{"mail.protonmail.ch."}
	sels := dkimSelectorsForDomain("example.com", mxHosts)

	for _, want := range []string{"protonmail", "protonmail2", "protonmail3", "pm"} {
		if !containsSelector(sels, want) {
			t.Fatalf("expected %q in proton selectors, got %v", want, sels[:min(8, len(sels))])
		}
	}
}

func TestDKIMSelectors_GoogleFromMX(t *testing.T) {
	mxHosts := []string{"aspmx.l.google.com."}
	sels := dkimSelectorsForDomain("example.com", mxHosts)

	for _, want := range []string{"google", "selector1", "selector2"} {
		if !containsSelector(sels, want) {
			t.Fatalf("expected %q in google selectors, got %v", want, sels[:min(6, len(sels))])
		}
	}
}

func TestDKIMSelectors_MicrosoftFromMX(t *testing.T) {
	mxHosts := []string{"example-com.mail.protection.outlook.com."}
	sels := dkimSelectorsForDomain("example.com", mxHosts)

	if !containsSelector(sels, "selector1") || !containsSelector(sels, "selector2") {
		t.Fatalf("expected Microsoft selectors first, got %v", sels[:min(8, len(sels))])
	}
}

func TestDKIMSelectors_AmazonDomain(t *testing.T) {
	mxHosts := []string{"amazon-smtp.amazon.com."}
	sels := dkimSelectorsForDomain("amazon.com", mxHosts)

	if !containsSelector(sels, "i5yz2egl2d6o3oxllmizbamyhdvt6x6k") {
		t.Fatalf("expected Amazon SES selector first, got %v", sels[:min(8, len(sels))])
	}
	if sels[0] != "i5yz2egl2d6o3oxllmizbamyhdvt6x6k" {
		t.Fatalf("expected Amazon selector at index 0, got %q at 0: %v", sels[0], sels[:min(5, len(sels))])
	}
}

func TestDKIMSelectors_CappedAtMax(t *testing.T) {
	sels := dkimSelectorsForDomain("example.com", nil)
	if len(sels) > MaxSelectors {
		t.Fatalf("got %d selectors, max is %d", len(sels), MaxSelectors)
	}
}

type fakeDNS struct {
	records map[string][]string
	// optional per-name rcode override; missing names default to NXDOMAIN (3)
	rcodes map[string]int
}

func (f fakeDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	txts, _, err := f.LookupTXTMeta(ctx, name)
	return txts, err
}

func (f fakeDNS) LookupTXTMeta(_ context.Context, name string) ([]string, int, error) {
	if f.rcodes != nil {
		if rc, ok := f.rcodes[name]; ok {
			return f.records[name], rc, nil
		}
	}
	if txts, ok := f.records[name]; ok {
		return txts, 0, nil
	}
	return nil, 3, nil
}