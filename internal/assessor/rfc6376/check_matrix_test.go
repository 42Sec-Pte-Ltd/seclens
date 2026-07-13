package rfc6376

import (
	"context"
	"strings"
	"testing"

	"seclens/internal/assessor/testutil"
)

// matrixDNS maps FQDNs (selector._domainkey.domain) to TXT RDATA strings.
// Present names (including empty slices) → NOERROR; missing names → NXDOMAIN.
type matrixDNS map[string][]string

func (m matrixDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	txts, _, err := m.LookupTXTMeta(ctx, name)
	return txts, err
}

func (m matrixDNS) LookupTXTMeta(_ context.Context, name string) ([]string, int, error) {
	if txts, ok := m[name]; ok {
		return txts, 0, nil
	}
	return nil, 3, nil
}

func dkimTXTName(selector, domain string) string {
	return selector + "._domainkey." + strings.TrimSuffix(domain, ".")
}

func matrixRecords(domain string, bySelector map[string][]string) matrixDNS {
	out := make(matrixDNS, len(bySelector))
	for sel, txts := range bySelector {
		out[dkimTXTName(sel, domain)] = txts
	}
	return out
}

func googleMX() []string {
	return []string{"aspmx.l.google.com."}
}

const matrixProdKey = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"

func bareDomainKey(domain string) string {
	return "_domainkey." + strings.TrimSuffix(domain, ".")
}

func TestCheck_Matrix(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name           string
		domain         string
		mxHosts        []string
		bySelector     map[string][]string
		// bareNOERROR marks bare _domainkey as existing ENT (empty NOERROR).
		// When false and no bare key is seeded via bySelector, bare is NXDOMAIN.
		bareNOERROR    bool
		// blackLies: bare and canary both NOERROR empty → subtree unknown.
		blackLies      bool
		gate           Gate
		wantStatus     string
		wantSubtree    string
	}{
		{
			name:        "no_keys_absent",
			domain:      "nokeys.example.com",
			mxHosts:     googleMX(),
			gate:        testutil.AllowGate{},
			wantStatus:  "info",
			wantSubtree: SubtreeAbsent,
		},
		{
			name:        "no_keys_present_ent",
			domain:      "ent.example.com",
			mxHosts:     googleMX(),
			bareNOERROR: true,
			gate:        testutil.AllowGate{},
			wantStatus:  "info",
			wantSubtree: SubtreePresent,
		},
		{
			name:        "no_keys_black_lies_unknown",
			domain:      "blacklies.example.com",
			mxHosts:     googleMX(),
			blackLies:   true,
			gate:        testutil.AllowGate{},
			wantStatus:  "info",
			wantSubtree: SubtreeUnknown,
		},
		{
			name:    "production_key_pass",
			domain:  "prod.example.com",
			mxHosts: googleMX(),
			bySelector: map[string][]string{
				"google": {matrixProdKey},
			},
			// bare ENT while a real selector exists: still pass; subtree still classified.
			bareNOERROR: true,
			gate:        testutil.AllowGate{},
			wantStatus:  "pass",
			wantSubtree: SubtreePresent,
		},
		{
			name:    "revoked_only_warn",
			domain:  "revoked.example.com",
			mxHosts: googleMX(),
			bySelector: map[string][]string{
				"google": {"v=DKIM1; p="},
			},
			gate:        testutil.AllowGate{},
			wantStatus:  "warn",
			// Selector hit upgrades ENT classification to present (bare probe may have been NXDOMAIN).
			wantSubtree: SubtreePresent,
		},
		{
			name:    "test_only_warn",
			domain:  "testonly.example.com",
			mxHosts: googleMX(),
			bySelector: map[string][]string{
				"google": {"v=DKIM1; t=y; p=abc123"},
			},
			gate:        testutil.AllowGate{},
			wantStatus:  "warn",
			wantSubtree: SubtreePresent,
		},
		{
			name:    "wildcard_warn",
			domain:  "wildcard.example.com",
			mxHosts: googleMX(),
			bySelector: map[string][]string{
				canarySelector: {"v=DKIM1; p=wildcard-key"},
			},
			gate:        testutil.AllowGate{},
			wantStatus:  "warn",
			wantSubtree: SubtreeUnknown,
		},
		{
			name:    "gate_skip",
			domain:  "gated.example.com",
			mxHosts: googleMX(),
			bySelector: map[string][]string{
				"google": {matrixProdKey},
			},
			gate:        testutil.DenyGate{},
			wantStatus:  "info",
			wantSubtree: SubtreeUnknown,
		},
		{
			name:    "non_dkim_txt_ignored",
			domain:  "nodkim.example.com",
			mxHosts: googleMX(),
			bySelector: map[string][]string{
				"google": {"v=spf1 -all"},
			},
			gate:        testutil.AllowGate{},
			wantStatus:  "info",
			wantSubtree: SubtreeAbsent,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gate := tc.gate
			if gate == nil {
				gate = testutil.AllowGate{}
			}
			dns := matrixRecords(tc.domain, tc.bySelector)
			if tc.bareNOERROR {
				dns[bareDomainKey(tc.domain)] = []string{}
			}
			if tc.blackLies {
				// bare + canary both exist with empty TXT → NOERROR/NOERROR → unknown
				dns[bareDomainKey(tc.domain)] = []string{}
				dns[dkimTXTName(canarySelector, tc.domain)] = []string{}
			}
			deps := Deps{
				DNS:  dns,
				Gate: gate,
			}
			res := Check(ctx, Request{Domain: tc.domain, MXHosts: tc.mxHosts}, deps)
			testutil.AssertStatus(t, res.Status, tc.wantStatus, tc.name)
			if tc.wantSubtree != "" && res.DomainKeySubtree != tc.wantSubtree {
				t.Fatalf("DomainKeySubtree=%q want %q", res.DomainKeySubtree, tc.wantSubtree)
			}

			switch tc.name {
			case "no_keys_absent":
				if !strings.Contains(res.Message, "subtree") && !strings.Contains(res.Message, "NXDOMAIN") {
					t.Fatalf("message=%q want absent-oriented subtree/NXDOMAIN message", res.Message)
				}
				if len(res.SelectorsFound) != 0 {
					t.Fatalf("SelectorsFound=%v want empty", res.SelectorsFound)
				}
			case "no_keys_present_ent":
				if !strings.Contains(res.Message, "custom selector") && !strings.Contains(res.Message, "s=") {
					t.Fatalf("message=%q want custom-selector ENT message", res.Message)
				}
				if len(res.SelectorsFound) != 0 {
					t.Fatalf("SelectorsFound=%v want empty", res.SelectorsFound)
				}
			case "no_keys_black_lies_unknown":
				if res.Message != "No DKIM keys discovered via common selectors" {
					t.Fatalf("message=%q want generic no-keys message", res.Message)
				}
			case "production_key_pass":
				if len(res.SelectorsFound) == 0 {
					t.Fatal("expected at least one selector")
				}
				if !containsSelector(res.SelectorsFound, "google") {
					t.Fatalf("SelectorsFound=%v want google", res.SelectorsFound)
				}
				if len(res.Keys) == 0 {
					t.Fatal("expected parsed keys")
				}
				for _, k := range res.Keys {
					if k.Selector == "google" {
						if !k.SyntaxOK || k.Revoked || k.TestKey {
							t.Fatalf("google key: SyntaxOK=%v Revoked=%v TestKey=%v", k.SyntaxOK, k.Revoked, k.TestKey)
						}
					}
				}
			case "revoked_only_warn":
				testutil.AssertIssuesContain(t, res.Issues, "revoked")
				if res.WildcardDetected {
					t.Fatal("unexpected wildcard")
				}
			case "test_only_warn":
				testutil.AssertIssuesContain(t, res.Issues, "testing key")
			case "wildcard_warn":
				if !res.WildcardDetected {
					t.Fatal("expected WildcardDetected true")
				}
				if len(res.SelectorsFound) != 0 || len(res.Keys) != 0 {
					t.Fatalf("wildcard should clear selectors/keys: selectors=%v keys=%d", res.SelectorsFound, len(res.Keys))
				}
				testutil.AssertIssuesContain(t, res.Issues, "wildcard")
			case "gate_skip":
				if res.Message != "skipped (input gated)" {
					t.Fatalf("message=%q want gated skip", res.Message)
				}
			case "non_dkim_txt_ignored":
				if len(res.SelectorsFound) != 0 {
					t.Fatalf("non-DKIM TXT must not count as discovery: %v", res.SelectorsFound)
				}
				// bare+canary NX → absent messaging (not generic)
				if res.DomainKeySubtree != SubtreeAbsent {
					t.Fatalf("DomainKeySubtree=%q want absent", res.DomainKeySubtree)
				}
			}
		})
	}
}