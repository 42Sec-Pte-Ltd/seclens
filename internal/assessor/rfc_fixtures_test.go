package assessor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"seclens/internal/assessor/rfc4034"
	"seclens/internal/assessor/rfc6376"
	"seclens/internal/assessor/rfc7208"
	"seclens/internal/assessor/rfc7489"
	"seclens/internal/assessor/rfc7505"
	"seclens/internal/assessor/rfc7672"
	"seclens/internal/assessor/rfc8460"
	"seclens/internal/assessor/rfc8461"
	"seclens/internal/report"
)

type fixtureWant struct {
	Status            *string `json:"status,omitempty"`
	SyntaxOK          *bool   `json:"syntax_ok,omitempty"`
	AllQualifier      *string `json:"all_qualifier,omitempty"`
	Policy            *string `json:"policy,omitempty"`
	Version           *string `json:"version,omitempty"`
	KeyType           *string `json:"key_type,omitempty"`
	HasKey            *bool   `json:"has_key,omitempty"`
	KeyState          *string `json:"key_state,omitempty"`
	RUACount          *int    `json:"rua_count,omitempty"`
	ID                *string `json:"id,omitempty"`
	IDValid           *bool   `json:"id_valid,omitempty"`
	Usage             *int    `json:"usage,omitempty"`
	Selector          *int    `json:"selector,omitempty"`
	Matching          *int    `json:"matching,omitempty"`
	Assoc             *string `json:"assoc,omitempty"`
	KeyTag            *int    `json:"key_tag,omitempty"`
	Algorithm         *int    `json:"algorithm,omitempty"`
	DigestType        *int    `json:"digest_type,omitempty"`
	DigestDeprecated  *bool   `json:"digest_deprecated,omitempty"`
	DNSKEYPresent     *bool   `json:"dnskey_present,omitempty"`
	ValidNullMX       *bool   `json:"valid_null_mx,omitempty"`
	Posture           *string `json:"posture,omitempty"`
	Violation         *string `json:"violation,omitempty"`
}

type stringFixture struct {
	Name  string      `json:"name"`
	Kind  string      `json:"kind,omitempty"`
	Input string      `json:"input"`
	Want  fixtureWant `json:"want"`
}

type mxRecordFixture struct {
	Pref int    `json:"pref"`
	Host string `json:"host"`
}

type mxFixture struct {
	Name  string            `json:"name"`
	Input []mxRecordFixture `json:"input"`
	Want  fixtureWant       `json:"want"`
}

type rfcFixturesFile struct {
	RFC7208 []stringFixture `json:"rfc7208"`
	RFC7489 []stringFixture `json:"rfc7489"`
	RFC6376 []stringFixture `json:"rfc6376"`
	RFC8460 []stringFixture `json:"rfc8460"`
	RFC8461 []stringFixture `json:"rfc8461"`
	RFC7672 []stringFixture `json:"rfc7672"`
	RFC4034 []stringFixture `json:"rfc4034"`
	RFC7505 []mxFixture     `json:"rfc7505"`
}

func loadRFCFixtures(t *testing.T) rfcFixturesFile {
	t.Helper()
	path := filepath.Join("testdata", "rfc_fixtures.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var fixtures rfcFixturesFile
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("parse fixtures: %v", err)
	}
	return fixtures
}

func assertStringPtr(t *testing.T, name, field, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: %s=%q want %q", name, field, got, want)
	}
}

func assertBoolPtr(t *testing.T, name, field string, got, want bool) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: %s=%v want %v", name, field, got, want)
	}
}

func assertIntPtr(t *testing.T, name, field string, got, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: %s=%d want %d", name, field, got, want)
	}
}

// fixtureSPFGate mirrors production SPF mechanism validation (macro-aware).
type fixtureSPFGate struct{}

func (fixtureSPFGate) ValidShape(domain string) bool { return domain != "" && len(domain) > 3 }
func (fixtureSPFGate) Allowed(domain string) bool    { return true }
func (fixtureSPFGate) ValidMechanismDomain(domain string) bool {
	return IsValidSPFMechanismDomain(domain)
}

func TestRFCFixtures_ParseOnly(t *testing.T) {
	fixtures := loadRFCFixtures(t)
	gate := fixtureSPFGate{}

	t.Run("rfc7208", func(t *testing.T) {
		for _, fx := range fixtures.RFC7208 {
			t.Run(fx.Name, func(t *testing.T) {
				res := rfc7208.AnalyzeRecord(fx.Input, gate)
				if fx.Want.Status != nil {
					assertStringPtr(t, fx.Name, "status", res.Status, *fx.Want.Status)
				}
				if fx.Want.AllQualifier != nil {
					assertStringPtr(t, fx.Name, "all_qualifier", res.AllQualifier, *fx.Want.AllQualifier)
				}
				if fx.Want.SyntaxOK != nil {
					syntaxOK := res.Status == "pass" || res.Status == "warn"
					assertBoolPtr(t, fx.Name, "syntax_ok", syntaxOK, *fx.Want.SyntaxOK)
				}
			})
		}
	})

	t.Run("rfc7489", func(t *testing.T) {
		for _, fx := range fixtures.RFC7489 {
			t.Run(fx.Name, func(t *testing.T) {
				res := rfc7489.AnalyzeRaw(fx.Input, false)
				if fx.Want.Status != nil {
					assertStringPtr(t, fx.Name, "status", res.Status, *fx.Want.Status)
				}
				if fx.Want.SyntaxOK != nil {
					assertBoolPtr(t, fx.Name, "syntax_ok", res.SyntaxOK, *fx.Want.SyntaxOK)
				}
				if fx.Want.Policy != nil {
					assertStringPtr(t, fx.Name, "policy", res.Policy, *fx.Want.Policy)
				}
			})
		}
	})

	t.Run("rfc6376", func(t *testing.T) {
		for _, fx := range fixtures.RFC6376 {
			t.Run(fx.Name, func(t *testing.T) {
				parsed := rfc6376.ParseDKIMRecord(fx.Input)
				if fx.Want.SyntaxOK != nil {
					assertBoolPtr(t, fx.Name, "syntax_ok", parsed.SyntaxOK, *fx.Want.SyntaxOK)
				}
				if fx.Want.Version != nil {
					assertStringPtr(t, fx.Name, "version", parsed.Version, *fx.Want.Version)
				}
				if fx.Want.KeyType != nil {
					assertStringPtr(t, fx.Name, "key_type", parsed.KeyType, *fx.Want.KeyType)
				}
				if fx.Want.HasKey != nil {
					hasKey := parsed.PublicKey != ""
					assertBoolPtr(t, fx.Name, "has_key", hasKey, *fx.Want.HasKey)
				}
				if fx.Want.KeyState != nil {
					state := string(rfc6376.ClassifyKeyState(parsed))
					assertStringPtr(t, fx.Name, "key_state", state, *fx.Want.KeyState)
				}
			})
		}
	})

	t.Run("rfc8460", func(t *testing.T) {
		for _, fx := range fixtures.RFC8460 {
			t.Run(fx.Name, func(t *testing.T) {
				parsed := rfc8460.ParseRecord(fx.Input)
				if fx.Want.SyntaxOK != nil {
					assertBoolPtr(t, fx.Name, "syntax_ok", parsed.SyntaxOK, *fx.Want.SyntaxOK)
				}
				if fx.Want.Version != nil {
					assertStringPtr(t, fx.Name, "version", parsed.Version, *fx.Want.Version)
				}
				if fx.Want.RUACount != nil {
					assertIntPtr(t, fx.Name, "rua_count", len(parsed.RUA), *fx.Want.RUACount)
				}
			})
		}
	})

	t.Run("rfc8461", func(t *testing.T) {
		for _, fx := range fixtures.RFC8461 {
			t.Run(fx.Name, func(t *testing.T) {
				switch fx.Kind {
				case "dns_id", "":
					id, valid := rfc8461.ParseDNSPolicyID(fx.Input)
					if fx.Want.ID != nil {
						assertStringPtr(t, fx.Name, "id", id, *fx.Want.ID)
					}
					if fx.Want.IDValid != nil {
						assertBoolPtr(t, fx.Name, "id_valid", valid, *fx.Want.IDValid)
					}
				case "policy":
					ok, _ := rfc8461.AnalyzePolicyBody(fx.Input)
					if fx.Want.SyntaxOK != nil {
						assertBoolPtr(t, fx.Name, "syntax_ok", ok, *fx.Want.SyntaxOK)
					}
				default:
					t.Fatalf("unknown kind %q", fx.Kind)
				}
			})
		}
	})

	t.Run("rfc7672", func(t *testing.T) {
		for _, fx := range fixtures.RFC7672 {
			t.Run(fx.Name, func(t *testing.T) {
				parsed := rfc7672.ParseTLSA(fx.Input)
				if fx.Want.SyntaxOK != nil {
					assertBoolPtr(t, fx.Name, "syntax_ok", parsed.SyntaxOK, *fx.Want.SyntaxOK)
				}
				if fx.Want.Usage != nil {
					assertIntPtr(t, fx.Name, "usage", int(parsed.Usage), *fx.Want.Usage)
				}
				if fx.Want.Selector != nil {
					assertIntPtr(t, fx.Name, "selector", int(parsed.Selector), *fx.Want.Selector)
				}
				if fx.Want.Matching != nil {
					assertIntPtr(t, fx.Name, "matching", int(parsed.MatchingType), *fx.Want.Matching)
				}
				if fx.Want.Assoc != nil {
					assertStringPtr(t, fx.Name, "assoc", parsed.AssociationData, *fx.Want.Assoc)
				}
			})
		}
	})

	t.Run("rfc4034", func(t *testing.T) {
		for _, fx := range fixtures.RFC4034 {
			t.Run(fx.Name, func(t *testing.T) {
				switch fx.Kind {
				case "ds", "":
					parsed := rfc4034.ParseDS(fx.Input)
					if fx.Want.SyntaxOK != nil {
						assertBoolPtr(t, fx.Name, "syntax_ok", parsed.SyntaxOK, *fx.Want.SyntaxOK)
					}
					if fx.Want.KeyTag != nil {
						assertIntPtr(t, fx.Name, "key_tag", int(parsed.KeyTag), *fx.Want.KeyTag)
					}
					if fx.Want.Algorithm != nil {
						assertIntPtr(t, fx.Name, "algorithm", int(parsed.Algorithm), *fx.Want.Algorithm)
					}
					if fx.Want.DigestType != nil {
						assertIntPtr(t, fx.Name, "digest_type", int(parsed.DigestType), *fx.Want.DigestType)
					}
					if fx.Want.DigestDeprecated != nil {
						deprecated := rfc4034.DigestTypeDeprecated(parsed.DigestType)
						assertBoolPtr(t, fx.Name, "digest_deprecated", deprecated, *fx.Want.DigestDeprecated)
					}
				case "dnskey":
					present := rfc4034.DNSKEYPresent(fx.Input)
					if fx.Want.DNSKEYPresent != nil {
						assertBoolPtr(t, fx.Name, "dnskey_present", present, *fx.Want.DNSKEYPresent)
					}
				default:
					t.Fatalf("unknown kind %q", fx.Kind)
				}
			})
		}
	})

	t.Run("rfc7505", func(t *testing.T) {
		for _, fx := range fixtures.RFC7505 {
			t.Run(fx.Name, func(t *testing.T) {
				mxs := make([]report.MXRecord, len(fx.Input))
				for i, m := range fx.Input {
					mxs[i] = report.MXRecord{Pref: uint16(m.Pref), Host: m.Host}
				}
				if fx.Want.ValidNullMX != nil {
					assertBoolPtr(t, fx.Name, "valid_null_mx", rfc7505.IsValidNullMX(mxs), *fx.Want.ValidNullMX)
				}
				if fx.Want.Posture != nil {
					assertStringPtr(t, fx.Name, "posture", rfc7505.DetectPosture(mxs), *fx.Want.Posture)
				}
				if fx.Want.Violation != nil {
					assertStringPtr(t, fx.Name, "violation", rfc7505.DetectViolation(mxs).String(), *fx.Want.Violation)
				}
			})
		}
	})
}