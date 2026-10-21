package bimi

import "testing"

func TestParseRecord(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		raw      string
		version  string
		location string
		evidence string
		declined bool
		syntaxOK bool
		errors   []string
	}{
		{
			name:     "logo and evidence",
			raw:      "v=BIMI1; l=https://example.com/a.svg; a=https://example.com/a.pem",
			version:  "BIMI1",
			location: "https://example.com/a.svg",
			evidence: "https://example.com/a.pem",
			syntaxOK: true,
		},
		{
			name:     "logo only",
			raw:      "v=BIMI1; l=https://cdn.example/logo.svg",
			version:  "BIMI1",
			location: "https://cdn.example/logo.svg",
			syntaxOK: true,
		},
		{
			name:     "declination with empty a",
			raw:      "v=BIMI1; l=; a=;",
			version:  "BIMI1",
			declined: true,
			syntaxOK: true,
		},
		{
			name:     "declination without a",
			raw:      "v=BIMI1; l=",
			version:  "BIMI1",
			declined: true,
			syntaxOK: true,
		},
		{
			name:     "unknown tag ignored",
			raw:      "v=BIMI1; l=https://example.com/a.svg; avp=brand; lps=news-",
			version:  "BIMI1",
			location: "https://example.com/a.svg",
			syntaxOK: true,
		},
		{
			name:     "whitespace around equals",
			raw:      "v = BIMI1 ; l = https://example.com/a.svg",
			version:  "BIMI1",
			location: "https://example.com/a.svg",
			syntaxOK: true,
		},
		{
			name:     "v not first",
			raw:      "l=https://example.com/a.svg; v=BIMI1",
			version:  "BIMI1",
			location: "https://example.com/a.svg",
			errors:   []string{"v=BIMI1 must be the first tag"},
		},
		{
			name:     "wrong version",
			raw:      "v=BIMI2; l=https://example.com/a.svg",
			location: "https://example.com/a.svg",
			errors:   []string{"v= must be BIMI1"},
		},
		{
			name:    "http logo",
			raw:     "v=BIMI1; l=http://example.com/a.svg",
			version: "BIMI1",
			errors:  []string{"l= URL must use https"},
		},
		{
			name:     "http evidence",
			raw:      "v=BIMI1; l=https://example.com/a.svg; a=http://example.com/a.pem",
			version:  "BIMI1",
			location: "https://example.com/a.svg",
			errors:   []string{"a= URL must use https"},
		},
		{
			name:     "missing l",
			raw:      "v=BIMI1; a=https://example.com/a.pem",
			version:  "BIMI1",
			evidence: "https://example.com/a.pem",
			errors:   []string{"l= tag is required"},
		},
		{
			name:     "duplicate l",
			raw:      "v=BIMI1; l=https://example.com/a.svg; l=https://example.com/b.svg",
			version:  "BIMI1",
			location: "https://example.com/a.svg",
			errors:   []string{"duplicate tag l"},
		},
		{
			name:   "empty",
			raw:    "   ",
			errors: []string{"v=BIMI1 must be the first tag"},
		},
		{
			name:    "non-443 rejected",
			raw:     "v=BIMI1; l=https://example.com:8443/a.svg",
			version: "BIMI1",
			errors:  []string{"l= URL must use https"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseRecord(tc.raw)
			if got.Version != tc.version || got.Location != tc.location || got.Evidence != tc.evidence || got.Declined != tc.declined || got.SyntaxOK != tc.syntaxOK {
				t.Fatalf("parsed %+v", got)
			}
			if len(got.Errors) != len(tc.errors) {
				t.Fatalf("errors %q want %q", got.Errors, tc.errors)
			}
			for i := range tc.errors {
				if got.Errors[i] != tc.errors[i] {
					t.Fatalf("errors %q want %q", got.Errors, tc.errors)
				}
			}
		})
	}
}

func TestClassifyTXT(t *testing.T) {
	t.Parallel()
	raw, n, bad := classifyTXT([]string{"google-site-verification=abc", "v=BIMI1; l=;"})
	if n != 1 || raw != "v=BIMI1; l=;" || bad != "" {
		t.Fatalf("raw=%q n=%d bad=%q", raw, n, bad)
	}
	_, n, bad = classifyTXT([]string{"v=BIMI1; l=https://a.example/a.svg", "v=BIMI1; l=https://b.example/b.svg"})
	if n != 2 || bad != "" {
		t.Fatalf("n=%d bad=%q", n, bad)
	}
	_, n, bad = classifyTXT([]string{"v=BIMI2; l="})
	if n != 0 || bad != "v=BIMI2; l=" {
		t.Fatalf("n=%d bad=%q", n, bad)
	}
	_, n, bad = classifyTXT(nil)
	if n != 0 || bad != "" {
		t.Fatalf("n=%d bad=%q", n, bad)
	}
}

func TestOrganizationalDomain(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"example.com", "example.com"},
		{"mail.example.com", "example.com"},
		{"a.b.example.com", "example.com"},
		{"example.co.uk", "example.co.uk"},
		{"mail.example.co.uk", "example.co.uk"},
		{"a.mail.example.co.uk", "example.co.uk"},
		{"co.uk", "co.uk"},
		{"BMW.DE.", "bmw.de"},
	}
	for _, tc := range cases {
		if got := OrganizationalDomain(tc.in); got != tc.want {
			t.Errorf("OrganizationalDomain(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}
