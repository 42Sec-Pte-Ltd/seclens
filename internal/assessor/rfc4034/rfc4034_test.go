package rfc4034

import "testing"

func TestParseDS(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		wantOK     bool
		wantTag    uint16
		wantAlg    uint8
		wantDigest uint8
	}{
		{
			name:       "cloudflare sample sha256",
			data:       "2371 13 2 E9D6FAE1DAD409B0EE20831B6B70C03C773E41A8",
			wantOK:     true,
			wantTag:    2371,
			wantAlg:    13,
			wantDigest: 2,
		},
		{
			name:       "cloudflare DoH mnemonic algorithm",
			data:       "2371 ECDSAP256SHA256 2 32996839a6d808afe3eb4a795a0e6a7a39a76fc52ff228b22b76f6d63826f2b9",
			wantOK:     true,
			wantTag:    2371,
			wantAlg:    13,
			wantDigest: 2,
		},
		{
			name:       "debian DoH RSASHA256 mnemonic",
			data:       "40756 RSASHA256 2 bbe42151b1a41efc1f7e6d74d86e601d55051d2b9eb99b1cd0ceaa6e2a5618f5",
			wantOK:     true,
			wantTag:    40756,
			wantAlg:    8,
			wantDigest: 2,
		},
		{
			name:       "rsa sha256",
			data:       "12345 8 2 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
			wantOK:     true,
			wantTag:    12345,
			wantAlg:    8,
			wantDigest: 2,
		},
		{
			name:       "sha1 digest warns later",
			data:       "2371 13 1 ABCDEF0123456789ABCDEF0123456789ABCDEF01",
			wantOK:     true,
			wantTag:    2371,
			wantAlg:    13,
			wantDigest: 1,
		},
		{name: "empty", data: ""},
		{name: "too few fields", data: "2371 13 2"},
		{name: "bad key tag", data: "xx 13 2 AABB"},
		{name: "bad digest hex", data: "2371 13 2 GGHHAABB"},
		{name: "odd digest length", data: "2371 13 2 ABC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseDS(tt.data)
			if got.SyntaxOK != tt.wantOK {
				t.Fatalf("SyntaxOK=%v want %v", got.SyntaxOK, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if got.KeyTag != tt.wantTag || got.Algorithm != tt.wantAlg || got.DigestType != tt.wantDigest {
				t.Fatalf("parsed=%+v want tag=%d alg=%d digest=%d", got, tt.wantTag, tt.wantAlg, tt.wantDigest)
			}
		})
	}
}

func TestDNSKEYPresent(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{
			name: "ksk ecdsa",
			data: "257 3 13 AwEAAc6h7Rfk3A1D0u1i0vYrK8mH3uG8o0o0o0o0o0o0o0o0o0o0o0o0o0o0",
			want: true,
		},
		{
			name: "cloudflare DoH mnemonic algorithm",
			data: "256 3 ECDSAP256SHA256 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==",
			want: true,
		},
		{
			name: "zsk rsa",
			data: "256 3 8 AwEAAc6h7Rfk3A1D0u1i0vYrK8mH3uG8o0o0o0o0o0o0o0o0o0o0o0o0o0o0",
			want: true,
		},
		{name: "empty", data: "", want: false},
		{name: "too short", data: "257 3 13", want: false},
		{name: "bad protocol", data: "257 4 13 AwEAAc6h7Rfk3A1D0u1i0vYrK8mH3uG8o0o0o0o0o0o0o0o0o0o0o0o0o0o0", want: false},
		{name: "bad flags", data: "x 3 13 AwEAAc6h7Rfk3A1D0u1i0vYrK8mH3uG8o0o0o0o0o0o0o0o0o0o0o0o0o0o0", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DNSKEYPresent(tt.data); got != tt.want {
				t.Fatalf("DNSKEYPresent(%q)=%v want %v", tt.data, got, tt.want)
			}
		})
	}
}

func TestAlgorithmAndDigestWarnings(t *testing.T) {
	if !AlgorithmDeprecated(AlgRSAMD5) {
		t.Fatal("RSA/MD5 should be deprecated")
	}
	if AlgorithmWarning(AlgECDSAP256SHA256) != "" {
		t.Fatal("ECDSA P-256 should not warn")
	}
	if !DigestTypeDeprecated(DigestSHA1) {
		t.Fatal("SHA-1 digest should be deprecated")
	}
	if DigestTypeWarning(DigestSHA256) != "" {
		t.Fatal("SHA-256 digest should not warn")
	}
}