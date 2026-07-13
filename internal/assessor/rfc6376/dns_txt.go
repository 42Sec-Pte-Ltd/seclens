package rfc6376

import (
	"strings"
)

// ParsedRecord holds tag values from a DKIM TXT record (RFC 6376 §3.6.3).
type ParsedRecord struct {
	Version   string // v=
	PublicKey string // p=
	KeyType   string // k= (default rsa)
	Flags     string // t=
	HashAlgos string // h=
	SyntaxOK  bool
	Raw       string
}

// IsDKIMTXTRecord reports whether a TXT value looks like a DKIM public key.
// Accepts full v=DKIM1 records and bare p= keys (common on Amazon SES CNAME targets).
func IsDKIMTXTRecord(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if strings.Contains(lower, "v=dkim1") {
		return true
	}
	if strings.Contains(lower, "p=mig") || strings.Contains(lower, "p=miib") {
		return true
	}
	return false
}

// ParseDKIMRecord parses v, p, k, t, and h tags from a DKIM TXT record (RFC 6376 §3.6.3).
func ParseDKIMRecord(raw string) ParsedRecord {
	rec := ParsedRecord{Raw: raw}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return rec
	}

	tags := parseTagList(trimmed)
	version, ok := tags["v"]
	if !ok || !strings.EqualFold(version, "DKIM1") {
		// Bare p= keys (Amazon SES CNAME targets) are syntactically valid for discovery.
		if p, hasP := tags["p"]; hasP && p != "" {
			rec.PublicKey = p
			rec.KeyType = defaultKeyType(tags["k"])
			rec.Flags = tags["t"]
			rec.HashAlgos = tags["h"]
			rec.SyntaxOK = true
		}
		return rec
	}

	rec.Version = version
	rec.PublicKey = tags["p"]
	rec.KeyType = defaultKeyType(tags["k"])
	rec.Flags = tags["t"]
	rec.HashAlgos = tags["h"]
	rec.SyntaxOK = true
	return rec
}

func defaultKeyType(k string) string {
	k = strings.TrimSpace(k)
	if k == "" {
		return "rsa"
	}
	return strings.ToLower(k)
}

func parseTagList(raw string) map[string]string {
	out := make(map[string]string)
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.Index(part, "=")
		if eq <= 0 {
			continue
		}
		tag := strings.ToLower(strings.TrimSpace(part[:eq]))
		val := strings.TrimSpace(part[eq+1:])
		out[tag] = val
	}
	return out
}