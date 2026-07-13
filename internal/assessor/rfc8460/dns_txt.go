package rfc8460

import (
	"strings"

	"seclens/internal/assessor/txtselect"
)

// selectTLSRPTTXT implements RFC 8460 §3.1 TXT record selection.
// Advertised (Present) but not selectable as a single valid record per RFC 8460 §3.1 when
// multiple matches are found.
func selectTLSRPTTXT(txts []string) (selected string, present bool, issue string) {
	return txtselect.SelectSingle(txts, "v=tlsrptv1;",
		"multiple _smtp._tls TXT records starting with v=TLSRPTv1; (RFC 8460 §3.1 requires exactly one)", true)
}

type tlsrptFields struct {
	version  string
	rua      []string
	syntaxOK bool
}

// TLSRPTParsed holds parsed TLS-RPT DNS TXT fields (RFC 8460 §3.1).
type TLSRPTParsed struct {
	Version  string
	RUA      []string
	SyntaxOK bool
}

// ParseRecord parses a TLS-RPT TXT value without DNS lookup.
func ParseRecord(rawTXT string) TLSRPTParsed {
	p := parseTLSRPTRecord(rawTXT)
	return TLSRPTParsed{
		Version:  p.version,
		RUA:      append([]string(nil), p.rua...),
		SyntaxOK: p.syntaxOK,
	}
}

// parseTLSRPTRecord extracts version and rua from a selected TLS-RPT TXT value.
func parseTLSRPTRecord(rawTXT string) tlsrptFields {
	trimmed := strings.TrimSpace(rawTXT)
	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, "v=tlsrptv1;") {
		return tlsrptFields{}
	}

	out := tlsrptFields{syntaxOK: true, version: "TLSRPTv1"}
	for _, part := range strings.Split(trimmed, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		switch key {
		case "v":
			if !strings.EqualFold(val, "TLSRPTv1") {
				out.syntaxOK = false
				out.version = val
			}
		case "rua":
			if val != "" {
				for _, u := range strings.Split(val, ",") {
					u = strings.TrimSpace(u)
					if u != "" {
						out.rua = append(out.rua, u)
					}
				}
			}
		}
	}
	return out
}