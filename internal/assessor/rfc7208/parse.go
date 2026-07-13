package rfc7208

import (
	"strings"
)

// token represents one SPF record token (mechanism or modifier) with optional qualifier.
type token struct {
	raw      string
	qual     string
	mech     string
	lower    string
}

// parsedRecord holds the structured output of tokenizing one SPF TXT record.
type parsedRecord struct {
	version        string
	tokens         []token
	mechanisms     []string
	includes       []string
	lookupCount    int
	hasAll         bool
	hasRedirect    bool
	redirectTarget string
	allQualifier   string
}

func tokenizeRecord(raw string) (parsedRecord, []string) {
	var rec parsedRecord
	var issues []string

	if raw == "" {
		return rec, []string{"empty SPF record"}
	}

	raw = normalizeGluedSPF(raw)
	parts := strings.Fields(raw)
	if len(parts) == 0 {
		return rec, []string{"empty SPF record"}
	}

	lower := strings.ToLower(parts[0])
	if lower != "v=spf1" {
		return rec, []string{"record does not start with v=spf1"}
	}
	rec.version = "spf1"

	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		qual := ""
		mech := p
		if len(p) > 0 && (p[0] == '+' || p[0] == '-' || p[0] == '~' || p[0] == '?') {
			qual = string(p[0])
			mech = p[1:]
		}

		lp := strings.ToLower(p)
		tok := token{raw: p, qual: qual, mech: mech, lower: lp}
		rec.tokens = append(rec.tokens, tok)
		rec.mechanisms = append(rec.mechanisms, p)

		switch {
		case strings.HasPrefix(lp, "include:"):
			rec.includes = append(rec.includes, strings.TrimPrefix(mech, "include:"))
			rec.lookupCount++
		case lp == "a" || strings.HasPrefix(lp, "a:") || strings.HasPrefix(lp, "a/"):
			rec.lookupCount++
		case lp == "mx" || strings.HasPrefix(lp, "mx:") || strings.HasPrefix(lp, "mx/"):
			rec.lookupCount++
		case lp == "ptr" || strings.HasPrefix(lp, "ptr:"):
			rec.lookupCount++
		case strings.HasPrefix(lp, "exists:"):
			rec.lookupCount++
		case strings.HasPrefix(lp, "redirect="):
			if rec.hasRedirect {
				issues = append(issues, "multiple redirect= modifiers (PermError)")
			}
			rec.hasRedirect = true
			rec.redirectTarget = strings.TrimPrefix(mech, "redirect=")
			rec.lookupCount++
		case strings.ToLower(mech) == "all":
			if rec.hasAll {
				issues = append(issues, "multiple 'all' mechanisms (only one terminating all permitted)")
			}
			rec.hasAll = true
			if qual == "" {
				qual = "+"
			}
			rec.allQualifier = qual
		}
	}

	return rec, issues
}

// normalizeGluedSPF inserts spaces after v=spf1 when operators publish a single glued token
// (common in broken but deployed records, e.g. "v=spf1include:foo ~all").
func normalizeGluedSPF(raw string) string {
	trimmed := strings.TrimSpace(raw)
	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, "v=spf1") || strings.HasPrefix(lower, "v=spf1 ") {
		return trimmed
	}
	body := trimmed[len("v=spf1"):]
	gluedPart := body
	if sp := strings.Index(body, " "); sp >= 0 {
		gluedPart = body[:sp]
	}
	bodyLower := strings.ToLower(gluedPart)
	knownGlued := strings.Contains(bodyLower, "include:") ||
		strings.Contains(bodyLower, "redirect=") ||
		strings.Contains(bodyLower, "ip4:") ||
		strings.Contains(bodyLower, "ip6:") ||
		strings.Contains(bodyLower, "mx:") ||
		strings.Contains(bodyLower, "a:") ||
		strings.Contains(bodyLower, "~all") ||
		strings.HasSuffix(bodyLower, "-all") ||
		strings.HasSuffix(bodyLower, "?all") ||
		strings.HasSuffix(bodyLower, "+all")
	if !knownGlued {
		return trimmed
	}
	for _, tok := range []string{
		"include:", "redirect=", "exists:", "exp=", "ip4:", "ip6:", "mx:", "a:", "ptr:", "mx/", "a/",
		"~all", "-all", "?all", "+all",
	} {
		body = insertSpacesBeforeToken(body, tok)
	}
	return strings.TrimSpace("v=spf1 " + strings.TrimSpace(body))
}

func insertSpacesBeforeToken(s, token string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if i+len(token) <= len(s) && strings.EqualFold(s[i:i+len(token)], token) {
			if out.Len() > 0 {
				out.WriteByte(' ')
			}
			out.WriteString(s[i : i+len(token)])
			i += len(token)
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}