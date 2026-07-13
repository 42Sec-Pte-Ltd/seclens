package rfc8461

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	maxPolicyBodyBytes = 64 * 1024
	maxAgeLimit        = 31557600
)

type policyFields struct {
	version       string
	mode          string
	maxAge        int
	mx            []string
	versionSet    bool
	modeSet       bool
	maxAgeSet     bool
	maxAgeRaw     string
	maxAgeInvalid bool
}

// AnalyzePolicyBody parses and validates an MTA-STS policy file body (no HTTPS fetch).
func AnalyzePolicyBody(body string) (syntaxOK bool, issues []string) {
	p := parsePolicyBody(body)
	return validatePolicy(p)
}

func parsePolicyBody(body string) policyFields {
	var p policyFields
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx == -1 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(line[:idx]))
		v := strings.TrimSpace(line[idx+1:])
		switch k {
		case "version":
			if !p.versionSet {
				p.version = v
				p.versionSet = true
			}
		case "mode":
			if !p.modeSet {
				p.mode = strings.ToLower(v)
				p.modeSet = true
			}
		case "mx":
			p.mx = append(p.mx, asciiHost(v))
		case "max_age":
			if !p.maxAgeSet && !p.maxAgeInvalid {
				if _, err := fmt.Sscanf(v, "%d", &p.maxAge); err == nil {
					p.maxAgeSet = true
				} else {
					p.maxAgeInvalid = true
					p.maxAgeRaw = v
				}
			}
		}
	}
	return p
}

func validatePolicy(p policyFields) (ok bool, issues []string) {
	if !p.versionSet || p.version != "STSv1" {
		issues = append(issues, "policy version must be STSv1 (RFC 8461 §3.2)")
	}
	if !p.modeSet {
		issues = append(issues, "policy missing required mode field (RFC 8461 §3.2)")
	} else if p.mode != "enforce" && p.mode != "testing" && p.mode != "none" {
		issues = append(issues, "unknown policy mode: "+p.mode)
	}
	if p.maxAgeInvalid {
		issues = append(issues, fmt.Sprintf("max_age must be an integer (got %q) (RFC 8461 §3.2)", p.maxAgeRaw))
	} else if !p.maxAgeSet {
		issues = append(issues, "policy missing required max_age field (RFC 8461 §3.2)")
	} else if p.maxAge < 0 || p.maxAge > maxAgeLimit {
		issues = append(issues, fmt.Sprintf("max_age=%d out of range (RFC 8461 §3.2 allows 0–%d)", p.maxAge, maxAgeLimit))
	}
	if p.mode != "none" && len(p.mx) == 0 {
		issues = append(issues, "policy missing required mx field(s) (RFC 8461 §3.2)")
	}
	ok = len(issues) == 0
	return ok, issues
}

func contentTypeIsTextPlain(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "" {
		return false
	}
	if i := strings.Index(ct, ";"); i != -1 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct == "text/plain"
}

func classifyFetchError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "x509") || strings.Contains(lower, "certificate"):
		return "HTTPS policy fetch failed: TLS certificate validation error (RFC 8461 §3.3)"
	case strings.Contains(lower, "policy http status"):
		return "DNS advertises MTA-STS but policy file returned non-200 status (RFC 8461 §3.3)"
	default:
		return "DNS advertises MTA-STS but policy file could not be fetched: " + msg
	}
}

type policyFetchResult struct {
	body        string
	contentType string
	statusCode  int
}

func readPolicyBody(resp *http.Response) (string, error) {
	limited := io.LimitReader(resp.Body, maxPolicyBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return "", err
	}
	if len(body) > maxPolicyBodyBytes {
		return "", fmt.Errorf("policy body exceeds %d bytes (RFC 8461 §3.3 suggested limit)", maxPolicyBodyBytes)
	}
	return string(body), nil
}
