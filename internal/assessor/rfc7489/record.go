package rfc7489

import (
	"fmt"
	"strings"
)

// Record holds parsed DMARC tag values (first occurrence wins per RFC 7489 §6.3).
type Record struct {
	Version    string
	VersionSet bool

	Policy    string
	PolicySet bool

	SubPolicy    string
	SubPolicySet bool

	Pct        int
	PctSet     bool
	PctInvalid bool
	PctRaw     string

	RUA []string
	RUF []string

	ADKIM    string
	ADKIMSet bool

	ASPF    string
	ASPFSet bool

	FO    string
	FOSet bool

	RI        int
	RISet     bool
	RIInvalid bool
	RIRaw     string
}

// ParseRecord splits semicolon-separated key=value pairs; duplicate tags use first-wins.
func ParseRecord(raw string) Record {
	var rec Record
	seen := make(map[string]bool)

	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		if seen[key] {
			continue
		}
		seen[key] = true
		val := strings.TrimSpace(kv[1])

		switch key {
		case "v":
			rec.Version = val
			rec.VersionSet = true
		case "p":
			rec.Policy = strings.ToLower(val)
			rec.PolicySet = true
		case "sp":
			rec.SubPolicy = strings.ToLower(val)
			rec.SubPolicySet = true
		case "pct":
			var n int
			if _, err := fmt.Sscanf(val, "%d", &n); err == nil {
				rec.Pct = n
				rec.PctSet = true
			} else {
				rec.PctInvalid = true
				rec.PctRaw = val
			}
		case "rua":
			rec.RUA = splitURIList(val)
		case "ruf":
			rec.RUF = splitURIList(val)
		case "adkim":
			rec.ADKIM = strings.ToLower(val)
			rec.ADKIMSet = true
		case "aspf":
			rec.ASPF = strings.ToLower(val)
			rec.ASPFSet = true
		case "fo":
			rec.FO = strings.ToLower(val)
			rec.FOSet = true
		case "ri":
			var n int
			if _, err := fmt.Sscanf(val, "%d", &n); err == nil {
				rec.RI = n
				rec.RISet = true
			} else {
				rec.RIInvalid = true
				rec.RIRaw = val
			}
		}
	}
	return rec
}

func splitURIList(s string) []string {
	var out []string
	for _, u := range strings.Split(s, ",") {
		u = strings.TrimSpace(u)
		if u != "" {
			out = append(out, u)
		}
	}
	return out
}
