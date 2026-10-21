package bimi

import (
	"net/url"
	"strings"
)

// Parsed is one BIMI assertion record after tag parsing.
// Declined is set only when l= and a= are both empty and the record is otherwise valid.
type Parsed struct {
	Version  string
	Location string
	Evidence string
	Declined bool
	SyntaxOK bool
	Errors   []string
}

// ParseRecord parses one TXT value. The caller has already chosen the record.
// Unknown tags are ignored. v=BIMI1 must be the first tag and the value is case-sensitive.
func ParseRecord(raw string) Parsed {
	raw = strings.TrimSpace(raw)
	var out Parsed
	if raw == "" {
		out.Errors = append(out.Errors, "v=BIMI1 must be the first tag")
		return out
	}

	segs := splitSegments(raw)
	if len(segs) == 0 {
		out.Errors = append(out.Errors, "v=BIMI1 must be the first tag")
		return out
	}

	seen := map[string]bool{}
	lSet := false
	aSet := false
	locationEmpty := true
	evidenceEmpty := true

	for i, seg := range segs {
		key, val, ok := splitTag(seg)
		if !ok {
			out.Errors = append(out.Errors, "tag is missing '='")
			continue
		}
		if i == 0 && key != "v" {
			out.Errors = append(out.Errors, "v=BIMI1 must be the first tag")
		}
		switch key {
		case "v":
			if seen["v"] {
				out.Errors = append(out.Errors, "duplicate tag v")
				continue
			}
			seen["v"] = true
			if val != "BIMI1" {
				out.Errors = append(out.Errors, "v= must be BIMI1")
				continue
			}
			out.Version = val
		case "l":
			if seen["l"] {
				out.Errors = append(out.Errors, "duplicate tag l")
				continue
			}
			seen["l"] = true
			lSet = true
			if val == "" {
				locationEmpty = true
				continue
			}
			u, okURL := httpsURL(val)
			if !okURL {
				out.Errors = append(out.Errors, "l= URL must use https")
				continue
			}
			locationEmpty = false
			out.Location = u
		case "a":
			if seen["a"] {
				out.Errors = append(out.Errors, "duplicate tag a")
				continue
			}
			seen["a"] = true
			aSet = true
			if val == "" {
				evidenceEmpty = true
				continue
			}
			u, okURL := httpsURL(val)
			if !okURL {
				out.Errors = append(out.Errors, "a= URL must use https")
				continue
			}
			evidenceEmpty = false
			out.Evidence = u
		default:
			// Draft: unknown tags MUST be ignored.
		}
	}

	if !lSet {
		out.Errors = append(out.Errors, "l= tag is required")
	}
	if !aSet {
		evidenceEmpty = true
	}
	out.SyntaxOK = len(out.Errors) == 0
	out.Declined = out.SyntaxOK && lSet && locationEmpty && evidenceEmpty
	return out
}

func splitSegments(raw string) []string {
	var segs []string
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part != "" {
			segs = append(segs, part)
		}
	}
	return segs
}

func splitTag(seg string) (key, val string, ok bool) {
	k, v, found := strings.Cut(seg, "=")
	if !found {
		return "", "", false
	}
	key = strings.TrimSpace(k)
	val = strings.TrimSpace(v)
	if key == "" {
		return "", "", false
	}
	return key, val, true
}

func firstTagIsBIMI1(raw string) bool {
	raw = strings.TrimSpace(raw)
	seg := raw
	if i := strings.IndexByte(raw, ';'); i >= 0 {
		seg = strings.TrimSpace(raw[:i])
	}
	key, val, ok := splitTag(seg)
	return ok && key == "v" && val == "BIMI1"
}

func hasVTag(raw string) bool {
	for _, seg := range splitSegments(raw) {
		key, _, ok := splitTag(seg)
		if ok && key == "v" {
			return true
		}
	}
	return false
}

// classifyTXT separates version-matching BIMI records from a v= record that is not BIMI1.
// Unrelated TXT strings are ignored. n>1 is the draft's multiple-record error.
func classifyTXT(txts []string) (raw string, n int, badVersion string) {
	var matched []string
	for _, t := range txts {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if firstTagIsBIMI1(t) {
			matched = append(matched, t)
			continue
		}
		if badVersion == "" && hasVTag(t) {
			badVersion = t
		}
	}
	switch len(matched) {
	case 0:
		return "", 0, badVersion
	case 1:
		return matched[0], 1, ""
	default:
		return "", len(matched), ""
	}
}

func httpsURL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return "", false
	}
	if p := u.Port(); p != "" && p != "443" {
		return "", false
	}
	return u.String(), true
}
