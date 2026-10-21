package bimi

import (
	"bytes"
	"regexp"
	"strings"

	"seclens/internal/report"
)

var titleRE = regexp.MustCompile(`(?i)<title[^>]*>([^<]*)</title>`)

// svgDocument drops a BOM, XML declaration, comments, and doctype so the
// first element can be checked. Illustrator writes a comment before <svg>.
func svgDocument(raw string) string {
	s := strings.TrimSpace(raw)
	for {
		s = strings.TrimSpace(s)
		low := strings.ToLower(s)
		switch {
		case strings.HasPrefix(low, "<?xml"):
			i := strings.Index(low, "?>")
			if i < 0 {
				return s
			}
			s = s[i+2:]
		case strings.HasPrefix(low, "<!--"):
			i := strings.Index(low, "-->")
			if i < 0 {
				return s
			}
			s = s[i+3:]
		case strings.HasPrefix(low, "<!doctype"):
			i := strings.Index(low, ">")
			if i < 0 {
				return s
			}
			s = s[i+1:]
		default:
			return s
		}
	}
}

// InspectLogo reports content-type and SVG Tiny PS hints. It does not schema-validate.
func InspectLogo(body []byte, contentType string) report.BIMILogo {
	out := report.BIMILogo{
		ContentType: contentType,
		Bytes:       len(body),
	}
	raw := string(bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF}))
	root := svgDocument(raw)
	out.StartsWithSVG = strings.HasPrefix(strings.ToLower(root), "<svg")
	out.BaseProfileTinyPS = strings.Contains(raw, `baseProfile="tiny-ps"`) || strings.Contains(raw, `baseProfile='tiny-ps'`)
	out.Version12 = strings.Contains(raw, `version="1.2"`) || strings.Contains(raw, `version='1.2'`)
	out.HasScript = strings.Contains(strings.ToLower(raw), "<script")
	if m := titleRE.FindStringSubmatch(raw); len(m) == 2 && strings.TrimSpace(m[1]) != "" {
		out.HasTitle = true
	}
	return out
}

func logoFindings(l report.BIMILogo) []string {
	if l.Error != "" {
		return []string{"logo: " + l.Error}
	}
	var out []string
	if !l.StartsWithSVG {
		out = append(out, "logo does not start with <svg")
	}
	if l.HasScript {
		out = append(out, "logo contains <script")
	}
	if l.StartsWithSVG && !l.BaseProfileTinyPS {
		out = append(out, `logo missing baseProfile="tiny-ps"`)
	}
	if l.StartsWithSVG && !l.Version12 {
		out = append(out, "logo version is not 1.2")
	}
	if l.StartsWithSVG && !l.HasTitle {
		out = append(out, "logo missing <title>")
	}
	return out
}
