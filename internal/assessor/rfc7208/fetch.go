package rfc7208

import (
	"context"
	"fmt"
	"strings"
)

// selectSPFTXT returns the unique v=spf1 TXT record from apex TXT answers.
// Per RFC 7208 §4.5, more than one v=spf1 record is a PermError.
func selectSPFTXT(txts []string) (raw string, err error) {
	var candidates []string
	for _, t := range txts {
		trimmed := strings.TrimSpace(t)
		if strings.HasPrefix(strings.ToLower(trimmed), "v=spf1") {
			candidates = append(candidates, trimmed)
		}
	}
	if len(candidates) > 1 {
		return "", fmt.Errorf("multiple v=spf1 records")
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	return "", nil
}

func fetchSPF(ctx context.Context, deps Deps, domain string) (string, error) {
	txts, err := deps.DNS.LookupTXT(ctx, domain)
	if err != nil {
		return "", err
	}
	return selectSPFTXT(txts)
}