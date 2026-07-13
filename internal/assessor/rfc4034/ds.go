package rfc4034

import (
	"strconv"
	"strings"
	"unicode"
)

// DSParsed is the wire-format fields of a DS record in presentation form (RFC 4034 §5.1).
type DSParsed struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string
	SyntaxOK   bool
}

// ParseDS parses DS RDATA in presentation form: "<key-tag> <algorithm> <digest-type> <digest>".
func ParseDS(data string) DSParsed {
	data = strings.TrimSpace(data)
	if data == "" {
		return DSParsed{}
	}
	fields := strings.Fields(data)
	if len(fields) < 4 {
		return DSParsed{}
	}

	keyTag64, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		return DSParsed{}
	}
	alg, ok := ParseAlgorithm(fields[1])
	if !ok {
		return DSParsed{}
	}
	dt64, err := strconv.ParseUint(fields[2], 10, 8)
	if err != nil {
		return DSParsed{}
	}
	digest := strings.ToUpper(fields[3])
	if digest == "" || len(digest)%2 != 0 {
		return DSParsed{}
	}
	for _, r := range digest {
		if !unicode.IsDigit(r) && (r < 'A' || r > 'F') {
			return DSParsed{}
		}
	}

	return DSParsed{
		KeyTag:     uint16(keyTag64),
		Algorithm:  alg,
		DigestType: uint8(dt64),
		Digest:     digest,
		SyntaxOK:   true,
	}
}