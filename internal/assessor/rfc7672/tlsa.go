package rfc7672

import (
	"strconv"
	"strings"
	"unicode"
)

// TLSAParsed is the wire-format fields of a TLSA record in presentation form (RFC 6698 §2.1).
type TLSAParsed struct {
	Usage            uint8
	Selector         uint8
	MatchingType     uint8
	AssociationData  string
	SyntaxOK         bool
}

// ParseTLSA parses TLSA RDATA in presentation form:
// "<certificate usage> <selector> <matching type> <certificate association data>".
func ParseTLSA(rdata string) TLSAParsed {
	rdata = strings.TrimSpace(rdata)
	if rdata == "" {
		return TLSAParsed{}
	}
	if strings.HasPrefix(rdata, `\#`) {
		return parseTLSAUnknownRR(rdata)
	}
	fields := strings.Fields(rdata)
	if len(fields) < 4 {
		return TLSAParsed{}
	}

	usage64, err := strconv.ParseUint(fields[0], 10, 8)
	if err != nil {
		return TLSAParsed{}
	}
	selector64, err := strconv.ParseUint(fields[1], 10, 8)
	if err != nil {
		return TLSAParsed{}
	}
	matching64, err := strconv.ParseUint(fields[2], 10, 8)
	if err != nil {
		return TLSAParsed{}
	}

	assoc := strings.ToUpper(strings.Join(fields[3:], ""))
	if assoc == "" || len(assoc)%2 != 0 {
		return TLSAParsed{}
	}
	for _, r := range assoc {
		if !unicode.IsDigit(r) && (r < 'A' || r > 'F') {
			return TLSAParsed{}
		}
	}

	parsed := TLSAParsed{
		Usage:           uint8(usage64),
		Selector:        uint8(selector64),
		MatchingType:    uint8(matching64),
		AssociationData: assoc,
	}
	parsed.SyntaxOK = ValidateTLSAFields(parsed.Usage, parsed.Selector, parsed.MatchingType)
	return parsed
}

// parseTLSAUnknownRR handles RFC 3597 "\# <len> <hex...>" TLSA presentation from DoH.
func parseTLSAUnknownRR(rdata string) TLSAParsed {
	fields := strings.Fields(rdata)
	if len(fields) < 5 {
		return TLSAParsed{}
	}
	hexStr := strings.Join(fields[2:], "")
	if len(hexStr) < 6 || len(hexStr)%2 != 0 {
		return TLSAParsed{}
	}
	usage64, err := strconv.ParseUint(hexStr[0:2], 16, 8)
	if err != nil {
		return TLSAParsed{}
	}
	selector64, err := strconv.ParseUint(hexStr[2:4], 16, 8)
	if err != nil {
		return TLSAParsed{}
	}
	matching64, err := strconv.ParseUint(hexStr[4:6], 16, 8)
	if err != nil {
		return TLSAParsed{}
	}
	assoc := strings.ToUpper(hexStr[6:])
	if assoc == "" {
		return TLSAParsed{}
	}
	parsed := TLSAParsed{
		Usage:           uint8(usage64),
		Selector:        uint8(selector64),
		MatchingType:    uint8(matching64),
		AssociationData: assoc,
	}
	parsed.SyntaxOK = ValidateTLSAFields(parsed.Usage, parsed.Selector, parsed.MatchingType)
	return parsed
}