package rfc7672

// ValidateTLSAFields checks RFC 6698 §2.1 field ranges:
// certificate usage 0–3, selector 0–1, matching type 0–2.
func ValidateTLSAFields(usage, selector, matching uint8) bool {
	return usage <= 3 && selector <= 1 && matching <= 2
}