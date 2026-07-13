package rfc6376

import "strings"

// KeyState classifies a parsed DKIM public key record.
type KeyState string

const (
	KeyStateActive  KeyState = "active"
	KeyStateRevoked KeyState = "revoked" // p= empty (RFC 6376 §3.6.1 key revocation)
	KeyStateTest    KeyState = "test"    // t=y testing key (RFC 6376 §3.6.1)
	KeyStateInvalid KeyState = "invalid"
)

// ClassifyKeyState returns active, revoked, test, or invalid for a parsed DKIM record.
func ClassifyKeyState(rec ParsedRecord) KeyState {
	if !rec.SyntaxOK {
		return KeyStateInvalid
	}
	if strings.TrimSpace(rec.PublicKey) == "" {
		return KeyStateRevoked
	}
	if hasTestFlag(rec.Flags) {
		return KeyStateTest
	}
	return KeyStateActive
}

func hasTestFlag(flags string) bool {
	flags = strings.TrimSpace(flags)
	if flags == "" {
		return false
	}
	for _, f := range strings.Split(flags, ":") {
		if strings.EqualFold(strings.TrimSpace(f), "y") {
			return true
		}
	}
	return false
}

// HasProductionKey reports whether at least one key is active (not revoked, not test-only).
func HasProductionKey(states []KeyState) bool {
	for _, s := range states {
		if s == KeyStateActive {
			return true
		}
	}
	return false
}