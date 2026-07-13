package testutil

import "testing"

func TestAllowDenyGate(t *testing.T) {
	allow := AllowGate{}
	if !allow.ValidShape("example.com") || !allow.Allowed("example.com") {
		t.Fatal("AllowGate should pass")
	}
	deny := DenyGate{}
	if deny.ValidShape("example.com") || deny.Allowed("example.com") {
		t.Fatal("DenyGate should block")
	}
}