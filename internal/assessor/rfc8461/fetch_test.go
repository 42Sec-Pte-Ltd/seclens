package rfc8461

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

type resolveStub struct {
	gotHost string
	ips     []net.IP
	err     error
}

func (s *resolveStub) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }

func (s *resolveStub) ResolveHostIPs(_ context.Context, host string) ([]net.IP, error) {
	s.gotHost = host
	return s.ips, s.err
}

func TestResolvePolicyHostIPsUsesDoHOnly(t *testing.T) {
	ctx := context.Background()
	stub := &resolveStub{err: errors.New("doh down")}
	deps := Deps{DNS: stub, IPGuard: ipGuardStub{}}

	// example.com resolves via the OS; a DoH error must still fail closed.
	_, err := resolvePolicyHostIPs(ctx, deps, "example.com.")
	if err == nil {
		t.Fatal("expected error when ResolveHostIPs fails")
	}
	if !strings.Contains(err.Error(), "doh down") {
		t.Fatalf("must surface DoH error without OS resolver fallback: %v", err)
	}
	if stub.gotHost != "example.com" {
		t.Fatalf("ResolveHostIPs host=%q want example.com", stub.gotHost)
	}
}

func TestResolvePolicyHostIPsFailClosed(t *testing.T) {
	ctx := context.Background()
	pub := net.ParseIP("93.184.216.34")
	priv := net.ParseIP("10.0.0.1")

	t.Run("empty name", func(t *testing.T) {
		_, err := resolvePolicyHostIPs(ctx, Deps{DNS: &resolveStub{}, IPGuard: ipGuardStub{}}, "  ")
		if err == nil || !strings.Contains(err.Error(), "empty name") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("no addresses", func(t *testing.T) {
		_, err := resolvePolicyHostIPs(ctx, Deps{DNS: &resolveStub{}, IPGuard: ipGuardStub{}}, "mta-sts.example.com")
		if err == nil || !strings.Contains(err.Error(), "no addresses resolved") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("private only", func(t *testing.T) {
		_, err := resolvePolicyHostIPs(ctx, Deps{
			DNS:     &resolveStub{ips: []net.IP{priv}},
			IPGuard: ipGuardStub{},
		}, "mta-sts.example.com")
		if err == nil || !strings.Contains(err.Error(), "private/local") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("public filtered", func(t *testing.T) {
		got, err := resolvePolicyHostIPs(ctx, Deps{
			DNS:     &resolveStub{ips: []net.IP{priv, pub}},
			IPGuard: ipGuardStub{},
		}, "mta-sts.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || !got[0].Equal(pub) {
			t.Fatalf("got=%v want only %v", got, pub)
		}
	})
}

func TestPolicyTransportDialGuard(t *testing.T) {
	deps := Deps{
		DNS:     &resolveStub{ips: []net.IP{net.ParseIP("93.184.216.34")}},
		IPGuard: ipGuardStub{},
	}
	tr := policyTransport(deps, "mta-sts.example.com")
	ctx := context.Background()

	tests := []struct {
		name, network, address, wantSub string
	}{
		{"http port", "tcp", "mta-sts.example.com:80", "443"},
		{"alt https port", "tcp", "mta-sts.example.com:8443", "443"},
		{"udp", "udp", "mta-sts.example.com:443", "network"},
		{"unix", "unix", "mta-sts.example.com:443", "network"},
		{"private literal", "tcp", "10.0.0.1:443", "private"},
		{"loopback literal", "tcp", "127.0.0.1:443", "private"},
		{"wrong host", "tcp", "evil.example.net:443", "unexpected host"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tr.DialContext(ctx, tt.network, tt.address)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantSub)) {
				t.Fatalf("err=%v want substring %q", err, tt.wantSub)
			}
		})
	}
}

func TestPolicyTransportPropagatesResolveError(t *testing.T) {
	deps := Deps{
		DNS:     &resolveStub{err: errors.New("doh down")},
		IPGuard: ipGuardStub{},
	}
	tr := policyTransport(deps, "mta-sts.example.com")
	_, err := tr.DialContext(context.Background(), "tcp", "mta-sts.example.com:443")
	if err == nil || !strings.Contains(err.Error(), "doh down") {
		t.Fatalf("err=%v", err)
	}
}
