package testutil

import (
	"context"
	"fmt"
)

// MockTXT maps DNS names to TXT record strings for assessor Check() tests.
// Names present in the map (including empty slices) are treated as NOERROR (rcode 0).
// Names absent from the map are treated as NXDOMAIN (rcode 3).
type MockTXT map[string][]string

func (m MockTXT) LookupTXT(ctx context.Context, name string) ([]string, error) {
	txts, _, err := m.LookupTXTMeta(ctx, name)
	return txts, err
}

// LookupTXTMeta returns TXT RDATA and RCODE. Missing names → rcode 3 (NXDOMAIN);
// present names (even with empty TXT) → rcode 0 (NOERROR).
func (m MockTXT) LookupTXTMeta(_ context.Context, name string) ([]string, int, error) {
	if txts, ok := m[name]; ok {
		return txts, 0, nil
	}
	return nil, 3, nil
}

// ErrTXT always returns an error (DNS failure paths).
type ErrTXT struct{ Err error }

func (e ErrTXT) LookupTXT(_ context.Context, _ string) ([]string, error) {
	if e.Err != nil {
		return nil, e.Err
	}
	return nil, fmt.Errorf("mock DNS lookup failed")
}

// LookupTXTMeta always fails with rcode -1 (unavailable).
func (e ErrTXT) LookupTXTMeta(_ context.Context, _ string) ([]string, int, error) {
	if e.Err != nil {
		return nil, -1, e.Err
	}
	return nil, -1, fmt.Errorf("mock DNS lookup failed")
}