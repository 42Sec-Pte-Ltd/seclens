package rfc6376

import "testing"

func TestClassifyDomainKeySubtree(t *testing.T) {
	// rcode: 0=NOERROR, 3=NXDOMAIN, -1=error/unavailable
	cases := []struct {
		name          string
		wildcard      bool
		bareRcode     int
		bareTXT       []string
		canaryRcode   int
		canaryHasDKIM bool
		want          string
	}{
		{"wildcard_unknown", true, 0, nil, 0, true, "unknown"},
		{"absent_both_nx", false, 3, nil, 3, false, "absent"},
		{"present_ent", false, 0, nil, 3, false, "present"},
		{"black_lies_unknown", false, 0, nil, 0, false, "unknown"},
		{"bare_error_unknown", false, -1, nil, 3, false, "unknown"},
		{"bare_dkim_txt_present", false, 0, []string{"v=DKIM1; p=abc"}, 3, false, "present"},
		{"canary_has_dkim_unknown", false, 0, nil, 0, true, "unknown"},
		{"bare_nx_canary_noerror_unknown", false, 3, nil, 0, false, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyDomainKeySubtree(SubtreeInput{
				WildcardDetected: tc.wildcard,
				BareRcode:        tc.bareRcode,
				BareTXT:          tc.bareTXT,
				CanaryRcode:      tc.canaryRcode,
				CanaryHasDKIM:    tc.canaryHasDKIM,
			})
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
