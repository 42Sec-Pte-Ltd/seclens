package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBand(t *testing.T) {
	t.Parallel()
	cases := []struct {
		score int
		want  string
	}{
		{100, "Excellent"},
		{90, "Excellent"},
		{89, "Good"},
		{70, "Good"},
		{69, "Fair"},
		{40, "Fair"},
		{39, "Poor"},
		{0, "Poor"},
	}
	for _, tc := range cases {
		if got := Band(tc.score); got != tc.want {
			t.Errorf("Band(%d)=%q want %q", tc.score, got, tc.want)
		}
	}
}

func TestJSONOmitsScoreForNXDOMAIN(t *testing.T) {
	t.Parallel()
	r := Report{
		Domain:    "missing.example",
		Generated: time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC),
		Profile:   StatusNXDOMAIN,
		Status:    StatusNXDOMAIN,
		Message:   "not assessable",
		Errors:    []string{"domain does not exist"},
		Score:     0,
	}
	raw := r.ToJSON()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["Score"]; ok {
		t.Fatalf("nxdomain JSON has Score: %s", raw)
	}
	if _, ok := m["band"]; ok {
		t.Fatalf("nxdomain JSON has band: %s", raw)
	}
	if _, ok := m["ApplicableMax"]; ok {
		t.Fatalf("nxdomain JSON has ApplicableMax: %s", raw)
	}
	if m["status"] != "nxdomain" || m["Profile"] != "nxdomain" || m["message"] != "not assessable" {
		t.Fatalf("nxdomain fields: %#v", m)
	}

	var buf bytes.Buffer
	r.PrintText(&buf)
	out := buf.String()
	if !strings.Contains(out, "Status: nxdomain (not assessable)") || !strings.Contains(out, "domain does not exist") {
		t.Fatalf("text:\n%s", out)
	}
}

func TestJSONKeepsZeroScore(t *testing.T) {
	t.Parallel()
	r := Report{Domain: "example.com", Profile: "mail", Score: 0, Band: Band(0)}
	var m map[string]any
	if err := json.Unmarshal(r.ToJSON(), &m); err != nil {
		t.Fatal(err)
	}
	score, ok := m["Score"].(float64)
	if !ok || score != 0 {
		t.Fatalf("Score=%v", m["Score"])
	}
	if m["band"] != "Poor" {
		t.Fatalf("band=%v", m["band"])
	}
}
