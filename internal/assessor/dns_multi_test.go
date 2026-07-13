package assessor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"seclens/internal/report"
)

func newFakeDoH(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func newTestPoolClient(urls ...string) *DoHClient {
	return &DoHClient{
		baseURLs:   urls,
		HTTPClient: &http.Client{Timeout: 3 * time.Second},
		retryCount: 0,
	}
}

const txtAnswerBody = `{"Status":0,"AD":false,"Answer":[{"name":"example.com","type":16,"TTL":300,"data":"\"v=spf1 -all\""}]}`

func TestDoQueryPoolPrefersAnswersOverEmpty(t *testing.T) {
	empty := newFakeDoH(t, `{"Status":0,"AD":false}`, http.StatusOK)
	defer empty.Close()
	full := newFakeDoH(t, txtAnswerBody, http.StatusOK)
	defer full.Close()

	c := newTestPoolClient(empty.URL, full.URL)
	txts, err := c.LookupTXT(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	if len(txts) != 1 || txts[0] != "v=spf1 -all" {
		t.Fatalf("expected SPF answer from second provider, got %v", txts)
	}
}

func TestDoQueryPoolPrefersAnswersOverServfailAndError(t *testing.T) {
	servfail := newFakeDoH(t, `{"Status":2,"AD":false}`, http.StatusOK)
	defer servfail.Close()
	broken := newFakeDoH(t, `oops`, http.StatusInternalServerError)
	defer broken.Close()
	full := newFakeDoH(t, txtAnswerBody, http.StatusOK)
	defer full.Close()

	c := newTestPoolClient(servfail.URL, broken.URL, full.URL)
	txts, err := c.LookupTXT(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	if len(txts) != 1 {
		t.Fatalf("expected 1 TXT despite servfail+error providers, got %v", txts)
	}
}

func TestDoQueryPoolAllFail(t *testing.T) {
	brokenA := newFakeDoH(t, `oops`, http.StatusInternalServerError)
	defer brokenA.Close()
	brokenB := newFakeDoH(t, `oops`, http.StatusBadGateway)
	defer brokenB.Close()

	c := newTestPoolClient(brokenA.URL, brokenB.URL)
	if _, err := c.LookupTXT(context.Background(), "example.com"); err == nil {
		t.Fatal("expected error when all providers fail")
	}
}

func TestBetterDoHResponseRanking(t *testing.T) {
	withAns := &DoHResponse{Status: 0}
	withAns.Answer = append(withAns.Answer, struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	}{Name: "x", Type: 16, Data: "a"})
	empty := &DoHResponse{Status: 0}
	nx := &DoHResponse{Status: 3}
	servfail := &DoHResponse{Status: 2}

	if !betterDoHResponse(withAns, empty) {
		t.Error("answers must beat empty NOERROR")
	}
	if !betterDoHResponse(empty, nx) {
		t.Error("empty NOERROR must beat NXDOMAIN")
	}
	if !betterDoHResponse(nx, servfail) {
		t.Error("NXDOMAIN must beat SERVFAIL")
	}
	if betterDoHResponse(empty, withAns) {
		t.Error("empty must not beat answers")
	}
	adTrue := &DoHResponse{Status: 0, AD: true}
	if !betterDoHResponse(adTrue, empty) {
		t.Error("AD=true must win the tie among equal rank/answers")
	}
}

func TestDNSTraceRecordsAllProviders(t *testing.T) {
	empty := newFakeDoH(t, `{"Status":0,"AD":false}`, http.StatusOK)
	defer empty.Close()
	full := newFakeDoH(t, txtAnswerBody, http.StatusOK)
	defer full.Close()

	c := newTestPoolClient(empty.URL, full.URL)
	ctx, trace := withDNSTrace(context.Background())

	if _, err := c.LookupTXT(ctx, "example.com"); err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}

	entries := trace.snapshot()
	if len(entries) != 1 {
		t.Fatalf("expected 1 trace entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Name != "example.com" || e.Type != 16 {
		t.Fatalf("unexpected trace query: %+v", e)
	}
	if len(e.Providers) != 2 {
		t.Fatalf("expected 2 provider outcomes, got %d", len(e.Providers))
	}
	if e.Chosen != full.URL {
		t.Fatalf("chosen=%q want %q (provider with answers)", e.Chosen, full.URL)
	}
	for _, p := range e.Providers {
		if len(p.Raw) == 0 || p.RawOmitted {
			t.Fatalf("expected raw JSON body for provider %s: %+v", p.Provider, p)
		}
	}
	var answers int
	for _, p := range e.Providers {
		answers += p.Answers
	}
	if answers != 1 {
		t.Fatalf("expected exactly 1 answer across providers, got %d", answers)
	}
}

func TestDNSTraceRawBudget(t *testing.T) {
	tr := &dnsTraceCollector{rawBudget: 10}
	e := traceEntryWithRaw(make([]byte, 8))
	tr.record(e)
	if got := tr.snapshot(); len(got) != 1 || got[0].Providers[0].RawOmitted || len(got[0].Providers[0].Raw) != 8 {
		t.Fatalf("first raw within budget must be kept: %+v", got)
	}
	tr.record(traceEntryWithRaw(make([]byte, 8)))
	got := tr.snapshot()
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	p := got[1].Providers[0]
	if !p.RawOmitted || p.Raw != nil {
		t.Fatalf("raw beyond budget must be omitted, summary kept: %+v", p)
	}
	if p.Answers != 1 {
		t.Fatal("summary fields must survive raw omission")
	}
}

func traceEntryWithRaw(raw []byte) (e report.DNSQueryTrace) {
	e.Name = "example.com"
	e.Type = 16
	e.Providers = []report.DNSProviderTrace{{Provider: "test", Answers: 1, Raw: raw}}
	return e
}
