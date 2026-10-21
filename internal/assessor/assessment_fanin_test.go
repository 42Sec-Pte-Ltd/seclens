package assessor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"seclens/internal/assessor/rfc7505"
	"seclens/internal/report"
)

func installTestDoH(t *testing.T, srv *httptest.Server) {
	t.Helper()
	c := NewDoHClient("cloudflare")
	c.baseURLs = []string{srv.URL}
	c.retryCount = 0
	c.HTTPClient.Timeout = 3 * time.Second

	defaultResolverMu.Lock()
	oldClient := DefaultClient
	oldKey := defaultResolverKey
	DefaultClient = c
	defaultResolverKey = "test-doh-" + srv.URL
	defaultResolverMu.Unlock()
	t.Cleanup(func() {
		defaultResolverMu.Lock()
		DefaultClient = oldClient
		defaultResolverKey = oldKey
		defaultResolverMu.Unlock()
	})
}

func writeDoH(w http.ResponseWriter, status int, ad bool, answers []map[string]any) {
	w.Header().Set("Content-Type", "application/dns-json")
	payload := map[string]any{"Status": status, "AD": ad}
	if answers != nil {
		payload["Answer"] = answers
	}
	_ = json.NewEncoder(w).Encode(payload)
}

func rrJSON(name string, typ int, data string) map[string]any {
	return map[string]any{"name": name, "type": typ, "TTL": 60, "data": data}
}

func TestAssess_MXNXDOMAIN(t *testing.T) {
	const domain = "com.apple"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		qtype := r.URL.Query().Get("type")
		if name == domain && qtype == "15" {
			writeDoH(w, 3, false, nil)
			return
		}
		t.Errorf("query after NXDOMAIN name=%s type=%s", name, qtype)
		writeDoH(w, 2, false, nil)
	}))
	defer srv.Close()
	installTestDoH(t, srv)

	r, err := Assess(context.Background(), domain, AssessmentOpts{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if r.Domain != domain || r.Profile != ProfileNXDOMAIN || r.Status != "nxdomain" || r.Message != "not assessable" {
		t.Fatalf("report=%+v", r)
	}
	if r.Score != 0 || r.Band != "" || r.SPF != nil || r.DMARC != nil {
		t.Fatalf("nxdomain must not be scored: %+v", r)
	}
	if len(r.Errors) != 1 || r.Errors[0] != "domain does not exist" {
		t.Fatalf("errors=%v", r.Errors)
	}
	raw := r.ToJSON()
	if strings.Contains(string(raw), `"Score"`) || strings.Contains(string(raw), `"band"`) {
		t.Fatalf("json leaked score or band: %s", raw)
	}
}

func TestRunBulk_AttachesErrorWhenDomainEmpty(t *testing.T) {
	reps := RunBulk(context.Background(), []string{"bad"}, AssessmentOpts{Timeout: time.Second}, 1)
	if len(reps) != 1 {
		t.Fatalf("len=%d", len(reps))
	}
	if reps[0].Domain != "bad" {
		t.Fatalf("domain=%q", reps[0].Domain)
	}
	if len(reps[0].Errors) != 1 || reps[0].Errors[0] != "invalid domain shape" {
		t.Fatalf("errors=%v", reps[0].Errors)
	}
}

func TestAssess_PreservesMXLookupFailure(t *testing.T) {
	const domain = "mxfail.example"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		qtype := r.URL.Query().Get("type")
		if name == domain && qtype == "15" {
			writeDoH(w, 2, false, nil)
			return
		}
		writeDoH(w, 0, false, nil)
	}))
	defer srv.Close()
	installTestDoH(t, srv)

	r, err := Assess(context.Background(), domain, AssessmentOpts{Timeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if r.SPF == nil {
		t.Fatalf("fan-in did not finish, errors=%v", r.Errors)
	}
	if !strings.Contains(strings.Join(r.Errors, "\n"), "MX DNS lookup failed") {
		t.Fatalf("MX lookup failure was dropped, errors=%v", r.Errors)
	}
}

func TestAssess_PreservesMixedMXViolation(t *testing.T) {
	const domain = "mixedmx.example"
	const host = "mx.mixedmx.example"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		qtype := r.URL.Query().Get("type")
		if name == domain && qtype == "15" {
			writeDoH(w, 0, false, []map[string]any{
				rrJSON(domain, 15, "0 ."),
				rrJSON(domain, 15, "10 "+host+"."),
			})
			return
		}
		writeDoH(w, 0, false, nil)
	}))
	defer srv.Close()
	installTestDoH(t, srv)

	r, err := Assess(context.Background(), domain, AssessmentOpts{Timeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if r.SPF == nil {
		t.Fatalf("fan-in did not finish, errors=%v", r.Errors)
	}
	if !strings.Contains(strings.Join(r.Errors, "\n"), rfc7505.MixedMXViolationMessage) {
		t.Fatalf("mixed MX violation was dropped, errors=%v", r.Errors)
	}
}

func TestAssess_MXCapDeniesFullDANEPass(t *testing.T) {
	const domain = "cap.example.com"
	const n = maxAssessedMXHosts + 1
	var mxAnswers []map[string]any
	hosts := make([]string, n)
	for i := 0; i < n; i++ {
		hosts[i] = fmt.Sprintf("mx%02d.cap.example.com", i+1)
		mxAnswers = append(mxAnswers, rrJSON(domain, 15, fmt.Sprintf("%d %s.", i+1, hosts[i])))
	}
	const ds = "30909 8 2 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"
	const dnskey = "257 3 13 AwEAAexample"
	const tlsa = "3 1 1 aabbccddeeff00112233445566778899"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSuffix(r.URL.Query().Get("name"), ".")
		qtype := r.URL.Query().Get("type")
		switch {
		case name == domain && qtype == "15":
			writeDoH(w, 0, false, mxAnswers)
		case qtype == "1" && strings.HasPrefix(name, "mx"):
			writeDoH(w, 0, false, []map[string]any{rrJSON(name, 1, "1.2.3.4")})
		case qtype == "52" && strings.HasPrefix(name, "_25._tcp.mx"):
			writeDoH(w, 0, true, []map[string]any{rrJSON(name, 52, tlsa)})
		case qtype == "43" && (name == "com" || name == domain):
			writeDoH(w, 0, true, []map[string]any{rrJSON(name, 43, ds)})
		case qtype == "48" && name == domain:
			writeDoH(w, 0, true, []map[string]any{rrJSON(name, 48, dnskey)})
		case qtype == "16" && name == domain:
			writeDoH(w, 0, true, []map[string]any{rrJSON(name, 16, "v=spf1 -all")})
		default:
			writeDoH(w, 0, false, nil)
		}
	}))
	defer srv.Close()
	installTestDoH(t, srv)

	r, err := Assess(context.Background(), domain, AssessmentOpts{Timeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	wantErr := fmt.Sprintf("MX host list capped at %d (lowest preference first); 1 additional MX not assessed", maxAssessedMXHosts)
	if !strings.Contains(strings.Join(r.Errors, "\n"), wantErr) {
		t.Fatalf("cap error missing, errors=%v", r.Errors)
	}
	if r.DANE == nil {
		t.Fatal("DANE result missing")
	}
	if r.DANE.MXCovered || r.DANE.Status == "pass" || r.DANE.EarnedPoints == MaxPointsDANE {
		t.Fatalf("capped MX set must not fully pass DANE: covered=%v status=%s points=%d msg=%q",
			r.DANE.MXCovered, r.DANE.Status, r.DANE.EarnedPoints, r.DANE.Message)
	}
	if r.DANE.Status != "warn" {
		t.Fatalf("DANE status=%s want warn", r.DANE.Status)
	}
}

func TestConstrainCappedMXChecks_PartialWarn(t *testing.T) {
	r := report.Report{
		Profile: ProfileMail,
		DANE: &report.DANEResult{
			AdvertisedFor:   []string{"mx1.example.com"},
			MXCovered:       true,
			SyntaxOK:        true,
			DNSSECValidated: true,
			Status:          "pass",
			Message:         "DANE TLSA published for all public MX hosts",
		},
		MTASTS: &report.MTASTSResult{
			DNSAdvertised: true,
			PolicyFetched: true,
			MXCoverageOK:  true,
			Mode:          "enforce",
			Status:        "pass",
			Message:       "MTA-STS fully configured",
		},
	}
	constrainCappedMXChecks(&r)
	PopulateCheckScores(&r)
	if r.DANE.MXCovered || r.DANE.Status != "warn" || r.DANE.EarnedPoints != MaxPointsDANE/2 {
		t.Fatalf("DANE capped: covered=%v status=%s points=%d", r.DANE.MXCovered, r.DANE.Status, r.DANE.EarnedPoints)
	}
	if r.MTASTS.MXCoverageOK || r.MTASTS.Status != "warn" || r.MTASTS.EarnedPoints != 10 {
		t.Fatalf("MTA-STS capped: covered=%v status=%s points=%d", r.MTASTS.MXCoverageOK, r.MTASTS.Status, r.MTASTS.EarnedPoints)
	}
}
