package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

// Public listing kinds for Report.Listing.
const (
	ListingCorpus    = "corpus"
	ListingEphemeral = "ephemeral"
)

// Report is the top-level result for one domain.
type Report struct {
	Domain          string
	Generated       time.Time
	IsMailEnabled   bool
	HasNullMX       bool   // RFC 7505: MX set contains a null MX RR (0 .); not equivalent to "no mail"
	Profile         string // "mail" | "null_mx" | "no_mx"
	NullMXCompliant bool   // true when no-mail profile fully hardened (score 100)
	ApplicableMax   int    // sum of applicable check max points (always 100)
	MXs             []MXRecord
	Nameservers     []string

	NullMX *NullMXResult
	SPF    *SPFResult
	DMARC  *DMARCResult
	DKIM   *DKIMResult
	MTASTS *MTASTSResult
	TLSRPT *TLSRPTResult
	DANE   *DANEResult
	DNSSEC *DNSSECResult
	// BIMI is informational. ComputeScore and ComputeApplicableMax ignore it.
	BIMI *BIMIResult `json:"BIMI,omitempty"`

	Errors []string
	Score  int // 0-100 rough. Omitted from JSON when Status is nxdomain.

	// Band is Excellent, Good, Fair, or Poor from the public grade thresholds.
	// Empty when the name is not assessable.
	Band string `json:"band,omitempty"`

	// Status is set only when the domain cannot be assessed.
	// "nxdomain" means the name does not exist. Score and band are then absent.
	Status string `json:"status,omitempty"`
	// Message is the short reason for Status, for example "not assessable".
	Message string `json:"message,omitempty"`

	// Listing selects public surface lifetime.
	// ListingCorpus (or empty on legacy disk): durable corpus; no deep-link TTL.
	// ListingEphemeral: API public scan; detail and summary honor publicResultTTL.
	Listing string `json:"listing,omitempty"`

	// DNSTrace records every DoH query of this assessment with the raw JSON answers
	// from all providers (multi-provider fan-out) and which provider's response was
	// chosen. Stored inside the report, so it is persisted/cached exactly as long as
	// the assessment result itself.
	DNSTrace []DNSQueryTrace `json:"dnsTrace,omitempty"`

	// Optional request metadata for embedders (e.g. multi-tenant frontends).
	
	RequestedByIP string     `json:"requestedByIP,omitempty"`
	RequestedAt   *time.Time `json:"requestedAt,omitempty"`
}

// MXRecord from DNS lookup.
type MXRecord struct {
	Pref uint16
	Host string
}

// DNSQueryTrace records one DNS query fan-out: the responses of all DoH providers
// and which provider's response won the best-result selection.
type DNSQueryTrace struct {
	Name      string             `json:"name"`
	Type      uint16             `json:"type"`
	Chosen    string             `json:"chosen,omitempty"`
	Providers []DNSProviderTrace `json:"providers"`
}

// DNSProviderTrace is one provider's outcome for a traced query.
// Raw carries the unmodified DoH JSON body; it may be omitted (RawOmitted=true)
// when the per-response cap or the per-report raw budget is exceeded.
type DNSProviderTrace struct {
	Provider   string          `json:"provider"`
	Status     int             `json:"status"` // DNS RCODE (0=NOERROR, 3=NXDOMAIN, ...)
	AD         bool            `json:"ad,omitempty"`
	Answers    int             `json:"answers"`
	RTTMs      int64           `json:"rttMs"`
	Error      string          `json:"error,omitempty"`
	Raw        json.RawMessage `json:"raw,omitempty"`
	RawOmitted bool            `json:"rawOmitted,omitempty"`
}

// PrintText renders a human-friendly report (used for default "text" output).
func (r Report) PrintText(w io.Writer) {
	fmt.Fprintf(w, "\n=== %s ===\n", r.Domain)
	if r.Status == StatusNXDOMAIN || r.Profile == StatusNXDOMAIN {
		fmt.Fprintln(w, "Status: nxdomain (not assessable)")
		if r.Message != "" {
			fmt.Fprintf(w, "%s\n", r.Message)
		}
		for _, e := range r.Errors {
			fmt.Fprintf(w, "  ! %s\n", e)
		}
		fmt.Fprintln(w)
		return
	}
	if r.Band != "" {
		fmt.Fprintf(w, "Generated: %s | Mail enabled: %v | Score: %d | Band: %s\n\n", r.Generated.Format(time.RFC3339), r.IsMailEnabled, r.Score, r.Band)
	} else {
		fmt.Fprintf(w, "Generated: %s | Mail enabled: %v\n\n", r.Generated.Format(time.RFC3339), r.IsMailEnabled)
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "Check\tStatus\tSummary")
	fmt.Fprintln(tw, "-----\t------\t-------")

	printRow := func(name, status, msg string) {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", name, statusLabel(status), msg)
	}

	if r.NullMX != nil {
		printRow("Null MX", r.NullMX.Status, r.NullMX.Message)
	}
	if r.SPF != nil {
		printRow("SPF", r.SPF.Status, r.SPF.Message)
	}
	if r.DMARC != nil {
		printRow("DMARC", r.DMARC.Status, r.DMARC.Message)
	}
	if r.DKIM != nil {
		printRow("DKIM", r.DKIM.Status, r.DKIM.Message)
	}
	if r.MTASTS != nil {
		printRow("MTA-STS", r.MTASTS.Status, r.MTASTS.Message)
	}
	if r.TLSRPT != nil {
		printRow("TLS-RPT", r.TLSRPT.Status, r.TLSRPT.Message)
	}
	if r.DANE != nil {
		printRow("DANE", r.DANE.Status, r.DANE.Message)
	}
	if r.DNSSEC != nil {
		printRow("DNSSEC", r.DNSSEC.Status, r.DNSSEC.Message)
	}

	_ = tw.Flush()

	if r.BIMI != nil {
		fmt.Fprintln(w, "\nBIMI (informational, not scored)")
		fmt.Fprintf(w, "  Status: %s\n", r.BIMI.Status)
		if r.BIMI.DNSName != "" {
			fmt.Fprintf(w, "  Record: %s\n", r.BIMI.DNSName)
		}
		if r.BIMI.Message != "" {
			fmt.Fprintf(w, "  Summary: %s\n", r.BIMI.Message)
		}
		if r.BIMI.Location != "" {
			fmt.Fprintf(w, "  l=: %s\n", r.BIMI.Location)
		}
		if r.BIMI.Evidence != "" {
			fmt.Fprintf(w, "  a=: %s\n", r.BIMI.Evidence)
		}
		if logo := r.BIMI.Logo; logo != nil && logo.Error == "" {
			fmt.Fprintf(w, "  Logo: %s, %d bytes, svg=%t, tiny-ps=%t, version1.2=%t, title=%t, script=%t\n",
				logo.ContentType, logo.Bytes, logo.StartsWithSVG, logo.BaseProfileTinyPS, logo.Version12, logo.HasTitle, logo.HasScript)
		}
		if cert := r.BIMI.Certificate; cert != nil && cert.Error == "" {
			fmt.Fprintf(w, "  Cert: subject=%s issuer=%s notAfter=%s expired=%t logotype=%t eku=%t hint=%s\n",
				cert.Subject, cert.Issuer, cert.NotAfter, cert.Expired, cert.LogotypeExt, cert.BIMIEKU, cert.MarkHint)
		}
		for _, f := range r.BIMI.Findings {
			fmt.Fprintf(w, "  - %s\n", f)
		}
	}

	// Issues section - direct and simple (no fancy interface tricks)
	hasIssues := false
	printIssue := func(issues []string) {
		for _, i := range issues {
			if !hasIssues {
				fmt.Fprintln(w, "\nFindings / recommendations:")
				hasIssues = true
			}
			fmt.Fprintf(w, "  - %s\n", i)
		}
	}

	if r.NullMX != nil {
		printIssue(r.NullMX.Issues)
	}
	if r.SPF != nil {
		printIssue(r.SPF.Issues)
	}
	if r.DMARC != nil {
		printIssue(r.DMARC.Issues)
	}
	if r.MTASTS != nil {
		printIssue(r.MTASTS.Issues)
	}

	if len(r.Errors) > 0 {
		fmt.Fprintln(w, "\nErrors during assessment:")
		for _, e := range r.Errors {
			fmt.Fprintf(w, "  ! %s\n", e)
		}
	}
	fmt.Fprintln(w)
}

const (
	// StatusNXDOMAIN is Report.Status when the name does not exist.
	StatusNXDOMAIN = "nxdomain"

	// Policy fetch outcomes on MTASTSResult.PolicyFetch.
	PolicyFetchFetched    = "fetched"
	PolicyFetchFailed     = "failed"
	PolicyFetchNotFetched = "not fetched"

	// AD-bit check outcomes on DNSSECResult.ADCheck.
	ADCheckObserved = "observed"
	ADCheckAbsent   = "absent"
	ADCheckNA       = "n/a"
)

// Band maps a 0-100 score to the public grade label.
// Excellent is 90 and above, Good is 70 and above, Fair is 40 and above, Poor is the rest.
func Band(score int) string {
	switch {
	case score >= 90:
		return "Excellent"
	case score >= 70:
		return "Good"
	case score >= 40:
		return "Fair"
	default:
		return "Poor"
	}
}

// MarshalJSON omits Score and ApplicableMax for a name that does not exist.
// A zero score would otherwise be read as a failed assessment.
func (r Report) MarshalJSON() ([]byte, error) {
	type alias Report
	if r.Status != StatusNXDOMAIN && r.Profile != StatusNXDOMAIN {
		return json.Marshal(alias(r))
	}
	raw, err := json.Marshal(alias(r))
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	delete(m, "Score")
	delete(m, "ApplicableMax")
	delete(m, "band")
	return json.Marshal(m)
}

// statusLabel maps a check status to the text-report marker.
// Exhaustive: every branch returns a label (no unused seed assignment).
func statusLabel(status string) string {
	switch strings.ToLower(status) {
	case "pass":
		return "[PASS]"
	case "warn":
		return "[WARN]"
	case "fail", "error":
		return "[FAIL]"
	default:
		return "[INFO]"
	}
}

// ToJSON returns compact JSON for the report (single domain).
func (r Report) ToJSON() []byte {
	b, _ := json.MarshalIndent(r, "", "  ")
	return b
}

// The following result types are defined here (moved from assessor package)
// to avoid import cycles (report is used by assessor and CLI).
// They are re-exported for convenience via the report package.

// SPFResult holds the analyzed SPF posture for a domain.
type SPFResult struct {
	Present              bool
	Raw                  string
	Version              string
	AllQualifier         string // "", "+", "-", "~", "?"
	Mechanisms           []string
	Includes             []string
	LookupCount          int // approximate number of DNS lookups (include/a/mx/ptr/exists)
	HasRedirect          bool
	RedirectTarget       string
	RedirectedSPFRaw     string // raw SPF record of the redirect target (if followed)
	IncludedRaws         map[string]string
	RedirectDepth        int // number of redirect hops followed in this chain (used for <20 safety leniency on scoring + >10 recommendation)
	EffectiveLookupCount int // the LookupCount of the final effective/leaf policy (target after its includes); used to award full lookup bonus for valid redirect chains <20 without penalizing the delegation hops themselves
	Issues               []string
	Status               string // "pass", "warn", "fail", "info"
	Message              string

	EarnedPoints int // per-check score contribution (0–MaxPoints)
	MaxPoints    int // maximum points for this check (SPF=20)

	// Hierarchical chain of all followed policies for full visualization.
	// Each entry represents one level in the SPF delegation (published record, redirect target,
	// or include target). The "effective" entry (the one whose *all counts per RFC 7208) is
	// marked. Includes all resulting policy raws at each level.
	SPFChain []SPFChainEntry `json:"spfChain,omitempty"`
}

// SPFChainEntry represents one level in the SPF evaluation chain (for hierarchical display).
type SPFChainEntry struct {
	Level       int    `json:"level"`
	Domain      string `json:"domain"`
	Raw         string `json:"raw"`
	Type        string `json:"type"`                  // "published", "redirect-target", "include"
	IsEffective bool   `json:"isEffective,omitempty"` // true for the policy whose *all actually terminates the evaluation
	Note        string `json:"note,omitempty"`
}

// DMARCResult captures DMARC posture (RFC 7489 assessor in internal/assessor/rfc7489).
type DMARCResult struct {
	Present   bool
	Raw       string
	Version   string
	Policy    string // none, quarantine, reject
	SubPolicy string // sp= (for subdomains)
	Pct       int
	RUA       []string // rua= reporting URIs
	RUF       []string
	ADKIM     string // r or s
	ASPF      string
	FO        string // fo= failure reporting options (when explicitly set)
	RI        int    // ri= reporting interval seconds (when explicitly set)
	SyntaxOK  bool   // true when v=DMARC1 and required tags pass RFC 7489 §6.3 syntax
	Issues    []string
	Status    string
	Message   string

	EarnedPoints int // per-check score contribution (0–MaxPoints)
	MaxPoints    int // maximum points for this check (DMARC=25)
}

// DKIMKeyRecord holds parsed metadata for a discovered DKIM public key (RFC 6376 §3.6.3).
type DKIMKeyRecord struct {
	Selector string
	Version  string
	KeyType  string
	Revoked  bool
	TestKey  bool
	SyntaxOK bool
	Raw      string
}

// DKIMResult ...
type DKIMResult struct {
	SelectorsFound   []string
	SelectorsProbed  int               // total distinct selector names probed during discovery
	RawRecords       map[string]string // selector -> raw DKIM TXT record value (populated by CheckDKIM)
	Keys             []DKIMKeyRecord
	Issues           []string
	Status           string
	Message          string
	WildcardDetected bool
	// DomainKeySubtree is evidence-only: "present" | "absent" | "unknown".
	// Classified via bare _domainkey + canary RCODEs; never awards score points alone.
	DomainKeySubtree string

	EarnedPoints int // per-check score contribution (0–MaxPoints)
	MaxPoints    int // maximum points for this check (DKIM=10)
}

// MTASTSResult ...
type MTASTSResult struct {
	DNSAdvertised  bool
	PolicyFetched  bool
	RawDNSTXT      string
	RawPolicy      string
	Version        string
	Mode           string // enforce, testing, none
	MXPatterns     []string
	MaxAge         int
	MXCoverageOK   bool
	PolicyID       string // id= from _mta-sts DNS TXT (RFC 8461 §3.1)
	DNSIDValid     bool   // id= matches RFC 8461 ABNF (1*32 ALPHA/DIGIT)
	PolicySyntaxOK bool   // version/mode/max_age/mx per RFC 8461 §3.2
	// PolicyFetch is "fetched", "failed", or "not fetched".
	// Empty when MTA-STS is not advertised, so there is nothing to fetch.
	PolicyFetch       string `json:"policyFetch,omitempty"`
	RecommendedPolicy string // RFC 8461 Appendix A style policy body for deployment
	RecommendedDNSTXT string // paired _mta-sts TXT recommendation (id= only in DNS)
	Issues            []string
	Status            string
	Message           string

	EarnedPoints int // per-check score contribution (0–MaxPoints)
	MaxPoints    int // maximum points for this check (MTA-STS=15)
}

// NullMXResult captures null MX posture for the null_mx profile.
type NullMXResult struct {
	Status       string
	Message      string
	Violation    string // None, MixedMX, MultipleMX, WrongPreference, WrongExchange
	Posture      string // MailEnabled, NullMXOnly, MixedInvalid, NoMX
	Issues       []string
	EarnedPoints int
	MaxPoints    int
}

// DNSSECResult ...
type DNSSECResult struct {
	DSPresent     bool
	DNSKEYPresent bool
	DSRecords     []string // raw DS RDATA strings
	AD            bool     // resolver AD bit (same as ResolverAD; legacy JSON field)
	ResolverAD    bool     // AD bit from DoH resolver on probe lookup
	// ADCheck is "observed", "absent", or "n/a".
	// "n/a" means the resolver does not validate, so a missing AD bit is not a failure.
	ADCheck      string `json:"adCheck,omitempty"`
	SyntaxOK     bool   // all published DS records parse cleanly
	TLDSupported bool   // false when parent TLD does not publish DS/DNSKEY
	Issues       []string
	Status       string
	Message      string

	EarnedPoints int // per-check score contribution (0–MaxPoints)
	MaxPoints    int // maximum points for this check (DNSSEC=10 mail / 15 null_mx)
}

// FullyValidated reports DS + DNSKEY published and a trusted DoH resolver reported the AD bit.
// SecLens does not perform its own cryptographic chain validation. JSON field name is unchanged.
func (d *DNSSECResult) FullyValidated() bool {
	if d == nil || !d.DSPresent || !d.DNSKEYPresent {
		return false
	}
	if d.ADCheck == ADCheckNA {
		return true
	}
	return d.ResolverAD || d.AD
}

// TLSARecord holds parsed TLSA RDATA per RFC 6698 §2.1.
type TLSARecord struct {
	Raw          string
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	SyntaxOK     bool
}

// DANEResult ...
type DANEResult struct {
	AdvertisedFor   []string
	Records         map[string][]string     // host -> raw TLSA RDATA strings (for detail)
	ParsedRecords   map[string][]TLSARecord // host -> parsed TLSA records
	MXCovered       bool                    // all MX hosts have valid TLSA
	SyntaxOK        bool                    // every published TLSA record parses cleanly
	DNSSECValidated bool                    // post-enrich: DS+DNSKEY+resolver AD observed (not a live cert match)
	Issues          []string
	Status          string
	Message         string

	EarnedPoints int // per-check score contribution (0–MaxPoints)
	MaxPoints    int // maximum points for this check (DANE=10)
}

// TLSRPTResult ...
type TLSRPTResult struct {
	Present           bool // TLS-RPT TXT advertised at _smtp._tls (may be syntactically invalid)
	Raw               string
	Version           string // v= (e.g. TLSRPTv1)
	RUA               []string
	SyntaxOK          bool   // v=TLSRPTv1; record selected per RFC 8460 §3.1
	RUAPresent        bool   // at least one rua= value parsed
	RecommendedDNSTXT string // recommended _smtp._tls TXT for deployment
	Issues            []string
	Status            string
	Message           string

	EarnedPoints int // per-check score contribution (0–MaxPoints)
	MaxPoints    int // maximum points for this check (TLS-RPT=10)
}

// BIMIResult is the informational BIMI assessment (draft-brand-indicators-for-message-identification).
// It has no point fields. Status is present, declined, absent, or invalid.
type BIMIResult struct {
	Status      string
	Message     string
	DNSName     string
	Queried     []string
	Raw         string
	Version     string
	Location    string
	Evidence    string
	Declined    bool
	SyntaxOK    bool
	Logo        *BIMILogo
	Certificate *BIMICert
	Findings    []string
}

// BIMILogo is a size-capped fetch of the l= document plus SVG Tiny PS hints.
type BIMILogo struct {
	ContentType       string
	Bytes             int
	StartsWithSVG     bool
	BaseProfileTinyPS bool
	Version12         bool
	HasTitle          bool
	HasScript         bool
	Error             string
}

// BIMICert is a parse of the first PEM certificate at a=.
// MarkHint is vmc, cmc, or bimi-eku. Empty means no BIMI EKU and no markType.
type BIMICert struct {
	Subject     string
	Issuer      string
	NotAfter    string
	Expired     bool
	LogotypeExt bool
	BIMIEKU     bool
	MarkHint    string
	Error       string
}
