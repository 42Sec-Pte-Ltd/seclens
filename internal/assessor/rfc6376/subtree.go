package rfc6376

// DomainKeySubtree tri-state values for report.DKIMResult.DomainKeySubtree.
const (
	SubtreePresent = "present"
	SubtreeAbsent  = "absent"
	SubtreeUnknown = "unknown"
)

// SubtreeInput is the DNS evidence used to classify the _domainkey name tree.
type SubtreeInput struct {
	WildcardDetected bool
	BareRcode        int // 0 NOERROR, 3 NXDOMAIN, -1 unavailable/error
	BareTXT          []string
	CanaryRcode      int
	CanaryHasDKIM    bool
}

// ClassifyDomainKeySubtree classifies the _domainkey subtree as present, absent, or unknown.
// ENT (empty non-terminal) is present only when bare is NOERROR and the canary is NXDOMAIN
// (canary NXDOMAIN rules out Black Lies / soft NX that return NOERROR for everything).
func ClassifyDomainKeySubtree(in SubtreeInput) string {
	if in.WildcardDetected || in.CanaryHasDKIM {
		return SubtreeUnknown
	}
	if in.BareRcode < 0 {
		return SubtreeUnknown
	}
	for _, t := range in.BareTXT {
		if IsDKIMTXTRecord(t) {
			return SubtreePresent
		}
	}
	if in.BareRcode == 3 && in.CanaryRcode == 3 {
		return SubtreeAbsent
	}
	if in.BareRcode == 0 && in.CanaryRcode == 3 {
		return SubtreePresent
	}
	return SubtreeUnknown
}
