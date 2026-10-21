package bimi

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"strings"
	"time"

	"seclens/internal/report"
)

var (
	oidLogotype = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 12}
	oidBIMIEKU  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 31}
	// markType is the BIMI Group subject attribute that distinguishes mark classes.
	// The shared BIMI EKU does not.
	oidMarkType = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 53087, 1, 13}
)

// InspectCert parses the first CERTIFICATE block. now decides Expired.
func InspectCert(pemBytes []byte, now time.Time) report.BIMICert {
	var out report.BIMICert
	block := firstCertBlock(pemBytes)
	if block == nil {
		out.Error = "no PEM CERTIFICATE block"
		return out
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		out.Error = "certificate parse: " + err.Error()
		return out
	}
	out.Subject = cert.Subject.String()
	out.Issuer = cert.Issuer.String()
	out.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	out.Expired = now.After(cert.NotAfter)
	out.LogotypeExt = hasExt(cert, oidLogotype)
	out.BIMIEKU = hasEKU(cert, oidBIMIEKU)
	out.MarkHint = markHint(cert, out.BIMIEKU)
	return out
}

func firstCertBlock(pemBytes []byte) *pem.Block {
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil
		}
		if block.Type == "CERTIFICATE" {
			return block
		}
	}
}

func hasExt(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func hasEKU(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, id := range cert.UnknownExtKeyUsage {
		if id.Equal(oid) {
			return true
		}
	}
	// Go files known key-purposes on ExtKeyUsage and leaves this OID in the
	// raw extension when the template set it explicitly.
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}) {
			continue
		}
		var oids []asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(ext.Value, &oids); err != nil {
			return false
		}
		for _, id := range oids {
			if id.Equal(oid) {
				return true
			}
		}
	}
	return false
}

func markHint(cert *x509.Certificate, eku bool) string {
	for _, atv := range cert.Subject.Names {
		if !atv.Type.Equal(oidMarkType) {
			continue
		}
		text, ok := atv.Value.(string)
		if !ok {
			continue
		}
		if hint := classifyMark(text); hint != "" {
			return hint
		}
	}
	if eku {
		return "bimi-eku"
	}
	return ""
}

func classifyMark(text string) string {
	s := strings.ToLower(text)
	switch {
	case strings.Contains(s, "prior use"), strings.Contains(s, "modified registered"):
		return "cmc"
	case strings.Contains(s, "registered mark"), strings.Contains(s, "government mark"):
		return "vmc"
	default:
		return ""
	}
}

func certFindings(c report.BIMICert) []string {
	if c.Error != "" {
		return []string{"certificate: " + c.Error}
	}
	var out []string
	if !c.LogotypeExt {
		out = append(out, "logotype extension 1.3.6.1.5.5.7.1.12 absent")
	}
	if !c.BIMIEKU {
		out = append(out, "BIMI EKU 1.3.6.1.5.5.7.3.31 absent")
	}
	if c.BIMIEKU && c.MarkHint == "bimi-eku" {
		out = append(out, "BIMI EKU present; markType does not say VMC or CMC")
	}
	if c.Expired {
		out = append(out, "certificate expired "+c.NotAfter)
	}
	return out
}
