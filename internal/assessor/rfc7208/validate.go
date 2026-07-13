package rfc7208

import (
	"net"
	"strconv"
	"strings"
)

// isValidSPFTerm returns whether the (qualifier-stripped) mechanism or modifier
// is known per RFC 7208 §5 (Mechanisms) and §6 (Modifiers). Unknown tokens cause PermError.
func isValidSPFTerm(term string) bool {
	lt := strings.ToLower(term)
	switch {
	case lt == "all":
		return true
	case strings.HasPrefix(lt, "include:"):
		return len(lt) > len("include:")
	case lt == "a" || strings.HasPrefix(lt, "a:") || strings.HasPrefix(lt, "a/"):
		return true
	case lt == "mx" || strings.HasPrefix(lt, "mx:") || strings.HasPrefix(lt, "mx/"):
		return true
	case lt == "ptr" || strings.HasPrefix(lt, "ptr:"):
		return true
	case strings.HasPrefix(lt, "ip4:"):
		return len(lt) > len("ip4:") && validateIP4Mechanism(strings.TrimPrefix(lt, "ip4:"))
	case strings.HasPrefix(lt, "ip6:"):
		return len(lt) > len("ip6:") && validateIP6Mechanism(strings.TrimPrefix(lt, "ip6:"))
	case strings.HasPrefix(lt, "exists:"):
		return len(lt) > len("exists:")
	case strings.HasPrefix(lt, "redirect="):
		return len(lt) > len("redirect=")
	case strings.HasPrefix(lt, "exp="):
		return len(lt) > len("exp=")
	}
	return false
}

// validateIP4Mechanism validates the value after ip4: per RFC 7208 §5.6.
func validateIP4Mechanism(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	ipStr, prefixStr := splitNetworkPrefix(value)
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		return false
	}
	if prefixStr == "" {
		return true
	}
	prefix, err := strconv.Atoi(prefixStr)
	return err == nil && prefix >= 0 && prefix <= 32
}

// validateIP6Mechanism validates the value after ip6: per RFC 7208 §5.6.
func validateIP6Mechanism(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	ipStr, prefixStr := splitNetworkPrefix(value)
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() != nil {
		return false
	}
	if prefixStr == "" {
		return true
	}
	prefix, err := strconv.Atoi(prefixStr)
	return err == nil && prefix >= 0 && prefix <= 128
}

func splitNetworkPrefix(value string) (ipStr, prefixStr string) {
	if i := strings.Index(value, "/"); i >= 0 {
		return strings.TrimSpace(value[:i]), strings.TrimSpace(value[i+1:])
	}
	return value, ""
}

// validateDomainSpec reports whether a domain-spec in a mechanism/modifier is syntactically valid.
func validateDomainSpec(domain string, gate Gate) bool {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return false
	}
	return gate.ValidMechanismDomain(domain)
}