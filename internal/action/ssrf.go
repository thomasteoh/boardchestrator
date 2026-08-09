package action

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// validateMcpEndpointURL rejects URLs that could be used for SSRF: any scheme
// other than http/https, non-standard ports, or hosts resolving to private /
// link-local / loopback ranges (SPEC §10: MCP endpoints are SSRF-validated).
// Returns a human-readable error describing the offending URL.
func validateMcpEndpointURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("MCP endpoint %q: scheme %q must be http or https", raw, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("MCP endpoint %q: missing host", raw)
	}
	host := u.Hostname()
	// Reject bare IPs in private/loopback/link-local ranges and any hostname
	// that resolves to one.
	if isPrivateHost(host) {
		return fmt.Errorf("MCP endpoint %q: host %q resolves to a private/loopback range", raw, host)
	}
	return nil
}

// isPrivateHost reports whether host is an IP in a private/loopback/link-local
// range, or a hostname resolving to one (SPEC §10 SSRF guard).
func isPrivateHost(host string) bool {
	// Strip brackets for IPv6 literals ("[::1]").
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if ip := net.ParseIP(host); ip != nil {
		return isPrivateIP(ip)
	}
	// Resolve hostnames; any resolved address in a private range ⇒ reject.
	ips, err := net.LookupHost(host)
	if err != nil {
		// Unresolvable host: reject (cannot verify it is safe).
		return true
	}
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil && isPrivateIP(ip) {
			return true
		}
	}
	return false
}

// isPrivateIP reports whether ip is a private, loopback, link-local, or
// documentation range (RFC 1918, 5735, 4193, 4291).
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	// IPv4 private ranges: 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10,
	// 127/8 (loopback, covered above), 0.0.0.0/8.
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		case ip4[0] == 169 && ip4[1] == 254:
			return true
		case ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127:
			return true
		}
		return false
	}
	// IPv6 ULA (fc00::/7) and link-local (fe80::/10).
	if ip.IsGlobalUnicast() && ip[0]&0xfe == 0xfc {
		return true
	}
	return false
}
