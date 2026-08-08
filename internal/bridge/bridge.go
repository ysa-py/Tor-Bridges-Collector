// Package bridge provides bridge-line parsing and normalization for Tor
// pluggable transports, including dual-stack IPv4/IPv6 WebTunnel support
// and v2.6.0 modern protocol dispatch (VLESS+REALITY, Hysteria2, TUIC v5,
// ShadowTLS v3).
package bridge

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// ipv6PortRE matches literal bracketed IPv6 endpoints: [2001:db8::1]:443
var ipv6PortRE = regexp.MustCompile(`^\[([0-9a-fA-F:]{2,39})\]:(\d{1,5})$`)

// ipv4PortRE matches literal IPv4 endpoints: 192.0.2.1:443
var ipv4PortRE = regexp.MustCompile(`^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$`)

// fqdnPortRE matches FQDN:PORT endpoints: cdn.example.com:443
var fqdnPortRE = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}):(\d{1,5})$`)

// Transport is a parsed bridge-line transport descriptor.
type Transport struct {
	// Type is the transport protocol name (e.g. "webtunnel", "obfs4").
	Type string
	// Host is the literal IP address or DNS hostname.
	Host string
	// Port is the TCP port.
	Port uint16
	// AddressFamily is "ipv4", "ipv6", or "dns".
	AddressFamily string
	// Params holds key=value tokens extracted from the bridge line
	// (url=, ver=, cert=, iat-mode=, fingerprint, etc.).
	Params map[string]string
	// Raw is the original, unmodified bridge line.
	Raw string
}

// parseWebTransport parses a WebTunnel bridge line into a Transport.
//
// Supported syntaxes:
//
//	webtunnel 192.0.2.1:443 FINGERPRINT url=https://example.com/path ver=0.0.4
//	webtunnel [2001:db8::1]:443 FINGERPRINT url=https://example.com/path ver=0.0.4
//	webtunnel cdn.example.com:443 FINGERPRINT url=https://backend.example.com ver=0.0.4
//	webtunnel FINGERPRINT url=https://example.com/path ver=0.0.4
//
// The literal IP:PORT (or [IPv6]:PORT or FQDN:PORT) token takes precedence
// over the url= host. URL-only WebTunnel lines (no literal endpoint) are
// accepted — the url= host serves as the implicit endpoint.
func parseWebTransport(raw string) (*Transport, error) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, fmt.Errorf("empty or comment line")
	}

	// Strip optional "Bridge " prefix.
	line = strings.TrimPrefix(line, "Bridge ")
	line = strings.TrimSpace(line)

	tokens := strings.Fields(line)
	if len(tokens) < 2 {
		return nil, fmt.Errorf("too few tokens in WebTunnel line")
	}

	transportType := strings.ToLower(tokens[0])
	if transportType != "webtunnel" {
		return nil, fmt.Errorf("not a webtunnel line: %s", transportType)
	}

	t := &Transport{
		Type:   transportType,
		Raw:    raw,
		Params: make(map[string]string),
	}

	// Scan tokens for endpoint and key=value pairs.
	foundEndpoint := false
	for i := 1; i < len(tokens); i++ {
		tok := tokens[i]

		// key=value token
		if strings.Contains(tok, "=") {
			parts := strings.SplitN(tok, "=", 2)
			key := strings.ToLower(strings.TrimSpace(parts[0]))
			val := strings.Trim(strings.TrimSpace(parts[1]), "\"")
			t.Params[key] = val
			continue
		}

		// Skip if we already found the endpoint or this is clearly not one.
		if foundEndpoint {
			continue
		}

		// Try IPv6: [addr]:port
		if matches := ipv6PortRE.FindStringSubmatch(tok); len(matches) == 3 {
			host := matches[1]
			port, err := strconv.ParseUint(matches[2], 10, 16)
			if err != nil || port == 0 {
				continue
			}
			// Validate the IPv6 address.
			if ip := net.ParseIP(host); ip == nil || ip.To16() == nil {
				continue
			}
			t.Host = host
			t.Port = uint16(port)
			t.AddressFamily = "ipv6"
			foundEndpoint = true
			continue
		}

		// Try IPv4: addr:port
		if matches := ipv4PortRE.FindStringSubmatch(tok); len(matches) == 3 {
			host := matches[1]
			port, err := strconv.ParseUint(matches[2], 10, 16)
			if err != nil || port == 0 {
				continue
			}
			if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
				t.Host = host
				t.Port = uint16(port)
				t.AddressFamily = "ipv4"
				foundEndpoint = true
				continue
			}
		}

		// Try FQDN:PORT: subdomain.domain.tld:443
		if matches := fqdnPortRE.FindStringSubmatch(tok); len(matches) == 4 {
			host := matches[1]
			port, err := strconv.ParseUint(matches[3], 10, 16)
			if err != nil || port == 0 {
				continue
			}
			if isDNSName(host) {
				t.Host = host
				t.Port = uint16(port)
				t.AddressFamily = "dns"
				foundEndpoint = true
				continue
			}
		}
	}

	// If no literal endpoint found, accept URL-only WebTunnel lines.
	if !foundEndpoint {
		if _, ok := t.Params["url"]; !ok {
			return nil, fmt.Errorf("WebTunnel line has no literal endpoint and no url= parameter")
		}
		t.AddressFamily = "dns"
	}

	return t, nil
}

// ── v2.6.0 Modern protocol URI parsers ────────────────────────────────

// parseVlessReality parses a VLESS+REALITY URI.
// Format: vless://UUID@HOST:PORT?security=reality&pbk=...&sid=...&fp=...&sni=...&flow=...&type=...
func parseVlessReality(raw string) (*Transport, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("transport=vless reason=invalid_uri: %v", err)
	}
	if u.Scheme != "vless" {
		return nil, fmt.Errorf("transport=vless reason=wrong_scheme")
	}
	host, port, af := splitHostPort(u.Host)
	t := &Transport{
		Type:          "vless",
		Host:          host,
		Port:          port,
		AddressFamily: af,
		Raw:           raw,
		Params:        make(map[string]string),
	}
	for k, v := range u.Query() {
		t.Params[strings.ToLower(k)] = strings.Join(v, ",")
	}
	return t, nil
}

// parseHysteria2 parses a Hysteria2 URI.
// Format: hysteria2://PASSWORD@HOST:PORT?sni=...&obfs=...&obfs-password=...
func parseHysteria2(raw string) (*Transport, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("transport=hysteria2 reason=invalid_uri: %v", err)
	}
	host, port, af := splitHostPort(u.Host)
	t := &Transport{
		Type:          "hysteria2",
		Host:          host,
		Port:          port,
		AddressFamily: af,
		Raw:           raw,
		Params:        make(map[string]string),
	}
	if u.User != nil {
		t.Params["auth"] = u.User.String()
	}
	for k, v := range u.Query() {
		t.Params[strings.ToLower(k)] = strings.Join(v, ",")
	}
	return t, nil
}

// parseTuicV5 parses a TUIC v5 URI.
// Format: tuic://UUID:PASSWORD@HOST:PORT?congestion_control=...&alpn=...&sni=...
func parseTuicV5(raw string) (*Transport, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("transport=tuic reason=invalid_uri: %v", err)
	}
	if u.Scheme != "tuic" {
		return nil, fmt.Errorf("transport=tuic reason=wrong_scheme")
	}
	host, port, af := splitHostPort(u.Host)
	t := &Transport{
		Type:          "tuic",
		Host:          host,
		Port:          port,
		AddressFamily: af,
		Raw:           raw,
		Params:        make(map[string]string),
	}
	if u.User != nil {
		t.Params["uuid"] = u.User.Username()
		if pwd, ok := u.User.Password(); ok {
			t.Params["password"] = pwd
		}
	}
	for k, v := range u.Query() {
		t.Params[strings.ToLower(k)] = strings.Join(v, ",")
	}
	return t, nil
}

// parseShadowTLS parses a ShadowTLS v3 URI.
// Format: shadow-tls://HOST:PORT?sni=...&password=...&version=3
func parseShadowTLS(raw string) (*Transport, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("transport=shadowtls reason=invalid_uri: %v", err)
	}
	host, port, af := splitHostPort(u.Host)
	t := &Transport{
		Type:          "shadow-tls",
		Host:          host,
		Port:          port,
		AddressFamily: af,
		Raw:           raw,
		Params:        make(map[string]string),
	}
	for k, v := range u.Query() {
		t.Params[strings.ToLower(k)] = strings.Join(v, ",")
	}
	return t, nil
}

// splitHostPort splits an authority component into host, port, and
// address family. Handles IPv4, bracketed IPv6, and bare hostnames.
func splitHostPort(authority string) (string, uint16, string) {
	host, portStr, err := net.SplitHostPort(authority)
	if err != nil {
		// No port in the authority; use host as-is with port 0.
		host = authority
		if ip := net.ParseIP(host); ip != nil {
			if ip.To4() != nil {
				return host, 0, "ipv4"
			}
			return host, 0, "ipv6"
		}
		return host, 0, "dns"
	}
	port, _ := strconv.ParseUint(portStr, 10, 16)
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return host, uint16(port), "ipv4"
		}
		return host, uint16(port), "ipv6"
	}
	return host, uint16(port), "dns"
}

// isDNSName returns true if host looks like a DNS name.
func isDNSName(host string) bool {
	if !strings.Contains(host, ".") {
		return false
	}
	for _, r := range host {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// ── v2.6.0 parseTransportLine — transport-aware URI dispatch ─────────

// parseTransportLine detects the transport type from a scheme-prefixed
// URI and dispatches to the appropriate structural parser. Returns nil
// if the line does not start with a known transport scheme — callers
// should fall back to ParseLine for token-based parsing.
// Never exposes credentials in error messages.
func parseTransportLine(raw string) (*Transport, error) {
	line := strings.TrimSpace(raw)
	if line == "" {
		return nil, fmt.Errorf("empty line")
	}
	lower := strings.ToLower(line)
	switch {
	case strings.HasPrefix(lower, "vless://"):
		return parseVlessReality(raw)
	case strings.HasPrefix(lower, "hysteria2://"), strings.HasPrefix(lower, "hysteria://"):
		return parseHysteria2(raw)
	case strings.HasPrefix(lower, "tuic://"):
		return parseTuicV5(raw)
	case strings.HasPrefix(lower, "shadow-tls://"):
		return parseShadowTLS(raw)
	default:
		return nil, nil // Not a URI-based transport; caller try ParseLine
	}
}

// ParseLine detects the transport type and dispatches to the appropriate parser.
// v2.6.0: tries parseTransportLine first for URI-based modern protocols.
func ParseLine(line string) (*Transport, error) {
	// v2.6.0: try URI-based modern protocol dispatch first
	if tr, err := parseTransportLine(line); err != nil || tr != nil {
		return tr, err
	}

	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil, fmt.Errorf("empty or comment")
	}

	// Strip optional "Bridge " prefix.
	trimmed = strings.TrimPrefix(trimmed, "Bridge ")
	trimmed = strings.TrimSpace(trimmed)

	if trimmed == "" {
		return nil, fmt.Errorf("empty after prefix strip")
	}

	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "webtunnel") {
		return parseWebTransport(line)
	}

	// For non-WebTunnel lines, do basic extraction.
	t := &Transport{
		Raw:    line,
		Params: make(map[string]string),
	}
	tokens := strings.Fields(trimmed)
	if len(tokens) > 0 {
		t.Type = strings.ToLower(tokens[0])
	}

	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]

		if strings.Contains(tok, "=") {
			parts := strings.SplitN(tok, "=", 2)
			key := strings.ToLower(strings.TrimSpace(parts[0]))
			val := strings.Trim(strings.TrimSpace(parts[1]), "\"")
			t.Params[key] = val
			continue
		}

		// IPv6 [addr]:port
		if matches := ipv6PortRE.FindStringSubmatch(tok); len(matches) == 3 {
			port, _ := strconv.ParseUint(matches[2], 10, 16)
			if port > 0 {
				t.Host = matches[1]
				t.Port = uint16(port)
				t.AddressFamily = "ipv6"
				break
			}
		}

		// IPv4 addr:port
		if matches := ipv4PortRE.FindStringSubmatch(tok); len(matches) == 3 {
			port, _ := strconv.ParseUint(matches[2], 10, 16)
			if port > 0 {
				t.Host = matches[1]
				t.Port = uint16(port)
				if net.ParseIP(matches[1]) != nil && net.ParseIP(matches[1]).To4() != nil {
					t.AddressFamily = "ipv4"
				}
				break
			}
		}

		// FQDN:PORT
		if matches := fqdnPortRE.FindStringSubmatch(tok); len(matches) == 4 {
			port, _ := strconv.ParseUint(matches[3], 10, 16)
			if port > 0 && isDNSName(matches[1]) {
				t.Host = matches[1]
				t.Port = uint16(port)
				t.AddressFamily = "dns"
				break
			}
		}
	}

	return t, nil
}
