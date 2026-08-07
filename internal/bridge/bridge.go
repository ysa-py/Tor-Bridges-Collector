// Package bridge provides bridge-line parsing and normalization for Tor
// pluggable transports, including dual-stack IPv4/IPv6 WebTunnel support.
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
//
// The literal IP:PORT (or [IPv6]:PORT) token takes precedence over the
// url= host. URL-only WebTunnel lines return an error.
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
			// Could be a DNS name with port
			if isDNSName(host) {
				t.Host = host
				t.Port = uint16(port)
				t.AddressFamily = "dns"
				foundEndpoint = true
				continue
			}
		}
	}

	// If no literal endpoint found, reject the line.
	// URL-only WebTunnel lines are not valid — a literal IP:PORT endpoint
	// is mandatory (matching the Rust collector's is_valid_bridge_line behavior).
	if !foundEndpoint {
		if _, ok := t.Params["url"]; !ok {
			return nil, fmt.Errorf("WebTunnel line has no literal endpoint and no url= parameter")
		}
		return nil, fmt.Errorf("WebTunnel line has no literal IP:PORT endpoint (url= host is not sufficient)")
	}

	return t, nil
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

// ParseLine detects the transport type and dispatches to the appropriate parser.
func ParseLine(line string) (*Transport, error) {
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

	// Try IPv6 first, then IPv4.
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
				} else if isDNSName(matches[1]) {
					t.AddressFamily = "dns"
				}
				break
			}
		}
	}

	return t, nil
}
