// Package bridge provides parsing and testing for Tor bridge lines.
// Supports vanilla, obfs4, webtunnel, meek_lite, and snowflake transports.
package bridge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Bridge represents a parsed Tor bridge line with extracted connection details.
type Bridge struct {
	Host      string // IP address or hostname
	Port      int    // Port number
	Transport string // Transport: vanilla, obfs4, webtunnel, meek_lite, snowflake
	Line      string // Original bridge line
	// Transport-specific fields
	Fingerprint string            // obfs4 fingerprint
	Params      map[string]string // Additional transport parameters
}

var (
	// IPv6 [addr]:port pattern
	ipv6PortRE = regexp.MustCompile(`\[([0-9a-fA-F:]+)\]:(\d+)`)
	// IPv4 addr:port pattern
	ipv4PortRE = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3}):(\d+)`)
	// HTTPS URL pattern
	httpsRE = regexp.MustCompile(`https?://([^/:\s]+)(?::(\d+))?`)
	// Domain:port pattern
	domainPortRE = regexp.MustCompile(`^((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}):(\d+)$`)
)

// Parse parses a bridge line and returns a Bridge struct or an error.
// Supports bridge lines in the format:
//   - "Bridge vanilla <IP>:<PORT>"
//   - "Bridge obfs4 <IP>:<PORT> cert=... iat-mode=..."
//   - "Bridge webtunnel <IP>:<PORT> url=https://... key=..."
//   - "Bridge meek_lite <IP>:<PORT> url=https://..."
//   - "Bridge snowflake ..."
//   - Plain strings like "<IP>:<PORT>" or "obfs4 <IP>:<PORT> ..."
func Parse(line string) (*Bridge, error) {
	if line == "" {
		return nil, errors.New("empty bridge line")
	}

	line = strings.TrimSpace(line)
	original := line

	// Remove "Bridge " prefix if present
	if strings.HasPrefix(line, "Bridge ") {
		line = strings.TrimPrefix(line, "Bridge ")
	}

	b := &Bridge{
		Line:   original,
		Params: make(map[string]string),
	}

	// Detect transport type
	transport := detectTransport(line)
	b.Transport = transport

	// Parse based on transport
	switch transport {
	case "snowflake":
		// Snowflake doesn't have a direct IP:port; it's handled specially
		return b, nil

	case "webtunnel", "meek_lite":
		// These use HTTPS URLs; extract from url=https://...
		if err := parseWebTransport(line, b); err != nil {
			return nil, err
		}

	case "obfs4":
		if err := parseObfs4(line, b); err != nil {
			return nil, err
		}

	default: // vanilla or unknown
		if err := parseVanilla(line, b); err != nil {
			return nil, err
		}
	}

	// Validate required fields
	if b.Host == "" || b.Port == 0 {
		return nil, fmt.Errorf("could not extract host:port from bridge line")
	}

	return b, nil
}

// detectTransport determines the transport type from the bridge line.
func detectTransport(line string) string {
	l := strings.ToLower(line)
	if strings.Contains(l, "snowflake") {
		return "snowflake"
	}
	if strings.Contains(l, "webtunnel") || strings.Contains(l, "url=https") {
		return "webtunnel"
	}
	if strings.Contains(l, "obfs4") {
		return "obfs4"
	}
	if strings.Contains(l, "meek") {
		return "meek_lite"
	}
	return "vanilla"
}

// parseVanilla parses vanilla or obfs4 bridge lines with direct IP:port.
func parseVanilla(line string, b *Bridge) error {
	// Remove transport name if present (e.g., "obfs4 <IP>:<PORT> ...")
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return errors.New("empty bridge line")
	}

	// Skip transport name if it's at the start
	idx := 0
	if parts[0] == "vanilla" || parts[0] == b.Transport {
		idx = 1
	}

	if idx >= len(parts) {
		return errors.New("no address found after transport")
	}

	// Try to parse IPv6 [addr]:port
	m := ipv6PortRE.FindStringSubmatch(parts[idx])
	if m != nil {
		port, err := parsePort(m[2])
		if err != nil {
			return err
		}
		b.Host = m[1]
		b.Port = port
		parseTransportParams(parts[idx+1:], b)
		return nil
	}

	// Try to parse IPv4 addr:port
	m = ipv4PortRE.FindStringSubmatch(parts[idx])
	if m != nil {
		port, err := parsePort(m[2])
		if err != nil {
			return err
		}
		b.Host = m[1]
		b.Port = port
		parseTransportParams(parts[idx+1:], b)
		return nil
	}

	// Try to parse domain:port
	m = domainPortRE.FindStringSubmatch(parts[idx])
	if m != nil {
		if err := validateDomain(m[1]); err != nil {
			return err
		}
		port, err := parsePort(m[2])
		if err != nil {
			return err
		}
		b.Host = m[1]
		b.Port = port
		parseTransportParams(parts[idx+1:], b)
		return nil
	}

	return errors.New("could not parse address:port")
}

// validateDomain verifies hostname labels after domainPortRE matches.
func validateDomain(host string) error {
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("invalid domain: empty label in %s", host)
		}
	}

	return nil
}

// parsePort parses and validates a TCP port number.
func parsePort(raw string) (int, error) {
	port, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid port: %s", raw)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port out of range: %d", port)
	}

	return port, nil
}

// parseObfs4 parses obfs4 bridge lines.
func parseObfs4(line string, b *Bridge) error {
	// Remove "obfs4" prefix if present
	if strings.HasPrefix(line, "obfs4 ") {
		line = strings.TrimPrefix(line, "obfs4 ")
	}

	// First token should be IP:port
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return errors.New("empty obfs4 line")
	}

	// Parse host:port
	addrStr := parts[0]
	m := ipv6PortRE.FindStringSubmatch(addrStr)
	if m == nil {
		m = ipv4PortRE.FindStringSubmatch(addrStr)
	}
	if m == nil {
		m = domainPortRE.FindStringSubmatch(addrStr)
		if m != nil {
			if err := validateDomain(m[1]); err != nil {
				return err
			}
		}
	}

	if m == nil {
		return fmt.Errorf("invalid obfs4 address: %s", addrStr)
	}

	port, err := parsePort(m[2])
	if err != nil {
		return err
	}
	b.Host = m[1]
	b.Port = port

	// Parse key=value parameters (cert, iat-mode, etc.)
	for i := 1; i < len(parts); i++ {
		if strings.Contains(parts[i], "=") {
			kv := strings.SplitN(parts[i], "=", 2)
			if len(kv) == 2 {
				key := kv[0]
				val := kv[1]
				b.Params[key] = val
				if key == "cert" {
					b.Fingerprint = val
				}
			}
		}
	}

	return nil
}

// parseWebTransport parses webtunnel and meek_lite bridge lines.
func parseWebTransport(line string, b *Bridge) error {
	// Look for "url=https://host:port" or "url=https://host"
	m := httpsRE.FindStringSubmatch(line)
	if m == nil {
		return errors.New("no HTTPS URL found in webtunnel/meek_lite line")
	}

	b.Host = m[1]
	if m[2] != "" {
		port, err := parsePort(m[2])
		if err != nil {
			return fmt.Errorf("invalid port in URL: %w", err)
		}
		b.Port = port
	} else {
		b.Port = 443 // Default HTTPS port
	}

	// Parse key=value parameters
	parseTransportParams(strings.Fields(line), b)

	return nil
}

// parseTransportParams extracts key=value parameters from bridge line tokens.
func parseTransportParams(parts []string, b *Bridge) {
	for _, part := range parts {
		if strings.Contains(part, "=") {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				b.Params[kv[0]] = kv[1]
			}
		}
	}
}

// TestWithContext performs a TCP connectivity test to the bridge.
// Returns true if the bridge is reachable, false otherwise.
// The test is context-aware: if the context is cancelled, it returns immediately.
func TestWithContext(ctx context.Context, b *Bridge, timeout time.Duration) bool {
	if b == nil {
		return false
	}

	// Snowflake uses WebRTC; cannot test with plain TCP
	if b.Transport == "snowflake" {
		return true // Assume snowflake is available; it's hard to test
	}

	// Create a timeout context
	testCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Resolve hostname if needed
	host := b.Host
	if !isIP(host) {
		resolved, err := net.DefaultResolver.LookupHost(testCtx, host)
		if err != nil || len(resolved) == 0 {
			return false
		}
		host = resolved[0]
	}

	// For webtunnel and meek_lite, try TLS handshake; otherwise plain TCP
	if b.Transport == "webtunnel" || b.Transport == "meek_lite" {
		return testTLS(testCtx, host, b.Port)
	}

	return testTCP(testCtx, host, b.Port)
}

// testTCP attempts a plain TCP connection.
func testTCP(ctx context.Context, host string, port int) bool {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// testTLS attempts a TLS handshake.
func testTLS(ctx context.Context, host string, port int) bool {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Keep certificate verification enabled for TLS probes. This function is used
	// to distinguish real TLS endpoints from plain TCP listeners, and callers that
	// need unauthenticated probing should add an explicit, separately configured
	// probe mode instead of silently disabling verification here.
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})

	return tlsConn.HandshakeContext(ctx) == nil
}

// isIP checks if a string is a valid IP address.
func isIP(host string) bool {
	return net.ParseIP(host) != nil
}
