package bridge

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestParse_Vanilla(t *testing.T) {
	line := "1.2.3.4:9999"
	b, err := Parse(line)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if b.Host != "1.2.3.4" || b.Port != 9999 {
		t.Errorf("got host=%s port=%d, want 1.2.3.4:9999", b.Host, b.Port)
	}
	if b.Transport != "vanilla" {
		t.Errorf("got transport=%s, want vanilla", b.Transport)
	}
}

func TestParse_Obfs4(t *testing.T) {
	line := "obfs4 1.2.3.4:9999 cert=test123 iat-mode=0"
	b, err := Parse(line)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if b.Host != "1.2.3.4" || b.Port != 9999 {
		t.Errorf("got host=%s port=%d, want 1.2.3.4:9999", b.Host, b.Port)
	}
	if b.Transport != "obfs4" {
		t.Errorf("got transport=%s, want obfs4", b.Transport)
	}
	if b.Params["cert"] != "test123" {
		t.Errorf("missing or wrong cert parameter")
	}
}

func TestParse_Obfs4DomainPort(t *testing.T) {
	tests := []struct {
		name string
		line string
		host string
		port int
	}{
		{
			name: "cloud TLD with iat-mode",
			line: "obfs4 bridge.example.cloud:443 cert=x iat-mode=0",
			host: "bridge.example.cloud",
			port: 443,
		},
		{
			name: "country-code TLD without iat-mode",
			line: "obfs4 x.y.ir:9001 cert=x",
			host: "x.y.ir",
			port: 9001,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := Parse(tt.line)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}
			if b.Host != tt.host || b.Port != tt.port {
				t.Errorf("got host=%s port=%d, want %s:%d", b.Host, b.Port, tt.host, tt.port)
			}
			if b.Transport != "obfs4" {
				t.Errorf("got transport=%s, want obfs4", b.Transport)
			}
			if b.Params["cert"] != "x" {
				t.Errorf("missing or wrong cert parameter")
			}
		})
	}
}

func TestParse_Obfs4DomainPortValidation(t *testing.T) {
	tests := []string{
		"obfs4 bridge..example.cloud:443 cert=x",
		"obfs4 bridge.example.cloud:0 cert=x",
	}

	for _, line := range tests {
		t.Run(line, func(t *testing.T) {
			if _, err := Parse(line); err == nil {
				t.Fatalf("Parse should fail for %q", line)
			}
		})
	}
}

func TestParse_WebTunnel(t *testing.T) {
	line := "webtunnel 1.2.3.4:443 url=https://example.com key=secret"
	b, err := Parse(line)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if b.Host != "example.com" || b.Port != 443 {
		t.Errorf("got host=%s port=%d, want example.com:443", b.Host, b.Port)
	}
	if b.Transport != "webtunnel" {
		t.Errorf("got transport=%s, want webtunnel", b.Transport)
	}
}

func TestParse_DomainPortWithUnlistedTLDs(t *testing.T) {
	tests := []struct {
		name string
		line string
		host string
		port int
	}{
		{
			name: "cloud TLD with multiple labels",
			line: "bridge.example.cloud:443",
			host: "bridge.example.cloud",
			port: 443,
		},
		{
			name: "country-code TLD with multiple labels",
			line: "x.y.ir:9001",
			host: "x.y.ir",
			port: 9001,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := Parse(tt.line)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}
			if b.Host != tt.host || b.Port != tt.port {
				t.Errorf("got host=%s port=%d, want %s:%d", b.Host, b.Port, tt.host, tt.port)
			}
		})
	}
}

func TestParse_DomainPortValidation(t *testing.T) {
	tests := []string{
		"bridge..example.cloud:443",
		"bridge.example.cloud:0",
		"bridge.example.cloud:65536",
	}

	for _, line := range tests {
		t.Run(line, func(t *testing.T) {
			if _, err := Parse(line); err == nil {
				t.Fatalf("Parse should fail for %q", line)
			}
		})
	}
}

func TestParse_PortValidation(t *testing.T) {
	tests := []string{
		"1.2.3.4:0",
		"1.2.3.4:65536",
		"[2001:db8::1]:0",
		"obfs4 1.2.3.4:99999 cert=x",
		"webtunnel 1.2.3.4:443 url=https://example.com:99999 key=x",
	}

	for _, line := range tests {
		t.Run(line, func(t *testing.T) {
			if _, err := Parse(line); err == nil {
				t.Fatalf("Parse should fail for %q", line)
			}
		})
	}
}

func TestParse_IPv6(t *testing.T) {
	line := "[2001:db8::1]:9999"
	b, err := Parse(line)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if b.Host != "2001:db8::1" || b.Port != 9999 {
		t.Errorf("got host=%s port=%d, want 2001:db8::1:9999", b.Host, b.Port)
	}
}

func TestParse_BridgePrefix(t *testing.T) {
	line := "Bridge 1.2.3.4:9999"
	b, err := Parse(line)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if b.Host != "1.2.3.4" || b.Port != 9999 {
		t.Errorf("got host=%s port=%d, want 1.2.3.4:9999", b.Host, b.Port)
	}
}

func TestParse_Empty(t *testing.T) {
	_, err := Parse("")
	if err == nil {
		t.Error("Parse should fail on empty line")
	}
}

func TestParse_NoPort(t *testing.T) {
	_, err := Parse("1.2.3.4")
	if err == nil {
		t.Error("Parse should fail when port is missing")
	}
}

func TestTestWithContext_Snowflake(t *testing.T) {
	b := &Bridge{Transport: "snowflake"}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	result := TestWithContext(ctx, b, 5*time.Second)
	if !result {
		t.Error("TestWithContext should return true for snowflake")
	}
}

func TestTestWithContext_InvalidBridge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	result := TestWithContext(ctx, nil, 5*time.Second)
	if result {
		t.Error("TestWithContext should return false for nil bridge")
	}
}

func TestTestTLSRequiresTLSHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("not tls"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	addr := listener.Addr().(*net.TCPAddr)
	if testTLS(ctx, "127.0.0.1", addr.Port) {
		t.Fatal("testTLS returned true for a plain TCP listener without a TLS handshake")
	}

	<-done
}
