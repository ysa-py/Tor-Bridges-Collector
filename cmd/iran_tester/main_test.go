package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ysa-py/MICAFP/internal/ipinfo"
	"github.com/ysa-py/MICAFP/internal/ooni"
)

func TestValidateWorkersAcceptsPositiveCounts(t *testing.T) {
	for _, workers := range []int{1, 100} {
		t.Run(fmt.Sprintf("workers_%d", workers), func(t *testing.T) {
			if err := validateWorkers(workers); err != nil {
				t.Fatalf("validateWorkers(%d) returned error: %v", workers, err)
			}
		})
	}
}

func TestValidateWorkersRejectsNonPositiveCounts(t *testing.T) {
	for _, workers := range []int{0, -1} {
		t.Run(fmt.Sprintf("workers_%d", workers), func(t *testing.T) {
			err := validateWorkers(workers)
			if err == nil {
				t.Fatalf("validateWorkers(%d) returned nil error, want validation failure", workers)
			}
			want := fmt.Sprintf("workers must be >= 1, got %d", workers)
			if err.Error() != want {
				t.Fatalf("validateWorkers(%d) error=%q, want %q", workers, err.Error(), want)
			}
		})
	}
}

// TestClassifyURLOnlyWebTunnelNotHardUnreachable covers the regression where
// domain-fronted WebTunnel bridges (URL-only lines, no literal IP:PORT) were
// hard-classified tcp_unreachable by the TCP early-return and therefore never
// reached the WebTunnel classification branch. The front-domain TLS/WebSocket
// probe runs in the Rust results stage, so the tester must emit an inconclusive
// status that the downstream probe can refine — never a terminal
// tcp_unreachable that publication treats as "failing" forever.
func TestClassifyURLOnlyWebTunnelNotHardUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ipClient := ipinfo.New()
	ooniClient := ooni.New()
	defer ooniClient.Close()

	lines := []struct {
		name string
		line string
		transport string
	}{
		{
			name:      "webtunnel_url_only",
			line:      "webtunnel 68674E54A17AEB1C9ADE878BBBB46C6975DD3105 url=https://vika7.space/83c1327ea78e32b5d151e872ca123f7858aec2e1 ver=0.0.4",
			transport: "webtunnel",
		},
		{
			name:      "meek_lite_url_only",
			line:      "meek_lite 97700DFE9F483596DDA6264C4D7DF7641E1E39CE url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com",
			transport: "meek_lite",
		},
	}
	for _, tc := range lines {
		t.Run(tc.name, func(t *testing.T) {
			result := classifyBridge(ctx, tc.line, time.Second, ipClient, ooniClient)
			if result.Transport != tc.transport {
				t.Fatalf("transport=%q, want %q", result.Transport, tc.transport)
			}
			if result.IranStatus == StatusTCPUnreachable {
				t.Fatalf(
					"URL-only fronted transport %q classified tcp_unreachable (host=%q port=%d); want an inconclusive status so the front-domain probe can test it",
					tc.transport, result.Host, result.Port,
				)
			}
		})
	}
}

// A webtunnel bridge with a literal (non-routable) IP endpoint must still
// hard-return tcp_unreachable — the exemption is deliberately narrow to
// endpoint-less, domain-fronted lines.
func TestClassifyWebTunnelLiteralEndpointStillProbed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ipClient := ipinfo.New()
	ooniClient := ooni.New()
	defer ooniClient.Close()

	// 192.0.2.1/24 is TEST-NET-1 and never accepts connections.
	result := classifyBridge(
		ctx,
		"webtunnel 192.0.2.1:443 0000000000000000000000000000000000000000 url=https://example.com/x ver=0.0.3",
		time.Second,
		ipClient,
		ooniClient,
	)
	if result.Host != "192.0.2.1" {
		t.Fatalf("host=%q, want 192.0.2.1", result.Host)
	}
	// TCP probe fails (no route / refused) and the line has a literal
	// endpoint, so the unreachable early-return still applies.
	if result.IranStatus != StatusTCPUnreachable {
		t.Fatalf("status=%q, want %q for literal-endpoint webtunnel", result.IranStatus, StatusTCPUnreachable)
	}
}
