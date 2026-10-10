package main

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/ysa-py/MICAFP/internal/bridge"
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

func TestTCPProbeRecordsTypedStageAndVantage(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for local probe fixture: %v", err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	transport := &bridge.Transport{Type: "obfs4", Host: "127.0.0.1", Port: port}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	observation := tcpProbeWithContext(ctx, transport, time.Second)
	if !observation.Reachable || observation.Status != "connected" {
		t.Fatalf("unexpected local TCP observation: %#v", observation)
	}
	if observation.Stage != "S1" || observation.Vantage == nil || observation.Vantage.Type != "github_actions_runner" {
		t.Fatalf("TCP observation lacks typed stage/vantage: %#v", observation)
	}
	if observation.RTTMS == nil || *observation.RTTMS < 0 {
		t.Fatalf("successful TCP observation lacks non-negative RTT: %#v", observation)
	}

	noEndpoint := tcpProbeWithContext(ctx, &bridge.Transport{Type: "webtunnel"}, time.Second)
	if noEndpoint.Status != "inconclusive" || noEndpoint.Stage != "S0" || noEndpoint.Vantage != nil {
		t.Fatalf("endpoint-less URL transport must be inconclusive without a vantage: %#v", noEndpoint)
	}
}

func TestFrontedAndSnowflakeTCPDoesNotClaimIranWorking(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, line := range []string{
		"snowflake 68674E54A17AEB1C9ADE878BBBB46C6975DD3105 url=https://front.example/",
		"webtunnel 68674E54A17AEB1C9ADE878BBBB46C6975DD3106 url=https://front.example/",
	} {
		result := classifyBridge(ctx, line, time.Second, nil, nil)
		if result.IranStatus == StatusIranLikelyWorking {
			t.Fatalf("generic non-Iran vantage promoted %q to Iran-working", result.Transport)
		}
		if result.Verification.Status != "inconclusive" || result.Verification.Stage != "S0" || result.Verification.Vantage != nil {
			t.Fatalf("endpoint-less fronted transport should remain untested: %#v", result.Verification)
		}
	}
}

type stubIPInfoLookup struct {
	response *ipinfo.Response
	calls    int
}

func (s *stubIPInfoLookup) Lookup(_ context.Context, _ string) (*ipinfo.Response, error) {
	s.calls++
	return s.response, nil
}

type stubOONIClassifier struct {
	status         ooni.OONIStatus
	rate           float64
	checked        bool
	recentAt       string
	historicalAt   string
	calls          int
}

func (s *stubOONIClassifier) Classify(_ context.Context, _ string) (ooni.OONIStatus, float64, bool) {
	s.calls++
	return s.status, s.rate, s.checked
}

func (s *stubOONIClassifier) LatestRecentMeasurementAt(_ string) (string, bool) {
	return s.recentAt, s.recentAt != ""
}

func (s *stubOONIClassifier) LatestTemporalMeasurementAt(_ string) (string, bool) {
	return s.historicalAt, s.historicalAt != ""
}

func TestRunnerTCPFailureDoesNotSuppressIranOONIAssessment(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen to reserve a local test port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("close reserved test listener: %v", err)
	}

	ipClient := &stubIPInfoLookup{response: &ipinfo.Response{
		IP: "127.0.0.1", Org: "AS12345 Test Network", Country: "DE",
	}}
	ooniClient := &stubOONIClassifier{
		status: ooni.StatusLikelyWorking, rate: 0, checked: true,
		recentAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	line := fmt.Sprintf("obfs4 127.0.0.1:%d cert=abc iat-mode=2", port)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := classifyBridge(ctx, line, time.Second, ipClient, ooniClient)

	if result.Verification.Status != "refused" && result.Verification.Status != "error" {
		t.Fatalf("expected a local runner-side TCP failure, got %#v", result.Verification)
	}
	if result.Verification.Stage != "S0" || result.Verification.Vantage == nil || result.Verification.Vantage.Type != "github_actions_runner" {
		t.Fatalf("failed TCP attempt must remain S0 with runner vantage: %#v", result.Verification)
	}
	if result.IranStatus != StatusIranLikelyWorking {
		t.Fatalf("Iran status=%q, want OONI-backed working despite runner TCP failure", result.IranStatus)
	}
	if result.IranAssessment == nil || result.IranAssessment.Vantage.Country != "IR" {
		t.Fatalf("missing OONI Iranian-vantage provenance: %#v", result.IranAssessment)
	}
	if result.IranAssessment.MeasurementAt != ooniClient.recentAt || result.IranAssessment.MeasurementWindowDays != 7 {
		t.Fatalf("original recent OONI measurement provenance was not retained: %#v", result.IranAssessment)
	}
	if ipClient.calls != 1 || ooniClient.calls != 1 {
		t.Fatalf("expected independent ASN/OONI checks (ipinfo=%d OONI=%d)", ipClient.calls, ooniClient.calls)
	}
}

func TestOONIStatusWithoutOriginalMeasurementTimeIsNotCurrentEvidence(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen to reserve a local test port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("close reserved test listener: %v", err)
	}

	ooniClient := &stubOONIClassifier{
		status: ooni.StatusLikelyWorking, checked: true,
	}
	line := fmt.Sprintf("obfs4 127.0.0.1:%d cert=abc iat-mode=2", port)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := classifyBridge(ctx, line, time.Second, nil, ooniClient)

	if result.IranStatus != StatusIranUnknown {
		t.Fatalf("status without original measurement time must stay unknown, got %q", result.IranStatus)
	}
	if result.IranAssessment == nil || result.IranAssessment.MeasurementAt != "" {
		t.Fatalf("missing measurement timestamp should remain explicit in the assessment: %#v", result.IranAssessment)
	}
}

// TestClassifyURLOnlyWebTunnelNotHardUnreachable covers URL-only fronted
// bridges: the TCP-only runner stage has no literal endpoint and must remain
// S0/inconclusive. A later front-domain probe may add runner-side evidence, but
// it cannot upgrade the Iran classification without an Iran-specific result.
func TestClassifyURLOnlyWebTunnelNotHardUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lines := []struct {
		name      string
		line      string
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
			result := classifyBridge(ctx, tc.line, time.Second, nil, nil)
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

// A webtunnel bridge with a literal (non-routable) IP endpoint is still
// probed at S1, but a runner-side failure remains iran_unknown.
func TestClassifyWebTunnelLiteralEndpointStillProbed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// 192.0.2.1/24 is TEST-NET-1 and never accepts connections.
	result := classifyBridge(
		ctx,
		"webtunnel 192.0.2.1:443 0000000000000000000000000000000000000000 url=https://example.com/x ver=0.0.3",
		time.Second,
		nil,
		nil,
	)
	if result.Host != "192.0.2.1" {
		t.Fatalf("host=%q, want 192.0.2.1", result.Host)
	}
	if result.IranStatus != StatusIranUnknown {
		t.Fatalf("status=%q, want %q for literal-endpoint webtunnel", result.IranStatus, StatusIranUnknown)
	}
	if result.Verification.Stage != "S1" || result.Verification.Vantage == nil {
		t.Fatalf("attempted literal endpoint must retain its TCP stage and vantage: %#v", result.Verification)
	}
}
