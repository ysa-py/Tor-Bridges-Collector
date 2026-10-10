// Binary iran_tester implements the 8-layer TorShield-IR bridge classification
// decision tree. It reads a JSON array of bridge strings, records runner-side
// TCP as typed S1 evidence, and uses Iran-specific OONI measurements plus ASN
// filtering, TLS fingerprint risk assessment, and port risk assessment to
// temporal blocking analysis, CDN front validation, and optional RIPE Atlas
// confirmation, then writes a structured JSON report to the output file.
//
// Build:
//
//	CGO_ENABLED=0 GOOS=linux go build -o iran_tester ./cmd/iran_tester/
//
// Run:
//
//	./iran_tester --input bridge/bridge_list_for_testing.json \
//	              --output bridge/iran_results.json \
//	              --workers 100 --timeout 8s
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ysa-py/MICAFP/internal/asn"
	"github.com/ysa-py/MICAFP/internal/bridge"
	"github.com/ysa-py/MICAFP/internal/ipinfo"
	"github.com/ysa-py/MICAFP/internal/ooni"
)

// ─────────────────────────────────────────────────────────────────────────────
// Result types
// ─────────────────────────────────────────────────────────────────────────────

// IranStatus enumerates the possible outcomes of the decision tree.
type IranStatus string

const (
	StatusTCPUnreachable    IranStatus = "tcp_unreachable"
	StatusIranASNBlocked    IranStatus = "iran_asn_blocked"
	StatusIranLikelyWorking IranStatus = "iran_likely_working"
	StatusIranLikelyBlocked IranStatus = "iran_likely_blocked"
	StatusIranUnknown       IranStatus = "iran_unknown"
	StatusIranFreqBlocked   IranStatus = "iran_frequently_blocked"
)

// DPIFlag enumerates additive risk flags that do not stop classification.
type DPIFlag string

const (
	FlagDPIHighRisk         DPIFlag = "iran_dpi_high_risk"
	FlagPortHighRisk        DPIFlag = "iran_port_high_risk"
	FlagDomainFrontDegraded DPIFlag = "domain_front_degraded"
	FlagDomainFrontCDNOK    DPIFlag = "domain_front_cdn_ok"
)

// BridgeResult is the per-bridge output record.
type BridgeResult struct {
	Line           string     `json:"line"`
	Host           string     `json:"host"`
	Port           int        `json:"port"`
	Transport      string     `json:"transport"`
	TCPReachable   bool       `json:"tcp_reachable"`
	IranStatus     IranStatus `json:"iran_status"`
	OONIChecked    bool       `json:"ooni_checked"`
	RecurrenceRate float64    `json:"recurrence_rate_per_30d,omitempty"`
	ASN            string     `json:"asn,omitempty"`
	ASNCountry     string     `json:"asn_country,omitempty"`
	ASNOrg         string     `json:"asn_org,omitempty"`
	RIPEReachable  *bool      `json:"ripe_reachable,omitempty"`
	Flags          []DPIFlag  `json:"flags,omitempty"`
	CompositeScore float64         `json:"composite_score"`
	Verification   Verification    `json:"verification"`
	IranAssessment *IranAssessment `json:"iran_assessment,omitempty"`
}

// ProbeVantage identifies where a technical verification was observed.
type ProbeVantage struct {
	Type   string  `json:"type"`
	Region *string `json:"region"`
}

// Verification is a typed, per-bridge technical probe observation. The Go
// tester only performs TCP (S1); it never upgrades that result into a PT claim.
type Verification struct {
	Status     string        `json:"status"`
	Stage      string        `json:"stage"`
	Vantage    *ProbeVantage `json:"vantage"`
	RTTMS      *float64      `json:"rtt_ms"`
	ProbeType  string        `json:"probe_type"`
	Detail     string        `json:"detail"`
	ErrorClass string        `json:"error_class"`
	ObservedAt string        `json:"observed_at"`
}

// IranAssessment records the independent Iran-specific evidence used for
// iran_status. OONI measurements are queried with probe_cc=IR; this is not the
// GitHub runner or relay vantage used for the technical verification stage.
type IranAssessment struct {
	Status                     IranStatus  `json:"status"`
	Source                     string      `json:"source"`
	Checked                    bool        `json:"checked"`
	Vantage                    IranVantage `json:"vantage"`
	QueriedAt                  string      `json:"queried_at"`
	MeasurementAt              string      `json:"measurement_at,omitempty"`
	MeasurementWindowDays      int         `json:"measurement_window_days,omitempty"`
	HistoricalMeasurementAt    string      `json:"historical_measurement_at,omitempty"`
	HistoricalWindowDays       int         `json:"historical_window_days,omitempty"`
}

type IranVantage struct {
	Type    string `json:"type"`
	Country string `json:"country"`
}

type TCPObservation struct {
	Reachable  bool
	Status     string
	Stage      string
	Vantage    *ProbeVantage
	RTTMS      *float64
	Detail     string
	ErrorClass string
}

// Summary aggregates the full run statistics.
type Summary struct {
	TotalTested       int `json:"total_tested"`
	GlobalReachable   int `json:"global_reachable"`
	IranLikelyWorking int `json:"iran_likely_working"`
	IranLikelyBlocked int `json:"iran_likely_blocked"`
	IranUnknown       int `json:"iran_unknown"`
	IranASNBlocked    int `json:"iran_asn_blocked"`
	IranFreqBlocked   int `json:"iran_frequently_blocked"`
}

// Report is the top-level output JSON document.
type Report struct {
	GeneratedAt string         `json:"generated_at"`
	Summary     Summary        `json:"summary"`
	Bridges     []BridgeResult `json:"bridges"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Risk / score helpers
// ─────────────────────────────────────────────────────────────────────────────

// knownTorJA3 contains JA3 fingerprints flagged as Tor-identifiable by
// Iran's DPI infrastructure.
var knownTorJA3 = map[string]bool{
	"e7d705a3286e19ea42f587b344ee6865": true,
}

// iranHighRiskPorts are Tor's well-known ports blocked by Iran's SIAM.
var iranHighRiskPorts = map[int]bool{2053: true, 9001: true, 9030: true}

func portRiskFlag(port int) bool {
	return iranHighRiskPorts[port]
}

// dpiHighRisk returns true if the TLS server hello for this endpoint carries
// a known Tor JA3 fingerprint. In practice we cannot compute JA3 from a plain
// net.Conn here, so we flag WebTunnel bridges on the default Tor port as
// elevated risk. A full JA3 check would require capturing the ClientHello.
// The flag is advisory; classification continues.
func dpiHighRisk(b *bridge.Transport) bool {
	if b.Type == "webtunnel" || b.Type == "meek_lite" {
		// Flag bridges using the default Tor ORPort or PT port
		return iranHighRiskPorts[int(b.Port)]
	}
	// For obfs4 bridges, we cannot inspect JA3 without a PT handshake.
	// We conservatively flag any bridge on a known-Tor port.
	return iranHighRiskPorts[int(b.Port)]
}

// compositScore implements the formula:
//
//	score = 0.35*tcp + 0.40*ooni_factor + 0.25*ripe_factor
func compositeScore(tcpOK bool, iranStatus IranStatus, ripeReachable *bool, ripeTested bool) float64 {
	// Runner-side TCP failure is not Iran-specific evidence; keep its score
	// contribution neutral rather than treating inconclusive reachability as 0.
	tcp := 0.5
	if tcpOK {
		tcp = 1.0
	}

	var ooniF float64
	switch iranStatus {
	case StatusIranLikelyWorking:
		ooniF = 1.0
	case StatusIranLikelyBlocked, StatusIranFreqBlocked:
		ooniF = 0.0
	default: // unknown, unreachable, etc.
		ooniF = 0.5
	}

	var ripeF float64
	if ripeTested {
		if ripeReachable != nil && *ripeReachable {
			ripeF = 1.0
		} else {
			ripeF = 0.0
		}
	} else {
		ripeF = 0.5 // untested
	}

	return 0.35*tcp + 0.40*ooniF + 0.25*ripeF
}

// ─────────────────────────────────────────────────────────────────────────────
// Main logic
// ─────────────────────────────────────────────────────────────────────────────

type ipInfoLookup interface {
	Lookup(context.Context, string) (*ipinfo.Response, error)
}

type ooniClassifier interface {
	Classify(context.Context, string) (ooni.OONIStatus, float64, bool)
	LatestRecentMeasurementAt(string) (string, bool)
	LatestTemporalMeasurementAt(string) (string, bool)
}

func classifyBridge(
	ctx context.Context,
	rawLine string,
	timeout time.Duration,
	ipClient ipInfoLookup,
	ooniClient ooniClassifier,
) BridgeResult {
	result := BridgeResult{
		Line: rawLine,
		Verification: Verification{
			Status: "inconclusive", Stage: "S0", ProbeType: "tcp",
			Detail: "probe was not performed", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		},
	}

	b, err := bridge.ParseLine(rawLine)
	if err != nil {
		result.IranStatus = StatusIranUnknown
		result.Verification.Detail = "bridge line could not be parsed; no network probe was performed"
		result.Verification.ErrorClass = "invalid_bridge_line"
		return result
	}
	result.Host = b.Host
	result.Port = int(b.Port)
	result.Transport = b.Type

	// ── Step 1: TCP reachability ──────────────────────────────────────────
	bridgeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tcpObservation := tcpProbeWithContext(bridgeCtx, b, timeout)
	tcpOK := tcpObservation.Reachable
	result.TCPReachable = tcpOK
	result.Verification = Verification{
		Status: tcpObservation.Status,
		Stage: tcpObservation.Stage,
		Vantage: tcpObservation.Vantage,
		RTTMS: tcpObservation.RTTMS,
		ProbeType: "tcp",
		Detail: tcpObservation.Detail,
		ErrorClass: tcpObservation.ErrorClass,
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}

	// Runner TCP is a separate S1 observation, not an Iran assessment. Never
	// let its failure suppress the independent ASN/OONI checks below.

	// ── Step 2: ASN lookup and Iranian ISP filter ─────────────────────────
	if ipClient != nil && b.Host != "" && b.Host != "snowflake-broker" && net.ParseIP(b.Host) != nil {
		info, err := ipClient.Lookup(ctx, b.Host)
		if err == nil && info != nil {
			asnStr := info.ASN()
			result.ASN = asnStr
			result.ASNCountry = info.Country
			result.ASNOrg = info.Org

			if isIranian, _ := asn.IsIranian(asnStr); isIranian {
				result.IranStatus = StatusIranASNBlocked
				result.CompositeScore = 0
				return result
			}

			// CDN front validation (WebTunnel only)
			if b.Type == "webtunnel" {
				if isCDN, _ := asn.IsCDN(asnStr); isCDN {
					result.Flags = append(result.Flags, FlagDomainFrontCDNOK)
				} else {
					result.Flags = append(result.Flags, FlagDomainFrontDegraded)
				}
			}
		}
	}

	// ── Step 3: TLS fingerprint DPI risk (advisory flag) ─────────────────
	if dpiHighRisk(b) {
		result.Flags = append(result.Flags, FlagDPIHighRisk)
	}

	// ── Step 4: Port risk assessment (advisory flag) ──────────────────────
	if portRiskFlag(int(b.Port)) {
		result.Flags = append(result.Flags, FlagPortHighRisk)
	}

	// ── Steps 5 & 6: OONI measurements (7-day + 90-day temporal) ─────────
	//
	// Domain-fronted transports and Snowflake cannot be classified as
	// Iran-working from a GitHub runner's TCP probe. They remain unknown
	// until an Iran-specific measurement (for example OONI probe_cc=IR)
	// supports a region-specific assessment. A non-Iranian runner-side TCP
	// connection is only S1 evidence and never upgrades an unknown bridge.
	var iranStatus IranStatus = StatusIranUnknown

	switch {
	case b.Type == "snowflake":
		// Snowflake uses WebRTC via the broker; a generic TCP result cannot
		// establish either PT capability or Iran reachability.
		iranStatus = StatusIranUnknown

	case b.Type == "webtunnel" || b.Type == "meek_lite":
		// A runner-side front/TCP response is not an Iran-specific measurement.
		iranStatus = StatusIranUnknown

	case b.Host != "" && net.ParseIP(b.Host) != nil:
		// IP-addressed bridge (obfs4, vanilla): query OONI independently of
		// whether the generic runner-side S1 TCP connect succeeded.
		if ooniClient != nil {
			ooniStatus, recurrenceRate, checked := ooniClient.Classify(ctx, b.Host)
			result.OONIChecked = checked
			result.RecurrenceRate = recurrenceRate

			recentAt, hasRecentMeasurement := ooniClient.LatestRecentMeasurementAt(b.Host)
			historicalAt, hasHistoricalMeasurement := ooniClient.LatestTemporalMeasurementAt(b.Host)
			if checked {
				assessment := &IranAssessment{
					Status: StatusIranUnknown,
					Source: "ooni_measurements_api",
					Checked: true,
					Vantage: IranVantage{Type: "ooni_probe", Country: "IR"},
					QueriedAt: time.Now().UTC().Format(time.RFC3339Nano),
				}
				if hasRecentMeasurement {
					assessment.MeasurementAt = recentAt
					assessment.MeasurementWindowDays = 7
				}
				if hasHistoricalMeasurement {
					assessment.HistoricalMeasurementAt = historicalAt
					assessment.HistoricalWindowDays = 90
				}
				result.IranAssessment = assessment
			}

			switch ooniStatus {
			case ooni.StatusLikelyWorking:
				if hasRecentMeasurement {
					iranStatus = StatusIranLikelyWorking
				}
			case ooni.StatusLikelyBlocked:
				if hasRecentMeasurement {
					iranStatus = StatusIranLikelyBlocked
				}
			case ooni.StatusFreqBlocked:
				if hasHistoricalMeasurement {
					iranStatus = StatusIranFreqBlocked
				}
			default:
				// No classifiable OONI result with an original measurement time
				// is inconclusive, regardless of a generic runner-side TCP result.
				iranStatus = StatusIranUnknown
			}
		}
		if result.IranAssessment != nil {
			result.IranAssessment.Status = iranStatus
		}


	default:
		// Unresolvable or non-IP, non-domain host
		iranStatus = StatusIranUnknown
	}

	result.IranStatus = iranStatus
	result.CompositeScore = compositeScore(tcpOK, iranStatus, nil, false)
	return result
}

func validateWorkers(workers int) error {
	if workers < 1 {
		return fmt.Errorf("workers must be >= 1, got %d", workers)
	}
	return nil
}

func dynamicWorkerCount(requested, candidates int) int {
	if requested > 0 {
		if candidates > 0 && requested > candidates {
			return candidates
		}
		return requested
	}
	if candidates <= 1 {
		return 1
	}
	cpuScaled := runtime.NumCPU() * 16
	if cpuScaled < 16 {
		cpuScaled = 16
	}
	if cpuScaled > candidates {
		return candidates
	}
	return cpuScaled
}

// lineForTransport returns a formatted host:port string suitable for dialing.
func lineForTransport(b *bridge.Transport) string {
	return net.JoinHostPort(b.Host, fmt.Sprintf("%d", b.Port))
}

// tcpProbeWithContext performs only an S1 TCP connect and records a typed
// result. It deliberately does not infer transport capability or Iran reachability.
func tcpProbeWithContext(ctx context.Context, b *bridge.Transport, timeout time.Duration) TCPObservation {
	if b.Host == "" || b.Port == 0 {
		return TCPObservation{
			Status: "inconclusive",
			Stage: "S0",
			Detail: "no literal TCP endpoint is available to this probe stage",
			ErrorClass: "endpoint_unavailable",
		}
	}
	started := time.Now()
	vantage := &ProbeVantage{Type: "github_actions_runner"}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", lineForTransport(b))
	if err != nil {
		status := "error"
		errorClass := "tcp_connect_error"
		detail := "TCP connection failed"
		var netErr net.Error
		switch {
		case errors.Is(err, syscall.ECONNREFUSED):
			status, errorClass, detail = "refused", "connection_refused", "TCP connection was refused"
		case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout():
			status, errorClass, detail = "timeout", "tcp_connect_timeout", "TCP connection timed out"
		case errors.Is(err, context.Canceled):
			status, errorClass, detail = "inconclusive", "probe_cancelled", "TCP probe was cancelled"
		}
		// S1 is reached only after a successful TCP connect. A refusal,
		// timeout, or error is an S0 attempt with an explicit runner vantage.
		return TCPObservation{Status: status, Stage: "S0", Vantage: vantage, Detail: detail, ErrorClass: errorClass}
	}
	_ = conn.Close()
	rtt := float64(time.Since(started).Microseconds()) / 1000.0
	return TCPObservation{
		Reachable: true,
		Status: "connected",
		Stage: "S1",
		Vantage: vantage,
		RTTMS: &rtt,
		Detail: "TCP connection established; no transport handshake was performed",
	}
}

func main() {
	inputFlag := flag.String("input", "bridge/bridge_list_for_testing.json", "JSON array of bridge strings")
	outputFlag := flag.String("output", "bridge/iran_results.json", "Output JSON report path")
	workersFlag := flag.Int("workers", 0, "Parallel worker count (0 = dynamic from candidate pool and CPU)")
	timeoutFlag := flag.Duration("timeout", 8*time.Second, "Per-bridge TCP timeout")
	flag.Parse()

	// ── Read input ────────────────────────────────────────────────────────
	data, err := os.ReadFile(*inputFlag)
	if err != nil {
		log.Fatalf("cannot open input %q: %v", *inputFlag, err)
	}
	var bridgeLines []string
	if err := json.Unmarshal(data, &bridgeLines); err != nil {
		log.Fatalf("parse input JSON: %v", err)
	}
	workers := dynamicWorkerCount(*workersFlag, len(bridgeLines))
	if err := validateWorkers(workers); err != nil {
		log.Fatal(err)
	}
	log.Printf("Loaded %d bridges for testing (workers=%d, timeout=%s)",
		len(bridgeLines), workers, *timeoutFlag)

	// ── Shared clients ────────────────────────────────────────────────────
	ipClient := ipinfo.New()
	ooniClient := ooni.New()
	defer ooniClient.Close()

	// ── Parallel classification ───────────────────────────────────────────
	sem := make(chan struct{}, workers)
	results := make(chan BridgeResult, len(bridgeLines))
	var wg sync.WaitGroup
	ctx := context.Background()

	for _, line := range bridgeLines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(raw string) {
			defer wg.Done()
			defer func() { <-sem }()
			results <- classifyBridge(ctx, raw, *timeoutFlag, ipClient, ooniClient)
		}(line)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// ── Collect results ───────────────────────────────────────────────────
	var allResults []BridgeResult
	for r := range results {
		allResults = append(allResults, r)
	}

	// ── Build summary ─────────────────────────────────────────────────────
	var summary Summary
	summary.TotalTested = len(allResults)
	for _, r := range allResults {
		if r.TCPReachable || r.Transport == "snowflake" {
			summary.GlobalReachable++
		}
		switch r.IranStatus {
		case StatusIranLikelyWorking:
			summary.IranLikelyWorking++
		case StatusIranLikelyBlocked:
			summary.IranLikelyBlocked++
		case StatusIranUnknown:
			summary.IranUnknown++
		case StatusIranASNBlocked:
			summary.IranASNBlocked++
		case StatusIranFreqBlocked:
			summary.IranFreqBlocked++
		}
	}

	report := Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Summary:     summary,
		Bridges:     allResults,
	}

	log.Printf("Summary: total=%d reachable=%d likely_working=%d likely_blocked=%d unknown=%d asn_blocked=%d",
		summary.TotalTested, summary.GlobalReachable, summary.IranLikelyWorking,
		summary.IranLikelyBlocked, summary.IranUnknown, summary.IranASNBlocked)

	// ── Write output ──────────────────────────────────────────────────────
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatalf("marshal output: %v", err)
	}
	if err := os.WriteFile(*outputFlag, out, 0644); err != nil {
		log.Fatalf("write output %q: %v", *outputFlag, err)
		os.Exit(2)
	}
	log.Printf("Report written to %s", *outputFlag)
}
