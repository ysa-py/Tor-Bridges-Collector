// Binary probe_scheduler orchestrates the full TorShield-IR measurement
// pipeline and exposes a lightweight HTTP summary endpoint for consumption
// by the Python correlator.
//
// Steps:
//  1. Fetch bridges from MOAT API and data/iran_bridges.json
//  2. Submit RIPE Atlas one-off measurements (if RIPE_ATLAS_API_KEY is set)
//  3. Merge RIPE Atlas and Rust bridge-probe PT handshake results
//  4. Expose merged JSON on http://localhost:{port}/results
//
// Build:
//
//	CGO_ENABLED=0 GOOS=linux go build -o probe_scheduler ./cmd/probe_scheduler/
//
// Run:
//
//	./probe_scheduler --bridges data/iran_bridges.json --port 8742
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ysa-py/MICAFP/internal/bridge"
	"github.com/ysa-py/MICAFP/internal/ripe"
)

// ─────────────────────────────────────────────────────────────────────────────
// Data types
// ─────────────────────────────────────────────────────────────────────────────

// IranBridgeRecord matches the schema of data/iran_bridges.json.
type IranBridgeRecord struct {
	Type          string   `json:"type"`
	BridgeLine    string   `json:"bridge_line"`
	LastKnownGood string   `json:"last_known_good"`
	ASNBlocked    []string `json:"asn_blocked"`
	Source        string   `json:"source"`
}

// PTResult is one bridge-probe (Rust) result from data/pt_results.json.
type PTResult struct {
	Bridge    string `json:"bridge"`
	Status    string `json:"status"` // reachable|timeout|refused|error
	LatencyMs int    `json:"latency_ms"`
	PTType    string `json:"pt_type"`
}

// MergedResult is the combined view from RIPE Atlas + PT handshake.
type MergedResult struct {
	BridgeLine    string `json:"bridge_line"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Transport     string `json:"transport"`
	RIPEReachable bool   `json:"ripe_reachable"`
	RIPETested    bool   `json:"ripe_tested"`
	PTStatus      string `json:"pt_status"`
	PTLatencyMs   int    `json:"pt_latency_ms"`
	Source        string `json:"source"`
}

// SchedulerReport is the JSON served at /results.
type SchedulerReport struct {
	Status       string         `json:"status,omitempty"`
	GeneratedAt  string         `json:"generated_at"`
	TotalBridges int            `json:"total_bridges"`
	Results      []MergedResult `json:"results"`
}

type schedulerState struct {
	mu     sync.RWMutex
	status string
	report SchedulerReport
}

func newSchedulerState() *schedulerState {
	return &schedulerState{
		status: "starting",
		report: SchedulerReport{
			Status:      "starting",
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Results:     []MergedResult{},
		},
	}
}

func (s *schedulerState) setStatus(status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = status
	s.report.Status = status
}

func (s *schedulerState) setReport(status string, report SchedulerReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	report.Status = status
	if report.Results == nil {
		report.Results = []MergedResult{}
	}
	s.status = status
	s.report = report
}

func (s *schedulerState) snapshot() SchedulerReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	report := s.report
	if report.Results == nil {
		report.Results = []MergedResult{}
	}
	return report
}

func (s *schedulerState) health() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]string{"status": s.status}
}

func validatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid --port: must be between 1 and 65535")
	}
	return nil
}

func normalizeSchedulerResults(results any) []MergedResult {
	resultsList, ok := results.([]MergedResult)
	if !ok {
		return []MergedResult{}
	}
	if resultsList == nil {
		return []MergedResult{}
	}
	return resultsList
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func readIranBridges(path string) ([]IranBridgeRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var records []IranBridgeRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return records, nil
}

func readPTResults(path string) (map[string]PTResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// PT results file may not exist if bridge-probe was not run.
		if os.IsNotExist(err) {
			return map[string]PTResult{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var results []PTResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	m := make(map[string]PTResult, len(results))
	for _, r := range results {
		m[r.Bridge] = r
	}
	return m, nil
}

// fetchMOATBridges fetches built-in bridges from the Tor Project MOAT API.
func fetchMOATBridges(ctx context.Context) ([]string, error) {
	const url = "https://bridges.torproject.org/moat/circumvention/builtin"
	body := `{"version":"0.1.0","transports":["obfs4","webTunnel","snowflake"],"country":"ir"}`

	// FIX: build the request directly with the body — no intermediate unused variable.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
		strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/vnd.api+json")
	req.Header.Set("Accept", "application/vnd.api+json")

	hc := &http.Client{Timeout: 30 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("MOAT fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MOAT API HTTP %d", resp.StatusCode)
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("MOAT decode: %w", err)
	}

	var lines []string
	if bridges, ok := data["bridges"].(map[string]interface{}); ok {
		for _, v := range bridges {
			if list, ok := v.([]interface{}); ok {
				for _, item := range list {
					if s, ok := item.(string); ok && s != "" {
						lines = append(lines, s)
					}
				}
			}
		}
	}
	return lines, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	bridgesFlag := flag.String("bridges", "data/iran_bridges.json", "Iran bridge database JSON")
	portFlag := flag.Int("port", 8742, "HTTP results port")
	flag.Parse()
	if err := validatePort(*portFlag); err != nil {
		log.Fatal(err)
	}

	state := newSchedulerState()
	mux := http.NewServeMux()
	mux.HandleFunc("/results", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state.snapshot()) //nolint:errcheck
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(state.health()) //nolint:errcheck
	})

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", *portFlag),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		ripeKey := os.Getenv("RIPE_ATLAS_API_KEY")
		ripeClient := ripe.New(ripeKey)
		if ripeClient.Enabled() {
			log.Println("RIPE Atlas: enabled (IR probes)")
		} else {
			log.Println("RIPE Atlas: disabled (RIPE_ATLAS_API_KEY not set) — OONI-only mode")
		}

		state.setStatus("running")

		ctx := context.Background()

		// ── Step 1: Bridge acquisition ────────────────────────────────────────
		log.Println("Fetching bridges from MOAT API…")
		moatLines, err := fetchMOATBridges(ctx)
		if err != nil {
			log.Printf("MOAT API error (non-fatal): %v", err)
		}
		log.Printf("MOAT: %d bridges fetched", len(moatLines))

		staticRecords, err := readIranBridges(*bridgesFlag)
		if err != nil {
			log.Printf("Cannot read iran bridges DB (non-fatal): %v", err)
		}

		// Combine all bridge lines (dedup by raw string)
		seen := make(map[string]bool)
		type taggedBridge struct {
			line   string
			source string
		}
		var allBridges []taggedBridge
		for _, line := range moatLines {
			if !seen[line] {
				seen[line] = true
				allBridges = append(allBridges, taggedBridge{line, "moat"})
			}
		}
		for _, r := range staticRecords {
			if r.BridgeLine != "" && !seen[r.BridgeLine] {
				seen[r.BridgeLine] = true
				allBridges = append(allBridges, taggedBridge{r.BridgeLine, r.Source})
			}
		}
		log.Printf("Total bridges to schedule: %d", len(allBridges))

		// ── Step 2: RIPE Atlas measurements ──────────────────────────────────
		type ripeResult struct {
			line      string
			reachable bool
			tested    bool
		}
		ripeCh := make(chan ripeResult, len(allBridges))

		if ripeClient.Enabled() {
			var ripeWG sync.WaitGroup
			sem := make(chan struct{}, 5) // max 5 concurrent RIPE submissions
			for _, tb := range allBridges {
				ripeWG.Add(1)
				sem <- struct{}{}
				go func(raw, src string) {
					defer ripeWG.Done()
					defer func() { <-sem }()
					b, err := bridge.Parse(raw)
					if err != nil || b.Transport == "snowflake" {
						ripeCh <- ripeResult{line: raw, reachable: false, tested: false}
						return
					}
					rCtx, cancel := context.WithTimeout(ctx, 12*time.Minute)
					defer cancel()
					ok, tested := ripeClient.Measure(rCtx, b.Host, b.Port)
					ripeCh <- ripeResult{raw, ok, tested}
				}(tb.line, tb.source)
			}
			ripeWG.Wait()
		}
		close(ripeCh)

		ripeMap := make(map[string]ripeResult)
		for r := range ripeCh {
			ripeMap[r.line] = r
		}

		// ── Step 3: Merge with PT handshake results ───────────────────────────
		ptMap, err := readPTResults("data/pt_results.json")
		if err != nil {
			log.Printf("Cannot read PT results (non-fatal): %v", err)
			ptMap = map[string]PTResult{}
		}

		var merged []MergedResult
		for _, tb := range allBridges {
			b, _ := bridge.Parse(tb.line)
			host, port, transport := "", 0, "unknown"
			if b != nil {
				host, port, transport = b.Host, b.Port, b.Transport
			}

			rr := ripeMap[tb.line]
			pt := ptMap[tb.line]
			mr := MergedResult{
				BridgeLine:    tb.line,
				Host:          host,
				Port:          port,
				Transport:     transport,
				RIPEReachable: rr.reachable,
				RIPETested:    rr.tested,
				PTStatus:      pt.Status,
				PTLatencyMs:   pt.LatencyMs,
				Source:        tb.source,
			}
			merged = append(merged, mr)
		}

		results := normalizeSchedulerResults(merged)
		report := SchedulerReport{
			Status:       "ready",
			GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
			TotalBridges: len(results),
			Results:      results,
		}

		// Persist merged results for Python correlator
		const schedulerResultsPath = "data/scheduler_results.json"
		writeStatus := "ready"
		persistedReport := report
		persistedReport.Status = ""
		if err := os.MkdirAll("data", 0755); err != nil {
			writeStatus = "error"
			log.Printf("Cannot create scheduler results directory (non-fatal): %v", err)
		} else if out, err := json.MarshalIndent(persistedReport, "", "  "); err != nil {
			writeStatus = "error"
			log.Printf("Cannot marshal scheduler results (non-fatal): %v", err)
		} else if err := os.WriteFile(schedulerResultsPath, out, 0644); err != nil {
			writeStatus = "error"
			log.Printf("Cannot write scheduler results to %s (non-fatal): %v", schedulerResultsPath, err)
		}
		state.setReport(writeStatus, report)

	}()

	// ── Step 4: HTTP exposure ─────────────────────────────────────────────
	log.Printf("Listening on http://localhost:%d/results", *portFlag)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("HTTP server: %v", err)
	}
}
