// Package ooni provides a rate-limited, backoff-capable client for the OONI
// (Open Observatory of Network Interference) Measurements API.
// It queries bridge-specific measurements from Iranian probes (probe_cc=IR)
// and classifies each bridge as iran_likely_working, iran_likely_blocked,
// or iran_unknown based on anomaly flags in recent measurements.
//
// WebTunnel classification note:
//
//	WebTunnel bridges use HTTPS domain-fronted URLs, not bare IP:port.
//	OONI measures by input (IP address), so WebTunnel bridges almost never
//	appear in OONI data. A successful front-domain probe from a non-Iranian
//	runner is separate technical evidence and must never be upgraded into an
//	Iran reachability status.
package ooni

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// OONIStatus represents the Iran-specific classification derived from OONI data.
type OONIStatus string

const (
	StatusLikelyWorking OONIStatus = "iran_likely_working"
	StatusLikelyBlocked OONIStatus = "iran_likely_blocked"
	StatusUnknown       OONIStatus = "iran_unknown"
	StatusFreqBlocked   OONIStatus = "iran_frequently_blocked"

	ooniBase        = "https://api.ooni.io/api/v1/measurements"
	recentDays      = 7
	temporalDays    = 90
	freqBlockThresh = 2.0 // anomalies per 30-day period that triggers frequently_blocked
)

// Measurement is the minimal subset of an OONI measurement result.
type Measurement struct {
	Anomaly              bool   `json:"anomaly"`
	Confirmed            bool   `json:"confirmed"`
	MeasurementStartTime string `json:"measurement_start_time"`
	TestStartTime        string `json:"test_start_time"`
	TestName             string `json:"test_name"`
}

// measurementsResponse is the top-level OONI API response envelope.
type measurementsResponse struct {
	Results []Measurement `json:"results"`
}

// Client is a rate-limited OONI API client.
// Rate limit: 5 req/s as per OONI guidelines.
// Backoff: exponential on HTTP 429, up to 3 retries.
type Client struct {
	hc      *http.Client
	ticker  *time.Ticker
	mu      sync.Mutex // protects ticker channel drain
	cache   map[string]*analysisResult
	cacheMu sync.Mutex
	now     func() time.Time
}

type analysisResult struct {
	Status                       OONIStatus
	RecurrenceRate               float64
	Checked                      bool
	LatestRecentMeasurementAt    string
	LatestTemporalMeasurementAt string
}

func measurementTimestamp(measurement Measurement) (time.Time, string, bool) {
	raw := measurement.MeasurementStartTime
	if raw == "" {
		raw = measurement.TestStartTime
	}
	if raw == "" {
		return time.Time{}, "", false
	}
	measuredAt, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, "", false
	}
	return measuredAt, raw, true
}

func newestMeasurement(measurements []Measurement) (Measurement, string, bool) {
	var newest Measurement
	var newestRaw string
	var newestAt time.Time
	found := false
	for _, measurement := range measurements {
		measuredAt, raw, ok := measurementTimestamp(measurement)
		if !ok {
			continue
		}
		if !found || measuredAt.After(newestAt) {
			newest = measurement
			newestRaw = raw
			newestAt = measuredAt
			found = true
		}
	}
	return newest, newestRaw, found
}

func latestMeasurementAt(measurements []Measurement) string {
	_, raw, ok := newestMeasurement(measurements)
	if !ok {
		return ""
	}
	return raw
}

// classifyRecentStatus uses only the newest original measurement time. Older
// anomaly/confirmed rows in the same window, and rows without a parseable
// timestamp, cannot override that current classification.
func classifyRecentStatus(measurements []Measurement) OONIStatus {
	newest, _, ok := newestMeasurement(measurements)
	if !ok {
		return StatusUnknown
	}
	if newest.Anomaly || newest.Confirmed {
		return StatusLikelyBlocked
	}
	return StatusLikelyWorking
}

func timestampedAnomalyCount(measurements []Measurement) int {
	count := 0
	for _, measurement := range measurements {
		if _, _, ok := measurementTimestamp(measurement); !ok {
			continue
		}
		if measurement.Anomaly || measurement.Confirmed {
			count++
		}
	}
	return count
}

const observationFutureSkew = 120 * time.Second

func inAgeWindow(measuredAt, now time.Time, maxAge time.Duration) bool {
	age := now.Sub(measuredAt)
	return age >= -observationFutureSkew && age <= maxAge
}

func filterByOriginalTime(measurements []Measurement, now time.Time, maxAge time.Duration) []Measurement {
	filtered := make([]Measurement, 0, len(measurements))
	for _, measurement := range measurements {
		measuredAt, _, ok := measurementTimestamp(measurement)
		if !ok {
			continue
		}
		if inAgeWindow(measuredAt, now, maxAge) {
			filtered = append(filtered, measurement)
		}
	}
	return filtered
}

func (c *Client) clock() time.Time {
	if c != nil && c.now != nil {
		return c.now()
	}
	return time.Now().UTC()
}

// New creates a Client that honours a 5-requests-per-second rate limit.
func New() *Client {
	return &Client{
		hc:     &http.Client{Timeout: 30 * time.Second},
		ticker: time.NewTicker(200 * time.Millisecond), // 5 req/s
		cache:  make(map[string]*analysisResult),
		now:    func() time.Time { return time.Now().UTC() },
	}
}

// Close releases the rate-limiting ticker.
func (c *Client) Close() {
	c.ticker.Stop()
}

// waitTick blocks until the rate-limiter permits the next request.
func (c *Client) waitTick(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ticker.C:
		return nil
	}
}

// fetch performs one HTTP GET with exponential backoff on HTTP 429.
func (c *Client) fetch(ctx context.Context, rawURL string) (*measurementsResponse, error) {
	const maxRetries = 3
	backoff := 2 * time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if err := c.waitTick(ctx); err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Accept", "application/json")

		resp, err := c.hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("HTTP GET: %w", err)
		}

		switch resp.StatusCode {
		case http.StatusOK:
			var data measurementsResponse
			err = json.NewDecoder(resp.Body).Decode(&data)
			resp.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("decode: %w", err)
			}
			return &data, nil

		case http.StatusTooManyRequests:
			resp.Body.Close()
			if attempt == maxRetries {
				return nil, fmt.Errorf("OONI API rate-limit exceeded after %d retries", maxRetries)
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
			}

		default:
			resp.Body.Close()
			return nil, fmt.Errorf("OONI API HTTP %d for %s", resp.StatusCode, rawURL)
		}
	}
	return nil, fmt.Errorf("fetch exhausted retries")
}

// buildURL constructs an OONI measurements query URL.
func buildURL(ip string, since, until time.Time, limit int) string {
	params := url.Values{}
	params.Set("probe_cc", "IR")
	params.Set("input", ip)
	params.Set("limit", fmt.Sprintf("%d", limit))
	// OONI API: the only valid value for order_by is "measurement_start_time".
	// "test_start_time" returns HTTP 422 (verified 2026-03-26 against api.ooni.io).
	params.Set("order_by", "measurement_start_time")
	params.Set("since", since.Format("2006-01-02"))
	params.Set("until", until.Format("2006-01-02"))
	return ooniBase + "?" + params.Encode()
}

// Classify queries OONI for the given IP address and returns its Iran status.
//
// Two time windows are queried:
//   - Last 7 days: determines current status (likely_working / likely_blocked / unknown).
//   - Last 90 days: computes blocking recurrence rate (frequently_blocked if > 2/month).
//
// When OONI has no measurement data for the IP (empty results), the function
// returns StatusUnknown. Transport-specific checks may add typed technical
// evidence, but a non-Iranian vantage must not be used to infer Iran reachability.
func (c *Client) Classify(ctx context.Context, ip string) (OONIStatus, float64, bool) {
	// Cache check
	c.cacheMu.Lock()
	if cached, ok := c.cache[ip]; ok {
		c.cacheMu.Unlock()
		return cached.Status, cached.RecurrenceRate, cached.Checked
	}
	c.cacheMu.Unlock()

	now := c.clock()
	recentWindow := time.Duration(recentDays) * 24 * time.Hour
	temporalWindow := time.Duration(temporalDays) * 24 * time.Hour

	// ── Recent window (7 days) ──────────────────────────────────────────
	recentURL := buildURL(ip, now.AddDate(0, 0, -recentDays), now, 5)
	recentData, err := c.fetch(ctx, recentURL)
	if err != nil || recentData == nil {
		return StatusUnknown, 0, false
	}

	recentInWindow := filterByOriginalTime(recentData.Results, now, recentWindow)
	status := classifyRecentStatus(recentInWindow)

	// ── Temporal window (90 days) ───────────────────────────────────────
	temporalURL := buildURL(ip, now.AddDate(0, 0, -temporalDays), now, 100)
	temporalData, err := c.fetch(ctx, temporalURL)

	var recurrenceRate float64
	var latestTemporalMeasurementAt string
	var temporalInWindow []Measurement
	if temporalData != nil {
		temporalInWindow = filterByOriginalTime(temporalData.Results, now, temporalWindow)
		latestTemporalMeasurementAt = latestMeasurementAt(temporalInWindow)
	}
	if err == nil && len(temporalInWindow) > 0 {
		anomalyCount := timestampedAnomalyCount(temporalInWindow)
		// blocks per 30-day period
		recurrenceRate = float64(anomalyCount) / (float64(temporalDays) / 30.0)
		if recurrenceRate > freqBlockThresh {
			status = StatusFreqBlocked
		}
	}

	result := &analysisResult{
		Status:                      status,
		RecurrenceRate:              recurrenceRate,
		Checked:                     true,
		LatestRecentMeasurementAt:   latestMeasurementAt(recentInWindow),
		LatestTemporalMeasurementAt: latestTemporalMeasurementAt,
	}
	c.cacheMu.Lock()
	c.cache[ip] = result
	c.cacheMu.Unlock()

	return status, recurrenceRate, true
}

// LatestRecentMeasurementAt returns the original timestamp of the newest
// measurement in the seven-day Iran-probe query cached by Classify. A checked
// empty query or a response without a parseable timestamp has no measurement
// time and must not be presented as current reachability evidence.
func (c *Client) LatestRecentMeasurementAt(ip string) (string, bool) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	cached, ok := c.cache[ip]
	if !ok || !cached.Checked || cached.LatestRecentMeasurementAt == "" {
		return "", false
	}
	return cached.LatestRecentMeasurementAt, true
}

// LatestTemporalMeasurementAt returns the original timestamp of the newest
// measurement in the ninety-day Iranian-probe query used for recurrence
// analysis. It is distinct from the seven-day current-assessment timestamp.
func (c *Client) LatestTemporalMeasurementAt(ip string) (string, bool) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	cached, ok := c.cache[ip]
	if !ok || !cached.Checked || cached.LatestTemporalMeasurementAt == "" {
		return "", false
	}
	return cached.LatestTemporalMeasurementAt, true
}
