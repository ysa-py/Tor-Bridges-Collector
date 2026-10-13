package ooni

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLatestMeasurementAtPreservesNewestOriginalTimestamp(t *testing.T) {
	measurements := []Measurement{
		{MeasurementStartTime: "2026-10-08T09:00:00Z"},
		{TestStartTime: "2026-10-08T10:30:00+01:00"}, // 09:30 UTC
		{MeasurementStartTime: "2026-10-08T10:00:00.125Z", TestStartTime: "2026-10-08T11:00:00Z"},
		{MeasurementStartTime: "not-a-timestamp"},
	}

	got := latestMeasurementAt(measurements)
	want := "2026-10-08T10:00:00.125Z"
	if got != want {
		t.Fatalf("latestMeasurementAt() = %q, want original timestamp %q", got, want)
	}
}

func TestLatestMeasurementAtDoesNotInventTime(t *testing.T) {
	for _, measurements := range [][]Measurement{
		{},
		{{MeasurementStartTime: "not-a-timestamp"}},
		{{TestStartTime: ""}},
	} {
		if got := latestMeasurementAt(measurements); got != "" {
			t.Fatalf("latestMeasurementAt(%#v) = %q, want empty for missing or invalid time", measurements, got)
		}
	}
}

func TestClassifyRecentStatusUsesNewestTimestampedMeasurement(t *testing.T) {
	measurements := []Measurement{
		{Confirmed: true, MeasurementStartTime: "2026-10-08T09:00:00Z"},
		{Confirmed: false, Anomaly: false, MeasurementStartTime: "2026-10-08T10:00:00.125Z"},
		{Confirmed: true, MeasurementStartTime: "not-a-timestamp"},
	}
	if got := classifyRecentStatus(measurements); got != StatusLikelyWorking {
		t.Fatalf("classifyRecentStatus() = %q, want %q from newest clean measurement", got, StatusLikelyWorking)
	}
}

func TestClassifyRecentStatusNewestAnomalyIsBlocked(t *testing.T) {
	measurements := []Measurement{
		{Confirmed: false, Anomaly: false, MeasurementStartTime: "2026-10-08T09:00:00Z"},
		{Anomaly: true, MeasurementStartTime: "2026-10-08T11:00:00Z"},
	}
	if got := classifyRecentStatus(measurements); got != StatusLikelyBlocked {
		t.Fatalf("classifyRecentStatus() = %q, want %q from newest anomaly", got, StatusLikelyBlocked)
	}
}

func TestClassifyRecentStatusMissingTimestampsStayUnknown(t *testing.T) {
	measurements := []Measurement{{Confirmed: true, Anomaly: true}}
	if got := classifyRecentStatus(measurements); got != StatusUnknown {
		t.Fatalf("classifyRecentStatus() = %q, want %q when original time is missing", got, StatusUnknown)
	}
}

func TestFilterByOriginalTimeDropsStaleAndFutureMeasurements(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	measurements := []Measurement{
		{Confirmed: true, MeasurementStartTime: "2026-10-01T12:00:00Z"},      // 9 days
		{Confirmed: false, MeasurementStartTime: "2026-10-10T11:30:00.125Z"}, // 30 min
		{Anomaly: true, MeasurementStartTime: "2026-10-10T12:03:00Z"},        // 180s future
		{Confirmed: true, MeasurementStartTime: "not-a-timestamp"},
	}
	got := filterByOriginalTime(measurements, now, 7*24*time.Hour)
	if len(got) != 1 || got[0].MeasurementStartTime != "2026-10-10T11:30:00.125Z" {
		t.Fatalf("filterByOriginalTime() = %#v, want only the in-window clean measurement", got)
	}
	if status := classifyRecentStatus(got); status != StatusLikelyWorking {
		t.Fatalf("classifyRecentStatus(filtered) = %q, want %q", status, StatusLikelyWorking)
	}
}

func TestFilterByOriginalTimeEmptyWhenAllStale(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	measurements := []Measurement{
		{Confirmed: true, MeasurementStartTime: "2026-10-01T00:00:00Z"},
	}
	got := filterByOriginalTime(measurements, now, 7*24*time.Hour)
	if len(got) != 0 {
		t.Fatalf("filterByOriginalTime() = %#v, want empty for stale original times", got)
	}
	if status := classifyRecentStatus(got); status != StatusUnknown {
		t.Fatalf("classifyRecentStatus(empty window) = %q, want %q", status, StatusUnknown)
	}
}

func TestTimestampedAnomalyCountIgnoresUntimestampedRows(t *testing.T) {
	measurements := []Measurement{
		{Confirmed: true},
		{Anomaly: true, MeasurementStartTime: "2026-10-08T09:00:00Z"},
		{Confirmed: false, Anomaly: false, MeasurementStartTime: "2026-10-08T10:00:00Z"},
	}
	if got := timestampedAnomalyCount(measurements); got != 1 {
		t.Fatalf("timestampedAnomalyCount() = %d, want 1 timestamped anomaly", got)
	}
}

// ── Persisted classification cache ───────────────────────────────────────────

// failingRoundTripper keeps cache tests fully offline: any Classify cache
// miss would otherwise hit the real OONI Measurements API.
type failingRoundTripper struct{}

func (failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("cache tests must not reach the network")
}

// mustClient builds a Client whose clock is frozen at now.
func mustClient(t *testing.T, now time.Time) *Client {
	t.Helper()
	c := New()
	c.now = func() time.Time { return now }
	return c
}

func TestCacheSaveLoadRoundTripPreservesQueriedAt(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	queriedAt := now.Add(-2 * time.Hour)

	c := mustClient(t, now)
	c.cacheMu.Lock()
	c.cache["198.51.100.10"] = &analysisResult{
		Status:                    StatusLikelyWorking,
		Checked:                   true,
		LatestRecentMeasurementAt: queriedAt.Format(time.RFC3339Nano),
		QueriedAt:                 queriedAt.Format(time.RFC3339Nano),
	}
	// Unchecked entries must never be persisted: they carry no evidence.
	c.cache["198.51.100.11"] = &analysisResult{Status: StatusUnknown, Checked: false}
	c.cacheMu.Unlock()

	path := filepath.Join(t.TempDir(), "ooni_cache.json")
	if err := c.SaveCache(path); err != nil {
		t.Fatalf("SaveCache: %v", err)
	}

	loaded := mustClient(t, now)
	n, err := loaded.LoadCache(path, 12*time.Hour)
	if err != nil {
		t.Fatalf("LoadCache: %v", err)
	}
	if n != 1 {
		t.Fatalf("loaded %d entries, want exactly the 1 checked entry", n)
	}
	status, _, checked := loaded.Classify(context.Background(), "198.51.100.10")
	if !checked || status != StatusLikelyWorking {
		t.Fatalf("Classify after LoadCache = (%v, %v), want (likely_working, true)", status, checked)
	}
	gotAt, ok := loaded.QueriedAtFor("198.51.100.10")
	if !ok || gotAt != queriedAt.Format(time.RFC3339Nano) {
		t.Fatalf("QueriedAtFor = %q (ok=%v), want original %q", gotAt, ok, queriedAt.Format(time.RFC3339Nano))
	}
}

func TestLoadCacheSkipsEntriesOlderThanTTL(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-1 * time.Hour)
	stale := now.Add(-25 * time.Hour)

	c := mustClient(t, now)
	c.cacheMu.Lock()
	c.cache["198.51.100.20"] = &analysisResult{Status: StatusLikelyBlocked, Checked: true, QueriedAt: stale.Format(time.RFC3339Nano)}
	c.cache["198.51.100.21"] = &analysisResult{Status: StatusLikelyWorking, Checked: true, QueriedAt: fresh.Format(time.RFC3339Nano)}
	c.cacheMu.Unlock()

	path := filepath.Join(t.TempDir(), "ooni_cache.json")
	if err := c.SaveCache(path); err != nil {
		t.Fatalf("SaveCache: %v", err)
	}

	loaded := mustClient(t, now)
	// A skipped (stale) entry falls through to a live Classify query; force
	// that query to fail offline so the test only exercises cache semantics.
	loaded.hc = &http.Client{Transport: failingRoundTripper{}}
	n, err := loaded.LoadCache(path, 12*time.Hour)
	if err != nil {
		t.Fatalf("LoadCache: %v", err)
	}
	if n != 1 {
		t.Fatalf("loaded %d entries, want only the fresh one", n)
	}
	if _, _, checked := loaded.Classify(context.Background(), "198.51.100.20"); checked {
		t.Fatalf("stale entry must not be served as checked evidence")
	}
}

func TestLoadCacheCorruptFileIsNonFatal(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatalf("write broken cache: %v", err)
	}
	loaded := mustClient(t, now)
	if _, err := loaded.LoadCache(path, time.Hour); err == nil {
		t.Fatalf("expected an error for a corrupt cache file")
	}
	if _, err := loaded.LoadCache(filepath.Join(t.TempDir(), "missing.json"), time.Hour); err != nil {
		t.Fatalf("missing cache file must be non-fatal, got %v", err)
	}
}
