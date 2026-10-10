package ooni

import (
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
		{Confirmed: true, MeasurementStartTime: "2026-10-01T12:00:00Z"},     // 9 days
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
